use ahash::HashMap;
use byteorder::{ByteOrder, NetworkEndian};
use color_eyre::{
    eyre::{bail, eyre, WrapErr},
    Result,
};
use macaddr::MacAddr6 as MacAddress;
use std::convert::{TryFrom, TryInto};
use std::fs::read_to_string;
use std::net::Ipv4Addr;
use toml::Value;

// Header setting taken from Demikernel's catnip OS:
// https://github.com/demikernel/demikernel/blob/master/src/rust/catnip/src/protocols/
pub const ETHERNET2_HEADER2_SIZE: usize = 14;
pub const IPV4_HEADER2_SIZE: usize = 20;
pub const UDP_HEADER2_SIZE: usize = 8;
pub const DEFAULT_IPV4_TTL: u8 = 64;
pub const IPV4_IHL_NO_OPTIONS: u8 = 5;
pub const IPV4_VERSION: u8 = 4;
pub const IPPROTO_UDP: u8 = 17;
pub const HEADER_PADDING_SIZE: usize = 0;
pub const TOTAL_HEADER_SIZE: usize =
    ETHERNET2_HEADER2_SIZE + IPV4_HEADER2_SIZE + UDP_HEADER2_SIZE + HEADER_PADDING_SIZE;

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EtherType2 {
    Arp = 0x0806,
    Ipv4 = 0x0800,
}

impl TryFrom<u16> for EtherType2 {
    type Error = color_eyre::eyre::Error;

    fn try_from(n: u16) -> Result<Self> {
        if n == EtherType2::Arp as u16 {
            Ok(EtherType2::Arp)
        } else if n == EtherType2::Ipv4 as u16 {
            Ok(EtherType2::Ipv4)
        } else {
            bail!("Unsupported ether type: {}", n);
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct AddressInfo {
    pub udp_port: u16,
    pub ipv4_addr: Ipv4Addr,
    pub ether_addr: MacAddress,
}

impl Default for AddressInfo {
    fn default() -> AddressInfo {
        AddressInfo {
            udp_port: 12345,
            ipv4_addr: Ipv4Addr::LOCALHOST,
            ether_addr: MacAddress::default(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Default, Copy)]
pub struct HeaderInfo {
    pub src_info: AddressInfo,
    pub dst_info: AddressInfo,
}

#[inline]
pub fn write_udp_hdr(header_info: &HeaderInfo, buf: &mut [u8], data_len: usize) -> Result<()> {
    let fixed_buf: &mut [u8; UDP_HEADER2_SIZE] = (&mut buf[..UDP_HEADER2_SIZE]).try_into()?;
    NetworkEndian::write_u16(&mut fixed_buf[0..2], header_info.src_info.udp_port);
    NetworkEndian::write_u16(&mut fixed_buf[2..4], header_info.dst_info.udp_port);
    NetworkEndian::write_u16(&mut fixed_buf[4..6], (UDP_HEADER2_SIZE + data_len) as u16);
    // no checksum
    NetworkEndian::write_u16(&mut fixed_buf[6..8], 0);
    Ok(())
}

#[inline]
fn ipv4_checksum(buf: &[u8]) -> Result<u16> {
    let buf: &[u8; IPV4_HEADER2_SIZE] = buf.try_into()?;
    let mut state = 0xffffu32;
    for i in 0..5 {
        state += NetworkEndian::read_u16(&buf[(2 * i)..(2 * i + 2)]) as u32;
    }
    // Skip the 5th u16 since octets 10-12 are the header checksum, whose value should be zero when
    // computing a checksum.
    for i in 6..10 {
        state += NetworkEndian::read_u16(&buf[(2 * i)..(2 * i + 2)]) as u32;
    }
    while state > 0xffff {
        state -= 0xffff;
    }
    Ok(!state as u16)
}

#[inline]
pub fn write_ipv4_hdr(
    header_info: &HeaderInfo,
    buf: &mut [u8],
    data_len: usize,
    ip_id: u16,
) -> Result<()> {
    // currently, this only sets some fields
    let buf: &mut [u8; IPV4_HEADER2_SIZE] = buf.try_into()?;
    buf[..].copy_from_slice(&[0u8; IPV4_HEADER2_SIZE]);

    buf[0] = (IPV4_VERSION << 4) | IPV4_IHL_NO_OPTIONS; // version IHL
    NetworkEndian::write_u16(&mut buf[2..4], (IPV4_HEADER2_SIZE + data_len) as u16); // payload size
    NetworkEndian::write_u16(&mut buf[4..6], ip_id as u16); // IP ID
    buf[8] = DEFAULT_IPV4_TTL; // time to live
    buf[9] = IPPROTO_UDP; // next_proto_id

    buf[12..16].copy_from_slice(&header_info.src_info.ipv4_addr.octets());
    buf[16..20].copy_from_slice(&header_info.dst_info.ipv4_addr.octets());

    let checksum = ipv4_checksum(buf)?;
    NetworkEndian::write_u16(&mut buf[10..12], checksum);
    Ok(())
}

#[inline]
pub fn write_eth_hdr(header_info: &HeaderInfo, buf: &mut [u8]) -> Result<()> {
    let buf: &mut [u8; ETHERNET2_HEADER2_SIZE] = buf.try_into()?;
    buf[0..6].copy_from_slice(header_info.dst_info.ether_addr.as_bytes());
    buf[6..12].copy_from_slice(header_info.src_info.ether_addr.as_bytes());
    NetworkEndian::write_u16(&mut buf[12..14], EtherType2::Ipv4 as u16);
    Ok(())
}

pub fn parse_cfg(
    config_path: &std::path::Path,
) -> Result<(Vec<String>, Ipv4Addr, HashMap<Ipv4Addr, MacAddress>)> {
    let file_str = read_to_string(config_path)?;
    let mut cfg: Value = file_str.parse().wrap_err("parse TOML config")?;

    fn dpdk_cfg(mut dpdk_cfg: toml::Value) -> Result<Vec<String>> {
        let tab = dpdk_cfg
            .as_table_mut()
            .ok_or_else(|| eyre!("Dpdk config key not a table"))?;
        let arr = tab
            .remove("eal_init")
            .ok_or_else(|| eyre!("No eal_init entry in dpdk config"))?;
        match arr {
            Value::Array(dpdk_cfg) => {
                let r: Result<_> = dpdk_cfg
                    .into_iter()
                    .map(|s| match s {
                        Value::String(s) => Ok(s),
                        _ => Err(eyre!("eal_init value not a string array")),
                    })
                    .collect();
                Ok(r?)
            }
            _ => bail!("eal_init value not a string array"),
        }
    }

    fn net_cfg(mut net_cfg: toml::Value) -> Result<(Ipv4Addr, HashMap<Ipv4Addr, MacAddress>)> {
        let tab = net_cfg
            .as_table_mut()
            .ok_or_else(|| eyre!("Net config not a table"))?;
        let my_ip = tab.remove("ip").ok_or_else(|| eyre!("No ip in net"))?;
        let my_ip = my_ip
            .as_str()
            .ok_or_else(|| eyre!("ip value should be a string: {:?}", my_ip))?
            .parse()
            .wrap_err(eyre!("tried to parse {:?} as an IPv4 address", my_ip))?;

        let arp = tab
            .remove("arp")
            .ok_or_else(|| eyre!("No arp table in net"))?;
        let arp_table: Result<HashMap<_, _>, _> = match arp {
            Value::Array(arp_table) => arp_table
                .into_iter()
                .map(|v| match v {
                    Value::Table(arp_entry) => {
                        let ip: Ipv4Addr = arp_entry
                            .get("ip")
                            .ok_or_else(|| eyre!("no ip in arp entry"))?
                            .as_str()
                            .ok_or_else(|| eyre!("value not a string"))?
                            .parse()?;
                        let mac: MacAddress = arp_entry
                            .get("mac")
                            .ok_or_else(|| eyre!("no mac in arp entry"))?
                            .as_str()
                            .ok_or_else(|| eyre!("value not a string"))?
                            .parse()?;
                        Ok((ip, mac))
                    }
                    _ => bail!("arp table values should be dicts"),
                })
                .collect(),
            _ => bail!("arp table should be an array"),
        };

        Ok((my_ip, arp_table?))
    }

    cfg.as_table_mut()
        .ok_or_else(|| eyre!("Malformed TOML, want table structure with dpdk and net sections"))
        .and_then(|tab| {
            let dpdk_cfg = dpdk_cfg(
                tab.remove("dpdk")
                    .ok_or_else(|| eyre!("No entry dpdk in cfg"))?,
            )?;
            let (ip, arp) = net_cfg(
                tab.remove("net")
                    .ok_or_else(|| eyre!("No entry net in cfg"))?,
            )?;

            Ok((dpdk_cfg, ip, arp))
        })
}

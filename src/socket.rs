//! Socket-like API to DPDK.
//!
//! At a high level, one thread is responsible for calling `wrapper::rx_burst` and distributing
//! resulting packets, via channels, to the right `UdpDpdkSk`. Send-side is the same but in reverse.

use crate::{bindings::*, utils::TOTAL_HEADER_SIZE, wrapper::*};
use ahash::AHashMap as HashMap;
use color_eyre::{
    eyre::{bail, ensure, eyre, WrapErr},
    Result,
};
use flume::{Receiver, Sender};
use std::collections::BTreeSet;
use std::fs::read_to_string;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use tracing::{trace, warn};

#[derive(Debug)]
pub struct Msg {
    port: u16,
    addr: SocketAddrV4,
    buf: Vec<u8>,
}

pub struct DpdkConn {
    local_port: u16,
    free_ports: Arc<Mutex<BTreeSet<u16>>>,
    outgoing_pkts: Sender<Msg>,
    incoming_pkts: Receiver<Msg>,
}

impl DpdkConn {
    pub fn send(&self, to: SocketAddrV4, msg: Vec<u8>) -> Result<()> {
        self.outgoing_pkts.send(Msg {
            port: self.local_port,
            addr: to,
            buf: msg,
        })?;
        Ok(())
    }

    /// Receive a packet.
    ///
    /// Returns (from_addr, payload)
    pub fn recv(&self) -> Result<(SocketAddrV4, Vec<u8>)> {
        let Msg { addr, buf, port } = self.incoming_pkts.recv()?;
        assert_eq!(port, self.local_port, "Port mismatched");
        Ok((addr, buf))
    }
}

impl Drop for DpdkConn {
    fn drop(&mut self) {
        // put the port back
        self.free_ports.lock().unwrap().insert(self.local_port);
    }
}

struct NewConn {
    local_port: u16,
    ch: Sender<Msg>,
}

#[derive(Clone, Debug)]
pub struct DpdkIoKernelHandle {
    free_ports: Arc<Mutex<BTreeSet<u16>>>,
    new_conns: Sender<NewConn>,
    outgoing_pkts: Sender<Msg>,
}

impl DpdkIoKernelHandle {
    fn new(new_conns: Sender<NewConn>, outgoing_pkts: Sender<Msg>) -> Self {
        Self {
            free_ports: Arc::new(Mutex::new((1001..=65535).collect())), // all ports start free.
            new_conns,
            outgoing_pkts,
        }
    }

    pub fn socket(&self, bind: Option<u16>) -> Result<DpdkConn> {
        // assign a port.
        let mut free_ports_g = self.free_ports.lock().unwrap();
        let port = match bind {
            Some(p) => {
                ensure!(free_ports_g.remove(&p), "Requested port not available");
                p
            }
            None => {
                let port = {
                    *free_ports_g
                        .iter()
                        .next()
                        .ok_or_else(|| eyre!("No ports left"))?
                };
                free_ports_g.remove(&port);
                port
            }
        };

        let (incoming_s, incoming_r) = flume::bounded(16);
        let out_ch = self.outgoing_pkts.clone();

        self.new_conns
            .send(NewConn {
                local_port: port,
                ch: incoming_s,
            })
            .wrap_err("channel send to iokernel failed")?;

        Ok(DpdkConn {
            local_port: port,
            free_ports: self.free_ports.clone(),
            outgoing_pkts: out_ch,
            incoming_pkts: incoming_r,
        })
    }
}

/// Spin-polling DPDK datapath event loop.
///
/// There should only be one of these. It is responsible for calling `wrapper::tx_burst` and
/// `wrapper::rx_burst`, and doing bookkeeping associated with tracking connections.
pub struct DpdkIoKernel {
    eth_addr: rte_ether_addr,
    ip_addr: u32,
    port: u16,
    mbuf_pool: *mut rte_mempool,
    new_conns: Receiver<NewConn>,
    outgoing_pkts: Receiver<Msg>,
    conns: HashMap<u16, Sender<Msg>>,
}

impl DpdkIoKernel {
    /// Do global initialization
    // config file example:
    //   [dpdk]
    //   eal_init = ["-n", "4", "-w", "0000:08:00.0","--proc-type=auto"]
    //   [net]
    //   ip = "10.1.1.2"
    pub fn new(config_path: std::path::PathBuf) -> Result<(Self, DpdkIoKernelHandle)> {
        let (dpdk_config, ip_config) = parse_cfg(config_path.as_path())?;
        let (mbuf_pools, nb_ports) = dpdk_init(dpdk_config, 1)?;

        let mbuf_pool = mbuf_pools[0];
        let port = nb_ports - 1;

        // what is my ethernet address (rte_ether_addr struct)
        let my_eth = get_my_macaddr(port)?;
        // what is my IpAddr
        let octets = ip_config.octets();
        let my_ip: u32 = unsafe { make_ip(octets[0], octets[1], octets[2], octets[3]) };

        // make connection tracking state.
        let (new_conns_s, new_conns_r) = flume::unbounded();
        let (outgoing_pkts_s, outgoing_pkts_r) = flume::bounded(16); // 16 is the max burst size
        let conns = Default::default();

        Ok((
            Self {
                eth_addr: my_eth,
                ip_addr: my_ip,
                port,
                mbuf_pool,
                new_conns: new_conns_r,
                outgoing_pkts: outgoing_pkts_r,
                conns,
            },
            DpdkIoKernelHandle::new(new_conns_s, outgoing_pkts_s),
        ))
    }

    /// Iokernel event loop.
    ///
    /// Responsibilities:
    /// 1. dpdk-poll for incoming packets,
    ///   1a. associate them with existing connections
    ///   1b. channel-send if connection, drop if not
    /// 2. channel-wait for outgoing packets, and transmit them.
    /// 3. channel-wait for new connections
    pub fn run(mut self) {
        let mut rx_bufs: [*mut rte_mbuf; RECEIVE_BURST_SIZE as usize] = unsafe { zeroed() };
        let mut tx_bufs: [*mut rte_mbuf; RECEIVE_BURST_SIZE as usize] = unsafe { zeroed() };

        loop {
            // 1. first try to receive.
            let num_received = unsafe {
                rte_eth_rx_burst(
                    self.port,
                    0,
                    rx_bufs.as_mut_ptr(),
                    RECEIVE_BURST_SIZE as u16,
                )
            } as usize;
            let mut num_valid = 0;
            for i in 0..num_received {
                // first: parse if valid packet, and what the payload size is
                let (is_valid, src_ip, src_port, dst_port, payload_length) =
                    unsafe { parse_packet(rx_bufs[i], &self.eth_addr as _, self.ip_addr) };
                if !is_valid {
                    unsafe { free_mbuf(rx_bufs[i]) };
                    continue;
                }

                num_valid += 1;
                trace!(?num_valid, "Received valid packet");
                match self.conns.get(&dst_port) {
                    Some(ch) => {
                        let [oct1, oct2, oct3, oct4] = src_ip.to_be_bytes();
                        let pkt_src_ip = Ipv4Addr::new(oct1, oct2, oct3, oct4);
                        let pkt_src_addr = SocketAddrV4::new(pkt_src_ip, src_port);
                        let payload =
                            unsafe { mbuf_slice!(rx_bufs[i], TOTAL_HEADER_SIZE, payload_length) };
                        let msg = Msg {
                            port: dst_port,
                            addr: pkt_src_addr,
                            buf: payload.to_vec(),
                        };
                        ch.send(msg).unwrap();
                    }
                    None => {
                        trace!(?dst_port, "Got packet for unassigned port, dropping");
                    }
                }
            }

            // 2. second, see if we have anything to send.
            let mut i = 0;
            while let Ok(Msg {
                buf,
                addr: to_addr,
                port: src_port,
            }) = self.outgoing_pkts.try_recv()
            {
                let to_ip = to_addr.ip().octets();
                let to_port = to_addr.port();
                unsafe {
                    tx_bufs[i] = alloc_mbuf(self.mbuf_pool).unwrap();
                    // fill header
                    fill_in_packet_header(
                        tx_bufs[i],
                        &self.eth_addr as _,
                        todo!(), // TODO need to hardcode an arp table
                        self.ip_addr,
                        u32::from_be_bytes(to_ip),
                        src_port,
                        to_port,
                        buf.len(),
                    );

                    // write payload
                    let payload_slice = mbuf_slice!(tx_bufs[i], TOTAL_HEADER_SIZE, buf.len());
                    rte_memcpy_wrapper(
                        payload_slice.as_mut_ptr() as _,
                        buf.as_ptr() as _,
                        buf.len(),
                    );
                }

                i += 1;
            }

            if i > 16 {
                warn!(?i, "tx_burst size > 16");
            }

            if let Err(err) = unsafe { tx_burst(self.port, 0, tx_bufs.as_mut_ptr(), 16) } {
                warn!(?err, "tx_burst error");
            }

            // 3. third, check for new connections
            while let Ok(NewConn { local_port, ch }) = self.new_conns.try_recv() {
                if let Some(c) = self.conns.insert(local_port, ch) {
                    warn!(?local_port, "Port double allocated");
                    self.conns.insert(local_port, c);
                }
            }
        }
    }
}

fn parse_cfg(config_path: &std::path::Path) -> Result<(Vec<String>, Ipv4Addr)> {
    let file_str = read_to_string(config_path)?;
    let mut cfg: toml::Value = file_str.parse().wrap_err("parse TOML config")?;

    fn dpdk_cfg(mut dpdk_cfg: toml::Value) -> Result<Vec<String>> {
        dpdk_cfg
            .as_table_mut()
            .ok_or_else(|| eyre!("Dpdk config key not a table"))
            .and_then(|tab| {
                let (was_eal, dpdk_cfg): (Vec<_>, Vec<_>) = tab
                    .iter()
                    .map(|(k, v)| (k == "eal_init", format!("{}={}", k, v)))
                    .unzip();
                ensure!(
                    was_eal.iter().any(|x| *x),
                    "No eal_init entry in dpdk config"
                );
                Ok(dpdk_cfg)
            })
    }

    fn net_cfg(mut net_cfg: toml::Value) -> Result<Ipv4Addr> {
        net_cfg
            .as_table_mut()
            .ok_or_else(|| eyre!("Net config not a table"))
            .and_then(|tab| {
                let s = tab.remove("ip").ok_or_else(|| eyre!("No ip in net"))?;
                match s {
                    toml::value::Value::String(s) => Ok(s.parse()?),
                    _ => bail!("ip value should be a string"),
                }
            })
    }

    cfg.as_table_mut()
        .ok_or_else(|| eyre!("Malformed TOML, want table structure with dpdk and net sections"))
        .and_then(|tab| {
            let dpdk_cfg = dpdk_cfg(
                tab.remove("dpdk")
                    .ok_or_else(|| eyre!("No entry dpdk in cfg"))?,
            )?;
            let ip = net_cfg(
                tab.remove("net")
                    .ok_or_else(|| eyre!("No entry net in cfg"))?,
            )?;

            Ok((dpdk_cfg, ip))
        })
}

pub struct UdpDpdkSk {
    outgoing: flume::Sender<Vec<u8>>,
    incoming: flume::Receiver<Vec<u8>>,
}

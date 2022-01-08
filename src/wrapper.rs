use crate::bindings::*;
use crate::utils;
use color_eyre::eyre::{bail, ensure, eyre, Result, WrapErr};
use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
    ptr,
    time::Duration,
};
use tracing::{debug, info, trace, warn};

#[inline]
unsafe fn dpdk_error(func_name: &str, retval: Option<std::os::raw::c_int>) -> Result<()> {
    let mut errno = match retval {
        Some(x) => x,
        None => rte_errno(),
    };
    if errno < 0 {
        errno *= -1;
    }
    let c_buf = rte_strerror(errno);
    let c_str: &CStr = CStr::from_ptr(c_buf);
    let str_slice: &str = c_str.to_str().unwrap();
    bail!(
        "Exiting from {}: Error {}: {:?}",
        func_name,
        errno,
        str_slice
    );
}

#[inline]
unsafe fn dpdk_check(func_name: &str, ret: ::std::os::raw::c_int, use_errno: bool) -> Result<()> {
    if ret != 0 {
        if use_errno {
            dpdk_error(func_name, None)?;
        } else {
            dpdk_error(func_name, Some(ret))?;
        }
    }
    Ok(())
}

macro_rules! dpdk_check_not_failed (
    ($x: ident ($($arg: expr),*)) =>  {{
        let ret = $x($($arg),*);
        if ret == -1 {
            dpdk_error(stringify!($x), None)?;
        }
    }};
    ($x: ident ($($arg: expr),*), $str: expr) => {{
        let ret = $x($($arg),*);
        if (ret == -1) {
            bail!("Exiting from {}: Error {}", stringify!($x), $str);
        }
        ret
    }};
);

macro_rules! dpdk_ok (
    ($x: ident ($($arg: expr),*)) => {
        dpdk_check(stringify!($x), $x($($arg),*), false).wrap_err(eyre!("Error running dpdk function {}", stringify!($x)))?
    };
    ($x: ident ($($arg: expr),*), $y: ident ($($arg2: expr),*)) => {
        match dpdk_check(stringify!($x), $x($($arg),*)) {
            Ok(_) => {}
            Err(e) => {
                // y is an error function to call
                $y($($arg2),*);
                bail!("{:?}", e);
            }
        }
    };
);

unsafe fn print_error() -> String {
    let errno = rte_errno();
    let c_buf = rte_strerror(errno);
    let c_str: &CStr = CStr::from_ptr(c_buf);
    let str_slice: &str = c_str.to_str().unwrap();
    format!("Error {}: {:?}", errno, str_slice)
}

/// Constants related to DPDK
pub const NUM_MBUFS: u16 = 8191;
pub const MBUF_CACHE_SIZE: u16 = 250;
const RX_RING_SIZE: u16 = 2048;
const TX_RING_SIZE: u16 = 2048;
pub const MAX_SCATTERS: usize = 33;
pub const RECEIVE_BURST_SIZE: u16 = 16;
pub const MEMPOOL_MAX_SIZE: usize = 65536;

pub const RX_PACKET_LEN: u32 = 9216;
pub const MBUF_BUF_SIZE: u32 = RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM;
pub const MBUF_PRIV_SIZE: usize = 8;
/// RX and TX Prefetch, Host, and Write-back threshold values should be
/// carefully set for optimal performance. Consult the network
/// controller's datasheet and supporting DPDK documentation for guidance
/// on how these parameters should be set.
const RX_PTHRESH: u8 = 8;
const RX_HTHRESH: u8 = 8;
const RX_WTHRESH: u8 = 0;

/// These default values are optimized for use with the Intel(R) 82599 10 GbE
/// Controller and the DPDK ixgbe PMD. Consider using other values for other
/// network controllers and/or network drivers.
const TX_PTHRESH: u8 = 0;
const TX_HTHRESH: u8 = 0;
const TX_WTHRESH: u8 = 0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MempoolPtr(pub *mut rte_mempool);
unsafe impl Send for MempoolPtr {}

fn dpdk_eal_init(eal_init: Vec<String>) -> Result<()> {
    let mut args = vec![];
    let mut ptrs = vec![];
    for entry in eal_init.iter() {
        let s = CString::new(entry.as_str()).unwrap();
        ptrs.push(s.as_ptr() as *mut u8);
        args.push(s);
    }

    debug!("DPDK init args: {:?}", args);
    // SAFETY: initialization, which is safe.
    unsafe { dpdk_check_not_failed!(rte_eal_init(ptrs.len() as i32, ptrs.as_ptr() as *mut _)) };
    Ok(())
}

fn wait_for_link_status_up(port_id: u16) -> Result<()> {
    let sleep_duration_ms = Duration::from_millis(100);
    let retry_count: u32 = 90;

    let mut link: MaybeUninit<rte_eth_link> = MaybeUninit::zeroed();
    for _i in 0..retry_count {
        let link = unsafe {
            dpdk_ok!(rte_eth_link_get_nowait(port_id, link.as_mut_ptr()));
            link.assume_init()
        };
        if ETH_LINK_UP == link.link_status() as u32 {
            let duplex = if link.link_duplex() as u32 == ETH_LINK_FULL_DUPLEX {
                "full"
            } else {
                "half"
            };
            info!(?port_id, speed_mbps = ?link.link_speed, ?duplex, "Link Up");
            return Ok(());
        }
        unsafe { rte_delay_us_block(sleep_duration_ms.as_micros() as u32) };
    }

    warn!(?port_id, "Link did not start");
    bail!("Link never came up");
}

unsafe fn initialize_dpdk_port(
    port_id: u16,
    num_queues: u16,
    rx_mbuf_pools: &Vec<*mut rte_mempool>,
) -> Result<()> {
    ensure!(
        num_queues as usize == rx_mbuf_pools.len(),
        format!(
            "Mbuf pool list length {} not the same as num_queues {}",
            rx_mbuf_pools.len(),
            num_queues
        )
    );
    assert_eq!(rte_eth_dev_is_valid_port(port_id), 1);
    let rx_rings: u16 = num_queues;
    let tx_rings: u16 = num_queues;
    let nb_rxd = RX_RING_SIZE;
    let nb_txd = TX_RING_SIZE;

    let mut rx_conf: MaybeUninit<rte_eth_rxconf> = MaybeUninit::zeroed();
    (*rx_conf.as_mut_ptr()).rx_thresh.pthresh = RX_PTHRESH;
    (*rx_conf.as_mut_ptr()).rx_thresh.hthresh = RX_HTHRESH;
    (*rx_conf.as_mut_ptr()).rx_thresh.wthresh = RX_WTHRESH;
    (*rx_conf.as_mut_ptr()).rx_free_thresh = 32;

    let mut tx_conf: MaybeUninit<rte_eth_txconf> = MaybeUninit::zeroed();
    (*tx_conf.as_mut_ptr()).tx_thresh.pthresh = TX_PTHRESH;
    (*tx_conf.as_mut_ptr()).tx_thresh.hthresh = TX_HTHRESH;
    (*tx_conf.as_mut_ptr()).tx_thresh.wthresh = TX_WTHRESH;

    eth_dev_configure(port_id, rx_rings, tx_rings);

    let socket_id =
        dpdk_check_not_failed!(rte_eth_dev_socket_id(port_id), "Port id is out of range") as u32;

    // allocate and set up 1 RX queue per Ethernet port
    for i in 0..rx_rings {
        trace!(?i, "Initializing rx ring");
        dpdk_ok!(rte_eth_rx_queue_setup(
            port_id,
            i,
            nb_rxd,
            socket_id,
            rx_conf.as_mut_ptr(),
            rx_mbuf_pools[i as usize]
        ));
    }

    for i in 0..tx_rings {
        trace!(?i, "Initializing tx ring");
        dpdk_ok!(rte_eth_tx_queue_setup(
            port_id,
            i,
            nb_txd,
            socket_id,
            tx_conf.as_mut_ptr()
        ));
    }

    // start the ethernet port
    trace!(?port_id, "starting port");
    dpdk_ok!(rte_eth_dev_start(port_id));

    // disable rx/tx flow control
    // TODO: why?

    trace!(?port_id, "port started, doing flow control");
    let mut fc_conf: MaybeUninit<rte_eth_fc_conf> = MaybeUninit::zeroed();
    dpdk_ok!(rte_eth_dev_flow_ctrl_get(port_id, fc_conf.as_mut_ptr()));
    (*fc_conf.as_mut_ptr()).mode = rte_eth_fc_mode_RTE_FC_NONE;
    dpdk_ok!(rte_eth_dev_flow_ctrl_set(port_id, fc_conf.as_mut_ptr()));

    trace!(?port_id, "waiting for link up");
    wait_for_link_status_up(port_id)?;
    Ok(())
}

/// Creates a mempool with the given value size, and number of values.
pub fn create_mempool(
    name: &str,
    nb_ports: u16,
    data_size: usize,
    num_values: usize,
) -> Result<*mut rte_mempool> {
    let name_str = CString::new(name)?;

    // SAFETY: only initializes things.
    unsafe {
        let mbuf_pool = rte_pktmbuf_pool_create(
            name_str.as_ptr(),
            (num_values as u16 * nb_ports) as u32,
            MBUF_CACHE_SIZE as u32,
            MBUF_PRIV_SIZE as u16,
            data_size as u16, // TODO: add headroom?
            rte_socket_id() as i32,
        );

        if mbuf_pool.is_null() {
            warn!(error=?print_error(), "mbuf pool is null.");
        }

        ensure!(!mbuf_pool.is_null(), "mbuf pool null");

        // initialize private data
        if rte_mempool_obj_iter(mbuf_pool, Some(custom_init_priv()), ptr::null_mut())
            != (num_values as u16 * nb_ports) as u32
        {
            rte_mempool_free(mbuf_pool);
            bail!("Not able to initialize private data in pool: failed on custom_init_priv.");
        }

        Ok(mbuf_pool)
    }
}

fn create_native_mempool(name: &str, nb_ports: u16) -> Result<*mut rte_mempool> {
    create_mempool(name, nb_ports, MBUF_BUF_SIZE as _, NUM_MBUFS.into())
}

/// Initializes DPDK ports, and memory pools.
/// Returns mempool that allocates mbufs with `MBUF_BUF_SIZE` of buffer space.
fn dpdk_init_helper(num_cores: usize) -> Result<(Vec<*mut rte_mempool>, u16)> {
    // SAFETY: only initializes things.
    unsafe {
        let nb_ports = rte_eth_dev_count_avail();
        info!(?nb_ports, "DPDK available ports",);
        if nb_ports <= 0 {
            bail!("DPDK INIT: No ports available.");
        }

        let mut default_pools: Vec<*mut rte_mempool> = Vec::new();
        for i in 0..num_cores {
            let name = format!("default_mbuf_pool_{}", i);
            let mbuf_pool = create_native_mempool(&name, nb_ports).wrap_err(format!(
                "Not able to create mbuf pool {} in dpdk_init.",
                nb_ports
            ))?;
            default_pools.push(mbuf_pool);
        }

        let mut found_port = None;
        let owner = RTE_ETH_DEV_NO_OWNER as u64;
        let mut p = rte_eth_find_next_owned_by(0, owner) as u16;
        while p < RTE_MAX_ETHPORTS as u16 {
            if let Ok(_) = initialize_dpdk_port(p, num_cores as u16, &default_pools) {
                found_port = Some(1);
                break;
            }

            p = rte_eth_find_next_owned_by(p + 1, owner) as u16;
        }

        Ok((
            default_pools,
            found_port.ok_or_else(|| eyre!("No ports came up"))?,
        ))
    }
}

/// Initializes DPDK EAL and ports.
///
/// Returns mempool that allocates mbufs with `MBUF_BUF_SIZE` of buffer space.
///
/// Arguments:
/// * eal_args: - DPDK eal initialization args.
pub fn dpdk_init(eal_args: Vec<String>, num_cores: usize) -> Result<(Vec<*mut rte_mempool>, u16)> {
    dpdk_eal_init(eal_args).wrap_err("EAL initialization failed.")?;

    // init ports, mempools on the rx side
    dpdk_init_helper(num_cores)
}

/// Returns the result of a mutable ptr to an rte_mbuf allocated from a particular mempool.
///
/// Arguments:
/// * mempool - *mut rte_mempool where packet should be allocated from.
///
/// Safety:
/// * `mempool` must be valid.
#[inline]
pub unsafe fn alloc_mbuf(mempool: *mut rte_mempool) -> Result<*mut rte_mbuf> {
    let mbuf = rte_pktmbuf_alloc(mempool);
    if mbuf.is_null() {
        warn!(
            avail_count = rte_mempool_avail_count(mempool),
            "Amount of mbufs available in mempool"
        );
        bail!("Allocated null mbuf from rte_pktmbuf_alloc.");
    }

    Ok(mbuf)
}

/// Takes an rte_mbuf, header information, and adds:
/// (1) An Ethernet header
/// (2) An Ipv4 header
/// (3) A Udp header
///
/// Arguments:
/// * pkt - The rte_mbuf where header information will be filled in.
/// * header_info - Struct that contains information about udp, ethernet, and ipv4 headers.
/// * data_len - The payload size, as these headers depend on knowing the size of the upcoming
/// payloads.
#[inline]
pub(crate) unsafe fn fill_in_header(
    pkt: *mut rte_mbuf,
    header_info: &utils::HeaderInfo,
    data_len: usize,
    ip_id: u16,
) -> Result<usize> {
    let eth_hdr_slice = mbuf_slice!(pkt, 0, utils::ETHERNET2_HEADER2_SIZE);
    utils::write_eth_hdr(header_info, eth_hdr_slice)?;

    let ipv4_hdr_slice = mbuf_slice!(pkt, utils::ETHERNET2_HEADER2_SIZE, utils::IPV4_HEADER2_SIZE);
    utils::write_ipv4_hdr(
        header_info,
        ipv4_hdr_slice,
        data_len + utils::UDP_HEADER2_SIZE,
        ip_id,
    )?;

    let udp_hdr_slice = mbuf_slice!(
        pkt,
        utils::ETHERNET2_HEADER2_SIZE + utils::IPV4_HEADER2_SIZE,
        utils::UDP_HEADER2_SIZE
    );
    utils::write_udp_hdr(header_info, udp_hdr_slice, data_len)?;

    Ok(utils::TOTAL_HEADER_SIZE)
}

/// Returns mac address given the port id.
#[inline]
pub fn get_my_macaddr(port_id: u16) -> Result<rte_ether_addr> {
    let mut ether_addr: MaybeUninit<rte_ether_addr> = MaybeUninit::zeroed();
    let ether_addr = unsafe {
        dpdk_ok!(rte_eth_macaddr_get(port_id, ether_addr.as_mut_ptr()));
        ether_addr.assume_init()
    };

    Ok(ether_addr)
}

/// Sends the specified linked list of mbufs.
/// Returns () if the packets were sent successfully.
/// Returns an error if they were not sent for some reason.
///
/// Arguments:
/// * port_id - u16 - port_id corresponding to the ethernet device.
/// * queue_id - u16 - index of the transmit queue through which output packets will be sent. Must
/// be in the range of queue ids configured via rte_eth_dev_configure().
/// * tx_pkts - Address of an array of nb_pkts pointers to rte_mbuf data structures which represent
/// the output packets.
/// * nb_pkts - Maximum packets to transmit.
///
/// Safety:
/// * tx_pkts must be valid.
#[inline]
pub unsafe fn tx_burst(
    port_id: u16,
    queue_id: u16,
    tx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> Result<()> {
    let mut num_sent: u16 = 0;
    while num_sent < nb_pkts {
        // TODO: should this be in a tight loop?
        num_sent = rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
    }

    trace!(?num_sent, "tx_burst");
    Ok(())
}

pub struct RxPkt {
    idx: usize,
    addr_info: utils::AddressInfo,
    payload_length: usize,
}

/// Tries to receive packets on the given transmit queue for the given ethernet advice.
///
/// Returns RxPkt: (index into `rx_pkts`, addr info, payload length)
/// Frees any invalid packets.  On error, bails out.
///
/// Arguments:
/// * port_id - u16 - port_id corresponding to the ethernet device.
/// * queue_id - u16 - index of the receive queue through which received packets will be sent. Must
/// be in the range of queue ids configured via rte_eth_dev_configure().
/// * rx_pkts - Address of an array, of size nb_pkts, of rte_mbuf data structure pointers, to put
/// the received packets.
/// * nb_pkts - Maximum burst size to receive.
///
/// Safety:
/// * `rx_pkts` must be valid.
#[inline]
pub unsafe fn rx_burst(
    port_id: u16,
    queue_id: u16,
    rx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
    my_addr_info: &utils::AddressInfo,
) -> Result<Vec<RxPkt>> {
    let num_received = rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
    Ok((0..num_received)
        .filter_map(|i| {
            let pkt = *(rx_pkts.offset(i as isize));
            match check_valid_packet(pkt, my_addr_info) {
                Some((addr_info, payload_length)) => Some(RxPkt {
                    idx: i as usize,
                    addr_info,
                    payload_length,
                }),
                None => {
                    trace!("Queue {} received invalid packet, idx {}", queue_id, i,);
                    rte_pktmbuf_free(pkt);
                    None
                }
            }
        })
        .collect())
}

/// Checks if the payload in the received mbuf is valid.
/// This filters for:
/// (1) packets with the right destination eth addr
/// (2) packets with the protocol UDP in the ip header, and the right destination IP address.
/// (3) packets with the right destination udp port in the udp header.
/// Returns the msg ID, and header info for the parse packet.
///
/// Arguments:
/// pkt - *mut rte_mbuf : pointer to rte_mbuf to check validity for.
///
/// Safety:
/// * `pkt` must be valid.
#[inline]
unsafe fn check_valid_packet(
    pkt: *mut rte_mbuf,
    my_addr_info: &utils::AddressInfo,
) -> Option<(utils::AddressInfo, usize)> {
    let eth_hdr_slice = mbuf_slice!(pkt, 0, utils::ETHERNET2_HEADER2_SIZE);
    let src_eth = match utils::check_eth_hdr(eth_hdr_slice, &my_addr_info.ether_addr) {
        Ok((eth, _)) => eth,
        Err(_) => {
            return None;
        }
    };

    let ipv4_hdr_slice = mbuf_slice!(pkt, utils::ETHERNET2_HEADER2_SIZE, utils::IPV4_HEADER2_SIZE);

    let src_ip = match utils::check_ipv4_hdr(ipv4_hdr_slice, &my_addr_info.ipv4_addr) {
        Ok((ip, _)) => ip,
        Err(_) => {
            return None;
        }
    };

    let udp_hdr_slice = mbuf_slice!(
        pkt,
        utils::ETHERNET2_HEADER2_SIZE + utils::IPV4_HEADER2_SIZE,
        utils::UDP_HEADER2_SIZE
    );

    let (src_port, udp_data_len) = match utils::check_udp_hdr(udp_hdr_slice, my_addr_info.udp_port)
    {
        Ok((port, _, size)) => (port, size),
        Err(_) => {
            return None;
        }
    };

    Some((
        (utils::AddressInfo::new(src_port, src_ip, src_eth)),
        udp_data_len - 4,
    ))
}

/// Safety:
/// `pkt` must be valid.
pub unsafe fn refcnt(pkt: *mut rte_mbuf) -> u16 {
    rte_pktmbuf_refcnt_read(pkt)
}

/// Frees the mbuf, returns it to it's original mempool.
///
/// Arguments:
/// * pkt - *mut rte_mbuf to free.
///
/// Safety:
/// `pkt` must be valid.
#[inline]
pub unsafe fn free_mbuf(pkt: *mut rte_mbuf) {
    debug!(packet=?pkt, cur_refcnt=rte_pktmbuf_refcnt_read(pkt), "Called free_mbuf on packet");
    rte_pktmbuf_refcnt_update_or_free(pkt, -1);
}

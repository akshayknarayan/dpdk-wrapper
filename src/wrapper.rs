use crate::bindings::*;
use crate::utils;
use color_eyre::eyre::{bail, ensure, eyre, Report, Result, WrapErr};
use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
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
        dpdk_check(stringify!($x), $x($($arg),*), false).wrap_err_with(|| eyre!("Error running dpdk function {}", stringify!($x)))?
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
//const RX_RING_SIZE: u16 = 2048;
//const TX_RING_SIZE: u16 = 2048;
const RX_RING_SIZE: u16 = 256;
const TX_RING_SIZE: u16 = 256;
pub const RECEIVE_BURST_SIZE: u16 = 16;

pub const MBUF_BUF_SIZE: u32 = RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM;
pub const MBUF_PRIV_SIZE: usize = 0;
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
    rx_mbuf_pools: &[*mut rte_mempool],
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

    let rx_conf = rte_eth_rxconf {
        rx_thresh: rte_eth_thresh {
            pthresh: RX_PTHRESH,
            hthresh: RX_HTHRESH,
            wthresh: RX_WTHRESH,
        },
        rx_free_thresh: 32,
        rx_drop_en: 0,
        rx_deferred_start: 0,
        rx_nseg: 0,
        offloads: 0,
        rx_seg: std::ptr::null_mut(),
        reserved_64s: [0, 0],
        reserved_ptrs: [std::ptr::null_mut(), std::ptr::null_mut()],
    };

    let tx_conf = rte_eth_txconf {
        tx_thresh: rte_eth_thresh {
            pthresh: TX_PTHRESH,
            hthresh: TX_HTHRESH,
            wthresh: TX_WTHRESH,
        },
        tx_rs_thresh: 0,
        tx_free_thresh: 0,
        tx_deferred_start: 0,
        offloads: 0,
        reserved_64s: [0, 0],
        reserved_ptrs: [std::ptr::null_mut(), std::ptr::null_mut()],
    };

    dpdk_ok!(eth_dev_configure(port_id, rx_rings, tx_rings));
    debug!("eth_dev_configure ok");

    // can be -1, which == SOCKET_ID_ANY, so cast is ok
    static_assert!(SOCKET_ID_ANY == -1);
    let socket_id = rte_eth_dev_socket_id(port_id) as u32;

    // allocate and set up 1 RX queue per Ethernet port
    for i in 0..rx_rings {
        debug!(?i, "Initializing rx ring");
        dpdk_ok!(rte_eth_rx_queue_setup(
            port_id,
            i,
            RX_RING_SIZE,
            socket_id,
            &rx_conf as _,
            rx_mbuf_pools[i as usize]
        ));
    }

    for i in 0..tx_rings {
        debug!(?i, "Initializing tx ring");
        dpdk_ok!(rte_eth_tx_queue_setup(
            port_id,
            i,
            TX_RING_SIZE,
            socket_id,
            &tx_conf as _
        ));
    }

    // start the ethernet port
    debug!(?port_id, "starting port");
    dpdk_ok!(rte_eth_dev_start(port_id));

    // disable rx/tx flow control
    debug!(?port_id, "port started, doing flow control");
    let mut fc_conf: MaybeUninit<rte_eth_fc_conf> = MaybeUninit::zeroed();
    dpdk_ok!(rte_eth_dev_flow_ctrl_get(port_id, fc_conf.as_mut_ptr()));
    (*fc_conf.as_mut_ptr()).mode = rte_eth_fc_mode_RTE_FC_NONE;
    dpdk_ok!(rte_eth_dev_flow_ctrl_set(port_id, fc_conf.as_mut_ptr()));

    debug!(?port_id, "waiting for link up");
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
            data_size as u16,
            rte_socket_id() as i32,
        );

        if mbuf_pool.is_null() {
            warn!(error=?print_error(), "mbuf pool is null.");
        }

        ensure!(!mbuf_pool.is_null(), "mbuf pool null");
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

        let mut found_port = Err(eyre!("Tried {} ports, none came up", nb_ports));
        let owner = RTE_ETH_DEV_NO_OWNER as u64;
        let mut p = rte_eth_find_next_owned_by(0, owner) as u16;
        while p < RTE_MAX_ETHPORTS as u16 {
            match initialize_dpdk_port(p, num_cores as u16, &default_pools) {
                Ok(_) => {
                    found_port = Ok(1);
                    break;
                }
                Err(e) => {
                    found_port = found_port.map_err(|err| err.wrap_err(e));
                }
            }

            p = rte_eth_find_next_owned_by(p + 1, owner) as u16;
        }

        Ok((default_pools, found_port?))
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

    let num_lcores = unsafe { rte_lcore_count() };
    debug!(?num_lcores, "lcore info");

    // init ports, mempools on the rx side
    dpdk_init_helper(num_cores)
}

pub fn affinitize_thread(core: usize) -> Result<()> {
    let err = unsafe { affinitize(core as _) };
    ensure!(err >= 0, "rte_thread_set_affinity failed");
    Ok(())
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
pub unsafe fn fill_in_header(
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
        num_sent += rte_eth_tx_burst(
            port_id,
            queue_id,
            tx_pkts.offset(num_sent as isize),
            nb_pkts - num_sent,
        );
    }

    trace!(?num_sent, "tx_burst");
    Ok(())
}

/// A handle to a flow steering entry.
///
/// This is `must_use` because its Drop impl will delete the flow steering entry.
#[must_use]
pub struct FlowSteeringHandle {
    dpdk_port: u16,
    udp_port: u16,
    handle: *mut rte_flow,
}

// SAFETY: This is not by-default Send because of the `*mut rte_flow`. It should in theory be
// possible to call `clear_flow_steering_` on a different core, but we will see if something breaks?
unsafe impl Send for FlowSteeringHandle {}

impl Drop for FlowSteeringHandle {
    fn drop(&mut self) {
        // deregister the rte_flow entry
        unsafe {
            if self.handle.is_null() {
                warn!("rte_flow pointer in FlowSteeringHandle is null");
                return;
            }
            let err = clear_flow_steering_(self.dpdk_port, self.handle);
            if err != 0 {
                warn!(?err, "Error clearing rte_flow entry");
                return;
            }
        }

        debug!(?self.udp_port, "Cleared flow steering rule");
    }
}

#[inline]
pub unsafe fn setup_flow_steering_solo(
    dpdk_port_id: u16,
    local_dst_port: u16,
    dst_queue_id: u16,
) -> Result<FlowSteeringHandle, Report> {
    let mut flow_handle = std::mem::MaybeUninit::uninit();
    let err = setup_flow_steering_solo_(
        dpdk_port_id,
        local_dst_port,
        dst_queue_id,
        flow_handle.as_mut_ptr(),
    );
    if err != 0 {
        let err_str = std::ffi::CStr::from_ptr(rte_strerror(err as _))
            .to_str()
            .unwrap_or_else(|_| "Unable to construct error string");
        return Err(eyre!("Error creating rte_flow entry: {}", err_str));
    }

    let flow_handle = flow_handle.assume_init();
    ensure!(!flow_handle.is_null(), "flow handle not initialized");
    Ok(FlowSteeringHandle {
        dpdk_port: dpdk_port_id,
        udp_port: local_dst_port,
        handle: flow_handle,
    })
}

#[inline]
pub unsafe fn setup_flow_steering_rss(
    dpdk_port_id: u16,
    local_dst_port: u16,
    dst_queue_ids: &[u16],
) -> Result<FlowSteeringHandle, Report> {
    ensure!(
        dst_queue_ids.len() > 1,
        "Need at least 2 dest-queues to RSS between"
    );

    let mut flow_handle = std::mem::MaybeUninit::uninit();
    let err = setup_flow_steering_rss_(
        dpdk_port_id,
        local_dst_port,
        dst_queue_ids.len() as _,
        dst_queue_ids.as_ptr(),
        flow_handle.as_mut_ptr(),
    );
    if err != 0 {
        let err_str = std::ffi::CStr::from_ptr(rte_strerror(err as _))
            .to_str()
            .unwrap_or_else(|_| "Unable to construct error string");
        return Err(eyre!("Error creating rte_flow entry: {}", err_str));
    }

    let flow_handle = flow_handle.assume_init();
    ensure!(!flow_handle.is_null(), "flow handle not initialized");

    Ok(FlowSteeringHandle {
        dpdk_port: dpdk_port_id,
        udp_port: local_dst_port,
        handle: flow_handle,
    })
}

#[inline]
pub unsafe fn flush_flow_steering(dpdk_port_id: u16) -> Result<(), Report> {
    let err = flush_flow_steering_(dpdk_port_id);
    if err != 0 {
        let err_str = std::ffi::CStr::from_ptr(rte_strerror(err as _))
            .to_str()
            .unwrap_or_else(|_| "Unable to construct error string");
        return Err(eyre!("Error flushing rte_flow rules: {}", err_str));
    }

    Ok(())
}

pub unsafe fn get_eth_stats(dpdk_port_id: u16) -> Result<rte_eth_stats, Report> {
    let mut stats = std::mem::MaybeUninit::uninit();
    let err = rte_eth_stats_get(dpdk_port_id, stats.as_mut_ptr());
    ensure!(err == 0, "Failed to get eth device stats");
    let stats = stats.assume_init();

    let num_elems = rte_eth_xstats_get_names(dpdk_port_id, std::ptr::null_mut(), 0);
    ensure!(num_elems >= 0, "Could not get names of xstats");
    if num_elems == 0 {
        debug!("no xstats");
        return Ok(stats);
    }

    let num_elems = num_elems as usize;

    let mut names: Vec<rte_eth_xstat_name> = Vec::with_capacity(num_elems);
    let name_slots = names.spare_capacity_mut();
    let res = rte_eth_xstats_get_names(
        dpdk_port_id,
        name_slots.as_mut_ptr() as *mut _,
        name_slots.len() as _,
    );
    ensure!(
        res > 0 && res as usize <= num_elems,
        "rte_eth_xstats_get_names LIED to us"
    );
    names.set_len(res as usize);
    let mut str_names = Vec::with_capacity(res as usize);
    for n in names {
        let s = std::ffi::CStr::from_ptr(n.name.as_ptr()).to_str()?;
        str_names.push(s.to_owned());
    }

    let mut values = Vec::with_capacity(num_elems);
    let values_slots = values.spare_capacity_mut();
    let res = rte_eth_xstats_get(
        dpdk_port_id,
        values_slots[0].as_mut_ptr(),
        values_slots.len() as _,
    );
    ensure!(
        res > 0 && res as usize <= num_elems,
        "rte_eth_xstats_get_names LIED to us"
    );
    values.set_len(res as usize);
    let values = values.into_iter().map(|v| v.value);

    // assemble the xstats hashmap
    let xstats: std::collections::HashMap<_, u64> = str_names.into_iter().zip(values).collect();
    debug!(?xstats, "xstats");

    Ok(stats)
}

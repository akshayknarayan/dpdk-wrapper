#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/dpdk_bindings.rs"));
}

pub use sys::*;

#[link(name = "inlined")]
extern "C" {
    pub fn rte_pktmbuf_alloc_(mp: *mut rte_mempool) -> *mut rte_mbuf;
    pub fn rte_pktmbuf_free_(packet: *mut rte_mbuf);
    pub fn rte_eth_tx_burst_(
        port_id: u16,
        queue_id: u16,
        tx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;
    pub fn rte_eth_rx_burst_(
        port_id: u16,
        queue_id: u16,
        rx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;
    pub fn rte_errno_() -> ::std::os::raw::c_int;
    pub fn rte_memcpy_(
        dst: *mut ::std::os::raw::c_void,
        src: *const ::std::os::raw::c_void,
        n: usize,
    );
    pub fn make_ip_(a: u8, b: u8, c: u8, d: u8) -> u32;
    pub fn parse_packet_(
        mbuf: *mut rte_mbuf,
        our_eth: *const rte_ether_addr,
        our_ip: u32,
        src_eth: *mut rte_ether_addr,
        ip_src_addr: *mut u32,
        udp_src_port: *mut u16,
        udp_dst_port: *mut u16,
        payload_len: *mut usize,
    ) -> bool;
    pub fn eth_dev_configure_(port_id: u16, rx_rings: u16, tx_rings: u16);
    pub fn affinitize_(core: u32) -> i32;
    pub fn lcore_count_() -> u32;
    pub fn lcore_id_() -> u32;
    pub fn get_lcore_map_(lcores: *mut u32, lcore_arr_size: u32) -> i32;
}

#[inline]
pub unsafe fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    rte_pktmbuf_alloc_(mp)
}

#[inline]
pub unsafe fn rte_pktmbuf_free(packet: *mut rte_mbuf) {
    rte_pktmbuf_free_(packet)
}

#[inline]
pub unsafe fn rte_eth_tx_burst(
    port_id: u16,
    queue_id: u16,
    tx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> u16 {
    rte_eth_tx_burst_(port_id, queue_id, tx_pkts, nb_pkts)
}

#[inline]
pub unsafe fn rte_eth_rx_burst(
    port_id: u16,
    queue_id: u16,
    rx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> u16 {
    rte_eth_rx_burst_(port_id, queue_id, rx_pkts, nb_pkts)
}

#[inline]
pub unsafe fn rte_errno() -> ::std::os::raw::c_int {
    rte_errno_()
}

#[inline]
pub unsafe fn rte_memcpy_wrapper(
    dst: *mut ::std::os::raw::c_void,
    src: *const ::std::os::raw::c_void,
    n: usize,
) {
    rte_memcpy_(dst, src, n);
}

#[inline]
pub unsafe fn make_ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    make_ip_(a, b, c, d)
}

#[inline]
pub unsafe fn parse_packet(
    mbuf: *mut rte_mbuf,
    our_eth: *const rte_ether_addr,
    our_ip: u32,
) -> (bool, rte_ether_addr, u32, u16, u16, usize) {
    let mut src_ether_addr: std::mem::MaybeUninit<rte_ether_addr> = std::mem::MaybeUninit::zeroed();
    let mut src_ip = 0u32;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut payload_len = 0usize;
    let valid = parse_packet_(
        mbuf,
        our_eth,
        our_ip,
        src_ether_addr.as_mut_ptr(),
        &mut src_ip as _,
        &mut src_port as _,
        &mut dst_port as _,
        &mut payload_len as _,
    );
    (
        valid,
        src_ether_addr.assume_init(),
        src_ip,
        src_port,
        dst_port,
        payload_len,
    )
}

#[inline]
pub unsafe fn eth_dev_configure(port_id: u16, rx_rings: u16, tx_rings: u16) {
    eth_dev_configure_(port_id, rx_rings, tx_rings);
}

#[inline]
pub unsafe fn affinitize(core: u32) -> i32 {
    affinitize_(core)
}

use color_eyre::eyre::{eyre, Report};

#[inline]
pub fn get_lcore_map() -> Result<Vec<u32>, Report> {
    let num_lcores = unsafe { lcore_count_() };
    let mut lcore_map = vec![0u32; num_lcores as _];
    let ok = unsafe { get_lcore_map_(lcore_map.as_mut_ptr(), num_lcores) };
    if ok < 0 {
        Err(eyre!("Error getting lcore map: Incorrect lcore_count or could not get local lcore_id. Thread may not be registered with EAL."))
    } else {
        Ok(lcore_map)
    }
}

#[inline]
pub fn get_lcore_id() -> u32 {
    unsafe { lcore_id_() }
}

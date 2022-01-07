#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/dpdk_bindings.rs"));

#[link(name = "inlined")]
extern "C" {
    pub fn mmap_huge_(
        num_pages: usize,
        addr: *mut *mut ::std::os::raw::c_void,
        paddrs: *mut usize,
    ) -> ::std::os::raw::c_int;

    pub fn munmap_huge_(addr: *mut ::std::os::raw::c_void, pgsize: usize, num_pages: usize);
    pub fn rte_mempool_count_(mempool: *mut rte_mempool) -> ::std::os::raw::c_int;
    pub fn rte_pktmbuf_refcnt_update_or_free_(packet: *mut rte_mbuf, val: i16);
    pub fn rte_pktmbuf_refcnt_set_(packet: *mut rte_mbuf, val: u16);
    pub fn rte_pktmbuf_refcnt_get_(packet: *mut rte_mbuf) -> u16;
    pub fn rte_pktmbuf_free_(packet: *mut rte_mbuf);
    pub fn rte_pktmbuf_alloc_(mp: *mut rte_mempool) -> *mut rte_mbuf;
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
    pub fn rte_get_timer_cycles_() -> u64;
    pub fn rte_get_timer_hz_() -> u64;
    pub fn general_free_cb_(addr: *mut ::std::os::raw::c_void, opaque: *mut ::std::os::raw::c_void);
    pub fn rte_memcpy_(
        dst: *mut ::std::os::raw::c_void,
        src: *const ::std::os::raw::c_void,
        n: usize,
    );
    pub fn rte_dev_dma_map_(
        device_id: u16,
        addr: *mut ::std::os::raw::c_void,
        iova: u64,
        len: size_t,
    ) -> ::std::os::raw::c_int;
    pub fn rte_dev_dma_unmap_(
        device_id: u16,
        addr: *mut ::std::os::raw::c_void,
        iova: u64,
        len: size_t,
    ) -> ::std::os::raw::c_int;

    pub fn custom_init_(
        mp: *mut rte_mempool,
        opaque_arg: *mut ::std::os::raw::c_void,
        m: *mut ::std::os::raw::c_void,
        i: u32,
    );

    pub fn custom_init_priv_(
        mp: *mut rte_mempool,
        opaque_arg: *mut ::std::os::raw::c_void,
        m: *mut ::std::os::raw::c_void,
        i: u32,
    );

    pub fn set_lkey_(packet: *mut rte_mbuf, lkey: u32);

    pub fn set_lkey_not_present_(packet: *mut rte_mbuf);

    pub fn set_refers_to_another_(packet: *mut rte_mbuf, val: u16);

    pub fn make_ip_(a: u8, b: u8, c: u8, d: u8) -> u32;

    pub fn fill_in_packet_header_(
        mbuf: *mut rte_mbuf,
        my_eth: *const rte_ether_addr,
        dst_eth: *const rte_ether_addr,
        my_ip: u32,
        dst_ip: u32,
        client_port: u16,
        server_port: u16,
        message_size: usize,
    ) -> usize;

    pub fn parse_packet_(
        mbuf: *mut rte_mbuf,
        our_eth: *const rte_ether_addr,
        our_ip: u32,
        ip_src_addr: *mut u32,
        udp_src_port: *mut u16,
        udp_dst_port: *mut u16,
        payload_len: *mut usize,
    ) -> bool;

    pub fn flip_headers_(mbuf: *mut rte_mbuf, id: u32);

    pub fn switch_headers_(rx_mbuf: *mut rte_mbuf, tx_mbuf: *mut rte_mbuf, payload_length: usize);

    pub fn shinfo_init_(
        extmem_addr: *mut ::std::os::raw::c_void,
        buf_len: *mut u16,
    ) -> *mut rte_mbuf_ext_shared_info;

    pub fn eth_dev_configure_(port_id: u16, rx_rings: u16, tx_rings: u16);

    pub fn compute_flow_affinity_(
        local_ip: u32,
        remote_ip: u32,
        local_port: u16,
        remote_port: u16,
        num_queues: usize,
    ) -> u32;

    pub fn set_checksums_(pkt: *mut rte_mbuf);

    pub fn copy_payload_(
        src_mbuf: *mut rte_mbuf,
        src_offset: usize,
        dst_mbuf: *mut rte_mbuf,
        dst_offset: usize,
        len: usize,
    );

    pub fn mem_lookup_page_phys_addrs_(
        addr: *mut ::std::os::raw::c_void,
        len: usize,
        pgsize: usize,
        paddrs: *mut usize,
    ) -> ::std::os::raw::c_int;
}

#[inline]
pub unsafe fn munmap_huge(addr: *mut ::std::os::raw::c_void, pgsize: usize, num_pages: usize) {
    munmap_huge_(addr, pgsize, num_pages);
}

#[inline]
pub unsafe fn mmap_huge(
    num_pages: usize,
    addr: *mut *mut ::std::os::raw::c_void,
    paddrs: *mut usize,
) -> ::std::os::raw::c_int {
    mmap_huge_(num_pages, addr, paddrs)
}

#[inline]
pub unsafe fn rte_mempool_count(mempool: *mut rte_mempool) -> ::std::os::raw::c_int {
    rte_mempool_count_(mempool)
}

#[inline]
pub unsafe fn rte_pktmbuf_refcnt_update_or_free(packet: *mut rte_mbuf, val: i16) {
    rte_pktmbuf_refcnt_update_or_free_(packet, val);
}

#[inline]
pub unsafe fn rte_pktmbuf_refcnt_set(packet: *mut rte_mbuf, val: u16) {
    rte_pktmbuf_refcnt_set_(packet, val);
}

#[inline]
pub unsafe fn rte_pktmbuf_refcnt_read(packet: *mut rte_mbuf) -> u16 {
    rte_pktmbuf_refcnt_get_(packet)
}

#[inline]
pub unsafe fn rte_pktmbuf_free(packet: *mut rte_mbuf) {
    rte_pktmbuf_free_(packet)
}

#[inline]
pub unsafe fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    rte_pktmbuf_alloc_(mp)
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
pub unsafe fn rte_get_timer_cycles() -> u64 {
    rte_get_timer_cycles_()
}

#[inline]
pub unsafe fn rte_get_timer_hz() -> u64 {
    rte_get_timer_hz_()
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
pub unsafe fn rte_dev_dma_map_wrapper(
    device_id: u16,
    addr: *mut ::std::os::raw::c_void,
    iova: u64,
    len: size_t,
) -> ::std::os::raw::c_int {
    rte_dev_dma_map_(device_id, addr, iova, len)
}

#[inline]
pub unsafe fn rte_dev_dma_unmap_wrapper(
    device_id: u16,
    addr: *mut ::std::os::raw::c_void,
    iova: u64,
    len: size_t,
) -> ::std::os::raw::c_int {
    rte_dev_dma_unmap_(device_id, addr, iova, len)
}

#[inline]
pub unsafe fn custom_init() -> unsafe extern "C" fn(
    mp: *mut rte_mempool,
    opaque_arg: *mut ::std::os::raw::c_void,
    m: *mut ::std::os::raw::c_void,
    i: u32,
) {
    custom_init_
}

#[inline]
pub unsafe fn custom_init_priv() -> unsafe extern "C" fn(
    mp: *mut rte_mempool,
    opaque_arg: *mut ::std::os::raw::c_void,
    m: *mut ::std::os::raw::c_void,
    i: u32,
) {
    custom_init_priv_
}

#[inline]
pub unsafe fn set_lkey(packet: *mut rte_mbuf, key: u32) {
    set_lkey_(packet, key);
}

#[inline]
pub unsafe fn set_lkey_not_present(packet: *mut rte_mbuf) {
    set_lkey_not_present_(packet);
}

#[inline]
pub unsafe fn set_refers_to_another(packet: *mut rte_mbuf, val: u16) {
    set_refers_to_another_(packet, val);
}

#[inline]
pub unsafe fn ip_from_octets(octets: &[u8; 4]) -> u32 {
    make_ip(octets[0], octets[1], octets[2], octets[3])
}

#[inline]
pub unsafe fn make_ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    make_ip_(a, b, c, d)
}

#[inline]
pub unsafe fn fill_in_packet_header(
    mbuf: *mut rte_mbuf,
    my_eth: *const rte_ether_addr,
    dst_eth: *const rte_ether_addr,
    my_ip: u32,
    dst_ip: u32,
    client_port: u16,
    server_port: u16,
    message_size: usize,
) -> usize {
    fill_in_packet_header_(
        mbuf,
        my_eth,
        dst_eth,
        my_ip,
        dst_ip,
        client_port,
        server_port,
        message_size,
    )
}

#[inline]
pub unsafe fn parse_packet(
    mbuf: *mut rte_mbuf,
    our_eth: *const rte_ether_addr,
    our_ip: u32,
) -> (bool, u32, u16, u16, usize) {
    let mut src_ip = 0u32;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut payload_len = 0usize;
    let valid = parse_packet_(
        mbuf,
        our_eth,
        our_ip,
        &mut src_ip as _,
        &mut src_port as _,
        &mut dst_port as _,
        &mut payload_len as _,
    );
    (valid, src_ip, src_port, dst_port, payload_len)
}

#[inline]
pub unsafe fn flip_headers(mbuf: *mut rte_mbuf, id: u32) {
    flip_headers_(mbuf, id);
}

#[inline]
pub unsafe fn switch_headers(
    rx_mbuf: *mut rte_mbuf,
    tx_mbuf: *mut rte_mbuf,
    payload_length: usize,
) {
    switch_headers_(rx_mbuf, tx_mbuf, payload_length);
}

#[inline]
pub unsafe fn shinfo_init(
    extmem_addr: *mut ::std::os::raw::c_void,
    buf_len: *mut u16,
) -> *mut rte_mbuf_ext_shared_info {
    shinfo_init_(extmem_addr, buf_len)
}

#[inline]
pub unsafe fn eth_dev_configure(port_id: u16, rx_rings: u16, tx_rings: u16) {
    eth_dev_configure_(port_id, rx_rings, tx_rings);
}

#[inline]
pub unsafe fn copy_payload(
    src_mbuf: *mut rte_mbuf,
    src_offset: usize,
    dst_mbuf: *mut rte_mbuf,
    dst_offset: usize,
    len: usize,
) {
    copy_payload_(src_mbuf, src_offset, dst_mbuf, dst_offset, len);
}

#[inline]
pub unsafe fn set_checksums(mbuf: *mut rte_mbuf) {
    set_checksums_(mbuf);
}

#[cfg(feature = "mlx5")]
#[inline(never)]
pub unsafe fn mlx5_manual_reg_mr_callback(
    port_id: u8,
    addr: *mut ::std::os::raw::c_void,
    length: usize,
    lkey_out: *mut u32,
) -> *mut ::std::os::raw::c_void {
    tracing::debug!(
        "Calling reg mr on {:?}, length {}, lkey: {:?}",
        addr,
        length,
        lkey_out
    );
    rte_pmd_mlx5_manual_reg_mr(port_id, addr, length, lkey_out)
}

#[cfg(feature = "mlx5")]
#[inline(never)]
pub unsafe fn mlx5_manual_dereg_mr_callback(ibv_mr: *mut ::std::os::raw::c_void) {
    rte_pmd_mlx5_manual_dereg_mr(ibv_mr)
}
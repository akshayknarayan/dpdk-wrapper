//! Socket-like API to DPDK.
//!
//! At a high level, one thread is responsible for calling `wrapper::rx_burst` and distributing
//! resulting packets, via channels, to the right `UdpDpdkSk`. Send-side is the same but in reverse.

use crate::{
    bindings::*,
    utils::{parse_cfg, AddressInfo, HeaderInfo, TOTAL_HEADER_SIZE},
    wrapper::*,
};
use ahash::HashMap;
use color_eyre::{
    eyre::{bail, eyre, WrapErr},
    Result,
};
use flume::{Receiver, Sender};
use macaddr::MacAddr6 as MacAddress;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::{fmt::Debug, mem::zeroed};
use tracing::{debug, trace, warn};

/// A message to/from DPDK.
#[derive(Debug)]
pub struct Msg {
    /// The local port.
    port: u16,
    /// The remote address.
    addr: SocketAddrV4,
    /// Payload.
    buf: Vec<u8>,
}

/// UDP Connection via DPDK.
///
/// Transmits packets over a channel to the [`DpdkIoKernel`] thread, which will actually transmit
/// them. Created by calling [`DpdkIoKernelHandle::socket`]. When dropped, will free its reserved
/// port.
pub struct DpdkConn {
    local_port: BoundPort,
    outgoing_pkts: Sender<Msg>,
    incoming_pkts: Receiver<Msg>,
}

impl DpdkConn {
    /// Send a packet.
    pub fn send(&self, to: SocketAddr, msg: Vec<u8>) -> Result<()> {
        let addr = match to {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(a) => bail!("Only IPv4 is supported: {:?}", a),
        };

        self.outgoing_pkts.send(Msg {
            port: self.local_port.bound_port,
            addr,
            buf: msg,
        })?;
        Ok(())
    }

    pub async fn send_async(&self, to: SocketAddr, msg: Vec<u8>) -> Result<()> {
        let addr = match to {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(a) => bail!("Only IPv4 is supported: {:?}", a),
        };

        self.outgoing_pkts
            .send_async(Msg {
                port: self.local_port.bound_port,
                addr,
                buf: msg,
            })
            .await?;
        Ok(())
    }

    /// Receive a packet.
    ///
    /// Returns (from_addr, payload)
    pub fn recv(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let Msg { addr, buf, port } = self.incoming_pkts.recv()?;
        assert_eq!(port, self.local_port.bound_port, "Port mismatched");
        Ok((SocketAddr::V4(addr), buf))
    }

    pub async fn recv_async(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let Msg { addr, buf, port } = self.incoming_pkts.recv_async().await?;
        assert_eq!(port, self.local_port.bound_port, "Port mismatched");
        Ok((SocketAddr::V4(addr), buf))
    }

    pub async fn recv_async_batch<'buf>(
        &self,
        msgs_buf: &'buf mut [Option<(SocketAddr, Vec<u8>)>],
    ) -> Result<&'buf mut [Option<(SocketAddr, Vec<u8>)>]> {
        if msgs_buf.is_empty() {
            return Ok(msgs_buf);
        }

        msgs_buf[0] = Some(self.recv_async().await.wrap_err("channel receive")?);
        let mut slot_idx = 1;
        while slot_idx < msgs_buf.len() {
            match self.incoming_pkts.try_recv() {
                Ok(Msg { addr, buf, port }) => {
                    assert_eq!(port, self.local_port.bound_port, "Port mismatched");
                    msgs_buf[slot_idx] = Some((SocketAddr::V4(addr), buf));
                    slot_idx += 1;
                }
                Err(_) => {
                    break;
                }
            }
        }

        Ok(&mut msgs_buf[..slot_idx])
    }

    pub fn get_port(&self) -> u16 {
        self.local_port.bound_port
    }
}

struct BoundPort {
    bound_port: u16,
    ports: Arc<PortManager>,
}

impl std::fmt::Debug for BoundPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bound_port.fmt(f)
    }
}

impl Drop for BoundPort {
    fn drop(&mut self) {
        // put the port back
        self.ports.release(self.bound_port);
    }
}

pub struct BoundDpdkConn {
    local_port: Arc<BoundPort>,
    remote_addr: SocketAddrV4,
    outgoing_pkts: Sender<Msg>,
    incoming_pkts: Receiver<Msg>,
}

impl BoundDpdkConn {
    pub fn remote_addr(&self) -> SocketAddrV4 {
        self.remote_addr
    }

    pub fn port(&self) -> u16 {
        self.local_port.bound_port
    }

    /// Send a packet.
    pub fn send(&self, msg: Vec<u8>) -> Result<()> {
        self.outgoing_pkts.send(Msg {
            port: self.local_port.bound_port,
            addr: self.remote_addr,
            buf: msg,
        })?;
        Ok(())
    }

    pub async fn send_async(&self, msg: Vec<u8>) -> Result<()> {
        self.outgoing_pkts
            .send_async(Msg {
                port: self.local_port.bound_port,
                addr: self.remote_addr,
                buf: msg,
            })
            .await?;
        Ok(())
    }

    /// Receive a packet.
    ///
    /// Returns (from_addr, payload)
    pub fn recv(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let Msg { addr, buf, port } = self.incoming_pkts.recv()?;
        assert_eq!(port, self.local_port.bound_port, "Port mismatched");
        assert_eq!(addr, self.remote_addr, "Remote address mismatched");
        Ok((SocketAddr::V4(addr), buf))
    }

    pub async fn recv_async(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let Msg { addr, buf, port } = self.incoming_pkts.recv_async().await?;
        assert_eq!(port, self.local_port.bound_port, "Port mismatched");
        assert_eq!(addr, self.remote_addr, "Remote address mismatched");
        Ok((SocketAddr::V4(addr), buf))
    }

    pub async fn recv_async_batch<'buf>(
        &self,
        msgs_buf: &'buf mut [Option<(SocketAddr, Vec<u8>)>],
    ) -> Result<&'buf mut [Option<(SocketAddr, Vec<u8>)>]> {
        if msgs_buf.is_empty() {
            return Ok(msgs_buf);
        }

        msgs_buf[0] = Some(
            self.recv_async()
                .await
                .wrap_err("BoundDpdkConn first receive")?,
        );
        let mut slot_idx = 1;
        while slot_idx < msgs_buf.len() {
            match self.incoming_pkts.try_recv() {
                Ok(Msg { addr, buf, port }) => {
                    assert_eq!(port, self.local_port.bound_port, "Port mismatched");
                    assert_eq!(addr, self.remote_addr, "Remote address mismatched");
                    msgs_buf[slot_idx] = Some((SocketAddr::V4(addr), buf));
                    slot_idx += 1;
                }
                Err(_) => {
                    break;
                }
            }
        }

        Ok(&mut msgs_buf[..slot_idx])
    }
}

#[derive(Clone, Debug)]
enum PortState {
    Free,
    Exclusive,
    NonExclusive(Receiver<BoundDpdkConn>),
}

impl Default for PortState {
    fn default() -> Self {
        Self::Free
    }
}

#[derive(Debug)]
struct PortManager(HashMap<u16, Mutex<PortState>>);

impl Default for PortManager {
    fn default() -> Self {
        PortManager((1024..=65535).map(|x| (x, Default::default())).collect())
    }
}

impl PortManager {
    fn bind_exclusive(&self, port: Option<u16>) -> Result<u16> {
        for cand_port in port.map_or(1024u16..=65535, |p| p..=p) {
            let ps = self
                .0
                .get(&cand_port)
                .ok_or_else(|| eyre!("Unregistered port {}", cand_port))?;
            let mut ps_g = ps.lock().unwrap();
            match &*ps_g {
                PortState::Free => {
                    debug!(?port, ?cand_port, "setting exclusive port");
                    *ps_g = PortState::Exclusive;
                    return Ok(cand_port);
                }
                x => {
                    debug!(?port, ?cand_port, ?x, "port not free");
                }
            }
        }

        Err(eyre!("Could not find a port for {:?}", port))
    }

    fn bind_non_exclusive(
        &self,
        port: u16,
    ) -> Result<(Receiver<BoundDpdkConn>, Option<Sender<BoundDpdkConn>>)> {
        let ps = self
            .0
            .get(&port)
            .ok_or_else(|| eyre!("Unregistered port {:?}", port))?;
        let mut ps_g = ps.lock().unwrap();
        match &*ps_g {
            PortState::Free => {
                let (accept_s, accept_r) = flume::bounded(16);
                *ps_g = PortState::NonExclusive(accept_r.clone());
                Ok((accept_r, Some(accept_s)))
            }
            PortState::NonExclusive(ref r) => Ok((r.clone(), None)),
            _ => {
                bail!("Requested port not available: {:?}", port);
            }
        }
    }

    fn release(&self, port: u16) {
        if let Some(ps) = self.0.get(&port) {
            let mut ps_g = ps.lock().unwrap();
            *ps_g = PortState::Free;
        }
    }
}

/// Socket manager for [`DPDKIoKernel`].
///
/// Created by [`DpdkIoKernel::new`]. Tracks available ports for sockets to use.
#[derive(Clone)]
pub struct DpdkIoKernelHandle {
    ip_addr: Ipv4Addr,
    arp_table: HashMap<Ipv4Addr, MacAddress>,
    ports: Arc<PortManager>,
    new_conns: Sender<Conn>,
    outgoing_pkts: Sender<Msg>,
    shutdown: Sender<()>,
}

impl Debug for DpdkIoKernelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DpdkIoKernelHandle")
            .field(&self.ip_addr)
            .finish()
    }
}

const CHANNEL_SIZE: usize = 256;

impl DpdkIoKernelHandle {
    fn new(
        ip_addr: Ipv4Addr,
        arp_table: HashMap<Ipv4Addr, MacAddress>,
        new_conns: Sender<Conn>,
        outgoing_pkts: Sender<Msg>,
        shutdown: Sender<()>,
    ) -> Self {
        Self {
            ip_addr,
            arp_table,
            ports: Default::default(), // all ports start free.
            new_conns,
            outgoing_pkts,
            shutdown,
        }
    }

    pub fn ip_addr(&self) -> Ipv4Addr {
        self.ip_addr
    }

    pub fn arp_table(&self) -> HashMap<Ipv4Addr, MacAddress> {
        self.arp_table.clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.send(()).unwrap();
    }

    /// Make a new UDP socket.
    pub fn socket(&self, bind: Option<u16>) -> Result<DpdkConn> {
        // assign a port.
        let port = self.ports.bind_exclusive(bind)?;

        let (incoming_s, incoming_r) = flume::bounded(CHANNEL_SIZE);
        let out_ch = self.outgoing_pkts.clone();

        self.new_conns
            .send(Conn::Socket {
                local_port: port,
                ch: incoming_s,
            })
            .wrap_err("channel send to iokernel failed")?;

        Ok(DpdkConn {
            local_port: BoundPort {
                bound_port: port,
                ports: self.ports.clone(),
            },
            outgoing_pkts: out_ch,
            incoming_pkts: incoming_r,
        })
    }

    /// Make a UDP socket that demuxes packets not just by dst port, but also by src ip/src port.
    ///
    /// This function can be called multiple times on a dest. port. In this case it will return a
    /// `Receiver` that splits new connections with previously returned `Receiver`s.
    pub fn accept(&self, port: u16) -> Result<Receiver<BoundDpdkConn>> {
        // try to claim the port.
        let (accept_r, sender_opt) = self.ports.bind_non_exclusive(port)?;
        if let Some(sender) = sender_opt {
            let bound_port = Arc::new(BoundPort {
                bound_port: port,
                ports: self.ports.clone(),
            });
            self.accept_inner(bound_port, sender, Default::default())?;
        }

        Ok(accept_r)
    }

    /// Make a UDP socket that demuxes packets not just by dst port, but also by src ip/src port.
    /// Pass in an iterator of remote addresses that there are already connections for.
    ///
    /// This function won't be called more than once per dest. port to set up.
    ///
    /// Connections already in `remote_addrs` will be in the returned Vec. Any *new* connections
    /// will arrive over the returned `Receiver`.
    pub fn init_accepted(
        &self,
        port: u16,
        remote_addrs: impl IntoIterator<Item = SocketAddrV4>,
    ) -> Result<(
        HashMap<SocketAddrV4, BoundDpdkConn>,
        Receiver<BoundDpdkConn>,
    )> {
        let (accept_r, sender_opt) = self.ports.bind_non_exclusive(port)?;
        let bound_port = Arc::new(BoundPort {
            bound_port: port,
            ports: self.ports.clone(),
        });

        let accept_s = sender_opt.ok_or(eyre!(
            "Cannot call init_accepted more than once per dest port to set up: {:?}",
            port
        ))?;

        // 1. make maps of addr -> BoundDpdkConn, addr -> Sender<Msg>)
        let (conns, remotes) = remote_addrs
            .into_iter()
            .map(|remote_addr| {
                let (incoming_s, incoming_r) = flume::bounded(CHANNEL_SIZE);
                let cn = BoundDpdkConn {
                    local_port: Arc::clone(&bound_port),
                    remote_addr,
                    outgoing_pkts: self.outgoing_pkts.clone(),
                    incoming_pkts: incoming_r,
                };

                ((remote_addr, cn), (remote_addr, incoming_s))
            })
            .unzip();
        // 2. call pre_accepted with the addr -> Sender map
        self.accept_inner(bound_port, accept_s, remotes)?;
        Ok((conns, accept_r))
    }

    /// Make a UDP socket that demuxes packets not just by dst port, but also by src ip/src port.
    /// Pass in a HashMap of already-initialized connections.
    ///
    /// Any *new* connections will arrive over the returned `Receiver`. Connections already in
    /// `remotes` won't be sent.
    fn accept_inner(
        &self,
        port: Arc<BoundPort>,
        accept_s: Sender<BoundDpdkConn>,
        remotes: HashMap<SocketAddrV4, Sender<Msg>>,
    ) -> Result<()> {
        let out_ch = self.outgoing_pkts.clone();
        self.new_conns
            .send(Conn::Accept {
                local_port: port,
                outgoing_pkts: out_ch,
                ch: accept_s,
                remotes,
            })
            .wrap_err("channel send to iokernel failed")?;
        Ok(())
    }
}

enum Conn {
    Socket {
        local_port: u16,
        ch: Sender<Msg>,
    },
    Accept {
        local_port: Arc<BoundPort>,
        outgoing_pkts: Sender<Msg>,
        ch: Sender<BoundDpdkConn>,
        remotes: HashMap<SocketAddrV4, Sender<Msg>>,
    },
}

impl Conn {
    fn local_port(&self) -> u16 {
        match self {
            Conn::Socket { local_port, .. } => *local_port,
            Conn::Accept { local_port, .. } => local_port.bound_port,
        }
    }

    fn got_packet(&mut self, msg: Msg, num_dropped: &mut usize) -> Result<()> {
        match self {
            Conn::Socket { ch, .. } => {
                match ch.try_send(msg) {
                    Err(flume::TrySendError::Disconnected(_)) => {
                        bail!("Disconnected");
                    }
                    Err(flume::TrySendError::Full(_msg)) => {
                        // drop the packet
                        *num_dropped += 1;
                    }
                    Ok(_) => (),
                }
            }
            Conn::Accept {
                local_port,
                outgoing_pkts,
                remotes,
                ch,
            } => {
                let from_addr = msg.addr;
                let mut new_conn_res = Ok(());
                let msg_sender = remotes.entry(from_addr).or_insert_with(|| {
                    let (cn_s, cn_r) = flume::bounded(CHANNEL_SIZE);
                    new_conn_res = ch.send(BoundDpdkConn {
                        local_port: Arc::clone(local_port),
                        remote_addr: from_addr,
                        outgoing_pkts: outgoing_pkts.clone(),
                        incoming_pkts: cn_r,
                    });
                    cn_s
                });
                new_conn_res.wrap_err("Could not send to new connections receiver")?;

                match msg_sender.try_send(msg) {
                    Err(flume::TrySendError::Disconnected(msg)) => {
                        remotes.remove(&from_addr).unwrap();
                        debug!(
                            ?local_port,
                            ?from_addr,
                            "Incoming channel dropped, resetting port"
                        );
                        let (cn_s, cn_r) = flume::bounded(CHANNEL_SIZE);
                        ch.send(BoundDpdkConn {
                            local_port: Arc::clone(local_port),
                            remote_addr: from_addr,
                            outgoing_pkts: outgoing_pkts.clone(),
                            incoming_pkts: cn_r,
                        })
                        .unwrap();
                        cn_s.send(msg).unwrap(); // cannot fail since we just made cn_r
                        remotes.insert(from_addr, cn_s);
                    }
                    Err(flume::TrySendError::Full(_msg)) => {
                        // drop the packet
                        *num_dropped += 1;
                    }
                    Ok(_) => (),
                }
            }
        }

        Ok(())
    }
}

/// Spin-polling DPDK datapath event loop.
///
/// There should only be one of these. It is responsible for actually sending and receiving
/// packets, and doing bookkeeping (mux/demux) associated with tracking sockets.
pub struct DpdkIoKernel {
    eth_addr: MacAddress,
    ip_addr: Ipv4Addr,
    port: u16,
    mbuf_pool: *mut rte_mempool,
    arp_table: HashMap<Ipv4Addr, MacAddress>,
    new_conns: Receiver<Conn>,
    outgoing_pkts: Receiver<Msg>,
    conns: HashMap<u16, Conn>,
    shutdown: Receiver<()>,
}

impl Drop for DpdkIoKernel {
    fn drop(&mut self) {
        unsafe {
            // TODO freeing this mempool causes segfault sadness later.
            //rte_mempool_free(self.mbuf_pool);
            debug!(lcore_id = ?get_lcore_id(), "un-registering single-thread lcore");
            rte_thread_unregister();
        }
    }
}

impl DpdkIoKernel {
    /// Do global initialization.
    ///
    /// `config_path` should be a TOML files with:
    /// - "dpdk" table with "eal_init" key. "eal_init" should be a string array of DPDK init args.
    /// - "net" table with "ip" key and "arp" list-of-tables.
    ///   - "arp" entries should have "ip" and "mac" keys.
    ///
    /// # Example Config
    ///
    /// EAL args:
    /// - `-n 4` is for memory channels
    /// - `-l 0-4` means run on cores 0-4
    /// - `--allow 0000:08:00.0` means use the device with PCIe address `0000:08:00.0`.
    ///
    /// ```toml
    /// [dpdk]
    /// eal_init = ["-n", "4", "-l", "0-4", "--allow", "0000:08:00.0", "--proc-type=auto"]
    ///
    /// [net]
    /// ip = "1.2.3.4"
    ///
    ///   [[net.arp]]
    ///   ip = "1.2.3.4"
    ///   mac = "00:01:02:03:04:05"
    ///
    ///   [[net.arp]]
    ///   ip = "4.3.2.1"
    ///   mac = "05:04:03:02:01:00"
    /// ```
    pub fn new(config_path: std::path::PathBuf) -> Result<(Self, DpdkIoKernelHandle)> {
        let (dpdk_config, ip_addr, arp_table) = parse_cfg(config_path.as_path())?;
        let (mbuf_pools, nb_ports) = dpdk_init(dpdk_config, 1)?;
        Self::do_new(mbuf_pools, nb_ports, ip_addr, arp_table)
    }

    pub fn new_configure_only(
        ip_addr: Ipv4Addr,
        arp_table: HashMap<Ipv4Addr, MacAddress>,
    ) -> Result<(Self, DpdkIoKernelHandle)> {
        let (mbuf_pools, nb_ports) = dpdk_configure(1)?;
        Self::do_new(mbuf_pools, nb_ports, ip_addr, arp_table)
    }

    fn do_new(
        mbuf_pools: Vec<*mut rte_mempool>,
        nb_ports: u16,
        ip_addr: Ipv4Addr,
        arp_table: HashMap<Ipv4Addr, MacAddress>,
    ) -> Result<(Self, DpdkIoKernelHandle)> {
        let mbuf_pool = mbuf_pools[0];
        let port = nb_ports - 1;

        // what is my ethernet address (rte_ether_addr struct)
        let my_eth = get_my_macaddr(port)?;
        let eth_addr = my_eth.addr_bytes.into();

        // make connection tracking state.
        let (new_conns_s, new_conns_r) = flume::unbounded();
        let (outgoing_pkts_s, outgoing_pkts_r) = flume::bounded(16); // 16 is the max burst size
        let conns = Default::default();

        // shutdown signaller.
        let (shutdown_s, shutdown_r) = flume::bounded(0);

        Ok((
            Self {
                eth_addr,
                ip_addr,
                port,
                mbuf_pool,
                arp_table: arp_table.clone(),
                new_conns: new_conns_r,
                outgoing_pkts: outgoing_pkts_r,
                conns,
                shutdown: shutdown_r,
            },
            DpdkIoKernelHandle::new(ip_addr, arp_table, new_conns_s, outgoing_pkts_s, shutdown_s),
        ))
    }

    /// Iokernel event loop.
    ///
    /// This function returns only if the shutdown channel receives something.
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

        let rte_eth_addr = rte_ether_addr {
            addr_bytes: self.eth_addr.into_array(),
        };

        let octets = self.ip_addr.octets();
        let my_ip: u32 = unsafe { make_ip(octets[0], octets[1], octets[2], octets[3]) };

        let mut ip_id = 1u16;

        loop {
            if let Ok(_) = self.shutdown.try_recv() {
                debug!("exiting dpdk-thread loop");
                break;
            }

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
            let mut num_dropped = 0;
            for i in 0..num_received {
                // first: parse if valid packet, and what the payload size is
                let (is_valid, src_ether, src_ip, src_port, dst_port, payload_length) =
                    unsafe { parse_packet(rx_bufs[i], &rte_eth_addr as _, my_ip) };
                if !is_valid {
                    unsafe { rte_pktmbuf_free(rx_bufs[i]) };
                    continue;
                }

                num_valid += 1;

                let [oct1, oct2, oct3, oct4] = src_ip.to_be_bytes();
                let pkt_src_ip = Ipv4Addr::new(oct1, oct2, oct3, oct4);

                // opportunistically update arp
                self.arp_table
                    .entry(pkt_src_ip)
                    .or_insert_with(|| src_ether.addr_bytes.into());

                let mut remove = false;
                match self.conns.get_mut(&dst_port) {
                    Some(ch) => {
                        let pkt_src_addr = SocketAddrV4::new(pkt_src_ip, src_port);
                        let payload =
                            unsafe { mbuf_slice!(rx_bufs[i], TOTAL_HEADER_SIZE, payload_length) };
                        let msg = Msg {
                            port: dst_port,
                            addr: pkt_src_addr,
                            buf: payload.to_vec(),
                        };

                        if let Err(_) = ch.got_packet(msg, &mut num_dropped) {
                            remove = true;
                        }
                    }
                    None => {
                        num_dropped += 1;
                    }
                }

                if remove {
                    self.conns.remove(&dst_port);
                }

                unsafe {
                    rte_pktmbuf_free(rx_bufs[i]);
                }
            }

            if num_valid > 0 || num_dropped > 0 {
                trace!(?num_valid, ?num_dropped, "Received valid packets");
            }

            // 2. second, see if we have anything to send.
            let mut i = 0;
            while let Ok(Msg {
                buf,
                addr: to_addr,
                port: src_port,
            }) = self.outgoing_pkts.try_recv()
            {
                let to_ip = to_addr.ip();
                let to_port = to_addr.port();
                unsafe {
                    let dst_ether_addr = match self.arp_table.get(to_ip) {
                        Some(eth) => eth,
                        None => {
                            warn!(?to_ip, "Could not find IP in ARP table");
                            continue;
                        }
                    };

                    tx_bufs[i] = alloc_mbuf(self.mbuf_pool).unwrap();

                    let src_info = AddressInfo {
                        udp_port: src_port,
                        ipv4_addr: self.ip_addr,
                        ether_addr: self.eth_addr,
                    };

                    let dst_info = AddressInfo {
                        udp_port: to_port,
                        ipv4_addr: *to_ip,
                        ether_addr: *dst_ether_addr,
                    };

                    // fill header
                    let hdr_size = match fill_in_header(
                        tx_bufs[i],
                        &HeaderInfo { src_info, dst_info },
                        buf.len(),
                        ip_id,
                    ) {
                        Ok(s) => {
                            ip_id += 1;
                            ip_id %= 0xffff;
                            s
                        }
                        Err(err) => {
                            debug!(?err, "Error writing header");
                            continue;
                        }
                    };

                    // write payload
                    let payload_slice = mbuf_slice!(tx_bufs[i], hdr_size, buf.len());
                    rte_memcpy_(
                        payload_slice.as_mut_ptr() as _,
                        buf.as_ptr() as _,
                        buf.len(),
                    );

                    (*tx_bufs[i]).pkt_len = (hdr_size + buf.len()) as u32;
                    (*tx_bufs[i]).data_len = (hdr_size + buf.len()) as u16;
                }

                i += 1;
                if i >= 16 {
                    break;
                }
            }

            if i > 0 {
                if let Err(err) = unsafe { tx_burst(self.port, 0, tx_bufs.as_mut_ptr(), i as u16) }
                {
                    warn!(?err, "tx_burst error");
                }
            }

            // 3. third, check for new connections
            while let Ok(conn) = self.new_conns.try_recv() {
                let local_port = conn.local_port();
                if let Some(_) = self.conns.insert(local_port, conn) {
                    debug!(?local_port, "New connection on port");
                }
            }
        }

        warn!(ip_addr = ?self.ip_addr, "exiting dpdk_thread");
    }
}

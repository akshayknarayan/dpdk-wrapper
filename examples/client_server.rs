//! Use DpdkConn to send and receive packets.

use color_eyre::{eyre::WrapErr, Result};
use dpdk_wrapper::{DpdkIoKernel, DpdkIoKernelHandle};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tracing::{debug, info};
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Debug, Clone, StructOpt)]
struct Opt {
    #[structopt(long)]
    cfg: PathBuf,

    #[structopt(short, long)]
    port: u16,

    #[structopt(short, long)]
    client: Option<Ipv4Addr>,
}

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(ErrorLayer::default());
    let d = tracing::Dispatch::new(subscriber);
    d.init();
    color_eyre::install()?;
    let Opt { cfg, port, client } = Opt::from_args();

    let (handle_s, handle_r) = flume::bounded(1);
    std::thread::spawn(move || {
        let handle = handle_r.recv().unwrap();
        match client {
            Some(ip) => {
                let mut times = do_client(handle, SocketAddrV4::new(ip, port)).unwrap();
                let (p5, p25, p50, p75, p95) = percentiles_us(&mut times);
                info!(?p5, ?p25, ?p50, ?p75, ?p95, "done");
                std::process::exit(0);
            }
            None => do_server(handle, port).unwrap(),
        }
    });

    do_iokernel(cfg, handle_s)?;
    Ok(())
}

#[tracing::instrument(err, skip(cfg, handle_s))]
fn do_iokernel(cfg: PathBuf, handle_s: flume::Sender<DpdkIoKernelHandle>) -> Result<()> {
    let (iokernel, handle) = match DpdkIoKernel::new(cfg) {
        Ok(x) => x,
        Err(err) => {
            tracing::error!(err = %format!("{:#?}", err), "Dpdk init failed");
            return Err(err);
        }
    };
    handle_s.send(handle).unwrap();
    iokernel.run();
}

#[tracing::instrument(err, skip(handle))]
fn do_client(handle: DpdkIoKernelHandle, remote: SocketAddrV4) -> Result<Vec<Duration>> {
    let conn = handle.socket(None)?;
    info!(?remote, "made client connection");
    let mut times = Vec::with_capacity(100);
    let start = Instant::now();
    for i in 0..100 {
        let msg = bincode::serialize(&TimeMsg::new(start))?;
        conn.send(remote, msg).wrap_err("send")?;
        info!(?i, "sent");
        let (from, buf) = conn.recv().wrap_err("recv")?;
        let msg: TimeMsg = bincode::deserialize(&buf)?;
        let elap = msg.elapsed(start);
        info!(?i, ?from, ?elap, "received response");
        times.push(elap);
    }

    Ok(times)
}

#[tracing::instrument(err, skip(handle))]
fn do_server(handle: DpdkIoKernelHandle, port: u16) -> Result<()> {
    let conn = handle.socket(Some(port))?;
    info!(?port, "listening");
    loop {
        let (from, buf) = conn.recv().wrap_err("recv")?;
        debug!(?from, "got msg");
        conn.send(from, buf).wrap_err("send echo")?;
        debug!(?from, "sent echo");
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct TimeMsg(Duration, u32);
impl TimeMsg {
    fn new(start: Instant) -> Self {
        Self(start.elapsed(), 0xdead)
    }

    fn elapsed(&self, start: Instant) -> Duration {
        assert_eq!(self.1, 0xdead);
        start.elapsed() - self.0
    }
}

fn percentiles_us(durs: &mut [Duration]) -> (Duration, Duration, Duration, Duration, Duration) {
    durs.sort();
    let len = durs.len() as f64;
    let quantile_idxs = [0.05, 0.25, 0.5, 0.75, 0.95];
    let quantiles: Vec<_> = quantile_idxs
        .iter()
        .map(|q| (len * q) as usize)
        .map(|i| durs[i])
        .collect();
    match quantiles[..] {
        [p5, p25, p50, p75, p95] => (p5, p25, p50, p75, p95),
        [..] => unreachable!(),
    }
}

//! Use DpdkConn to send and receive packets.

use color_eyre::{eyre::WrapErr, Report, Result};
use dpdk_wrapper::{DpdkIoKernel, DpdkIoKernelHandle};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
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
    std::thread::spawn(move || do_iokernel(cfg, handle_s));
    let handle = handle_r.recv().unwrap();

    match client {
        Some(ip) => {
            do_client(handle, SocketAddrV4::new(ip, port))?;
        }
        None => do_server(handle, port)?,
    }

    Ok(())
}

#[tracing::instrument(err, skip(cfg, handle_s))]
fn do_iokernel(cfg: PathBuf, handle_s: flume::Sender<DpdkIoKernelHandle>) -> Result<()> {
    let (iokernel, handle) = DpdkIoKernel::new(cfg).wrap_err("dpdk init")?;
    handle_s.send(handle).unwrap();
    iokernel.run();
    Ok::<_, Report>(())
}

fn do_client(handle: DpdkIoKernelHandle, remote: SocketAddrV4) -> Result<()> {
    let conn = handle.socket(None)?;
    info!(?remote, "made client connection");
    let buf = vec![12u8; 128];
    for i in 0..100 {
        info!(?i, "sending");
        conn.send(remote, buf.clone()).wrap_err("send")?;
        info!(?i, "sent");
        let (from, _) = conn.recv().wrap_err("recv")?;
        info!(?i, ?from, "received response");
    }

    Ok(())
}

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

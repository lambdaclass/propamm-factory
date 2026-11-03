//! The `vsock` link: what an AWS Nitro enclave has, a vsock to its host and no network
//! interface at all. The boot helper connects on the link's port. Every outbound
//! destination (a venue, a builder, the RPC node, the key service) is a loopback address
//! inside piped to a vsock port on the host, where a proxy dials the real host; every
//! inbound listener (the backoffice, the metrics scrape) is a vsock port piped to the
//! address the server inside listens on. TLS runs end to end through both, so the host
//! carries ciphertext either way.

use std::{net::SocketAddr, time::Duration};

use eyre::{Result, WrapErr};
use futures_util::future::BoxFuture;
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use super::{Accept, Forward, HostLink, Stream};

/// A vsock link and its tunnels.
pub struct VsockLink {
    /// The port the host's boot helper connects to.
    pub port: u32,
    /// Outbound tunnels.
    pub forward: Vec<Forward>,
    /// Inbound tunnels.
    pub accept: Vec<Accept>,
}

impl HostLink for VsockLink {
    fn accept(&self) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            for tunnel in &self.forward {
                let (listen, cid, port) = (tunnel.listen, tunnel.cid, tunnel.port);
                tokio::spawn(async move {
                    if let Err(err) = outbound(listen, cid, port).await {
                        tracing::error!("tunnel {listen}: {err:#}");
                    }
                });
            }
            for tunnel in &self.accept {
                let (port, to) = (tunnel.port, tunnel.to);
                tokio::spawn(async move {
                    if let Err(err) = inbound(port, to).await {
                        tracing::error!("tunnel vsock {port}: {err:#}");
                    }
                });
            }
            let port = self.port;
            let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
                .wrap_err_with(|| format!("binding the link's vsock port {port}"))?;
            tracing::info!("waiting for the boot helper on vsock port {port}");
            let (stream, _) = listener.accept().await?;
            Ok(Box::pin(stream) as Stream)
        })
    }
}

/// Accepts on `listen` forever, piping each connection to vsock `cid:port` on the host.
async fn outbound(listen: SocketAddr, cid: u32, port: u32) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .wrap_err_with(|| format!("binding {listen}"))?;
    tracing::info!("tunnel: {listen} to vsock {cid}:{port}");
    loop {
        let mut inbound = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                accept_failed(&format!("tunnel {listen}"), &err).await;
                continue;
            }
        };
        tokio::spawn(async move {
            match VsockStream::connect(VsockAddr::new(cid, port)).await {
                Ok(mut outbound) => {
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    {
                        tracing::debug!("tunnel to {cid}:{port} ended: {err}");
                    }
                }
                Err(err) => tracing::warn!("cannot reach vsock {cid}:{port}: {err}"),
            }
        });
    }
}

/// Accepts on vsock `port` forever, piping each connection to `to` inside.
async fn inbound(port: u32, to: SocketAddr) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .wrap_err_with(|| format!("binding vsock port {port}"))?;
    tracing::info!("tunnel: vsock port {port} to {to}");
    loop {
        let mut inbound = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                accept_failed(&format!("tunnel vsock {port}"), &err).await;
                continue;
            }
        };
        tokio::spawn(async move {
            match TcpStream::connect(to).await {
                Ok(mut outbound) => {
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    {
                        tracing::debug!("tunnel from vsock {port} ended: {err}");
                    }
                }
                Err(err) => tracing::warn!("nothing listening on {to} for vsock {port}: {err}"),
            }
        });
    }
}

/// A failed accept (out of file descriptors, a connection reset before it was taken) is
/// that one connection's, not the tunnel's: returning would unbind the tunnel for the rest of
/// the run. Said, then a pause so a persistent cause does not spin, as `TlsListener` does.
async fn accept_failed(what: &str, err: &std::io::Error) {
    tracing::warn!("{what}: accept failed, retrying: {err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

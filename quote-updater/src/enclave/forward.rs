//! The tunnels an enclave reaches the world through. An enclave has no network interface;
//! its one connection is a vsock to the host. So every outbound destination (an exchange,
//! a builder, the RPC node, KMS) is a loopback port inside the enclave piped to a vsock
//! port on the host, where a proxy dials the real host; and every inbound listener (the
//! backoffice, the metrics scrape) is a vsock port the enclave accepts on, piped to the
//! loopback port the server inside listens on. TLS runs end to end through either, so the
//! host sees ciphertext in both directions.

use std::net::SocketAddr;

use eyre::{Result, WrapErr};
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

/// Accepts on `listen` forever, piping each connection to vsock `cid:port` on the host.
pub async fn outbound(listen: SocketAddr, cid: u32, port: u32) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .wrap_err_with(|| format!("binding {listen}"))?;
    tracing::info!("tunnel: {listen} to vsock {cid}:{port}");
    loop {
        let (mut inbound, _) = listener.accept().await?;
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

/// Accepts on vsock `port` forever, piping each connection to `to` inside the enclave.
pub async fn inbound(port: u32, to: SocketAddr) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port))
        .wrap_err_with(|| format!("binding vsock port {port}"))?;
    tracing::info!("tunnel: vsock port {port} to {to}");
    loop {
        let (mut inbound, _) = listener.accept().await?;
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

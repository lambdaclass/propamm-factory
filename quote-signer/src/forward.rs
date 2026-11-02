//! A loopback TCP port tunnelled to a vsock port: how a process in an enclave, which has
//! no network, reaches a service on the host side. The host runs a proxy that accepts the
//! vsock connection and dials the real host; inside, the service's hostname is pointed at
//! the loopback address (an `/etc/hosts` line) and TLS runs end to end through the tunnel.

use std::net::SocketAddr;

use eyre::{Result, WrapErr};
use tokio::net::TcpListener;

/// Accepts on `listen` forever, piping each connection to vsock `cid:port`.
pub async fn run(listen: SocketAddr, cid: u32, port: u32) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .wrap_err_with(|| format!("binding {listen}"))?;
    tracing::info!("forwarding {listen} to vsock {cid}:{port}");
    loop {
        let (mut inbound, _) = listener.accept().await?;
        tokio::spawn(async move {
            let outbound =
                tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await;
            match outbound {
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

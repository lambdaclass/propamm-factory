//! Dialing a WebSocket the way both the builder and the Binance connections need it:
//! bounded by a connect timeout, so one dead endpoint cannot hold a redial hostage for the
//! OS connect timeout (minutes), and with Nagle's algorithm off, so a small frame goes out
//! the moment it is written instead of waiting on an earlier segment's ack.

use std::net::SocketAddr;
use std::time::Duration;

use eyre::{Result, WrapErr, eyre};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::client::IntoClientRequest};

/// How long to wait for the connect handshake before giving up on the attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub type Stream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Opens the connection described by `request` (a URL, or a request carrying headers).
///
/// The addresses are dialled one at a time, IPv4 before IPv6, each attempt bounded on its
/// own, all of them inside [`CONNECT_TIMEOUT`] together with the TLS and WebSocket
/// handshakes. Not left to the library's default, which dials the resolved addresses in
/// the order DNS returned them: a host with an IPv6 address but no IPv6 route out sees a
/// venue that publishes AAAA records as a connect that hangs on the first address until
/// the whole timeout, redials, and hangs again, forever. curl does not have this problem
/// because it races both families; this dials the family that works here first, and
/// still reaches the rest if it does not.
pub async fn connect<R: IntoClientRequest + Unpin>(request: R) -> Result<Stream> {
    let request = request.into_client_request().wrap_err("invalid endpoint")?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| eyre!("endpoint has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") | Some("https") => 443,
        _ => 80,
    });
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .wrap_err_with(|| format!("dns lookup of {host} failed"))?
            .collect();
        let tcp = dial_in_order(&ipv4_first(resolved)).await?;
        // The third argument is `disable_nagle`. `connect_async` passes false, which is
        // tokio-tungstenite's conservative default for a library, not the right setting
        // for a socket whose every write is one small latency-sensitive frame.
        tcp.set_nodelay(true).wrap_err("set_nodelay failed")?;
        let (ws, _) = tokio_tungstenite::client_async_tls_with_config(request, tcp, None, None)
            .await
            .wrap_err("handshake failed")?;
        Ok(ws)
    })
    .await
    .map_err(|_| eyre!("connect timed out after {CONNECT_TIMEOUT:?}"))?
}

/// How long one address may take to answer a TCP connect before the next is tried. Short
/// against `CONNECT_TIMEOUT`, so a dead first address still leaves room for the rest.
const PER_ADDRESS_TIMEOUT: Duration = Duration::from_secs(3);

/// The resolved addresses with every IPv4 one before every IPv6 one, each family in the
/// order DNS gave it.
fn ipv4_first(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    // Stable, so DNS's own ordering within a family (its rotation) is kept.
    addrs.sort_by_key(|addr| addr.is_ipv6());
    addrs
}

/// The first address that accepts a TCP connection, tried in order.
async fn dial_in_order(addrs: &[SocketAddr]) -> Result<TcpStream> {
    let mut last = eyre!("the name resolved to no addresses");
    for addr in addrs {
        match tokio::time::timeout(PER_ADDRESS_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last = eyre!("connect to {addr} failed: {err}"),
            Err(_) => last = eyre!("connect to {addr} timed out after {PER_ADDRESS_TIMEOUT:?}"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    /// A venue that publishes AAAA records first must not be dialled over IPv6 first on a
    /// host that cannot route it. The families are reordered; the order inside each is
    /// kept.
    #[test]
    fn ipv4_addresses_are_dialled_before_ipv6_ones() {
        let v6a: SocketAddr = "[2600::1]:443".parse().unwrap();
        let v6b: SocketAddr = "[2600::2]:443".parse().unwrap();
        let v4a: SocketAddr = "13.0.0.1:443".parse().unwrap();
        let v4b: SocketAddr = "13.0.0.2:443".parse().unwrap();
        assert_eq!(
            ipv4_first(vec![v6a, v6b, v4a, v4b]),
            vec![v4a, v4b, v6a, v6b]
        );
        assert_eq!(ipv4_first(vec![v4b, v4a]), vec![v4b, v4a]);
        assert!(ipv4_first(Vec::new()).is_empty());
    }

    /// A first address that refuses is skipped for one that answers, inside the budget.
    #[tokio::test]
    async fn a_dead_first_address_falls_through_to_the_next() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        // A port nothing listens on: bind, learn the port, drop it.
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let stream = dial_in_order(&[dead, live]).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), live);
        let err = dial_in_order(&[dead]).await.unwrap_err().to_string();
        assert!(err.contains("failed"), "{err}");
    }

    /// Every message on these sockets is a small frame that must go out the moment it is
    /// written: a quote update waits for its ack before the next one is sent, and a
    /// Binance ping is a keepalive. Nagle's algorithm buffers small writes while an earlier
    /// segment is unacknowledged, which is latency for nothing here.
    #[tokio::test]
    async fn dialing_disables_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ws = accept_async(stream).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let ws = connect(format!("ws://{addr}/ws")).await.unwrap();
        let MaybeTlsStream::Plain(tcp) = ws.get_ref() else {
            panic!("a ws:// dial must not be wrapped in TLS");
        };
        assert!(
            tcp.nodelay().unwrap(),
            "TCP_NODELAY must be set on a dialed socket"
        );
    }
}

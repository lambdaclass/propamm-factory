//! HTTPS for the backoffice: a certificate and key read from PEM files, TLS handshakes off
//! the accept path, and a renewed certificate picked up without a restart.
//!
//! The certificate is read at startup, where a bad path, an empty chain, an encrypted key or
//! a key that is not the certificate's refuses the run. After that the two files are looked
//! at on every new connection, and when either has changed (its modification time or its
//! length) the pair is read again; a pair that does not load, such as the moment between
//! `tailscale cert` writing the certificate and writing its key, is warned about and the
//! certificate loaded before goes on being served until the files change again.
//! Connections already open keep the certificate they were made with.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use eyre::{Result, WrapErr, eyre};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
    server::TlsStream,
};

/// Longest a client may take over its handshake. A client that opens a connection and says
/// nothing holds a task this long, not the accept loop.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a file looked like when it was read: its modification time and its length, or
/// `None` when it could not be looked at. Length as well as time, so a rewrite inside one
/// tick of a coarse clock is still seen when the size changed.
type Stamp = Option<(Option<SystemTime>, u64)>;

fn stamp(path: &Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .map(|meta| (meta.modified().ok(), meta.len()))
}

/// The backoffice's certificate, and where it was read from so it can be read again.
pub(crate) struct Tls {
    cert: PathBuf,
    key: PathBuf,
    config: Arc<ServerConfig>,
    /// The two files as they were when `config` was read from them.
    loaded: [Stamp; 2],
    /// The two files as they were when they last failed to load, so a broken pair is
    /// warned about once rather than on every connection.
    failed: Option<[Stamp; 2]>,
}

impl Tls {
    /// Reads the certificate chain at `cert` and its private key at `key`. Every failure
    /// names the file it is about.
    pub(crate) fn load(cert: &Path, key: &Path) -> Result<Self> {
        let loaded = [stamp(cert), stamp(key)];
        Ok(Self {
            cert: cert.to_owned(),
            key: key.to_owned(),
            config: Arc::new(server_config(cert, key)?),
            loaded,
            failed: None,
        })
    }

    /// The configuration for the next handshake, read again first if either file changed
    /// since it was.
    fn current(&mut self) -> Arc<ServerConfig> {
        let now = [stamp(&self.cert), stamp(&self.key)];
        if now != self.loaded && Some(now) != self.failed {
            match server_config(&self.cert, &self.key) {
                Ok(config) => {
                    self.config = Arc::new(config);
                    self.loaded = now;
                    self.failed = None;
                    tracing::info!(
                        "backoffice: {} changed; new connections get the certificate it holds",
                        self.cert.display()
                    );
                }
                Err(err) => {
                    self.failed = Some(now);
                    tracing::warn!(
                        "backoffice: the certificate changed but does not load ({err:#}); \
                         still serving the one loaded before, until the files change again"
                    );
                }
            }
        }
        Arc::clone(&self.config)
    }
}

/// The server side of TLS for `cert` and `key`: TLS 1.2 and 1.3 with rustls' safe
/// defaults, ring for the crypto (named, so a binary that also enables another provider
/// cannot make this ambiguous), no client certificates, and HTTP/1.1 only, the protocol
/// the backoffice's websocket upgrade runs over.
fn server_config(cert: &Path, key: &Path) -> Result<ServerConfig> {
    let cert_pem = std::fs::read(cert)
        .wrap_err_with(|| format!("could not read the TLS certificate {}", cert.display()))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| eyre!("{} is not a PEM certificate chain: {err}", cert.display()))?;
    eyre::ensure!(
        !chain.is_empty(),
        "{} holds no certificate; it should hold the certificate and any intermediates, \
         PEM, the server's own first",
        cert.display()
    );
    let key_pem = std::fs::read(key)
        .wrap_err_with(|| format!("could not read the TLS private key {}", key.display()))?;
    let private = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|err| {
        eyre!(
            "{} holds no private key this can read ({err}). It reads one unencrypted PEM \
             key: PKCS#8 (BEGIN PRIVATE KEY), SEC1 (BEGIN EC PRIVATE KEY, what `tailscale \
             cert` writes) or PKCS#1 (BEGIN RSA PRIVATE KEY); an encrypted key has to be \
             decrypted first",
            key.display()
        )
    })?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .wrap_err("TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|err| {
            eyre!(
                "{} and {} are not a certificate and its private key: {err}",
                cert.display(),
                key.display()
            )
        })?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The backoffice's connections once their handshake is done, for `axum::serve`. Handed
/// over by [`accept`], which runs beside it.
pub(crate) struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(connection) => connection,
            // The accept loop is gone, so no connection is coming: wait to be dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Splits `tcp` into the listener `axum::serve` takes and the loop that feeds it, which
/// the caller runs beside the server, in the same task, so neither outlives the other.
pub(crate) fn listener(
    tcp: TcpListener,
    tls: Tls,
) -> std::io::Result<(TlsListener, impl Future<Output = ()> + Send)> {
    let local = tcp.local_addr()?;
    let (sender, ready) = mpsc::channel(64);
    Ok((TlsListener { ready, local }, accept(tcp, tls, sender)))
}

/// Accepts TCP connections and runs each one's handshake as a task of its own, bounded by
/// [`HANDSHAKE_TIMEOUT`], so a slow or silent client never holds up the next. The tasks are
/// owned here and end with it.
async fn accept(
    tcp: TcpListener,
    mut tls: Tls,
    ready: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    let mut handshakes = JoinSet::new();
    loop {
        tokio::select! {
            accepted = tcp.accept() => match accepted {
                Ok((stream, peer)) => {
                    let acceptor = TlsAcceptor::from(tls.current());
                    let ready = ready.clone();
                    handshakes.spawn(async move {
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => {
                                let _ = ready.send((stream, peer)).await;
                            }
                            // Plain HTTP sent to the HTTPS port is the likely one, and the
                            // client only sees a dropped connection, so it is said here.
                            Ok(Err(err)) => tracing::warn!(
                                "backoffice: TLS handshake with {peer} failed: {err} (the \
                                 backoffice is served over https://)"
                            ),
                            Err(_) => tracing::warn!(
                                "backoffice: {peer} did not finish its TLS handshake within \
                                 {}s",
                                HANDSHAKE_TIMEOUT.as_secs()
                            ),
                        }
                    });
                }
                // As axum's own listener does: a connection that died before it was
                // accepted is nobody's problem, anything else is waited out.
                Err(err) if is_connection_error(&err) => {}
                Err(err) => {
                    tracing::warn!("backoffice: accept failed: {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            Some(_) = handshakes.join_next() => {}
        }
    }
}

fn is_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixture under `testdata/tls` (see its README).
    pub(crate) fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/tls")
            .join(name)
    }

    /// The DER of the first certificate in a fixture: what a server serving it presents.
    pub(crate) fn leaf(name: &str) -> Vec<u8> {
        CertificateDer::pem_file_iter(fixture(name))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .to_vec()
    }

    /// Every key form the pusher is told to expect, the one `tailscale cert` writes first.
    #[test]
    fn a_pkcs8_sec1_or_pkcs1_key_loads() {
        for (cert, key) in [
            ("a.crt", "a.key"),
            ("b.crt", "b.key"),
            ("b.crt", "b.pk8.key"),
        ] {
            Tls::load(&fixture(cert), &fixture(key))
                .unwrap_or_else(|err| panic!("{cert} with {key}: {err:#}"));
        }
    }

    /// Each refusal names the file it is about, and says what would be read instead.
    #[test]
    fn a_pair_that_cannot_serve_is_refused_naming_its_file() {
        let refused = |cert: &Path, key: &Path| match Tls::load(cert, key) {
            Ok(_) => panic!("{} with {} loaded", cert.display(), key.display()),
            Err(err) => format!("{err:#}"),
        };
        let dir = std::env::temp_dir().join(format!("quote-updater-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").unwrap();

        let err = refused(&fixture("a.crt"), &fixture("b.key"));
        assert!(err.contains("a.crt") && err.contains("b.key"), "{err}");
        assert!(
            err.contains("not a certificate and its private key"),
            "{err}"
        );

        let err = refused(&fixture("a.crt"), &fixture("a.enc.key"));
        assert!(
            err.contains("a.enc.key") && err.contains("encrypted"),
            "{err}"
        );

        let err = refused(&empty, &fixture("a.key"));
        assert!(
            err.contains("empty.pem") && err.contains("no certificate"),
            "{err}"
        );

        let err = refused(&fixture("a.key"), &fixture("a.key"));
        assert!(
            err.contains("a.key") && err.contains("no certificate"),
            "{err}"
        );

        let err = refused(&dir.join("missing.crt"), &fixture("a.key"));
        assert!(err.contains("missing.crt"), "{err}");
    }

    /// A renewal: the files change and the next handshake gets the new certificate. Half a
    /// renewal (the certificate written, its key not yet) keeps the old one, without asking
    /// again until the files change once more.
    #[test]
    fn a_changed_certificate_is_read_again_and_a_broken_one_is_not_served() {
        let dir =
            std::env::temp_dir().join(format!("quote-updater-tls-renew-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("server.crt"), dir.join("server.key"));
        std::fs::copy(fixture("a.crt"), &cert).unwrap();
        std::fs::copy(fixture("a.key"), &key).unwrap();
        let mut tls = Tls::load(&cert, &key).unwrap();
        let first = tls.current();
        assert!(Arc::ptr_eq(&first, &tls.current()), "nothing changed");

        std::fs::copy(fixture("b.crt"), &cert).unwrap();
        let half = tls.current();
        assert!(
            Arc::ptr_eq(&first, &half),
            "a mismatched pair is not served"
        );
        assert!(tls.failed.is_some());
        assert!(
            Arc::ptr_eq(&first, &tls.current()),
            "and is not retried as it is"
        );

        std::fs::copy(fixture("b.key"), &key).unwrap();
        let renewed = tls.current();
        assert!(
            !Arc::ptr_eq(&first, &renewed),
            "the whole renewal is picked up"
        );
        assert!(tls.failed.is_none());
    }
}

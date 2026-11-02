//! Running inside an AWS Nitro enclave: a sealed compartment of the host with no network,
//! no disk and no console, reachable only over a vsock. Everything the run needs crosses
//! that one channel at boot, and everything it must keep crosses it back.
//!
//! The sequence, driven by `--enclave <file>` (the file is baked into the enclave image):
//!
//! 1. The tunnels in the file are opened ([`forward`]), so the run can reach the venues,
//!    the builders, the RPC node and KMS, and so the backoffice and the metrics scrape can
//!    reach in.
//! 2. The enclave listens on the link port and the host's boot helper connects, sending
//!    one [`protocol::ToEnclave::Boot`]: temporary AWS credentials, every secret as KMS
//!    ciphertext, the config sealed under one of those secrets, and the backoffice's
//!    certificate.
//! 3. The secrets are decrypted by KMS against the enclave's attestation document
//!    ([`nitro`]): KMS releases them only to this image, wrapped so only this process can
//!    read them. They are installed as the process's secrets ([`crate::secrets`]), so the
//!    config's `key_env` names and every other secret name resolve as they would from an
//!    environment.
//! 4. The config is opened ([`seal`]) and written to `--config`, a path on the enclave's
//!    in-memory filesystem, and the run proceeds exactly as it does outside an enclave.
//! 5. For the rest of the run the link carries log lines out, the re-sealed config out
//!    after every save, and reload and shutdown requests in, since nothing outside can
//!    send the process a signal.

pub mod protocol;
pub mod seal;

#[cfg(target_os = "linux")]
pub mod forward;
#[cfg(feature = "nitro")]
pub mod nitro;

use std::{collections::BTreeMap, net::SocketAddr, path::Path, sync::OnceLock};

use base64::Engine;
use eyre::{Result, WrapErr, bail, ensure, eyre};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};

use protocol::{Credentials, FromEnclave, ToEnclave, read_frame, write_frame};

/// The secret the config is sealed under: 32 bytes as hex, released at boot like every
/// other.
pub const SEAL_KEY_SECRET: &str = "CONFIG_SEAL_KEY";

/// The file `--enclave` points at, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    link_port: u32,
    kms: RawKms,
    #[serde(default)]
    forward: Vec<RawForward>,
    #[serde(default)]
    accept: Vec<RawAccept>,
    backoffice: Option<RawBackoffice>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKms {
    region: String,
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForward {
    listen: SocketAddr,
    cid: u32,
    port: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccept {
    port: u32,
    to: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackoffice {
    key_secret: String,
    google: RawGoogle,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGoogle {
    client_id: String,
    client_secret_secret: String,
    redirect_url: String,
    #[serde(default)]
    allowed_domain: Option<String>,
    #[serde(default)]
    allowed_accounts: Vec<String>,
}

/// The KMS the secrets are decrypted by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kms {
    /// The region the key lives in.
    pub region: String,
    /// Where KMS is reached, when not its public endpoint.
    pub endpoint: Option<String>,
}

/// A loopback port tunnelled to a vsock port on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The loopback address to listen on.
    pub listen: SocketAddr,
    /// The context id to connect to (the host is `3`).
    pub cid: u32,
    /// The vsock port there.
    pub port: u32,
}

/// A vsock port accepted on, piped to a port inside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accept {
    /// The vsock port.
    pub port: u32,
    /// The address inside it is piped to.
    pub to: SocketAddr,
}

/// How the backoffice authenticates inside an enclave: its own TLS, and a Google login
/// checked in the process. See `backoffice::auth`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackofficeSettings {
    /// The secret holding the PEM private key of the certificate the host hands in.
    pub key_secret: String,
    /// The Google OAuth client id.
    pub client_id: String,
    /// The secret holding the client secret.
    pub client_secret_secret: String,
    /// Where Google sends the browser back: this backoffice's `/auth/callback`.
    pub redirect_url: String,
    /// A Google Workspace domain whose accounts may log in.
    pub allowed_domain: Option<String>,
    /// Accounts that may log in, whatever their domain.
    pub allowed_accounts: Vec<String>,
}

/// The enclave file, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The vsock port the host's boot helper connects to.
    pub link_port: u32,
    /// The KMS the secrets are decrypted by.
    pub kms: Kms,
    /// Outbound tunnels.
    pub forward: Vec<Forward>,
    /// Inbound tunnels.
    pub accept: Vec<Accept>,
    /// The backoffice's authentication, when it is served from inside.
    pub backoffice: Option<BackofficeSettings>,
}

impl Settings {
    /// Reads and parses the file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        Self::parse(&text).wrap_err_with(|| path.display().to_string())
    }

    /// Parses the file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: Raw = toml::from_str(text).wrap_err("enclave file")?;
        let backoffice = raw.backoffice.map(|b| {
            ensure!(
                b.google.allowed_domain.is_some() || !b.google.allowed_accounts.is_empty(),
                "[backoffice.google]: set allowed_domain or allowed_accounts, or nobody can log in"
            );
            ensure!(
                b.google.redirect_url.starts_with("https://"),
                "[backoffice.google]: redirect_url must be https://"
            );
            Ok::<_, eyre::Report>(BackofficeSettings {
                key_secret: b.key_secret,
                client_id: b.google.client_id,
                client_secret_secret: b.google.client_secret_secret,
                redirect_url: b.google.redirect_url,
                allowed_domain: b.google.allowed_domain,
                allowed_accounts: b.google.allowed_accounts,
            })
        });
        let backoffice = match backoffice {
            Some(result) => Some(result?),
            None => None,
        };
        Ok(Self {
            link_port: raw.link_port,
            kms: Kms {
                region: raw.kms.region,
                endpoint: raw.kms.endpoint,
            },
            forward: raw
                .forward
                .into_iter()
                .map(|f| Forward {
                    listen: f.listen,
                    cid: f.cid,
                    port: f.port,
                })
                .collect(),
            accept: raw
                .accept
                .into_iter()
                .map(|a| Accept {
                    port: a.port,
                    to: a.to,
                })
                .collect(),
            backoffice,
        })
    }
}

/// How the boot turns the host's ciphertexts into secrets: KMS against the enclave's
/// attestation in production (`nitro`), given the credentials and the ciphertexts in the
/// order asked, answering the plaintexts in that order.
pub type Release = Box<
    dyn Fn(
            Credentials,
            Vec<Vec<u8>>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Vec<u8>>>> + Send>>
        + Send
        + Sync,
>;

/// The link to the host for the rest of the run, set once by [`boot`].
static LINK: OnceLock<Link> = OnceLock::new();

/// The channel to the host, as the rest of the process uses it.
pub struct Link {
    out: mpsc::UnboundedSender<Outgoing>,
    seal_key: [u8; seal::KEY_LEN],
}

/// What the writer task is asked to do, in order.
enum Outgoing {
    Frame(FromEnclave),
    /// Answered once every frame queued before it has been written.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// How long [`Link::flush`] waits for the host to take what is queued.
const FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The link, if this run booted in an enclave.
pub fn link() -> Option<&'static Link> {
    LINK.get()
}

impl Link {
    /// Sends one log line to the host. Never blocks: the channel is unbounded and the
    /// writer task drains it.
    pub fn log(&self, stream: &str, line: &str) {
        let _ = self.out.send(Outgoing::Frame(FromEnclave::Log {
            stream: stream.to_owned(),
            line: line.to_owned(),
        }));
    }

    /// Waits, at most [`FLUSH_TIMEOUT`], until everything sent so far has been written to
    /// the host: for the last lines before the process exits.
    pub async fn flush(&self) {
        let (done, written) = tokio::sync::oneshot::channel();
        if self.out.send(Outgoing::Flush(done)).is_ok() {
            let _ = tokio::time::timeout(FLUSH_TIMEOUT, written).await;
        }
    }

    /// Seals the config at `path` as it now is and sends it to the host to keep. Called
    /// after every write of the config file.
    pub fn config_written(&self, path: &Path) -> Result<()> {
        let text = std::fs::read(path)
            .wrap_err_with(|| format!("reading {} to seal it", path.display()))?;
        let sealed = seal::seal(&self.seal_key, &text)?;
        let _ = self.out.send(Outgoing::Frame(FromEnclave::Config {
            sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
        }));
        Ok(())
    }
}

/// What a boot leaves behind for the run.
#[derive(Debug)]
pub struct Booted {
    /// The names of the secrets installed.
    pub secrets: Vec<String>,
    /// The backoffice's PEM certificate chain, if the host handed one in.
    pub backoffice_certificate: Option<String>,
}

/// The release this build has: KMS against the enclave's attestation with the `nitro`
/// feature, none without it.
pub fn release(kms: &Kms) -> Result<Release> {
    #[cfg(feature = "nitro")]
    {
        let kms = kms.clone();
        Ok(Box::new(move |credentials, ciphertexts| {
            let kms = kms.clone();
            Box::pin(async move { nitro::decrypt_all(&kms, &credentials, &ciphertexts).await })
        }))
    }
    #[cfg(not(feature = "nitro"))]
    {
        let _ = kms;
        bail!("--enclave needs a build with the quote-updater `nitro` feature")
    }
}

/// Opens the tunnels, waits for the host's boot message on the link, releases the secrets
/// with `release`, installs them, writes the opened config to `config_path`, and keeps the
/// link for the run.
pub async fn boot(settings: &Settings, config_path: &Path, release: Release) -> Result<Booted> {
    let stream = accept_link(settings).await?;
    boot_on(config_path, stream, release).await
}

#[cfg(target_os = "linux")]
async fn accept_link(settings: &Settings) -> Result<tokio_vsock::VsockStream> {
    spawn_tunnels(settings);
    let port = settings.link_port;
    let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
        tokio_vsock::VMADDR_CID_ANY,
        port,
    ))
    .wrap_err_with(|| format!("binding the link's vsock port {port}"))?;
    tracing::info!("waiting for the boot helper on vsock port {port}");
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

/// Off Linux there is no vsock and so no enclave.
#[cfg(not(target_os = "linux"))]
async fn accept_link(_settings: &Settings) -> Result<tokio::io::DuplexStream> {
    bail!("--enclave runs inside a Nitro enclave, which is Linux only")
}

/// [`boot`] on an already connected link: what the tests drive over a socket pair.
pub async fn boot_on<S>(config_path: &Path, stream: S, release: Release) -> Result<Booted>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let first: ToEnclave = read_frame(&mut reader)
        .await?
        .ok_or_else(|| eyre!("the boot helper closed the link before sending anything"))?;
    let outcome = match first {
        ToEnclave::Boot {
            credentials,
            secrets,
            config,
            backoffice_certificate,
        } => install(config_path, credentials, secrets, config, release)
            .await
            .map(|(names, seal_key)| {
                (
                    Booted {
                        secrets: names,
                        backoffice_certificate,
                    },
                    seal_key,
                )
            }),
        other => Err(eyre!(
            "the first message on the link must be boot, not {other:?}"
        )),
    };
    match &outcome {
        Ok((booted, _)) => {
            write_frame(
                &mut writer,
                &FromEnclave::Ready {
                    secrets: booted.secrets.clone(),
                },
            )
            .await?;
        }
        Err(err) => {
            let _ = write_frame(
                &mut writer,
                &FromEnclave::Failed {
                    message: format!("{err:#}"),
                },
            )
            .await;
        }
    }
    let (booted, seal_key) = outcome?;

    // A reload asked for over the link is delivered as SIGHUP. Registering a listener now
    // replaces the signal's default action, which is to end the process, so one that
    // arrives before the run installs its own handler is dropped rather than fatal.
    #[cfg(unix)]
    drop(tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::hangup(),
    ));

    let (out, mut pending) = mpsc::unbounded_channel();
    LINK.set(Link { out, seal_key })
        .map_err(|_| eyre!("the enclave link was set up twice"))?;
    tokio::spawn(async move {
        let mut up = true;
        while let Some(message) = pending.recv().await {
            match message {
                Outgoing::Frame(frame) if up => {
                    if let Err(err) = write_frame(&mut writer, &frame).await {
                        // The host's end is gone; the run goes on without it. Nothing else
                        // can be done from inside, and quoting does not depend on it.
                        up = false;
                        // Not `tracing`: the operator layer would route the line back into
                        // this link. The enclave's debug console is the one place left.
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("the enclave link is down: {err:#}");
                        }
                    }
                }
                Outgoing::Frame(_) => {}
                Outgoing::Flush(done) => {
                    let _ = done.send(());
                }
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match read_frame::<_, ToEnclave>(&mut reader).await {
                Ok(Some(ToEnclave::Reload)) => raise(libc::SIGHUP),
                Ok(Some(ToEnclave::Shutdown)) => raise(libc::SIGINT),
                Ok(Some(ToEnclave::Boot { .. })) => {
                    tracing::warn!("a second boot message on the link; ignored")
                }
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!("the enclave link is unreadable: {err:#}");
                    break;
                }
            }
        }
    });
    Ok(booted)
}

/// Refuses any endpoint that is not `https://` or `wss://`. Inside an enclave every
/// connection is carried by the host, which reads and changes whatever is not under TLS
/// opened from inside. Each entry is `(what, url)`; the error names `what` and never the
/// URL, which can carry an API key.
pub fn require_tls(urls: &[(String, String)]) -> Result<()> {
    let plain: Vec<&str> = urls
        .iter()
        .filter(|(_, url)| {
            let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
            !matches!(scheme.to_ascii_lowercase().as_str(), "https" | "wss")
        })
        .map(|(what, _)| what.as_str())
        .collect();
    ensure!(
        plain.is_empty(),
        "inside an enclave every endpoint must be https:// or wss://, since the host carries \
         the bytes and could read or change anything else; not so: {}",
        plain.join(", ")
    );
    Ok(())
}

/// Sends the process the signal the host asked for, so a reload or a shutdown over the
/// link goes through exactly the handlers SIGHUP and ctrl-c do.
fn raise(signal: libc::c_int) {
    // SAFETY: `raise` takes a signal number and has no other precondition; the handlers for
    // both are installed by the run.
    unsafe {
        libc::raise(signal);
    }
}

async fn install(
    config_path: &Path,
    credentials: Credentials,
    ciphertexts: BTreeMap<String, String>,
    config: String,
    release: Release,
) -> Result<(Vec<String>, [u8; seal::KEY_LEN])> {
    ensure!(
        !ciphertexts.is_empty(),
        "the boot message carries no secrets"
    );
    let names: Vec<String> = ciphertexts.keys().cloned().collect();
    let blobs = ciphertexts
        .values()
        .map(|text| {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| eyre!("a secret's ciphertext is not base64"))
        })
        .collect::<Result<Vec<_>>>()?;
    let plaintexts = release(credentials, blobs)
        .await
        .wrap_err("releasing the secrets")?;
    ensure!(
        plaintexts.len() == names.len(),
        "the release answered {} secrets for {} ciphertexts",
        plaintexts.len(),
        names.len()
    );
    let mut secrets = BTreeMap::new();
    for (name, plaintext) in names.iter().zip(plaintexts) {
        let text = String::from_utf8(plaintext)
            .map_err(|_| eyre!("secret {name} does not decrypt to text"))?;
        secrets.insert(name.clone(), text.trim_end_matches(['\n', '\r']).to_owned());
    }
    let seal_key = seal::parse_key(secrets.get(SEAL_KEY_SECRET).ok_or_else(|| {
        eyre!("no {SEAL_KEY_SECRET} among the secrets; the config cannot be opened")
    })?)
    .wrap_err(SEAL_KEY_SECRET)?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(config.trim())
        .map_err(|_| eyre!("the sealed config is not base64"))?;
    let opened = seal::open(&seal_key, &sealed)?;
    write_private(config_path, &opened)?;
    crate::secrets::install(secrets)?;
    Ok((names, seal_key))
}

/// Writes `bytes` to `path`, readable by this process only.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("opening {}", path.display()))?;
    file.write_all(bytes)
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_tunnels(settings: &Settings) {
    for tunnel in &settings.forward {
        let (listen, cid, port) = (tunnel.listen, tunnel.cid, tunnel.port);
        tokio::spawn(async move {
            if let Err(err) = forward::outbound(listen, cid, port).await {
                tracing::error!("tunnel {listen}: {err:#}");
            }
        });
    }
    for tunnel in &settings.accept {
        let (port, to) = (tunnel.port, tunnel.to);
        tokio::spawn(async move {
            if let Err(err) = forward::inbound(port, to).await {
                tracing::error!("tunnel vsock {port}: {err:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
link_port = 5000

[kms]
region = "eu-west-1"
endpoint = "https://127.0.0.1:8443"

[[forward]]
listen = "127.0.0.1:443"
cid = 3
port = 8001

[[accept]]
port = 9464
to = "127.0.0.1:9464"

[backoffice]
key_secret = "BACKOFFICE_TLS_KEY"
google = { client_id = "id.apps.googleusercontent.com", client_secret_secret = "BACKOFFICE_OAUTH_SECRET", redirect_url = "https://quotes.example.com/auth/callback", allowed_domain = "example.com" }
"#;

    #[test]
    fn only_tls_endpoints_pass_and_the_refusal_does_not_print_the_url() {
        let ok = vec![
            (
                "rpc_url".to_owned(),
                "https://node.example/key123".to_owned(),
            ),
            (
                "builder a".to_owned(),
                "WSS://builder.example/ws".to_owned(),
            ),
        ];
        require_tls(&ok).unwrap();
        let bad = vec![
            (
                "rpc_url".to_owned(),
                "http://node.example/key123".to_owned(),
            ),
            ("endpoints.binance".to_owned(), "ws://mock".to_owned()),
            ("rpc_ws_url".to_owned(), "wss://fine".to_owned()),
        ];
        let err = require_tls(&bad).unwrap_err().to_string();
        assert!(
            err.contains("rpc_url") && err.contains("endpoints.binance"),
            "{err}"
        );
        assert!(!err.contains("rpc_ws_url"), "{err}");
        assert!(!err.contains("key123"), "{err}");
    }

    #[test]
    fn the_enclave_file_parses_and_names_its_mistakes() {
        let settings = Settings::parse(FILE).unwrap();
        assert_eq!(settings.link_port, 5000);
        assert_eq!(settings.kms.region, "eu-west-1");
        assert_eq!(settings.forward[0].port, 8001);
        assert_eq!(settings.accept[0].port, 9464);
        let backoffice = settings.backoffice.unwrap();
        assert_eq!(backoffice.allowed_domain.as_deref(), Some("example.com"));

        let cases = [
            (FILE.replace("link_port = 5000", ""), "link_port"),
            (FILE.replace("region = \"eu-west-1\"", ""), "region"),
            (
                FILE.replace(", allowed_domain = \"example.com\"", ""),
                "allowed_domain",
            ),
            (FILE.replace("https://quotes", "http://quotes"), "https"),
            (
                FILE.replace("cid = 3", "cid = 3\nextra = 1"),
                "unknown field",
            ),
        ];
        for (text, expected) in cases {
            let err = format!("{:#}", Settings::parse(&text).unwrap_err());
            assert!(err.contains(expected), "{expected:?} not in {err}");
        }
    }

    /// A release that answers each ciphertext with the same bytes: what a test's host
    /// sends is already the plaintext, and the boot's own steps are what is under test.
    fn plain_release() -> Release {
        Box::new(|_, ciphertexts| Box::pin(async move { Ok(ciphertexts) }))
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[tokio::test]
    async fn a_boot_installs_the_secrets_opens_the_config_and_keeps_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let seal_key_hex = "0303030303030303030303030303030303030303030303030303030303030303";
        let seal_key = seal::parse_key(seal_key_hex).unwrap();
        let sealed = seal::seal(&seal_key, b"[settings]\nrequote_ms = 40\n").unwrap();

        let (host, enclave) = tokio::io::duplex(1 << 16);
        let (mut host_reader, mut host_writer) = tokio::io::split(host);
        write_frame(
            &mut host_writer,
            &ToEnclave::Boot {
                credentials: Credentials {
                    access_key_id: "a".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                secrets: [
                    (SEAL_KEY_SECRET.to_owned(), b64(seal_key_hex.as_bytes())),
                    ("QU_ENCLAVE_TEST_KEY".to_owned(), b64(b"0xabc\n")),
                ]
                .into(),
                config: b64(&sealed),
                backoffice_certificate: Some("-----BEGIN CERTIFICATE-----".into()),
            },
        )
        .await
        .unwrap();

        let booted = boot_on(&config_path, enclave, plain_release())
            .await
            .unwrap();
        assert_eq!(booted.secrets.len(), 2);
        assert_eq!(
            booted.backoffice_certificate.as_deref(),
            Some("-----BEGIN CERTIFICATE-----")
        );
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            "[settings]\nrequote_ms = 40\n"
        );
        assert_eq!(
            crate::secrets::lookup("QU_ENCLAVE_TEST_KEY").as_deref(),
            Some("0xabc")
        );
        let ready: FromEnclave = read_frame(&mut host_reader).await.unwrap().unwrap();
        assert_eq!(
            ready,
            FromEnclave::Ready {
                secrets: vec![SEAL_KEY_SECRET.to_owned(), "QU_ENCLAVE_TEST_KEY".to_owned()]
            }
        );

        // The link carries log lines out, and a saved config back, sealed under the key.
        // It is the process's one link, so while this test holds it the other tests running
        // beside it log into it and write configs through it too: wait for our frames.
        let link = link().expect("the boot kept the link");
        link.log("stdout", "hello");
        loop {
            let frame: FromEnclave = read_frame(&mut host_reader).await.unwrap().unwrap();
            if frame
                == (FromEnclave::Log {
                    stream: "stdout".into(),
                    line: "hello".into(),
                })
            {
                break;
            }
        }
        std::fs::write(&config_path, "[settings]\nrequote_ms = 30\n").unwrap();
        link.config_written(&config_path).unwrap();
        loop {
            let frame: FromEnclave = read_frame(&mut host_reader).await.unwrap().unwrap();
            let FromEnclave::Config { sealed } = frame else {
                continue;
            };
            let blob = base64::engine::general_purpose::STANDARD
                .decode(sealed)
                .unwrap();
            // Every config is sealed under this link's key; ours is the one with our text.
            if seal::open(&seal_key, &blob).unwrap() == b"[settings]\nrequote_ms = 30\n" {
                break;
            }
        }
    }

    #[tokio::test]
    async fn a_boot_without_the_sealing_secret_or_with_a_tampered_config_fails_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let (host, enclave) = tokio::io::duplex(1 << 16);
        let (mut host_reader, mut host_writer) = tokio::io::split(host);
        write_frame(
            &mut host_writer,
            &ToEnclave::Boot {
                credentials: Credentials {
                    access_key_id: "a".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                secrets: [("OTHER".to_owned(), b64(b"x"))].into(),
                config: b64(b"not sealed"),
                backoffice_certificate: None,
            },
        )
        .await
        .unwrap();
        let err = boot_on(&config_path, enclave, plain_release())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains(SEAL_KEY_SECRET), "{err:#}");
        let failed: FromEnclave = read_frame(&mut host_reader).await.unwrap().unwrap();
        assert!(
            matches!(failed, FromEnclave::Failed { message } if message.contains(SEAL_KEY_SECRET))
        );
        assert!(!config_path.exists(), "nothing was written");
    }
}

//! Running inside an enclave: a compartment the host's own root cannot read or change (an
//! AWS Nitro enclave, for one), whose only connection is a channel to the host. Everything
//! the run needs crosses that channel at boot, and everything it must keep crosses it back,
//! unreadable or unforgeable by the host.
//!
//! Two things differ from platform to platform, and each is a trait with one implementation
//! per platform, chosen by `kind` in the enclave file:
//!
//! - [`SecretRelease`]: how the secrets the host hands in, encrypted, are decrypted by a key
//!   service that releases them only to this exact program, as the platform proves it.
//!   Shipped: `aws-nitro-kms` ([`aws_nitro`], behind the `aws-nitro` feature).
//! - [`HostLink`]: how the run reaches its host, and whatever the platform needs for the
//!   run's other connections. Shipped: `vsock` ([`vsock`], Linux only), with the tunnels a
//!   compartment without a network needs.
//!
//! Everything else is the same everywhere. The sequence, driven by `--enclave <file>`
//! (the file is part of the image, so the host cannot change it):
//!
//! 1. The link waits for the host, and the host's boot helper sends one
//!    [`protocol::HostMessage::Boot`]: credentials for the key service, every secret as
//!    ciphertext, the config sealed under one of those secrets, and the backoffice's
//!    certificate.
//! 2. The release decrypts the secrets, which are installed as the process's secrets
//!    ([`crate::secrets`]), so the config's `key_env` names and every other secret name
//!    resolve as they would from an environment.
//! 3. The config is opened ([`seal`]) and written to `--config`, and the run proceeds as it
//!    does anywhere else.
//! 4. For the rest of the run the link carries log lines out, the re-sealed config out
//!    after every save, and reload and shutdown requests in, since nothing outside may be
//!    able to send the process a signal.

#[cfg(feature = "aws-nitro")]
pub mod aws_nitro;
pub mod protocol;
pub mod seal;
#[cfg(target_os = "linux")]
pub mod vsock;

use std::{collections::BTreeMap, net::SocketAddr, path::Path, pin::Pin, sync::OnceLock};

use base64::Engine;
use eyre::{Result, WrapErr, ensure, eyre};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};

use protocol::{Credentials, HostMessage, RunMessage, read_frame, write_frame};

/// The secret the config is sealed under: 32 bytes as hex, released at boot like every
/// other.
pub const SEAL_KEY_SECRET: &str = "CONFIG_SEAL_KEY";

/// How the secrets the host hands in are decrypted: by a key service that releases them
/// only to this program, as proven by the platform it runs on.
pub trait SecretRelease: Send + Sync {
    /// The plaintext of every ciphertext, in the same order.
    fn release<'a>(
        &'a self,
        credentials: &'a Credentials,
        ciphertexts: &'a [Vec<u8>],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>>;
}

/// How the run reaches its host: sets up what the platform needs for the run's own
/// connections, then waits for the host's boot helper and answers with that connection.
pub trait HostLink: Send + Sync {
    /// The connection to the host, once it has connected.
    fn accept(&self) -> BoxFuture<'_, Result<Stream>>;
}

/// One connection to the host, whatever carries it.
pub type Stream = Pin<Box<dyn Connection>>;

/// The two traits a [`Stream`] needs, as one for the trait object.
pub trait Connection: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> Connection for T {}

/// The enclave file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    link: LinkKind,
    release: ReleaseKind,
    backoffice: Option<RawBackoffice>,
}

/// Which [`HostLink`] this run uses, and its settings.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LinkKind {
    /// A vsock to the host: what an AWS Nitro enclave has, and nothing else.
    Vsock {
        /// The port the host's boot helper connects to.
        port: u32,
        /// Outbound tunnels: how the run reaches anything at all.
        #[serde(default)]
        forward: Vec<Forward>,
        /// Inbound tunnels: how the backoffice and the metrics scrape are reached.
        #[serde(default)]
        accept: Vec<Accept>,
    },
}

/// Which [`SecretRelease`] this run uses, and its settings.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReleaseKind {
    /// AWS KMS, against an AWS Nitro enclave's attestation document.
    AwsNitroKms {
        /// The region the KMS key lives in.
        region: String,
        /// Where KMS is reached, when not its public endpoint.
        #[serde(default)]
        endpoint: Option<String>,
    },
}

/// A loopback address inside, piped to a vsock port on the host, where a proxy dials the
/// real destination.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    /// The loopback address to listen on.
    pub listen: SocketAddr,
    /// The context id to connect to (the host is `3`).
    pub cid: u32,
    /// The vsock port there.
    pub port: u32,
}

/// A vsock port accepted on, piped to an address inside.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    /// The vsock port.
    pub port: u32,
    /// The address inside it is piped to.
    pub to: SocketAddr,
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

/// How the backoffice is reached in an enclave: its own HTTPS, and a Google login
/// checked in the process. See `login.rs`.
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
    /// How the run reaches its host.
    pub link: LinkKind,
    /// How the secrets are decrypted.
    pub release: ReleaseKind,
    /// The backoffice's login, when it is served from inside.
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
        let backoffice = match raw.backoffice {
            None => None,
            Some(b) => {
                ensure!(
                    b.google.allowed_domain.is_some() || !b.google.allowed_accounts.is_empty(),
                    "[backoffice.google]: set allowed_domain or allowed_accounts, or nobody \
                     can log in"
                );
                ensure!(
                    b.google.redirect_url.starts_with("https://"),
                    "[backoffice.google]: redirect_url must be https://"
                );
                Some(BackofficeSettings {
                    key_secret: b.key_secret,
                    client_id: b.google.client_id,
                    client_secret_secret: b.google.client_secret_secret,
                    redirect_url: b.google.redirect_url,
                    allowed_domain: b.google.allowed_domain,
                    allowed_accounts: b.google.allowed_accounts,
                })
            }
        };
        Ok(Self {
            link: raw.link,
            release: raw.release,
            backoffice,
        })
    }
}

impl LinkKind {
    /// The link this kind names.
    pub fn build(&self) -> Result<Box<dyn HostLink>> {
        match self {
            #[cfg(target_os = "linux")]
            LinkKind::Vsock {
                port,
                forward,
                accept,
            } => Ok(Box::new(vsock::VsockLink {
                port: *port,
                forward: forward.clone(),
                accept: accept.clone(),
            })),
            #[cfg(not(target_os = "linux"))]
            LinkKind::Vsock { .. } => eyre::bail!("[link] kind = \"vsock\" exists on Linux only"),
        }
    }
}

impl ReleaseKind {
    /// The release this kind names, if this build has it.
    pub fn build(&self) -> Result<Box<dyn SecretRelease>> {
        match self {
            #[cfg(feature = "aws-nitro")]
            ReleaseKind::AwsNitroKms { region, endpoint } => Ok(Box::new(aws_nitro::AwsNitroKms {
                region: region.clone(),
                endpoint: endpoint.clone(),
            })),
            #[cfg(not(feature = "aws-nitro"))]
            ReleaseKind::AwsNitroKms { .. } => eyre::bail!(
                "[release] kind = \"aws-nitro-kms\" needs a build with the quote-updater \
                 `aws-nitro` feature"
            ),
        }
    }
}

/// The channel to the host for the rest of the run, set once by [`boot`].
static HOST: OnceLock<Host> = OnceLock::new();

/// The channel to the host, as the rest of the process uses it.
pub struct Host {
    out: mpsc::UnboundedSender<Outgoing>,
    seal_key: [u8; seal::KEY_LEN],
}

/// What the writer task is asked to do, in order.
enum Outgoing {
    Frame(RunMessage),
    /// Answered once every frame queued before it has been written.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// How long [`Host::flush`] waits for the host to take what is queued.
const FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The channel to the host, if this run booted in an enclave.
pub fn host() -> Option<&'static Host> {
    HOST.get()
}

impl Host {
    /// Sends one log line to the host. Never blocks: the channel is unbounded and the
    /// writer task drains it.
    pub fn log(&self, stream: &str, line: &str) {
        let _ = self.out.send(Outgoing::Frame(RunMessage::Log {
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
        let _ = self.out.send(Outgoing::Frame(RunMessage::Config {
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

/// Builds the file's link and release, waits for the host on the link, decrypts the
/// secrets, installs them, writes the opened config to `config_path`, and keeps the
/// channel to the host for the run.
pub async fn boot(settings: &Settings, config_path: &Path) -> Result<Booted> {
    let release = settings.release.build()?;
    let link = settings.link.build()?;
    let stream = link.accept().await?;
    boot_on(config_path, stream, release.as_ref()).await
}

/// [`boot`] on an already connected link, with a given release: what the tests drive over
/// an in-memory connection.
pub async fn boot_on<S>(
    config_path: &Path,
    stream: S,
    release: &dyn SecretRelease,
) -> Result<Booted>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let first: HostMessage = read_frame(&mut reader)
        .await?
        .ok_or_else(|| eyre!("the boot helper closed the link before sending anything"))?;
    let outcome = match first {
        HostMessage::Boot {
            credentials,
            secrets,
            config,
            backoffice_certificate,
        } => install(config_path, &credentials, secrets, config, release)
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
                &RunMessage::Ready {
                    secrets: booted.secrets.clone(),
                },
            )
            .await?;
        }
        Err(err) => {
            let _ = write_frame(
                &mut writer,
                &RunMessage::Failed {
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
    HOST.set(Host { out, seal_key })
        .map_err(|_| eyre!("the channel to the host was set up twice"))?;
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
                        // this channel. A debug console is the one place left.
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("the channel to the host is down: {err:#}");
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
            match read_frame::<_, HostMessage>(&mut reader).await {
                Ok(Some(HostMessage::Reload)) => raise(libc::SIGHUP),
                Ok(Some(HostMessage::Shutdown)) => raise(libc::SIGINT),
                Ok(Some(HostMessage::Boot { .. })) => {
                    tracing::warn!("a second boot message from the host; ignored")
                }
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!("the channel to the host is unreadable: {err:#}");
                    break;
                }
            }
        }
    });
    Ok(booted)
}

/// Refuses any endpoint that is not `https://` or `wss://`. In an enclave every
/// connection may be carried by the host, which reads and changes whatever is not under
/// TLS opened from inside. Each entry is `(what, url)`; the error names `what` and never
/// the URL, which can carry an API key.
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
        "in an enclave every endpoint must be https:// or wss://, since the host may \
         carry the bytes and could read or change anything else; not so: {}",
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
    credentials: &Credentials,
    ciphertexts: BTreeMap<String, String>,
    config: String,
    release: &dyn SecretRelease,
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
    let plaintexts = release
        .release(credentials, &blobs)
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

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[link]
kind = "vsock"
port = 5000

[[link.forward]]
listen = "127.0.0.1:443"
cid = 3
port = 8001

[[link.accept]]
port = 9464
to = "127.0.0.1:9464"

[release]
kind = "aws-nitro-kms"
region = "eu-west-1"
endpoint = "https://127.0.0.1:8443"

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
    fn the_file_names_its_link_and_release_by_kind_and_its_mistakes_are_named() {
        let settings = Settings::parse(FILE).unwrap();
        let LinkKind::Vsock {
            port,
            forward,
            accept,
        } = &settings.link;
        assert_eq!((*port, forward[0].port, accept[0].port), (5000, 8001, 9464));
        let ReleaseKind::AwsNitroKms { region, .. } = &settings.release;
        assert_eq!(region, "eu-west-1");
        let backoffice = settings.backoffice.unwrap();
        assert_eq!(backoffice.allowed_domain.as_deref(), Some("example.com"));

        let cases = [
            (
                FILE.replace("kind = \"vsock\"", "kind = \"carrier-pigeon\""),
                "unknown variant",
            ),
            (
                FILE.replace("kind = \"aws-nitro-kms\"", "kind = \"other\""),
                "unknown variant",
            ),
            (FILE.replace("port = 5000\n", ""), "port"),
            (FILE.replace("region = \"eu-west-1\"\n", ""), "region"),
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

    /// A release that answers each ciphertext with the same bytes: what a test's host sends
    /// is already the plaintext, and the boot's own steps are what is under test.
    struct PlainRelease;

    impl SecretRelease for PlainRelease {
        fn release<'a>(
            &'a self,
            _credentials: &'a Credentials,
            ciphertexts: &'a [Vec<u8>],
        ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>> {
            Box::pin(async move { Ok(ciphertexts.to_vec()) })
        }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[tokio::test]
    async fn a_boot_installs_the_secrets_opens_the_config_and_keeps_the_channel() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let seal_key_hex = "0303030303030303030303030303030303030303030303030303030303030303";
        let seal_key = seal::parse_key(seal_key_hex).unwrap();
        let sealed = seal::seal(&seal_key, b"[settings]\nrequote_ms = 40\n").unwrap();

        let (host_end, run_end) = tokio::io::duplex(1 << 16);
        let (mut host_reader, mut host_writer) = tokio::io::split(host_end);
        write_frame(
            &mut host_writer,
            &HostMessage::Boot {
                credentials: Credentials::default(),
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

        let booted = boot_on(&config_path, run_end, &PlainRelease).await.unwrap();
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
        let ready: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
        assert_eq!(
            ready,
            RunMessage::Ready {
                secrets: vec![SEAL_KEY_SECRET.to_owned(), "QU_ENCLAVE_TEST_KEY".to_owned()]
            }
        );

        // The channel carries log lines out, and a saved config back, sealed under the key.
        // It is the process's one channel, so while this test holds it the other tests
        // running beside it log into it and write configs through it too: wait for ours.
        let host = host().expect("the boot kept the channel");
        host.log("stdout", "hello");
        loop {
            let frame: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
            if frame
                == (RunMessage::Log {
                    stream: "stdout".into(),
                    line: "hello".into(),
                })
            {
                break;
            }
        }
        std::fs::write(&config_path, "[settings]\nrequote_ms = 30\n").unwrap();
        host.config_written(&config_path).unwrap();
        loop {
            let frame: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
            let RunMessage::Config { sealed } = frame else {
                continue;
            };
            let blob = base64::engine::general_purpose::STANDARD
                .decode(sealed)
                .unwrap();
            // Every config is sealed under this channel's key; ours is the one with our text.
            if seal::open(&seal_key, &blob).unwrap() == b"[settings]\nrequote_ms = 30\n" {
                break;
            }
        }
    }

    #[tokio::test]
    async fn a_boot_without_the_sealing_secret_or_with_a_tampered_config_fails_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let (host_end, run_end) = tokio::io::duplex(1 << 16);
        let (mut host_reader, mut host_writer) = tokio::io::split(host_end);
        write_frame(
            &mut host_writer,
            &HostMessage::Boot {
                credentials: Credentials::default(),
                secrets: [("OTHER".to_owned(), b64(b"x"))].into(),
                config: b64(b"not sealed"),
                backoffice_certificate: None,
            },
        )
        .await
        .unwrap();
        let err = boot_on(&config_path, run_end, &PlainRelease)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains(SEAL_KEY_SECRET), "{err:#}");
        let failed: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
        assert!(
            matches!(failed, RunMessage::Failed { message } if message.contains(SEAL_KEY_SECRET))
        );
        assert!(!config_path.exists(), "nothing was written");
    }
}

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

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc, LazyLock, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::Engine;
use eyre::{Result, WrapErr, ensure, eyre};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
};

use protocol::{Credentials, HostMessage, RunMessage, read_body, read_frame, write_frame};

/// The secret the config is sealed under: 32 bytes as hex, released at boot like every
/// other.
pub const SEAL_KEY_SECRET: &str = "CONFIG_SEAL_KEY";

/// How the secrets the host hands in are decrypted: by a key service that releases them
/// only to this program, as proven by the platform it runs on.
pub trait SecretRelease: Send + Sync {
    /// The plaintext of every `(name, ciphertext)`, in the same order. The name is handed
    /// over so the release can hold the key service to it: the host chooses which
    /// ciphertext it sends under which name, and a ciphertext must open only under the
    /// name it was made for.
    fn release<'a>(
        &'a self,
        credentials: &'a Credentials,
        secrets: &'a [(String, Vec<u8>)],
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
        /// The KMS key's full ARN. Every decrypt names it, so a ciphertext under any other
        /// key (one the host made itself, in its own account or this one) is refused by
        /// KMS rather than opened.
        key_id: String,
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
/// checked in the process. See `login/mod.rs`.
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
        match &raw.release {
            ReleaseKind::AwsNitroKms {
                key_id, endpoint, ..
            } => {
                // An ARN names one key in one account; a bare id or an alias would let the
                // decrypt resolve to whatever key the name points at when it runs.
                ensure!(
                    key_id.starts_with("arn:") && key_id.contains(":key/"),
                    "[release] key_id must be the KMS key's full ARN \
                     (arn:aws:kms:<region>:<account>:key/<id>), not an id or an alias"
                );
                if let Some(endpoint) = endpoint {
                    ensure!(
                        endpoint.to_ascii_lowercase().starts_with("https://"),
                        "[release] endpoint must be https://: the request carries the \
                         credentials and the attestation through the host"
                    );
                }
            }
        }
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
            ReleaseKind::AwsNitroKms {
                region,
                key_id,
                endpoint,
            } => Ok(Box::new(aws_nitro::AwsNitroKms {
                region: region.clone(),
                key_id: key_id.clone(),
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

/// Raised by [`boot`] and never by [`boot_on`] alone: what the checks that hold only inside
/// an enclave read (the TLS-only rule on a builder or a setting saved later, the Ondo API's
/// https). Separate from [`HOST`] because the tests drive [`boot_on`] in the same process as
/// every other test, whose mock endpoints are plain `ws://127.0.0.1`.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether this process booted inside an enclave.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Raised when the host asks the run to stop. A value rather than a signal, so the run's own
/// shutdown path takes it whatever trigger the binary set, and one that arrives before the
/// run is listening is still there when it looks.
static SHUTDOWN: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);

/// Resolves once the host has asked the run to stop; never outside an enclave.
pub async fn shutdown_requested() {
    let mut asked = SHUTDOWN.subscribe();
    // Err only if the sender is dropped, which a static never is.
    let _ = asked.wait_for(|asked| *asked).await;
}

/// The channel to the host, as the rest of the process uses it.
pub struct Host {
    out: mpsc::UnboundedSender<Outgoing>,
    seal_key: [u8; seal::KEY_LEN],
    /// Lowered by the writer the first time a frame fails to reach the host. From then on
    /// nothing reaches it, so a save that depends on it says so instead of passing.
    up: Arc<AtomicBool>,
}

/// What the writer task is asked to do, in order.
enum Outgoing {
    Frame(RunMessage),
    /// Answered once every frame queued before it has been written.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// How long [`Host::flush`] waits for the host to take what is queued.
const FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The channel to the host, if this run booted in an enclave. Gated on [`active`] as well, so
/// a test that drives [`boot_on`] does not route every other test's output and config writes
/// into its channel.
pub fn host() -> Option<&'static Host> {
    if active() { HOST.get() } else { None }
}

impl Host {
    /// Sends one log line to the host, every URL in it cut to its scheme and host (see
    /// [`scrub_urls`]). Never blocks: the channel is unbounded and the writer task drains it.
    pub fn log(&self, stream: &str, line: &str) {
        let _ = self.out.send(Outgoing::Frame(RunMessage::Log {
            stream: stream.to_owned(),
            line: scrub_urls(line),
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

    /// Refuses once the link to the host is down: a config saved now would last only as long
    /// as this run, and the next boot would start from the one before it.
    pub fn ensure_up(&self) -> Result<()> {
        ensure!(
            self.up.load(Ordering::SeqCst),
            "the link to the host is down, so a config saved now could not be kept: the host \
             still holds the one before it, and a restart of the enclave would start from \
             that. Restart the enclave once the host's boot helper is back"
        );
        Ok(())
    }

    /// Seals the config at `path` as it now is and sends it to the host to keep. Called
    /// after every write of the config file.
    pub fn config_written(&self, path: &Path) -> Result<()> {
        self.ensure_up()?;
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
    let booted = boot_on(config_path, stream, release.as_ref()).await?;
    ACTIVE.store(true, Ordering::Relaxed);
    // A panic's message goes to stderr, which nothing reads in here: send it where the
    // operator looks, then do what the hook did before.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(host) = host() {
            host.log("stderr", &info.to_string());
        }
        previous(info);
    }));
    Ok(booted)
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
                    message: scrub_urls(&format!("{err:#}")),
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
    let up = Arc::new(AtomicBool::new(true));
    HOST.set(Host {
        out,
        seal_key,
        up: Arc::clone(&up),
    })
    .map_err(|_| eyre!("the channel to the host was set up twice"))?;
    tokio::spawn(async move {
        while let Some(message) = pending.recv().await {
            match message {
                Outgoing::Frame(frame) if up.load(Ordering::SeqCst) => {
                    if let Err(err) = write_frame(&mut writer, &frame).await {
                        // The host's end is gone, and the link is never accepted again: the
                        // run goes on without it, quoting does not depend on it, and a save
                        // from now on says it was not kept (`config_written`).
                        up.store(false, Ordering::SeqCst);
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
            // A frame that arrived whole but does not parse (a kind this build does not know,
            // from a newer helper) is skipped: the stream is still aligned on the next frame.
            // Only a broken stream ends the loop.
            let body = match read_body(&mut reader).await {
                Ok(Some(body)) => body,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!("the channel to the host is unreadable: {err:#}");
                    break;
                }
            };
            match serde_json::from_slice::<HostMessage>(&body) {
                Ok(HostMessage::Reload) => raise(libc::SIGHUP),
                Ok(HostMessage::Shutdown) => {
                    SHUTDOWN.send_replace(true);
                }
                Ok(HostMessage::Boot { .. }) => {
                    tracing::warn!("a second boot message from the host; ignored")
                }
                Err(err) => {
                    tracing::warn!("a message from the host this run cannot read, ignored: {err}")
                }
            }
        }
    });
    Ok(booted)
}

/// `text` with every URL in it cut to its scheme and host, the way the recorder cuts
/// `rpc_url`: a provider's key rides in the path (`/v2/<key>`), the query or the userinfo,
/// and an HTTP client's error quotes the whole URL (`... for url (https://...)`). Applied to
/// everything that crosses to the host, which must not read the config's secrets.
pub fn scrub_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        // The scheme: the letters, digits, `+`, `-` and `.` just before `://`.
        let scheme_start = rest[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        // The URL runs to whitespace or a quote; a closing bracket or punctuation at its
        // end is the sentence's, not the URL's, and is kept.
        let tail = &rest[at + 3..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>'))
            .unwrap_or(tail.len());
        let token = &tail[..end];
        let kept = token.len() - token.trim_end_matches([')', ',', '.', ';', ':']).len();
        let url = &rest[scheme_start..at + 3 + end - kept];
        out.push_str(&rest[..scheme_start]);
        if scheme_start == at {
            // `://` with no scheme in front of it is not a URL.
            out.push_str("://");
            rest = tail;
            continue;
        }
        match url::Url::parse(url) {
            Ok(parsed) => match (parsed.host_str(), parsed.port()) {
                (Some(host), Some(port)) => {
                    out.push_str(&format!("{}://{host}:{port}", parsed.scheme()))
                }
                (Some(host), None) => out.push_str(&format!("{}://{host}", parsed.scheme())),
                (None, _) => out.push_str(&format!("{}://<redacted>", parsed.scheme())),
            },
            Err(_) => out.push_str(&format!("{}://<redacted>", &rest[scheme_start..at])),
        }
        out.push_str(&token[token.len() - kept..]);
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Every endpoint the settings and builders name, as `(what, url)` for [`require_tls`]: the
/// one list startup checks and the backoffice checks again before it saves, so the two
/// cannot disagree about what a run inside an enclave will refuse.
pub fn named_endpoints(
    rpc_url: &str,
    rpc_ws_url: Option<&str>,
    binance_ws: Option<&str>,
    endpoints: &BTreeMap<String, String>,
    builders: &[crate::config::BuilderConfig],
) -> Vec<(String, String)> {
    let mut urls = vec![("rpc_url".to_owned(), rpc_url.to_owned())];
    if let Some(ws) = rpc_ws_url {
        urls.push(("rpc_ws_url".to_owned(), ws.to_owned()));
    }
    if let Some(binance) = binance_ws {
        urls.push(("binance_ws".to_owned(), binance.to_owned()));
    }
    for (venue, url) in endpoints {
        urls.push((format!("endpoints.{venue}"), url.clone()));
    }
    for builder in builders {
        urls.push((
            format!("builder {}", builder.name),
            builder.endpoint.clone(),
        ));
    }
    urls
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

/// Sends the process the signal the host asked for, so a reload over the link goes through
/// exactly the handler SIGHUP does. A shutdown is not a signal: see [`shutdown_requested`].
fn raise(signal: libc::c_int) {
    // SAFETY: `raise` takes a signal number and has no other precondition; the boot
    // registered a listener for SIGHUP, so its default action (ending the process) is off.
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
        .into_iter()
        .map(|(name, text)| {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map(|blob| (name, blob))
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
    use tokio::io::AsyncWriteExt;

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
key_id = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
endpoint = "https://127.0.0.1:8443"

[backoffice]
key_secret = "BACKOFFICE_TLS_KEY"
google = { client_id = "id.apps.googleusercontent.com", client_secret_secret = "BACKOFFICE_OAUTH_SECRET", redirect_url = "https://quotes.example.com/auth/callback", allowed_domain = "example.com" }
"#;

    /// The shipped example is a file the parser takes, so the docs that point at it do not
    /// point at something stale.
    #[test]
    fn the_example_enclave_file_parses() {
        let example = include_str!("../../../deploy/aws-nitro/enclave.example.toml");
        let settings = Settings::parse(example).unwrap();
        assert!(settings.backoffice.is_some());
    }

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
                FILE.replace("arn:aws:kms:eu-west-1:111122223333:key/", "alias/"),
                "ARN",
            ),
            (
                FILE.replace("https://127.0.0.1:8443", "http://127.0.0.1:8443"),
                "endpoint must be https",
            ),
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
            secrets: &'a [(String, Vec<u8>)],
        ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>> {
            Box::pin(async move { Ok(secrets.iter().map(|(_, blob)| blob.clone()).collect()) })
        }
    }

    /// A release that records what it was asked to open and opens nothing: the boot's side of
    /// the binding is that each ciphertext reaches the release under the name the host sent
    /// it with, for KMS to hold it to (the name is the encryption context).
    struct RecordingRelease(std::sync::Mutex<Vec<(String, Vec<u8>)>>);

    impl SecretRelease for RecordingRelease {
        fn release<'a>(
            &'a self,
            _credentials: &'a Credentials,
            secrets: &'a [(String, Vec<u8>)],
        ) -> BoxFuture<'a, Result<Vec<Vec<u8>>>> {
            self.0.lock().unwrap().extend_from_slice(secrets);
            Box::pin(async move { Err(eyre!("InvalidCiphertextException")) })
        }
    }

    #[tokio::test]
    async fn each_ciphertext_reaches_the_release_under_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let release = RecordingRelease(Default::default());
        let secrets: BTreeMap<String, String> = [
            ("UPDATER_KEY_B".to_owned(), b64(b"ct-b")),
            (SEAL_KEY_SECRET.to_owned(), b64(b"ct-seal")),
            ("UPDATER_KEY_A".to_owned(), b64(b"ct-a")),
        ]
        .into();
        let err = install(
            &config_path,
            &Credentials::default(),
            secrets,
            b64(b"sealed"),
            &release,
        )
        .await
        .unwrap_err();
        // A refusal from the key service is a refused boot, with nothing written.
        assert!(format!("{err:#}").contains("InvalidCiphertext"), "{err:#}");
        assert!(!config_path.exists());
        assert_eq!(
            *release.0.lock().unwrap(),
            [
                (SEAL_KEY_SECRET.to_owned(), b"ct-seal".to_vec()),
                ("UPDATER_KEY_A".to_owned(), b"ct-a".to_vec()),
                ("UPDATER_KEY_B".to_owned(), b"ct-b".to_vec()),
            ]
        );
    }

    #[test]
    fn a_url_crossing_to_the_host_keeps_its_scheme_and_host_only() {
        let line = "Error: failed to connect to RPC: reqwest error: error sending request for \
                    url (https://eth-mainnet.g.alchemy.com/v2/k3yk3yk3y?x=1): connection closed";
        let scrubbed = scrub_urls(line);
        assert_eq!(
            scrubbed,
            "Error: failed to connect to RPC: reqwest error: error sending request for url \
             (https://eth-mainnet.g.alchemy.com): connection closed"
        );
        assert_eq!(
            scrub_urls("wss://user:pw@node.example:8546/ws, then postgres://u:p@db:5432/feed."),
            "wss://node.example:8546, then postgres://db:5432."
        );
        // Text with no URL, a bare `://`, and a non-ASCII character before a scheme.
        assert_eq!(scrub_urls("halted WETH/USDC"), "halted WETH/USDC");
        assert_eq!(scrub_urls("a :// b"), "a :// b");
        assert_eq!(scrub_urls("é https://h/k"), "é https://h");
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

        // The channel carries log lines out, URLs cut to their host, and a saved config back,
        // sealed under the key. `HOST` directly: `host()` answers only in a process that
        // booted for real, which a test process never is.
        let host = HOST.get().expect("the boot kept the channel");
        host.log("stdout", "hello from https://node.example/v2/key");
        let frame: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
        assert_eq!(
            frame,
            RunMessage::Log {
                stream: "stdout".into(),
                line: "hello from https://node.example".into(),
            }
        );
        std::fs::write(&config_path, "[settings]\nrequote_ms = 30\n").unwrap();
        host.config_written(&config_path).unwrap();
        let frame: RunMessage = read_frame(&mut host_reader).await.unwrap().unwrap();
        let RunMessage::Config { sealed } = frame else {
            panic!("expected the sealed config, got {frame:?}");
        };
        let blob = base64::engine::general_purpose::STANDARD
            .decode(sealed)
            .unwrap();
        assert_eq!(
            seal::open(&seal_key, &blob).unwrap(),
            b"[settings]\nrequote_ms = 30\n"
        );

        // A frame this build cannot read is skipped, and the next one still arrives: a
        // reload, delivered as the SIGHUP the boot made safe to raise.
        let mut hangup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        let unknown = br#"{"kind":"rotate_keys"}"#;
        host_writer
            .write_all(&(unknown.len() as u32).to_be_bytes())
            .await
            .unwrap();
        host_writer.write_all(unknown).await.unwrap();
        write_frame(&mut host_writer, &HostMessage::Reload)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), hangup.recv())
            .await
            .expect("the reload after an unreadable frame was delivered");

        // Once the host's end is gone, a save says it was not kept rather than passing.
        drop((host_reader, host_writer));
        let refused = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                host.log("stdout", "is anyone there");
                if let Err(err) = host.config_written(&config_path) {
                    break err;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the writer noticed the link is down");
        assert!(format!("{refused:#}").contains("link to the host is down"));
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

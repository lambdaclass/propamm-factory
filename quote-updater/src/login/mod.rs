//! The backoffice's own front door, for a run whose host is not trusted with it (an
//! enclave): HTTPS terminated in this process, so the host carries ciphertext only, and a
//! Google login checked in this process on every request.
//!
//! The login is OpenID Connect's authorization-code flow. A request without a valid session
//! is sent to Google with a fresh `state` and `nonce`, remembered in a short-lived cookie.
//! Google sends the browser back to `/auth/callback` with a code; the code is exchanged at
//! Google's token endpoint for an ID token, whose signature is checked against Google's
//! published keys, along with its audience (this client), issuer, expiry and nonce. The
//! account must have a verified email and be on the allowed list (a Workspace domain, or
//! named accounts). The session is then a cookie this process signs with a key it made at
//! startup, so a restart logs everyone out and nothing outside can mint one.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine;
use eyre::{Result, WrapErr, ensure, eyre};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, RwLock, Semaphore, mpsc},
    time::Sleep,
};
use tokio_rustls::{TlsAcceptor, rustls, server::TlsStream};

use crate::enclave::BackofficeSettings;

/// The session cookie. `__Host-`: the browser takes it only from this exact origin over
/// HTTPS, so a sibling subdomain cannot plant or overwrite one.
const SESSION_COOKIE: &str = "__Host-qu_session";
/// The cookie carrying a login in progress: its `state` and `nonce`.
const LOGIN_COOKIE: &str = "__Host-qu_login";
/// How long a session lasts before the login is asked again.
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// How long a login may take between leaving for Google and coming back.
const LOGIN_LIFETIME: Duration = Duration::from_secs(10 * 60);

const GOOGLE_AUTH: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_KEYS: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
/// Google rotates its signing keys every few days and publishes them ahead of use.
const KEYS_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// How long a TLS handshake may take before the connection is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection may go without a byte in either direction before it is dropped.
/// The server applies no read timeout of its own, so without this a client that completes
/// the handshake and then says nothing holds its connection for ever.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// The most connections served at once, handshakes included. Past it new ones wait in the
/// kernel's queue: the backoffice has a handful of users, and an enclave has a fixed number
/// of file descriptors that the run's own connections need too.
const MAX_CONNECTIONS: usize = 128;

/// The backoffice's TLS and login, built once at startup.
pub struct Secure {
    pub(crate) login: Arc<Login>,
    pub(crate) tls: Arc<rustls::ServerConfig>,
}

impl Secure {
    /// From the enclave file's `[backoffice]` and what the host handed in at boot: the
    /// certificate as is, its private key and the OAuth client secret from the secrets KMS
    /// released. A certificate that does not match the key is refused.
    pub fn new(settings: &BackofficeSettings, certificate: Option<&str>) -> Result<Self> {
        let certificate = certificate.ok_or_else(|| {
            eyre!("the enclave file has a [backoffice] but the host handed in no certificate")
        })?;
        let key = crate::secrets::lookup(&settings.key_secret)
            .ok_or_else(|| eyre!("{} is not among the secrets", settings.key_secret))?;
        let client_secret = crate::secrets::lookup(&settings.client_secret_secret)
            .ok_or_else(|| eyre!("{} is not among the secrets", settings.client_secret_secret))?;
        Ok(Self {
            login: Arc::new(Login::new(settings, client_secret)?),
            tls: tls_config(certificate.as_bytes(), key.as_bytes())?,
        })
    }
}

/// Who may log in.
#[derive(Clone, Debug)]
struct Allow {
    domain: Option<String>,
    accounts: Vec<String>,
}

impl Allow {
    /// Whether the account the token names may use the backoffice, or why not.
    fn admits(&self, claims: &Claims) -> std::result::Result<(), String> {
        if !claims.email_verified {
            return Err(format!("{} has no verified email", claims.email));
        }
        let email = claims.email.to_ascii_lowercase();
        if self.accounts.iter().any(|a| a.eq_ignore_ascii_case(&email)) {
            return Ok(());
        }
        // `hd` is the account's Workspace domain, which Google sets only for an account
        // that domain administers: an email address ending in it is not the same thing.
        if let (Some(domain), Some(hd)) = (&self.domain, &claims.hd)
            && domain.eq_ignore_ascii_case(hd)
        {
            return Ok(());
        }
        Err(format!(
            "{} is not allowed to use this backoffice",
            claims.email
        ))
    }
}

/// What the ID token says, as far as this login reads it.
#[derive(Debug, Deserialize)]
struct Claims {
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    hd: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// The login: the OAuth client, the allowed accounts, the session key, and Google's keys.
pub struct Login {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    /// `redirect_url`'s origin (`https://host[:port]`): the only one a change may come from.
    origin: String,
    allow: Allow,
    session_key: [u8; 32],
    http: reqwest::Client,
    keys: RwLock<Option<(JwkSet, Instant)>>,
}

impl Login {
    fn new(settings: &BackofficeSettings, client_secret: String) -> Result<Self> {
        let redirect = url::Url::parse(&settings.redirect_url)
            .wrap_err("[backoffice.google] redirect_url is not a URL")?;
        Ok(Self {
            client_id: settings.client_id.clone(),
            client_secret,
            redirect_url: settings.redirect_url.clone(),
            origin: redirect.origin().ascii_serialization(),
            allow: Allow {
                domain: settings.allowed_domain.clone(),
                accounts: settings.allowed_accounts.clone(),
            },
            session_key: rand::random(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .wrap_err("http client")?,
            keys: RwLock::new(None),
        })
    }

    /// Google's signing keys, fetched at most once an hour, and again when a token names a
    /// key the cached set does not have.
    async fn keys(&self, kid: &str) -> Result<JwkSet> {
        if let Some((set, at)) = self.keys.read().await.as_ref()
            && at.elapsed() < KEYS_MAX_AGE
            && set.find(kid).is_some()
        {
            return Ok(set.clone());
        }
        let body = self
            .http
            .get(GOOGLE_KEYS)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let set: JwkSet = serde_json::from_str(&body).wrap_err("Google's keys")?;
        *self.keys.write().await = Some((set.clone(), Instant::now()));
        Ok(set)
    }

    /// The ID token for `code`, from Google's token endpoint.
    async fn exchange(&self, code: &str) -> Result<String> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", code)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("grant_type", "authorization_code")
            .finish();
        let answer = self
            .http
            .post(GOOGLE_TOKEN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;
        let status = answer.status();
        let text = answer.text().await?;
        ensure!(
            status.is_success(),
            "Google's token endpoint answered {status}"
        );
        #[derive(Deserialize)]
        struct Tokens {
            id_token: String,
        }
        Ok(serde_json::from_str::<Tokens>(&text)
            .wrap_err("Google's token answer")?
            .id_token)
    }

    /// Where a browser is sent to log in.
    fn authorize_url(&self, state: &str, nonce: &str) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", "openid email")
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("prompt", "select_account");
        if let Some(domain) = &self.allow.domain {
            query.append_pair("hd", domain);
        }
        format!("{GOOGLE_AUTH}?{}", query.finish())
    }
}

/// The claims of `token` once its signature, audience, issuer, expiry and nonce are checked.
fn verify_id_token(token: &str, keys: &JwkSet, client_id: &str, nonce: &str) -> Result<Claims> {
    let header = jsonwebtoken::decode_header(token).wrap_err("not a token")?;
    ensure!(
        header.alg == Algorithm::RS256,
        "token signed with {:?}",
        header.alg
    );
    let kid = header.kid.ok_or_else(|| eyre!("the token names no key"))?;
    let jwk = keys
        .find(&kid)
        .ok_or_else(|| eyre!("the token is signed with a key Google does not publish"))?;
    let key = DecodingKey::from_jwk(jwk).wrap_err("Google's key")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&GOOGLE_ISSUERS);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);
    let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|err| eyre!("the token does not check: {err}"))?
        .claims;
    ensure!(
        claims.nonce.as_deref() == Some(nonce),
        "the token's nonce is not this login's"
    );
    Ok(claims)
}

type HmacSha256 = Hmac<Sha256>;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `payload` with its MAC under `key`, scoped to `purpose` so a value signed for one cookie
/// cannot be presented as the other.
fn sign(key: &[u8; 32], purpose: &str, payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(purpose.as_bytes());
    mac.update(b"\n");
    mac.update(payload.as_bytes());
    format!(
        "{}.{}",
        b64(payload.as_bytes()),
        b64(&mac.finalize().into_bytes())
    )
}

/// The payload of a value [`sign`] produced under `key` for `purpose`, or `None`.
fn open(key: &[u8; 32], purpose: &str, value: &str) -> Option<String> {
    let (payload, tag) = value.split_once('.')?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = String::from_utf8(engine.decode(payload).ok()?).ok()?;
    let tag = engine.decode(tag).ok()?;
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(purpose.as_bytes());
    mac.update(b"\n");
    mac.update(payload.as_bytes());
    mac.verify_slice(&tag).ok()?;
    Some(payload)
}

/// A session cookie's value for `email`, good until `expires` (UNIX seconds).
fn session_value(key: &[u8; 32], email: &str, expires: u64) -> String {
    sign(key, "session", &format!("{expires} {email}"))
}

/// The account a session cookie stands for, if it is ours and not expired at `now`.
fn session_email(key: &[u8; 32], value: &str, now: u64) -> Option<String> {
    let payload = open(key, "session", value)?;
    let (expires, email) = payload.split_once(' ')?;
    (expires.parse::<u64>().ok()? > now).then(|| email.to_owned())
}

/// The value of cookie `name` in a request's headers.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// A `Set-Cookie` for `name`, good for `max_age`, sent back on HTTPS only and never readable
/// by the page's scripts.
fn set_cookie(name: &str, value: &str, max_age: Duration) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        max_age.as_secs()
    ))
    .expect("cookie values are base64 and digits")
}

/// The account a request was let through for, as [`require`] leaves it on the request:
/// what the backoffice logs a change against, since every peer inside an enclave is the
/// tunnel's loopback address.
#[derive(Clone, Debug)]
pub struct Account(pub String);

/// Lets a request through with a valid session; otherwise sends a page load to the login
/// and refuses anything else. A change (anything but GET and HEAD) must also come from this
/// page's own origin: the session cookie is `SameSite=Lax`, which a browser that does not
/// count the scheme as part of the site would still send with a form posted from
/// `http://` at the same name, which whoever controls the host can serve.
pub async fn require(
    State(login): State<Arc<Login>>,
    mut request: Request,
    next: Next,
) -> Response {
    let email = cookie(request.headers(), SESSION_COOKIE)
        .and_then(|value| session_email(&login.session_key, value, unix_now()));
    let change = request.method() != Method::GET && request.method() != Method::HEAD;
    match email {
        Some(email) => {
            if change && !same_origin(request.headers(), &login.origin) {
                tracing::warn!(
                    "backoffice: {email} {} {} refused: not from this page's origin",
                    request.method(),
                    request.uri().path()
                );
                return (StatusCode::FORBIDDEN, "a change must come from this page")
                    .into_response();
            }
            request.extensions_mut().insert(Account(email));
            next.run(request).await
        }
        None if request.method() == Method::GET => Redirect::to("/auth/login").into_response(),
        None => (StatusCode::UNAUTHORIZED, "log in first: /auth/login").into_response(),
    }
}

/// Whether a request says it came from `origin`, scheme included: its `Origin` header, which
/// every current browser sends on a form post, or failing that `Sec-Fetch-Site`.
fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        Some(sent) => sent.eq_ignore_ascii_case(origin),
        None => headers
            .get("sec-fetch-site")
            .is_some_and(|value| value == "same-origin"),
    }
}

/// The headers every response of the HTTPS backoffice carries: stay on HTTPS for this name
/// (so a later `http://` link is never followed to whatever the host serves there), and
/// never be framed by another page.
pub async fn harden(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// The login's own routes, outside [`require`].
pub fn routes(login: Arc<Login>) -> Router {
    Router::new()
        .route("/auth/login", get(start))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .with_state(login)
}

async fn start(State(login): State<Arc<Login>>) -> Response {
    let state = b64(&rand::random::<[u8; 16]>());
    let nonce = b64(&rand::random::<[u8; 16]>());
    let expires = unix_now() + LOGIN_LIFETIME.as_secs();
    let value = sign(
        &login.session_key,
        "login",
        &format!("{expires} {state} {nonce}"),
    );
    let mut response = Redirect::to(&login.authorize_url(&state, &nonce)).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(LOGIN_COOKIE, &value, LOGIN_LIFETIME),
    );
    response
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(
    State(login): State<Arc<Login>>,
    headers: HeaderMap,
    Query(answer): Query<Callback>,
) -> Response {
    match finish(&login, &headers, answer).await {
        Ok(email) => {
            tracing::info!("backoffice: {email} logged in");
            let value = session_value(
                &login.session_key,
                &email,
                unix_now() + SESSION_LIFETIME.as_secs(),
            );
            let mut response = Redirect::to("/").into_response();
            let headers = response.headers_mut();
            headers.append(
                header::SET_COOKIE,
                set_cookie(SESSION_COOKIE, &value, SESSION_LIFETIME),
            );
            headers.append(
                header::SET_COOKIE,
                set_cookie(LOGIN_COOKIE, "", Duration::ZERO),
            );
            response
        }
        Err(reason) => {
            // Debug-formatted: `reason` can carry text from the query string, and a newline
            // in it must not start a line of its own in the log.
            tracing::warn!("backoffice: login refused: {reason:?}");
            (StatusCode::FORBIDDEN, format!("login refused: {reason}")).into_response()
        }
    }
}

/// The account a callback logs in, or why it does not.
async fn finish(
    login: &Login,
    headers: &HeaderMap,
    answer: Callback,
) -> std::result::Result<String, String> {
    if let Some(error) = answer.error {
        // Anyone can send this: kept short, and quoted rather than echoed as it came.
        let error: String = error.chars().take(64).collect();
        return Err(format!("Google answered {error:?}"));
    }
    let pending = cookie(headers, LOGIN_COOKIE)
        .and_then(|value| open(&login.session_key, "login", value))
        .ok_or("no login in progress in this browser")?;
    let mut parts = pending.splitn(3, ' ');
    let (expires, state, nonce) = match (parts.next(), parts.next(), parts.next()) {
        (Some(expires), Some(state), Some(nonce)) => (expires, state, nonce),
        _ => return Err("no login in progress in this browser".into()),
    };
    if expires.parse::<u64>().unwrap_or(0) <= unix_now() {
        return Err("the login took too long; start again".into());
    }
    if answer.state.as_deref() != Some(state) {
        return Err("the answer is not for this login".into());
    }
    let code = answer.code.ok_or("Google sent no code")?;
    let token = login
        .exchange(&code)
        .await
        .map_err(|err| format!("{err:#}"))?;
    let kid = jsonwebtoken::decode_header(&token)
        .ok()
        .and_then(|header| header.kid)
        .unwrap_or_default();
    let keys = login.keys(&kid).await.map_err(|err| format!("{err:#}"))?;
    let claims = verify_id_token(&token, &keys, &login.client_id, nonce)
        .map_err(|err| format!("{err:#}"))?;
    login.allow.admits(&claims)?;
    Ok(claims.email)
}

async fn logout() -> Response {
    let mut response = Redirect::to("/auth/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, "", Duration::ZERO),
    );
    response
}

/// The TLS the backoffice serves: the certificate chain and its private key, both PEM.
pub fn tls_config(certificate: &[u8], key: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain = CertificateDer::pem_slice_iter(certificate)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| eyre!("the backoffice certificate is not PEM: {err}"))?;
    ensure!(
        !chain.is_empty(),
        "the backoffice certificate file holds no certificate"
    );
    // Never quoted: what failed to parse may be most of a key.
    let key = PrivateKeyDer::from_pem_slice(key)
        .map_err(|_| eyre!("the backoffice TLS key is not a PEM private key"))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .wrap_err("TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .wrap_err("the backoffice certificate and key do not go together")?;
    Ok(Arc::new(config))
}

/// A TCP listener whose connections are handed on once their TLS handshake completes.
/// Handshakes run on their own tasks, so one slow or stalled client holds up nobody else.
/// At most [`MAX_CONNECTIONS`] at once, each dropped after [`IDLE_TIMEOUT`] of silence.
pub struct TlsListener {
    ready: mpsc::Receiver<(Guarded<TlsStream<TcpStream>>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    /// Starts accepting on `tcp` with `config`.
    pub fn spawn(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let local = tcp.local_addr().wrap_err("listener address")?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, ready) = mpsc::channel(16);
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        tokio::spawn(async move {
            loop {
                // Taken before the accept, so a connection past the bound costs nothing here.
                let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::debug!("backoffice accept failed: {err}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    return;
                }
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((Guarded::new(tls, slot), peer)).await;
                        }
                        Ok(Err(err)) => tracing::debug!("backoffice TLS from {peer}: {err}"),
                        Err(_) => tracing::debug!("backoffice TLS from {peer}: timed out"),
                    }
                });
            }
        });
        Ok(Self { ready, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = Guarded<TlsStream<TcpStream>>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // The accept task is gone: nothing will ever arrive.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// A served connection that holds its slot under [`MAX_CONNECTIONS`] for as long as it lives,
/// and fails once neither side has moved a byte for [`IDLE_TIMEOUT`].
pub struct Guarded<S> {
    inner: S,
    idle: Pin<Box<Sleep>>,
    _slot: OwnedSemaphorePermit,
}

impl<S> Guarded<S> {
    fn new(inner: S, slot: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            idle: Box::pin(tokio::time::sleep(IDLE_TIMEOUT)),
            _slot: slot,
        }
    }

    /// Called on every bit of progress: the connection is in use.
    fn touch(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
    }

    /// While the inner stream is waiting: whether it has waited too long.
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.idle.as_mut().poll(cx).is_ready()
    }
}

fn idle_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "backoffice connection idle")
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(idle_error())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.touch();
                Poll::Ready(result)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(idle_error())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "test-client.apps.googleusercontent.com";

    fn keys() -> JwkSet {
        serde_json::from_str(include_str!("testdata/jwks.json")).unwrap()
    }

    fn token(name: &str) -> String {
        let all: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("testdata/tokens.json")).unwrap();
        all[name].clone()
    }

    fn allow_domain() -> Allow {
        Allow {
            domain: Some("example.com".into()),
            accounts: vec![],
        }
    }

    #[test]
    fn a_google_token_checks_only_when_every_part_of_it_does() {
        let claims = verify_id_token(&token("VALID"), &keys(), CLIENT, "n0nce").unwrap();
        assert_eq!(claims.email, "ops@example.com");
        assert_eq!(allow_domain().admits(&claims), Ok(()));

        let expired = verify_id_token(&token("EXPIRED"), &keys(), CLIENT, "n0nce").unwrap_err();
        assert!(expired.to_string().contains("xpired"), "{expired}");
        assert!(verify_id_token(&token("OTHER_AUDIENCE"), &keys(), CLIENT, "n0nce").is_err());
        assert!(verify_id_token(&token("VALID"), &keys(), CLIENT, "another").is_err());

        // One byte of the payload changed: the signature no longer covers it.
        let valid = token("VALID");
        let mut parts: Vec<String> = valid.split('.').map(str::to_owned).collect();
        let mut payload: Vec<char> = parts[1].chars().collect();
        payload[10] = if payload[10] == 'A' { 'B' } else { 'A' };
        parts[1] = payload.into_iter().collect();
        assert!(verify_id_token(&parts.join("."), &keys(), CLIENT, "n0nce").is_err());

        let empty: JwkSet = serde_json::from_str(r#"{"keys":[]}"#).unwrap();
        let unknown = verify_id_token(&valid, &empty, CLIENT, "n0nce").unwrap_err();
        assert!(
            unknown.to_string().contains("does not publish"),
            "{unknown}"
        );
    }

    #[test]
    fn only_verified_accounts_on_the_list_are_admitted() {
        let check = |name: &str, allow: &Allow| {
            let claims = verify_id_token(&token(name), &keys(), CLIENT, "n0nce").unwrap();
            allow.admits(&claims)
        };
        assert!(
            check("UNVERIFIED", &allow_domain())
                .unwrap_err()
                .contains("verified")
        );
        assert!(
            check("OTHER_DOMAIN", &allow_domain())
                .unwrap_err()
                .contains("not allowed")
        );
        // An address in the domain without Google saying the domain administers it.
        assert!(check("PERSONAL", &allow_domain()).is_err());
        let named = Allow {
            domain: None,
            accounts: vec!["Friend@Gmail.com".into()],
        };
        assert_eq!(check("PERSONAL", &named), Ok(()));
        assert!(check("VALID", &named).is_err());
    }

    #[test]
    fn a_session_is_ours_unexpired_and_for_one_purpose() {
        let key = [7u8; 32];
        let value = session_value(&key, "ops@example.com", 2_000);
        assert_eq!(
            session_email(&key, &value, 1_999).as_deref(),
            Some("ops@example.com")
        );
        assert_eq!(session_email(&key, &value, 2_000), None, "expired");
        assert_eq!(
            session_email(&[8u8; 32], &value, 1_000),
            None,
            "another key"
        );
        let forged = format!(
            "{}.{}",
            b64(b"9999999999 root@example.com"),
            value.split_once('.').unwrap().1
        );
        assert_eq!(session_email(&key, &forged, 1_000), None, "payload swapped");
        let login = sign(&key, "login", "2000 ops@example.com");
        assert_eq!(
            session_email(&key, &login, 1_000),
            None,
            "a login cookie is not a session"
        );
    }

    #[test]
    fn cookies_are_read_by_name_and_set_https_only() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-qu_session=xyz"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-qu_login=abc"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE), Some("xyz"));
        assert_eq!(cookie(&headers, LOGIN_COOKIE), Some("abc"));
        assert_eq!(cookie(&headers, "qu"), None);
        let set = set_cookie(SESSION_COOKIE, "v", Duration::from_secs(60));
        let set = set.to_str().unwrap();
        assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("Max-Age=60"));
    }

    fn login(allow: Allow) -> Arc<Login> {
        Arc::new(Login {
            client_id: CLIENT.into(),
            client_secret: "unused".into(),
            redirect_url: "https://localhost/auth/callback".into(),
            origin: "https://localhost".into(),
            allow,
            session_key: [9u8; 32],
            http: reqwest::Client::new(),
            keys: RwLock::new(None),
        })
    }

    /// A certificate and key for `localhost`, made in memory for this run of the tests.
    fn localhost_certificate() -> (String, String) {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (made.cert.pem(), made.key_pair.serialize_pem())
    }

    /// The backoffice's front door, served over TLS with a throwaway localhost certificate:
    /// a page load without a session goes to the login, the login goes to Google with its
    /// state remembered, a change without a session is refused, and a session gets through.
    #[tokio::test]
    async fn the_front_door_serves_tls_and_lets_only_a_session_through() {
        use axum::serve::ListenerExt;
        let (certificate, key) = localhost_certificate();
        let tls = tls_config(certificate.as_bytes(), key.as_bytes()).unwrap();
        let login = login(allow_domain());
        let app = Router::new()
            .route("/", get(|| async { "the page" }))
            .route("/pairs/halt", post(|| async { "halted" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&login),
                require,
            ))
            .merge(routes(Arc::clone(&login)))
            .layer(axum::middleware::from_fn(harden));
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TlsListener::spawn(tcp, tls).unwrap();
        let addr = axum::serve::Listener::local_addr(&listener).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener.tap_io(|_| {}),
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let base = format!("https://localhost:{}", addr.port());
        let client_at = |path: &str| format!("{base}{path}");

        let page = client.get(client_at("/")).send().await.unwrap();
        assert_eq!(page.status(), StatusCode::SEE_OTHER);
        assert_eq!(page.headers()[header::LOCATION], "/auth/login");
        assert!(
            page.headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );
        assert_eq!(
            page.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'"
        );

        let start = client.get(client_at("/auth/login")).send().await.unwrap();
        assert_eq!(start.status(), StatusCode::SEE_OTHER);
        let location = start.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(location.starts_with(GOOGLE_AUTH), "{location}");
        assert!(
            location.contains("hd=example.com") && location.contains("nonce="),
            "{location}"
        );
        let set = start.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            set.starts_with("__Host-qu_login=") && set.contains("Secure"),
            "{set}"
        );

        let change = client.post(client_at("/pairs/halt")).send().await.unwrap();
        assert_eq!(change.status(), StatusCode::UNAUTHORIZED);

        let session = session_value(&login.session_key, "ops@example.com", unix_now() + 60);
        let cookie = format!("{SESSION_COOKIE}={session}");
        let page = client
            .get(client_at("/"))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.text().await.unwrap(), "the page");
        // A change with the session goes through from the page's own origin only: not from
        // the same name over http, and not with no origin at all.
        for (origin, expected) in [
            (Some("https://localhost"), StatusCode::OK),
            (Some("http://localhost"), StatusCode::FORBIDDEN),
            (Some("https://evil.example"), StatusCode::FORBIDDEN),
            (None, StatusCode::FORBIDDEN),
        ] {
            let mut request = client
                .post(client_at("/pairs/halt"))
                .header(header::COOKIE, &cookie);
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let change = request.send().await.unwrap();
            assert_eq!(change.status(), expected, "{origin:?}");
        }

        // A callback with no login in progress in this browser is refused, and Google's
        // error, which anyone can put in the query, comes back quoted on one line.
        let stray = client
            .get(client_at("/auth/callback?code=x&state=y"))
            .send()
            .await
            .unwrap();
        assert_eq!(stray.status(), StatusCode::FORBIDDEN);
        let forged = client
            .get(client_at(
                "/auth/callback?error=x%0Aops%40example.com%20logged%20in",
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::FORBIDDEN);
        assert!(!forged.text().await.unwrap().contains('\n'));
        server.abort();
    }

    /// A client that completes the handshake and then says nothing is dropped, and its slot
    /// under the connection bound comes back with it.
    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_is_dropped_and_frees_its_slot() {
        use tokio::io::AsyncReadExt;
        let slots = Arc::new(Semaphore::new(1));
        let (_client, server) = tokio::io::duplex(64);
        let mut served = Guarded::new(server, Arc::clone(&slots).acquire_owned().await.unwrap());
        assert_eq!(slots.available_permits(), 0);
        let err = served.read(&mut [0u8; 1]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        drop(served);
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn a_key_that_is_not_pem_is_refused_without_being_quoted() {
        let (certificate, key) = localhost_certificate();
        let err = tls_config(certificate.as_bytes(), b"secretstuff")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secretstuff"), "{err}");
        assert!(tls_config(b"nothing", key.as_bytes()).is_err());
        // A certificate and a key that do not belong together are refused: what stops a host
        // that hands in some other certificate from having it served.
        let (_, other_key) = localhost_certificate();
        let err = tls_config(certificate.as_bytes(), other_key.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(err.contains("do not go together"), "{err}");
    }
}

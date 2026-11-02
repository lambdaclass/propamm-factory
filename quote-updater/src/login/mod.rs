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
    sync::Arc,
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
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc},
};
use tokio_rustls::{TlsAcceptor, rustls, server::TlsStream};

use crate::enclave::BackofficeSettings;

/// The session cookie.
const SESSION_COOKIE: &str = "qu_session";
/// The cookie carrying a login in progress: its `state` and `nonce`.
const LOGIN_COOKIE: &str = "qu_login";
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
    allow: Allow,
    session_key: [u8; 32],
    http: reqwest::Client,
    keys: RwLock<Option<(JwkSet, Instant)>>,
}

impl Login {
    fn new(settings: &BackofficeSettings, client_secret: String) -> Result<Self> {
        Ok(Self {
            client_id: settings.client_id.clone(),
            client_secret,
            redirect_url: settings.redirect_url.clone(),
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

/// Lets a request through with a valid session; otherwise sends a page load to the login
/// and refuses anything else. Every change made through the page is logged with who made it.
pub async fn require(State(login): State<Arc<Login>>, request: Request, next: Next) -> Response {
    let email = cookie(request.headers(), SESSION_COOKIE)
        .and_then(|value| session_email(&login.session_key, value, unix_now()));
    match email {
        Some(email) => {
            if request.method() != Method::GET && request.method() != Method::HEAD {
                tracing::info!(
                    "backoffice: {email} {} {}",
                    request.method(),
                    request.uri().path()
                );
            }
            next.run(request).await
        }
        None if request.method() == Method::GET => Redirect::to("/auth/login").into_response(),
        None => (StatusCode::UNAUTHORIZED, "log in first: /auth/login").into_response(),
    }
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
            tracing::warn!("backoffice: login refused: {reason}");
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
        return Err(format!("Google answered {error}"));
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
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    /// Starts accepting on `tcp` with `config`.
    pub fn spawn(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let local = tcp.local_addr().wrap_err("listener address")?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, ready) = mpsc::channel(16);
        tokio::spawn(async move {
            loop {
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
                            let _ = tx.send((tls, peer)).await;
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
    type Io = TlsStream<TcpStream>;
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
            HeaderValue::from_static("a=1; qu_session=xyz"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("qu_login=abc"));
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
            allow,
            session_key: [9u8; 32],
            http: reqwest::Client::new(),
            keys: RwLock::new(None),
        })
    }

    /// The backoffice's front door, served over TLS with a throwaway localhost certificate:
    /// a page load without a session goes to the login, the login goes to Google with its
    /// state remembered, a change without a session is refused, and a session gets through.
    #[tokio::test]
    async fn the_front_door_serves_tls_and_lets_only_a_session_through() {
        use axum::serve::ListenerExt;
        let tls = tls_config(
            include_bytes!("testdata/localhost.crt"),
            include_bytes!("testdata/localhost.key"),
        )
        .unwrap();
        let login = login(allow_domain());
        let app = Router::new()
            .route("/", get(|| async { "the page" }))
            .route("/pairs/halt", post(|| async { "halted" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&login),
                require,
            ))
            .merge(routes(Arc::clone(&login)));
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
            set.starts_with("qu_login=") && set.contains("Secure"),
            "{set}"
        );

        let change = client.post(client_at("/pairs/halt")).send().await.unwrap();
        assert_eq!(change.status(), StatusCode::UNAUTHORIZED);

        let session = session_value(&login.session_key, "ops@example.com", unix_now() + 60);
        let page = client
            .get(client_at("/"))
            .header(header::COOKIE, format!("qu_session={session}"))
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.text().await.unwrap(), "the page");
        let change = client
            .post(client_at("/pairs/halt"))
            .header(header::COOKIE, format!("qu_session={session}"))
            .send()
            .await
            .unwrap();
        assert_eq!(change.status(), StatusCode::OK);

        // A callback with no login in progress in this browser is refused.
        let stray = client
            .get(client_at("/auth/callback?code=x&state=y"))
            .send()
            .await
            .unwrap();
        assert_eq!(stray.status(), StatusCode::FORBIDDEN);
        server.abort();
    }

    #[test]
    fn a_key_that_is_not_pem_is_refused_without_being_quoted() {
        let err = tls_config(include_bytes!("testdata/localhost.crt"), b"secretstuff")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secretstuff"), "{err}");
        assert!(tls_config(b"nothing", include_bytes!("testdata/localhost.key")).is_err());
    }
}

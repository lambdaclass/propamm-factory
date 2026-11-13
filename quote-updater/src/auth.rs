//! Google sign-in for the backoffice: optional, and off unless
//! `--backoffice-google-client-id` is given.
//!
//! The front end signs the operator in with Google and sends the ID token Google hands it as
//! `Authorization: Bearer <token>` on every request (`backoffice::guard`). Here the token is
//! checked the way Google says a backend must: signed by one of Google's published keys,
//! issued by Google, for this backoffice's own client ID, and not expired. Then the account
//! has to be allowed: its verified address listed with `--backoffice-allow-email`, or its
//! Workspace domain, which Google states in the token's `hd` claim, listed with
//! `--backoffice-allow-domain`. The address's own domain is never trusted for that: anyone
//! can have a Google account under an address at any domain, and only `hd` says the domain
//! manages it.
//!
//! No cookie, session, redirect or client secret: a browser never sends the token on its
//! own, so a page on another site has nothing of the operator's to use (audit F-02).
//!
//! Google's keys are fetched at start and again as their `Cache-Control` says, by a task of
//! their own. A request is never held up by that fetch while the keys it needs are known:
//! in particular a halt (audit F-06) is checked against keys already in memory. A failed
//! fetch keeps the keys already held. Only a token signed by a key not yet seen (Google
//! rotates them) waits for a fetch, at most one at a time and one every [`REFETCH_EVERY`].

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, ensure, eyre};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;

/// Where Google publishes the keys its ID tokens are signed with, as a JWK set.
pub(crate) const GOOGLE_KEYS: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// The two ways Google writes itself into an ID token's `iss`.
const ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

/// How long one fetch of the keys may take, whoever asked for it.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a token signed by an unknown key may set off a fetch. Bounds what a stream of
/// made-up key ids can make this process ask of Google.
const REFETCH_EVERY: Duration = Duration::from_secs(30);

/// The bounds on how long a fetched set is kept before the next scheduled fetch, whatever
/// `Cache-Control` says, and what is used when it says nothing.
const FRESH_MIN: Duration = Duration::from_secs(5 * 60);
const FRESH_MAX: Duration = Duration::from_secs(24 * 60 * 60);
const FRESH_DEFAULT: Duration = Duration::from_secs(60 * 60);

/// After a failed scheduled fetch, the first wait before the next one, doubling to the
/// last.
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);

/// How far a token's times may be off this host's clock.
const LEEWAY_SECS: u64 = 60;

/// Who may sign in, as the flags say, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GoogleSignIn {
    /// The OAuth client ID the front end signs in with: what a token's `aud` must be.
    pub(crate) client_id: String,
    /// Workspace domains whose accounts are let in, matched on the token's `hd`.
    pub(crate) domains: Vec<String>,
    /// Addresses let in one by one, lowercased.
    pub(crate) emails: Vec<String>,
    /// Where the keys are fetched: [`GOOGLE_KEYS`], but in a test.
    pub(crate) keys_url: String,
}

impl GoogleSignIn {
    /// `--backoffice-google-client-id`, `--backoffice-allow-domain` and
    /// `--backoffice-allow-email`: `None` when none is given, refused when only some are. A
    /// client ID with no one allowed would let in every Google account there is; a list with
    /// no client ID would check nothing.
    pub(crate) fn from_flags(
        client_id: Option<&str>,
        domains: &[String],
        emails: &[String],
    ) -> Result<Option<Self>> {
        let client_id = client_id.map(str::trim).filter(|id| !id.is_empty());
        let domains = parse_domains(domains)?;
        let emails = parse_emails(emails)?;
        let Some(client_id) = client_id else {
            ensure!(
                domains.is_empty() && emails.is_empty(),
                "--backoffice-allow-domain or --backoffice-allow-email is set without \
                 --backoffice-google-client-id: Google sign-in needs the OAuth client ID the \
                 front end signs in with"
            );
            return Ok(None);
        };
        ensure!(
            client_id.ends_with(".apps.googleusercontent.com"),
            "--backoffice-google-client-id {client_id:?} is not a Google OAuth client ID, which \
             ends in .apps.googleusercontent.com. The client secret is not needed, and must not \
             be given here"
        );
        ensure!(
            !domains.is_empty() || !emails.is_empty(),
            "--backoffice-google-client-id is set, but no one is allowed in: list a Workspace \
             domain with --backoffice-allow-domain, or addresses with \
             --backoffice-allow-email. Without either, every Google account would get in"
        );
        Ok(Some(Self {
            client_id: client_id.to_owned(),
            domains,
            emails,
            keys_url: GOOGLE_KEYS.to_owned(),
        }))
    }

    /// Who is let in, for the startup line.
    pub(crate) fn describe(&self) -> String {
        let mut who = Vec::new();
        if !self.domains.is_empty() {
            who.push(format!("accounts of {}", self.domains.join(", ")));
        }
        if !self.emails.is_empty() {
            who.push(self.emails.join(", "));
        }
        format!("Google sign-in for {}", who.join(" and "))
    }
}

/// Each a bare domain, lowercased. A consumer domain is refused: its accounts carry no `hd`,
/// so listing it would let no one in while reading as if it did.
fn parse_domains(domains: &[String]) -> Result<Vec<String>> {
    domains
        .iter()
        .map(|domain| domain.trim())
        .filter(|domain| !domain.is_empty())
        .map(|domain| {
            let name = domain
                .strip_prefix('@')
                .unwrap_or(domain)
                .to_ascii_lowercase();
            let labels_ok = name.contains('.')
                && name.split('.').all(|label| {
                    !label.is_empty()
                        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                });
            ensure!(
                labels_ok,
                "--backoffice-allow-domain {domain:?} is not a domain; write it alone, such as \
                 example.com"
            );
            ensure!(
                !matches!(name.as_str(), "gmail.com" | "googlemail.com"),
                "--backoffice-allow-domain {domain:?} lets no one in: a personal Google \
                 account belongs to no Workspace domain. List its address with \
                 --backoffice-allow-email instead"
            );
            Ok(name)
        })
        .collect()
}

/// Each a whole address, lowercased.
fn parse_emails(emails: &[String]) -> Result<Vec<String>> {
    emails
        .iter()
        .map(|email| email.trim())
        .filter(|email| !email.is_empty())
        .map(|email| {
            let ok = email.split_once('@').is_some_and(|(user, domain)| {
                !user.is_empty() && domain.contains('.') && !domain.contains('@')
            });
            ensure!(
                ok,
                "--backoffice-allow-email {email:?} is not an email address"
            );
            Ok(email.to_ascii_lowercase())
        })
        .collect()
}

/// Why a request was not let in.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    /// No token, or one that does not check out: 401, sign in (again).
    Unauthenticated(String),
    /// A good sign-in by an account that is not allowed: 403.
    NotAllowed(String),
    /// Google's keys have never been fetched, so nothing can be checked: 503.
    NoKeys,
}

/// The claims of a Google ID token this reads past the ones `jsonwebtoken` checks.
#[derive(Deserialize)]
struct Claims {
    email: Option<String>,
    #[serde(default, deserialize_with = "flag")]
    email_verified: bool,
    hd: Option<String>,
}

/// `email_verified` is a JSON boolean, and was once the string `"true"`.
fn flag<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Text(String),
    }
    Ok(match Flag::deserialize(d)? {
        Flag::Bool(b) => b,
        Flag::Text(s) => s == "true",
    })
}

/// Google's keys, by key id.
type Keys = Arc<HashMap<String, DecodingKey>>;

/// What checks a token: who may sign in, and Google's keys as last fetched. Cheap to clone.
#[derive(Clone)]
pub(crate) struct Verifier {
    inner: Arc<Inner>,
}

struct Inner {
    sign_in: GoogleSignIn,
    http: reqwest::Client,
    /// Never held across an await: a check reads the set and lets go.
    keys: RwLock<Keys>,
    /// When a token with an unknown key last set off a fetch. Held across that fetch, so
    /// there is one at a time and the others wait for it rather than fetch again.
    refetched: tokio::sync::Mutex<Option<Instant>>,
}

impl Verifier {
    pub(crate) fn new(sign_in: GoogleSignIn) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .user_agent(concat!("quote-updater/", env!("CARGO_PKG_VERSION")))
            .build()
            .wrap_err("http client for Google's keys")?;
        Ok(Self {
            inner: Arc::new(Inner {
                sign_in,
                http,
                keys: RwLock::new(Arc::default()),
                refetched: tokio::sync::Mutex::new(None),
            }),
        })
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.inner.sign_in.client_id
    }

    /// Checks `token`, answering the signed-in address.
    pub(crate) async fn verify(&self, token: &str) -> std::result::Result<String, Denied> {
        let unauthenticated = |why: &str| Denied::Unauthenticated(why.to_owned());
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| unauthenticated("the token is not a Google ID token; sign in again"))?;
        // Pinned, whatever the token says: a key is only ever an RSA key here, and an
        // `alg` taken from the token is how a forged one gets checked as something else.
        if header.alg != Algorithm::RS256 {
            return Err(unauthenticated(
                "the token is not signed the way Google signs ID tokens; sign in again",
            ));
        }
        let kid = header
            .kid
            .ok_or_else(|| unauthenticated("the token names no signing key; sign in again"))?;
        let key = match self.key(&kid) {
            Some(key) => key,
            None => {
                self.refetch().await;
                match self.key(&kid) {
                    Some(key) => key,
                    None if self.keys().is_empty() => return Err(Denied::NoKeys),
                    None => {
                        return Err(unauthenticated(
                            "the token is signed with a key Google does not publish; sign in \
                             again",
                        ));
                    }
                }
            }
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.inner.sign_in.client_id]);
        validation.set_issuer(&ISSUERS);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECS;
        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|err| {
                use jsonwebtoken::errors::ErrorKind;
                Denied::Unauthenticated(
                    match err.kind() {
                        ErrorKind::ExpiredSignature => "the sign-in has expired; sign in again",
                        ErrorKind::InvalidAudience => {
                            "the token was issued to another application, not this backoffice"
                        }
                        ErrorKind::InvalidIssuer => "the token was not issued by Google",
                        ErrorKind::ImmatureSignature => "the token is not valid yet",
                        ErrorKind::InvalidSignature => "the token's signature does not check out",
                        _ => "the token is not a valid Google ID token; sign in again",
                    }
                    .to_owned(),
                )
            })?
            .claims;
        self.allows(&claims)
    }

    /// Whether the signed-in account is one the flags let in.
    fn allows(&self, claims: &Claims) -> std::result::Result<String, Denied> {
        let sign_in = &self.inner.sign_in;
        let email = claims
            .email
            .as_deref()
            .filter(|email| !email.is_empty())
            .ok_or_else(|| {
                Denied::NotAllowed(
                    "the sign-in carries no email address, so it cannot be checked against \
                     the accounts allowed here"
                        .to_owned(),
                )
            })?
            .to_ascii_lowercase();
        if !claims.email_verified {
            return Err(Denied::NotAllowed(format!(
                "{email} is not a verified Google address"
            )));
        }
        let by_domain = claims
            .hd
            .as_deref()
            .is_some_and(|hd| sign_in.domains.contains(&hd.to_ascii_lowercase()));
        if sign_in.emails.contains(&email) || by_domain {
            Ok(email)
        } else {
            Err(Denied::NotAllowed(format!(
                "{email} is signed in, but is not allowed to use this backoffice; it is let in \
                 by --backoffice-allow-email or --backoffice-allow-domain"
            )))
        }
    }

    fn keys(&self) -> Keys {
        Arc::clone(&self.inner.keys.read().unwrap_or_else(|p| p.into_inner()))
    }

    fn key(&self, kid: &str) -> Option<DecodingKey> {
        self.keys().get(kid).cloned()
    }

    fn store(&self, keys: HashMap<String, DecodingKey>) {
        *self.inner.keys.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(keys);
    }

    /// A fetch for a token signed by a key not seen yet: one at a time, at most one every
    /// [`REFETCH_EVERY`], and a failure keeps the keys already held.
    async fn refetch(&self) {
        let mut last = self.inner.refetched.lock().await;
        if last.is_some_and(|at| at.elapsed() < REFETCH_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        match self.fetch().await {
            Ok((keys, _)) => self.store(keys),
            Err(err) => tracing::warn!("backoffice: Google's signing keys: {err:#}"),
        }
    }

    /// Fetches the keys, at start and again whenever `Cache-Control` says they may have
    /// changed, for as long as the backoffice runs. A failure keeps the keys already held
    /// and is tried again sooner. Never returns.
    pub(crate) async fn keep_keys_fresh(self) {
        let mut retry = RETRY_FIRST;
        loop {
            let wait = match self.fetch().await {
                Ok((keys, fresh)) => {
                    tracing::debug!("backoffice: {} Google signing keys fetched", keys.len());
                    self.store(keys);
                    retry = RETRY_FIRST;
                    fresh
                }
                Err(err) => {
                    let held = self.keys().len();
                    tracing::warn!(
                        "backoffice: could not fetch Google's signing keys ({err:#}); {}, \
                         trying again in {}s",
                        if held == 0 {
                            "no sign-in can be checked until they are".to_owned()
                        } else {
                            format!("checking sign-ins with the {held} already held")
                        },
                        retry.as_secs()
                    );
                    let wait = retry;
                    retry = (retry * 2).min(RETRY_MAX);
                    wait
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// One fetch: the keys by id, and how long they may be kept.
    async fn fetch(&self) -> Result<(HashMap<String, DecodingKey>, Duration)> {
        let url = &self.inner.sign_in.keys_url;
        let response = self
            .inner
            .http
            .get(url)
            .send()
            .await
            .wrap_err_with(|| format!("GET {url}"))?
            .error_for_status()
            .wrap_err_with(|| format!("GET {url}"))?;
        let fresh = response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .and_then(max_age)
            .unwrap_or(FRESH_DEFAULT)
            .clamp(FRESH_MIN, FRESH_MAX);
        let set: JwkSet = response
            .json()
            .await
            .wrap_err_with(|| format!("{url} did not answer a JWK set"))?;
        let keys: HashMap<String, DecodingKey> = set
            .keys
            .iter()
            .filter(|jwk| {
                matches!(
                    jwk.algorithm,
                    jsonwebtoken::jwk::AlgorithmParameters::RSA(_)
                )
            })
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                DecodingKey::from_jwk(jwk).ok().map(|key| (kid, key))
            })
            .collect();
        if keys.is_empty() {
            return Err(eyre!("{url} answered no RSA key with an id"));
        }
        Ok((keys, fresh))
    }
}

/// `max-age` out of a `Cache-Control` value.
fn max_age(cache_control: &str) -> Option<Duration> {
    cache_control.split(',').find_map(|directive| {
        let (name, value) = directive.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| value.trim().trim_matches('"').parse().ok())
            .flatten()
            .map(Duration::from_secs)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::{Value, json};

    pub(crate) const CLIENT_ID: &str = "1234-test.apps.googleusercontent.com";

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/oauth")
                .join(name),
        )
        .unwrap()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// The claims of a good sign-in by `email`, issued now for [`CLIENT_ID`].
    pub(crate) fn claims(email: &str, hd: Option<&str>) -> Value {
        let mut claims = json!({
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": "1000",
            "email": email,
            "email_verified": true,
            "iat": now(),
            "exp": now() + 3600,
        });
        if let Some(hd) = hd {
            claims["hd"] = json!(hd);
        }
        claims
    }

    /// `claims` signed as Google would, with test key `signer` (`a` or `b`) under its id.
    pub(crate) fn sign(signer: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(format!("key-{signer}"));
        let key = EncodingKey::from_rsa_pem(&fixture(&format!("signer-{signer}.key"))).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    /// A good token for `email`, signed with key `a`.
    pub(crate) fn token(email: &str) -> String {
        sign("a", &claims(email, None))
    }

    /// Google's keys endpoint, as a test sets it: what it answers, and whether it answers at
    /// all. Counts the fetches.
    #[derive(Clone)]
    pub(crate) struct KeysEndpoint {
        pub(crate) url: String,
        jwks: Arc<std::sync::Mutex<&'static str>>,
        stalled: Arc<std::sync::atomic::AtomicBool>,
        fetches: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl KeysEndpoint {
        /// Answering `jwks-<set>.json`, as Google's endpoint answers.
        pub(crate) async fn spawn(set: &'static str) -> Self {
            let endpoint = Self {
                url: String::new(),
                jwks: Arc::new(std::sync::Mutex::new(set)),
                stalled: Arc::default(),
                fetches: Arc::default(),
            };
            let served = endpoint.clone();
            let app = axum::Router::new().route(
                "/certs",
                axum::routing::get(move || {
                    let served = served.clone();
                    async move {
                        served
                            .fetches
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if served.stalled.load(std::sync::atomic::Ordering::SeqCst) {
                            std::future::pending::<()>().await;
                        }
                        let set = *served.jwks.lock().unwrap();
                        (
                            [(
                                axum::http::header::CACHE_CONTROL,
                                "public, max-age=21600, must-revalidate",
                            )],
                            fixture(&format!("jwks-{set}.json")),
                        )
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await });
            Self {
                url: format!("http://{addr}/certs"),
                ..endpoint
            }
        }

        pub(crate) fn answer(&self, set: &'static str) {
            *self.jwks.lock().unwrap() = set;
        }

        /// From now on, every fetch hangs, as an endpoint that takes the connection and never
        /// answers.
        pub(crate) fn stall(&self) {
            self.stalled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        pub(crate) fn fetches(&self) -> usize {
            self.fetches.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// Sign-in for [`CLIENT_ID`], letting in `example.com`'s Workspace and
    /// `ops@gmail.com`, with its keys at `keys`.
    pub(crate) fn sign_in(keys: &KeysEndpoint) -> GoogleSignIn {
        GoogleSignIn {
            client_id: CLIENT_ID.to_owned(),
            domains: vec!["example.com".to_owned()],
            emails: vec!["ops@gmail.com".to_owned()],
            keys_url: keys.url.clone(),
        }
    }

    #[test]
    fn the_flags_turn_it_on_only_whole() {
        let none: [String; 0] = [];
        let domain = ["Example.COM".to_owned()];
        assert_eq!(GoogleSignIn::from_flags(None, &none, &none).unwrap(), None);
        let on = GoogleSignIn::from_flags(Some(CLIENT_ID), &domain, &none)
            .unwrap()
            .unwrap();
        assert_eq!(on.domains, ["example.com"]);
        assert_eq!(on.keys_url, GOOGLE_KEYS);

        for (client_id, domains, emails, expected) in [
            (
                Some(CLIENT_ID),
                &none[..],
                &none[..],
                "every Google account",
            ),
            (
                None,
                &domain[..],
                &none[..],
                "without --backoffice-google-client-id",
            ),
            (
                Some("GOCSPX-secret"),
                &domain[..],
                &none[..],
                "not a Google OAuth client ID",
            ),
            (
                Some(CLIENT_ID),
                &["gmail.com".to_owned()][..],
                &none[..],
                "lets no one in",
            ),
            (
                Some(CLIENT_ID),
                &["https://example.com".to_owned()][..],
                &none[..],
                "not a domain",
            ),
            (
                Some(CLIENT_ID),
                &none[..],
                &["ops".to_owned()][..],
                "not an email address",
            ),
        ] {
            let err = format!(
                "{:#}",
                GoogleSignIn::from_flags(client_id, domains, emails).unwrap_err()
            );
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn max_age_is_read_out_of_cache_control() {
        assert_eq!(
            max_age("public, max-age=21600, must-revalidate"),
            Some(Duration::from_secs(21600))
        );
        assert_eq!(max_age("no-store"), None);
        assert_eq!(max_age("max-age=junk"), None);
    }

    /// A verifier keeping its keys fresh from `keys`, once it holds them.
    pub(crate) async fn verifier(keys: &KeysEndpoint) -> Verifier {
        let verifier = Verifier::new(sign_in(keys)).unwrap();
        tokio::spawn(verifier.clone().keep_keys_fresh());
        tokio::time::timeout(Duration::from_secs(5), async {
            while verifier.keys().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first fetch");
        verifier
    }

    #[tokio::test]
    async fn a_good_sign_in_by_an_allowed_account_is_let_in() {
        let keys = KeysEndpoint::spawn("a").await;
        let verifier = verifier(&keys).await;
        // By domain, on `hd`; by address, whatever its case.
        assert_eq!(
            verifier
                .verify(&sign(
                    "a",
                    &claims("Alice@Example.com", Some("example.com"))
                ))
                .await,
            Ok("alice@example.com".to_owned())
        );
        assert_eq!(
            verifier.verify(&token("OPS@gmail.com")).await,
            Ok("ops@gmail.com".to_owned())
        );
    }

    #[tokio::test]
    async fn an_account_not_listed_is_refused_even_at_a_listed_domain() {
        let keys = KeysEndpoint::spawn("a").await;
        let verifier = verifier(&keys).await;
        let not_allowed = |result| matches!(result, Err(Denied::NotAllowed(_)));
        // An address at the domain, but no `hd`: a personal account under a work address.
        assert!(not_allowed(
            verifier.verify(&token("mallory@example.com")).await
        ));
        // Another Workspace.
        assert!(not_allowed(
            verifier
                .verify(&sign("a", &claims("eve@other.com", Some("other.com"))))
                .await
        ));
        // A listed address Google has not verified.
        let mut unverified = claims("ops@gmail.com", None);
        unverified["email_verified"] = json!(false);
        assert!(not_allowed(verifier.verify(&sign("a", &unverified)).await));
        // The old string form still reads.
        let mut text = claims("ops@gmail.com", None);
        text["email_verified"] = json!("true");
        assert!(verifier.verify(&sign("a", &text)).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_that_does_not_check_out_is_refused() {
        let keys = KeysEndpoint::spawn("a").await;
        let verifier = verifier(&keys).await;
        let refused = |result: std::result::Result<String, Denied>, why: &str| match result {
            Err(Denied::Unauthenticated(message)) => {
                assert!(message.contains(why), "{why}: {message}")
            }
            other => panic!("{why}: {other:?}"),
        };
        let with = |field: &str, value: Value| {
            let mut claims = claims("ops@gmail.com", None);
            claims[field] = value;
            sign("a", &claims)
        };
        refused(
            verifier.verify(&with("exp", json!(now() - 3600))).await,
            "expired",
        );
        refused(
            verifier
                .verify(&with("aud", json!("other.apps.googleusercontent.com")))
                .await,
            "another application",
        );
        refused(
            verifier
                .verify(&with("iss", json!("https://evil.example")))
                .await,
            "not issued by Google",
        );
        refused(
            verifier.verify("not.a.token").await,
            "not a Google ID token",
        );

        // Key `a`'s id over key `b`'s signature: a forgery.
        let forged = sign("b", &claims("ops@gmail.com", None));
        let mut parts: Vec<&str> = forged.split('.').collect();
        let header = sign("a", &claims("ops@gmail.com", None));
        parts[0] = header.split('.').next().unwrap();
        refused(verifier.verify(&parts.join(".")).await, "signature");

        // An HMAC token, keyed with anything a forger likes: never checked as one.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("key-a".to_owned());
        let hmac = jsonwebtoken::encode(
            &header,
            &claims("ops@gmail.com", None),
            &EncodingKey::from_secret(b"guess"),
        )
        .unwrap();
        refused(
            verifier.verify(&hmac).await,
            "not signed the way Google signs",
        );
    }

    /// Google rotates its keys: a token signed by one not yet held sets off a fetch, and is
    /// let in once it is published. A made-up key id fetches at most once in a while.
    #[tokio::test]
    async fn a_new_key_is_fetched_once_and_a_made_up_one_rarely() {
        let keys = KeysEndpoint::spawn("a").await;
        let verifier = verifier(&keys).await;
        assert!(verifier.verify(&token("ops@gmail.com")).await.is_ok());
        let before = keys.fetches();

        keys.answer("ab");
        assert_eq!(
            verifier
                .verify(&sign("b", &claims("ops@gmail.com", None)))
                .await,
            Ok("ops@gmail.com".to_owned())
        );
        assert_eq!(keys.fetches(), before + 1, "one fetch for the new key");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("made-up".to_owned());
        let made_up = jsonwebtoken::encode(
            &header,
            &claims("ops@gmail.com", None),
            &EncodingKey::from_rsa_pem(&fixture("signer-a.key")).unwrap(),
        )
        .unwrap();
        for _ in 0..5 {
            assert!(matches!(
                verifier.verify(&made_up).await,
                Err(Denied::Unauthenticated(_))
            ));
        }
        assert_eq!(keys.fetches(), before + 1, "no fetch inside REFETCH_EVERY");
    }

    /// The F-06 half: with Google's endpoint hanging, a token signed by a key already held is
    /// checked at once, from memory.
    #[tokio::test]
    async fn a_known_key_is_checked_without_waiting_for_google() {
        let keys = KeysEndpoint::spawn("a").await;
        let verifier = verifier(&keys).await;
        assert!(verifier.verify(&token("ops@gmail.com")).await.is_ok());
        keys.stall();
        let checked = tokio::time::timeout(
            Duration::from_millis(200),
            verifier.verify(&token("ops@gmail.com")),
        )
        .await
        .expect("checked without a fetch");
        assert_eq!(checked, Ok("ops@gmail.com".to_owned()));
    }

    /// Before any key has been fetched nothing can be checked, and that is said apart from
    /// a bad token.
    #[tokio::test]
    async fn no_keys_yet_is_its_own_answer() {
        let verifier = Verifier::new(GoogleSignIn {
            // Nothing listens there: the fetch fails at once.
            keys_url: "http://127.0.0.1:1/certs".to_owned(),
            ..sign_in(&KeysEndpoint::spawn("a").await)
        })
        .unwrap();
        assert_eq!(
            verifier.verify(&token("ops@gmail.com")).await,
            Err(Denied::NoKeys)
        );
    }
}

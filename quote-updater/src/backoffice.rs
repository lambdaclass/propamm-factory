//! The backoffice: a JSON API for changing the pusher's pairs and builders without a
//! deploy, and for looking up and previewing a pair's venues before adding it. It serves
//! no pages; whatever front end an operator uses talks to it under `/api`.
//!
//! Every change goes through the shared config (`state.rs`), which applies it to a copy,
//! writes `config.toml`, has the service converge the running pairs onto it, and keeps it
//! only if the service accepts: so the config in memory and the file on disk both describe
//! what is running. `[settings]` are read once, at start, and the API only shows them.
//!
//! No login: the address it binds (`--backoffice-ip` and `--backoffice-port`, or `[settings]
//! backoffice_addr`) is the host's tailnet address, so reaching this API means being past
//! the tailnet ACL. Binding every interface is refused, because unlike `/metrics` this API
//! writes. Every change logs the peer that made it.
//!
//! Plain HTTP unless `--backoffice-tls-cert` and `--backoffice-tls-key` are given; then
//! HTTPS only, with the certificate read again whenever its files change (`tls.rs`).
//!
//! Being past the ACL is not the same as meaning to be here: a browser on the tailnet sends
//! whatever another site's page tells it to (audit F-02). So [`guard`] answers only requests
//! addressed to a name the API is served under, which stops a site that points its own
//! domain at this host (DNS rebinding); takes a change only as JSON, which a page on another
//! site cannot send here without CORS approval; and refuses one whose `Origin` names another
//! site. The approval goes to the origins `--backoffice-cors-origin` lists, and only to
//! those: a front end served from one of them can call the API, and every other site still
//! cannot.
//!
//! | Route                             | What it does                                     |
//! |-----------------------------------|--------------------------------------------------|
//! | `GET /api/pairs`                  | every pair, with what the pusher is doing with it |
//! | `POST /api/pairs`                 | adds a pair (its `[[pairs]]` stanza, as JSON)    |
//! | `GET /api/pairs/{key_env}`        | one pair                                         |
//! | `PUT /api/pairs/{key_env}`        | replaces a pair's stanza                         |
//! | `DELETE /api/pairs/{key_env}`     | removes a pair                                   |
//! | `POST /api/pairs/{key_env}/halt`  | stops a pair quoting at once, keeping it         |
//! | `POST /api/pairs/{key_env}/resume`| clears a halt                                    |
//! | `POST /api/halt`                  | halts every pair                                 |
//! | `POST /api/reload`                | restarts the pairs halted here, re-arms the rest |
//! | `GET /api/builders`               | every builder, without its API key               |
//! | `POST /api/builders`              | adds a builder                                   |
//! | `DELETE /api/builders/{name}`     | removes a builder                                |
//! | `GET /api/settings`               | `target` and `[settings]`, read-only             |
//! | `GET /api/kinds`                  | the registered pricing kinds and their fields    |
//! | `GET /api/venues`                 | the venues a pair can read                       |
//! | `GET /api/lookup`                 | where a token pair trades; saves nothing         |
//! | `GET /api/preview`                | a websocket of live venue mids; saves nothing    |
//!
//! A change answers `{"status": "applied" | "partial", "message": ...}` with a 2xx; a
//! `partial` one is kept, though some pair kept its previous config (see
//! [`ReloadFailure::Partial`]). Anything refused answers `{"error": ...}` with a 4xx, and
//! changed nothing. A fault on this side answers `{"error": ...}` with a 5xx: 500 for a
//! change that could not be made (see [`ReloadFailure::Fault`]), 502 for a lookup that
//! could not ask the chain or the venues.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State, rejection::JsonRejection},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use eyre::{Result, WrapErr, eyre};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::config::{self, BuilderConfig, RawConfig, RawPair};
use crate::service::ReloadFailure;
use crate::state::{Refused, SharedConfig};
use crate::venue::VenueId;

/// What the running pusher is doing with each pair, by `key_env`: for every pair that has
/// a task, the flag its circuit breaker raises when it trips. The service keeps it current
/// as pairs start and stop, so the API can say what is actually running rather than only
/// what the config asks for.
pub type PairStates = Arc<std::sync::Mutex<std::collections::BTreeMap<String, Arc<AtomicBool>>>>;

#[derive(Clone)]
struct Backoffice {
    /// What the API reads and changes; the service converges onto it.
    config: Arc<SharedConfig>,
    states: PairStates,
    /// The registered pricing kinds: what `/api/kinds` lists, with each kind's fields.
    kinds: Arc<crate::kinds::Kinds>,
    /// For the venue lookup (`discover.rs`): the node that reads the tokens' `symbol()`, the
    /// client that asks the exchanges, and where each exchange's API is.
    client: ethrex_rpc::clients::eth::EthClient,
    http: reqwest::Client,
    rest: Arc<crate::discover::Rest>,
    /// Market lists already fetched, kept for a while: Binance's alone is megabytes.
    lookups: Arc<crate::discover::Cache>,
    /// Open previews, capped at PREVIEW_PAGES. Each connects to each venue at most once,
    /// so this bounds the venue connections previews can hold at once.
    preview_pages: Arc<tokio::sync::Semaphore>,
    /// The origins besides its own whose pages may change things here, as
    /// [`parse_origins`] writes them: the same list the CORS layer answers to.
    origins: Arc<[String]>,
    /// The names besides an IP address and `localhost` that requests may be addressed to,
    /// as [`parse_hosts`] writes them.
    hosts: Arc<[String]>,
}

/// Who may reach the API, and how: the names it answers to, the browser origins besides its
/// own it answers CORS for, and its certificate when it is HTTPS. The default is plain HTTP,
/// answering to IP addresses and `localhost` alone, with no CORS.
#[derive(Default)]
pub(crate) struct Access {
    /// `--backoffice-host` or `[settings] backoffice_hosts`; see [`parse_hosts`].
    pub(crate) hosts: Vec<String>,
    /// `--backoffice-cors-origin`; see [`parse_origins`].
    pub(crate) origins: Vec<String>,
    /// `--backoffice-tls-cert` and `--backoffice-tls-key`, read.
    pub(crate) tls: Option<crate::tls::Tls>,
}

/// `0.0.0.0:8088` binds every interface, including whatever the host has facing the
/// internet. The easy mistake, and the dangerous one.
pub(crate) fn is_unspecified_bind(addr: SocketAddr) -> bool {
    addr.ip().is_unspecified()
}

/// Refuses [`is_unspecified_bind`]. Startup asks before it connects to anything, and
/// [`bind`] again.
pub(crate) fn refuse_unspecified_bind(addr: SocketAddr) -> Result<()> {
    eyre::ensure!(
        !is_unspecified_bind(addr),
        "the backoffice address is {addr}, which binds every interface on this host. This \
         API rewrites the pusher's config and has no authentication of its own; bind it to \
         the host's tailnet address instead (--backoffice-ip, or [settings] \
         backoffice_addr), where the tailnet ACL is the access control."
    );
    Ok(())
}

/// `--backoffice-cors-origin`, checked, and each written as a browser writes `Origin`
/// (lowercase, no default port, no trailing slash), which is what both the CORS layer and
/// [`guard`] compare a request's against, byte for byte. `*` and `null` are refused: the API
/// has no login, so an origin that answers for any page would let any site an operator's
/// browser visits drive it.
pub(crate) fn parse_origins(origins: &[String]) -> Result<Vec<String>> {
    origins
        .iter()
        .map(|origin| origin.trim())
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            eyre::ensure!(
                origin != "*",
                "\"*\" would let a page on any site an operator's browser visits drive this \
                 API, which has no login; list the front end's own origin, such as \
                 http://100.64.1.2:3000"
            );
            let written = || {
                eyre!(
                    "{origin:?} is not an origin; write the scheme, host and port alone, such \
                     as http://100.64.1.2:3000, with no path"
                )
            };
            let url = url::Url::parse(origin).map_err(|_| written())?;
            eyre::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.has_host()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none(),
                written()
            );
            Ok(url.origin().ascii_serialization())
        })
        .collect()
}

/// `--backoffice-host` and `[settings] backoffice_hosts`, checked: each a bare hostname, as
/// a `Host` header carries it without its port, lowercased and without a trailing dot. The
/// names the API is reached by besides an IP address and `localhost`, which it always
/// answers to: its tailnet name (the one its certificate names, over HTTPS), or the name a
/// reverse proxy serves it under. Never a front end's: that is an origin, for
/// `--backoffice-cors-origin`.
pub(crate) fn parse_hosts(hosts: &[String]) -> Result<Vec<String>> {
    hosts
        .iter()
        .map(|host| host.trim())
        .filter(|host| !host.is_empty())
        .map(|host| {
            let name = host.strip_suffix('.').unwrap_or(host);
            let labels_ok = name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });
            eyre::ensure!(
                labels_ok,
                "{host:?} is not a hostname; write the name alone, such as \
                 pusher.your-tailnet.ts.net, without a scheme, a port or a path"
            );
            Ok(name.to_ascii_lowercase())
        })
        .collect()
}

/// The CORS answers for `origins`, `None` when there are none to give: a preflight from
/// one of them is answered for the methods and the one header this API takes, and every
/// answer to one carries `Access-Control-Allow-Origin`. No credentials: the API has no
/// cookie or login to send.
fn cors(origins: &[String]) -> Option<tower_http::cors::CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let origins: Vec<axum::http::HeaderValue> = origins
        .iter()
        .map(|origin| origin.parse().expect("parse_origins writes ASCII"))
        .collect();
    Some(
        tower_http::cors::CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600)),
    )
}

/// Binds `addr` and serves the API as `access` says: the names it answers to, its CORS
/// answers, and HTTPS when it has a certificate. Fatal on failure: an operator who believes
/// this is up and whose changes are going nowhere is worse off than one whose service
/// refused to start.
pub(crate) async fn bind(
    addr: SocketAddr,
    config: Arc<SharedConfig>,
    client: ethrex_rpc::clients::eth::EthClient,
    states: PairStates,
    kinds: Arc<crate::kinds::Kinds>,
    access: Access,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    bind_with(
        addr,
        config,
        client,
        states,
        kinds,
        access,
        crate::discover::Rest::default(),
    )
    .await
}

/// [`bind`], with the exchanges' APIs somewhere else: a test's mock.
async fn bind_with(
    addr: SocketAddr,
    config: Arc<SharedConfig>,
    client: ethrex_rpc::clients::eth::EthClient,
    states: PairStates,
    kinds: Arc<crate::kinds::Kinds>,
    access: Access,
    rest: crate::discover::Rest,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    refuse_unspecified_bind(addr)?;
    // Written as the headers are, whatever the caller did, so the guard and the CORS layer
    // compare against the same strings.
    let origins = parse_origins(&access.origins).wrap_err("--backoffice-cors-origin")?;
    let hosts = parse_hosts(&access.hosts).wrap_err("--backoffice-host")?;
    let tls = access.tls;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .wrap_err_with(|| format!("failed to bind the backoffice listener on {addr}"))?;
    let local = listener
        .local_addr()
        .wrap_err("bound backoffice listener has no local address")?;

    let state = Backoffice {
        config,
        states,
        kinds,
        client,
        rest: Arc::new(rest),
        // A User-Agent, because CoinGecko and Coinbase answer 403 to a request without one.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(concat!("quote-updater/", env!("CARGO_PKG_VERSION")))
            .build()
            .wrap_err("http client")?,
        lookups: Arc::new(crate::discover::Cache::default()),
        preview_pages: Arc::new(tokio::sync::Semaphore::new(PREVIEW_PAGES)),
        origins: origins.clone().into(),
        hosts: hosts.into(),
    };

    let app = Router::new()
        .route("/api/pairs", get(list_pairs).post(add_pair))
        .route(
            "/api/pairs/{key_env}",
            get(get_pair).put(edit_pair).delete(remove_pair),
        )
        .route("/api/pairs/{key_env}/halt", post(halt_pair))
        .route("/api/pairs/{key_env}/resume", post(resume_pair))
        .route("/api/halt", post(halt_all))
        .route("/api/reload", post(reload))
        .route("/api/builders", get(list_builders).post(add_builder))
        .route("/api/builders/{name}", delete(remove_builder))
        .route("/api/settings", get(settings))
        .route("/api/kinds", get(list_kinds))
        .route("/api/venues", get(list_venues))
        .route("/api/lookup", get(lookup_pair))
        .route("/api/preview", get(preview_socket))
        .fallback(|| async {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "no such route; the backoffice API is under /api",
            )
        })
        // Around every route above, so one added later is guarded without saying so.
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard));
    // Around the guard, so a preflight (an `OPTIONS` with no JSON and no route) is answered
    // before it, and every answer to a listed origin, a refusal included, carries the
    // header that lets its page read it.
    let app = match cors(&origins) {
        Some(cors) => app.layer(cors),
        None => app,
    }
    .with_state(state);

    // With connect info, so every change can be logged against its peer.
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    let task = match tls {
        None => tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::warn!("backoffice listener stopped: {err}");
            }
        }),
        Some(tls) => {
            let (listener, accepting) = crate::tls::listener(listener, tls)
                .wrap_err("bound backoffice listener has no local address")?;
            // The accept loop and the server in one task, so ending it ends both. `tap_io`
            // only so axum hands the peer's address to `ConnectInfo`, which it does for a
            // wrapped listener of any kind and for its own `TcpListener` alone otherwise.
            use axum::serve::ListenerExt;
            tokio::spawn(async move {
                let serving = axum::serve(listener.tap_io(|_| {}), app);
                tokio::select! {
                    served = serving.into_future() => {
                        if let Err(err) = served {
                            tracing::warn!("backoffice listener stopped: {err}");
                        }
                    }
                    () = accepting => {}
                }
            })
        }
    };

    Ok((local, task))
}

// ---------------------------------------------------------------------------
// Which requests are answered
// ---------------------------------------------------------------------------

/// Runs before every route. This API has no login, so what it must not do is act on a
/// request that an operator's browser sent without the operator meaning it (audit F-02).
/// A page on another site can make a browser send a plain form post anywhere, without
/// asking and without the server's say; a `PUT`, a `DELETE`, or a post of JSON it cannot
/// send without first asking this server, which says yes only to the origins
/// `--backoffice-cors-origin` lists. And a site can point its own domain at this host's
/// address once its page has loaded (DNS rebinding): to the browser that page and this API
/// are then one origin, so it sends anything and reads every answer, `Origin` and `Host`
/// both carrying the site's name. What gives it away is that name. So:
///
/// - every request, reads included, must be addressed (`Host`) to an IP address,
///   `localhost`, or a name `--backoffice-host` lists ([`host_allowed`]);
/// - a `POST` or `PUT` is taken only as `Content-Type: application/json`, a bodiless one
///   (a halt, a reload) included;
/// - a change whose `Origin` (which a browser sets and a page cannot) is neither this API's
///   own address nor a listed origin is refused, whatever its method. A request with no
///   `Origin` is not from a browser page, and goes on.
async fn guard(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let method = request.method();
    let headers = request.headers();
    let refusal = if !host_allowed(headers, request.uri(), &state.hosts) {
        Some((
            StatusCode::FORBIDDEN,
            "this request was addressed to a name the backoffice does not answer to. It \
             answers to an IP address, to localhost, and to the names listed with \
             --backoffice-host or [settings] backoffice_hosts; list this one there and \
             restart if it is how you reach the backoffice",
        ))
    } else if method.is_safe() {
        None
    } else if !origin_allowed(headers, &state.origins) {
        Some((
            StatusCode::FORBIDDEN,
            "the backoffice only takes a change from a page served under its own address or \
             an origin --backoffice-cors-origin lists, or from a client that is not a browser",
        ))
    } else if (method == Method::POST || method == Method::PUT) && !is_json(headers) {
        Some((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "send a change as JSON, with Content-Type: application/json, even one with no \
             body",
        ))
    } else {
        None
    };
    match refusal {
        Some((status, why)) => {
            let header = |name| {
                headers
                    .get(name)
                    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            };
            tracing::warn!(
                "backoffice: refused {method} {} from {peer} (Host {:?}, Origin {:?}): {why}",
                request.uri().path(),
                header(header::HOST),
                header(header::ORIGIN),
            );
            ApiError::new(status, why).into_response()
        }
        None => next.run(request).await,
    }
}

/// Whether the request is addressed to a name this API is served under: any IP address,
/// `localhost`, or one of `hosts` ([`parse_hosts`]). The port is not part of the question.
/// An IP address needs no listing because a rebound name is always a name; see [`guard`].
/// `Host`, or the request line's own authority when a client sent one there instead.
fn host_allowed(headers: &axum::http::HeaderMap, uri: &axum::http::Uri, hosts: &[String]) -> bool {
    let authority = match headers.get(header::HOST) {
        Some(host) => host
            .to_str()
            .ok()
            .and_then(|host| host.parse::<axum::http::uri::Authority>().ok()),
        None => uri.authority().cloned(),
    };
    let Some(authority) = authority else {
        return false;
    };
    let name = authority.host();
    let name = name.strip_suffix('.').unwrap_or(name);
    // An IPv6 address is written in brackets in a `Host`.
    let address = name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(name);
    address.parse::<std::net::IpAddr>().is_ok()
        || name.eq_ignore_ascii_case("localhost")
        || hosts.iter().any(|host| host.eq_ignore_ascii_case(name))
}

/// Whether the body is declared JSON, parameters such as `charset` aside.
fn is_json(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
}

/// No `Origin` (not a browser page), this API's own address ([`same_origin`]), or one of
/// `origins`, matched as the CORS layer matches it.
fn origin_allowed(headers: &axum::http::HeaderMap, origins: &[String]) -> bool {
    match headers.get(header::ORIGIN) {
        None => true,
        Some(origin) => {
            same_origin(headers)
                || origin
                    .to_str()
                    .is_ok_and(|origin| origins.iter().any(|listed| listed == origin))
        }
    }
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

/// A request refused before anything changed: `{"error": ...}` with its status.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// Clashes with what the config holds: a key or name taken, a halt already in place.
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    /// Well-formed, and not a change the config can take.
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, message)
    }

    /// Nothing wrong with the request: this side could not do it.
    fn fault(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    /// Something this API asks on the caller's behalf (the chain, a venue) did not answer.
    fn upstream(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }
}

/// A body that is not JSON, or not the shape the route takes, says so in serde's words.
impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self::new(rejection.status(), rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

/// What a change answers. A partial apply is a 2xx, because the change is kept (a retry
/// would find it already made), and says `partial` rather than `applied`, because a pair
/// still runs its previous config. A rejection is a 422: nothing changed. A fault on this
/// side (the config file could not be written or put back, the pusher is stopping) is a
/// 500, so a client can tell it from a change it should fix.
fn respond(result: std::result::Result<String, Refused<ApiError>>, created: bool) -> Response {
    let kept = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let body = |status: &str, message: String| {
        Json(serde_json::json!({ "status": status, "message": message }))
    };
    match result {
        Ok(message) => (kept, body("applied", message)).into_response(),
        Err(Refused::Reload(ReloadFailure::Partial(message))) => {
            (kept, body("partial", message)).into_response()
        }
        Err(Refused::Reload(ReloadFailure::Rejected(message))) => {
            ApiError::invalid(message).into_response()
        }
        Err(Refused::Reload(ReloadFailure::Fault(message))) => {
            ApiError::fault(message).into_response()
        }
        Err(Refused::Change(err)) => err.into_response(),
    }
}

/// Makes `change` through the shared config and answers with how it went. The one place a
/// handler changes anything, so none can skip the converge or the revert.
async fn apply(
    state: &Backoffice,
    peer: SocketAddr,
    created: bool,
    change: impl FnOnce(&mut RawConfig) -> std::result::Result<String, ApiError>,
) -> Response {
    let by = format!("backoffice: {peer}");
    respond(state.config.change(&by, change).await, created)
}

// ---------------------------------------------------------------------------
// Pairs
// ---------------------------------------------------------------------------

/// What the running pusher is doing with a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PairStatus {
    /// Quoting.
    Live,
    /// Halted in the config: kept, not quoting.
    Halted,
    /// Running, but its circuit breaker tripped: not quoting until a reload re-arms it.
    BreakerTripped,
    /// In the config, with no task: its feed never came up, say. A reload tries again.
    NotRunning,
}

/// `running` is the pair's breaker flag if the pusher has a task for it, `None` if not.
fn pair_status(pair: &RawPair, running: Option<bool>) -> PairStatus {
    match (pair.halted, running) {
        (true, _) => PairStatus::Halted,
        (false, Some(true)) => PairStatus::BreakerTripped,
        (false, Some(false)) => PairStatus::Live,
        (false, None) => PairStatus::NotRunning,
    }
}

/// A pair as the API shows it: its stanza as the config holds it, which is what a `PUT`
/// takes back, beside what the running pusher is doing with it.
#[derive(Serialize)]
struct PairView {
    pair: RawPair,
    status: PairStatus,
    /// The pricing kind's one-line summary of the stanza, as `--check` prints it.
    pricing: String,
}

/// A snapshot of [`PairStates`], so every pair in an answer reads the same moment and the
/// lock is not held while answering. A poisoned lock still holds a usable map.
fn running(states: &PairStates) -> std::collections::BTreeMap<String, bool> {
    states
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(key, tripped)| (key.clone(), tripped.load(Ordering::SeqCst)))
        .collect()
}

fn pair_view(
    pair: &RawPair,
    running: &std::collections::BTreeMap<String, bool>,
    kinds: &crate::kinds::Kinds,
) -> PairView {
    PairView {
        pair: pair.clone(),
        status: pair_status(pair, running.get(&pair.key_env).copied()),
        pricing: kinds.pricer_summary(&config::PricingSpec {
            kind: pair
                .pricing
                .get("kind")
                .and_then(|kind| kind.as_str())
                .unwrap_or("")
                .to_owned(),
            config: pair.pricing.clone(),
        }),
    }
}

async fn list_pairs(State(state): State<Backoffice>) -> Json<Vec<PairView>> {
    let config = state.config.snapshot();
    let running = running(&state.states);
    Json(
        config
            .pairs
            .iter()
            .map(|pair| pair_view(pair, &running, &state.kinds))
            .collect(),
    )
}

async fn get_pair(
    State(state): State<Backoffice>,
    Path(key_env): Path<String>,
) -> std::result::Result<Json<PairView>, ApiError> {
    let config = state.config.snapshot();
    let pair = config
        .pairs
        .iter()
        .find(|pair| pair.key_env == key_env)
        .ok_or_else(|| no_pair(&key_env))?;
    Ok(Json(pair_view(pair, &running(&state.states), &state.kinds)))
}

fn no_pair(key_env: &str) -> ApiError {
    ApiError::not_found(format!("no pair with key_env {key_env:?}"))
}

/// Adds a pair: its `[[pairs]]` stanza, as JSON, exactly as the config file would hold it.
/// A pair is added quoting; one to be added halted is added and then halted.
async fn add_pair(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: std::result::Result<Json<RawPair>, JsonRejection>,
) -> std::result::Result<Response, ApiError> {
    let Json(pair) = body?;
    if pair.halted || pair.halt_reason.is_some() {
        return Err(ApiError::invalid(format!(
            "a pair is added quoting; halt it after with POST /api/pairs/{}/halt",
            pair.key_env
        )));
    }
    config::check_source_keys(&pair).map_err(|err| ApiError::invalid(format!("{err:#}")))?;
    Ok(apply(&state, peer, true, move |config| {
        if config
            .pairs
            .iter()
            .any(|existing| existing.key_env == pair.key_env)
        {
            return Err(ApiError::conflict(format!(
                "a pair already uses key_env {:?}; every pair needs its own key, since two \
                 pairs on one address share a nonce and only one of them could land per \
                 block",
                pair.key_env
            )));
        }
        let what = format!("added pair {}", pair.key_env);
        config.pairs.push(pair);
        Ok(what)
    })
    .await)
}

/// Replaces a pair's stanza with the body, which is the `pair` of a `GET` of it with
/// whatever changed. Its identity stays: `key_env` and `tokens` are what the lane and the
/// signer are derived from, so a pair on other ones is a `DELETE` and a `POST`. Its halt
/// stays too, changed only by the halt and resume routes, so an edit cannot lift a kill
/// switch by leaving the flag out.
async fn edit_pair(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key_env): Path<String>,
    body: std::result::Result<Json<RawPair>, JsonRejection>,
) -> std::result::Result<Response, ApiError> {
    let Json(edited) = body?;
    if edited.key_env != key_env {
        return Err(ApiError::invalid(format!(
            "the body's key_env is {:?} but the path names {key_env:?}; a pair's key_env and \
             tokens are its identity, so a pair on another key is a DELETE and a POST",
            edited.key_env
        )));
    }
    config::check_source_keys(&edited).map_err(|err| ApiError::invalid(format!("{err:#}")))?;
    Ok(apply(&state, peer, false, move |config| {
        let pair = config
            .pairs
            .iter_mut()
            .find(|pair| pair.key_env == key_env)
            .ok_or_else(|| no_pair(&key_env))?;
        let same_tokens = pair.tokens.len() == edited.tokens.len()
            && pair
                .tokens
                .iter()
                .zip(&edited.tokens)
                .all(|(was, is)| was.eq_ignore_ascii_case(is));
        if !same_tokens {
            return Err(ApiError::invalid(
                "a pair's tokens cannot change: the lane and its orientation are derived from \
                 them, so a pair on other tokens is a DELETE and a POST",
            ));
        }
        if pair.halted != edited.halted || pair.halt_reason != edited.halt_reason {
            return Err(ApiError::conflict(format!(
                "an edit keeps the pair's halt as it is; send halted and halt_reason as a GET \
                 shows them, and halt or resume it with POST /api/pairs/{key_env}/halt or \
                 /resume"
            )));
        }
        *pair = edited;
        Ok(format!("edited pair {key_env}"))
    })
    .await)
}

async fn remove_pair(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key_env): Path<String>,
) -> Response {
    apply(&state, peer, false, move |config| {
        let before = config.pairs.len();
        config.pairs.retain(|pair| pair.key_env != key_env);
        if config.pairs.len() == before {
            return Err(no_pair(&key_env));
        }
        // Removing the last pair is allowed: a process with a backoffice may run with none,
        // which is the state a fresh host starts in, and this API is how it gets out of it.
        Ok(format!("removed pair {key_env}"))
    })
    .await
}

/// Stops a pair quoting and keeps it, with every setting, in the config: the kill switch
/// (audit F-06, `SharedConfig::halt`). Its lane withdraws its quote at every builder on its
/// next tick, with no reload, no RPC call and no other pair's check in the way, so it is
/// never refused for another pair's sake and never waits on the chain; then the halt is
/// recorded, in the config and the file.
async fn halt_pair(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key_env): Path<String>,
) -> Response {
    let by = format!("backoffice: {peer}");
    let halted = state
        .config
        .halt(
            &by,
            move |config| {
                let pair = config
                    .pairs
                    .iter()
                    .find(|pair| pair.key_env == key_env)
                    .ok_or_else(|| no_pair(&key_env))?;
                if pair.halted {
                    return Err(ApiError::conflict("already halted"));
                }
                Ok((vec![key_env.clone()], format!("halted pair {key_env}")))
            },
            None,
        )
        .await;
    respond(halted, false)
}

async fn resume_pair(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key_env): Path<String>,
) -> Response {
    apply(&state, peer, false, move |config| {
        set_halted(config, Some(&key_env), false)?;
        Ok(format!("resumed pair {key_env}"))
    })
    .await
}

/// [`halt_pair`], for every pair not halted already.
async fn halt_all(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let by = format!("backoffice: {peer}");
    let halted = state
        .config
        .halt(
            &by,
            |config| {
                if config.pairs.is_empty() {
                    return Err(ApiError::conflict("there are no pairs to halt"));
                }
                let keys: Vec<String> = config
                    .pairs
                    .iter()
                    .filter(|pair| !pair.halted)
                    .map(|pair| pair.key_env.clone())
                    .collect();
                if keys.is_empty() {
                    return Err(ApiError::conflict("already halted"));
                }
                Ok((keys, "halted every pair".to_owned()))
            },
            None,
        )
        .await;
    respond(halted, false)
}

/// A reload with no edit behind it: covers the ways the running pairs drift from the
/// config on their own, a pair its circuit breaker halted (much the commonest) or one whose
/// feed never came up.
///
/// Pairs halted through this API are resumed too: their flag is cleared and the reload
/// starts them, as a change, so a refused reload leaves the flags as they were. A halt with
/// a reason is left as it is and named in the answer (see [`set_halted`]). Decided under
/// the shared config's edit lock, so two at once cannot both see a flag the first is about
/// to clear, which would have the second report an error for a restart that worked.
async fn reload(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let by = format!("backoffice: {peer}");
    let mut editing = state.config.edit().await;
    let current = editing.config();
    let any_flagged = current
        .pairs
        .iter()
        .any(|pair| pair.halted && !is_explained(pair));
    let kept = explained_halts(&current);
    if any_flagged {
        let mut result = editing
            .change(&by, |config| {
                set_halted(config, None, false)?;
                Ok::<_, ApiError>("restarted halted pairs".to_owned())
            })
            .await;
        // Not on a rejection: a refused restart changed nothing, so nothing was "left".
        match &mut result {
            Ok(message) | Err(Refused::Reload(ReloadFailure::Partial(message))) => {
                message.push_str(&kept)
            }
            Err(_) => {}
        }
        return respond(result, false);
    }
    let result = match editing.reload().await {
        Ok(summary) => {
            tracing::info!("{by} reloaded; {summary}");
            // The service's no-op line is not what someone asking for a reload wants to
            // know.
            Ok(match (summary.contains("nothing to do"), kept.is_empty()) {
                (true, true) => {
                    "nothing was halted; the running pairs already match the config".to_owned()
                }
                (true, false) => format!("nothing was restarted{kept}"),
                (false, _) => format!("{summary}{kept}"),
            })
        }
        Err(ReloadFailure::Partial(line)) => Err(Refused::Reload(ReloadFailure::Partial(format!(
            "the reload applied in part: {line}{kept}"
        )))),
        Err(ReloadFailure::Rejected(err)) => Err(Refused::Reload(ReloadFailure::Rejected(
            format!("the reload was rejected: {err}"),
        ))),
        Err(ReloadFailure::Fault(err)) => Err(Refused::Reload(ReloadFailure::Fault(format!(
            "the reload was not made: {err}"
        )))),
    };
    respond(result, false)
}

// ---------------------------------------------------------------------------
// Builders, settings, kinds and venues
// ---------------------------------------------------------------------------

/// A builder as the API shows it: everything but its API key, which is a live credential
/// and goes in, never out.
#[derive(Serialize)]
struct BuilderView {
    name: String,
    endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_cross_region: Option<bool>,
}

async fn list_builders(State(state): State<Backoffice>) -> Json<Vec<BuilderView>> {
    Json(
        state
            .config
            .snapshot()
            .builders
            .iter()
            .map(|builder| BuilderView {
                name: builder.name.clone(),
                endpoint: builder.endpoint.clone(),
                disable_cross_region: builder.disable_cross_region,
            })
            .collect(),
    )
}

/// Adds a builder: `{"name", "endpoint", "api_key", "disable_cross_region"?}`, as its
/// `[[builder]]` table holds it. Every pair is restarted onto the new list, and the reload
/// refuses a list none of whose builders would connect.
async fn add_builder(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: std::result::Result<Json<BuilderConfig>, JsonRejection>,
) -> std::result::Result<Response, ApiError> {
    let Json(builder) = body?;
    Ok(apply(&state, peer, true, move |config| {
        if config
            .builders
            .iter()
            .any(|existing| existing.name == builder.name)
        {
            return Err(ApiError::conflict(format!(
                "a builder is already named {:?}; names identify a builder in the logs, so \
                 they must be unique (try {:?}-eu and {:?}-us)",
                builder.name, builder.name, builder.name
            )));
        }
        let what = format!("added builder {}", builder.name);
        config.builders.push(builder);
        config::validate_builders(&config.builders)
            .map_err(|err| ApiError::invalid(format!("{err:#}")))?;
        Ok(what)
    })
    .await)
}

async fn remove_builder(
    State(state): State<Backoffice>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
) -> Response {
    apply(&state, peer, false, move |config| {
        let before = config.builders.len();
        config.builders.retain(|builder| builder.name != name);
        if config.builders.len() == before {
            return Err(ApiError::not_found(format!("no builder named {name:?}")));
        }
        Ok(format!("removed builder {name}"))
    })
    .await
}

/// `target` and `[settings]`, as the pusher read them at start. Read-only: each is consumed
/// once, at start (the RPC client, the listeners, the price scale), so changing one is an
/// edit of the config file and a restart, not something this API could apply. The API's
/// own writes keep whatever the file says for them meanwhile (see `state.rs`).
async fn settings(State(state): State<Backoffice>) -> Json<serde_json::Value> {
    let config = state.config.snapshot();
    Json(serde_json::json!({
        "config_path": state.config.path().display().to_string(),
        "target": config.target,
        "settings": config.settings,
    }))
}

/// The pricing kinds this binary registered, in order, each with the fields a form for its
/// `[pairs.pricing]` stanza would offer (`pricing::FormField`). A kind with no fields has
/// a stanza only the file's own syntax can write.
async fn list_kinds(State(state): State<Backoffice>) -> Json<Vec<serde_json::Value>> {
    let kinds = &state.kinds;
    Json(
        kinds
            .pricer_kinds()
            .into_iter()
            .map(|kind| {
                let fields: Vec<serde_json::Value> = kinds
                    .pricer_fields(kind)
                    .unwrap_or(&[])
                    .iter()
                    .map(|field| {
                        serde_json::json!({
                            "name": field.name,
                            "placeholder": field.placeholder,
                            "hint": field.hint,
                            "number": field.number,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "kind": kind,
                    "help_html": kinds.pricer_form_help(kind).unwrap_or(""),
                    "fields": fields,
                })
            })
            .collect(),
    )
}

/// Every venue a pair's `sources` can name, with how it spells a market and where it is
/// reached unless `[settings.endpoints]` says otherwise.
async fn list_venues() -> Json<Vec<serde_json::Value>> {
    Json(
        VenueId::ALL
            .iter()
            .map(|venue| {
                serde_json::json!({
                    "venue": venue.as_str(),
                    "example": venue.expected_symbol("ETH", "USDC"),
                    "default_endpoint": venue.default_endpoint(),
                    "polled": matches!(venue, VenueId::Mexc),
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Lookup and preview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Tokens {
    token0: String,
    token1: String,
}

/// Which venues list a token pair and how (`discover.rs`), one entry per venue the pusher
/// knows so a front end can draw its venue table whole: what to ask as soon as both
/// addresses of a new pair are known. Saves nothing.
async fn lookup_pair(State(state): State<Backoffice>, Query(tokens): Query<Tokens>) -> Response {
    // Checked before anything is asked: the addresses are read on chain.
    let (Ok(base), Ok(quote)) = (
        config::parse_address(tokens.token0.trim()),
        config::parse_address(tokens.token1.trim()),
    ) else {
        return ApiError::new(StatusCode::BAD_REQUEST, "token addresses are not valid")
            .into_response();
    };
    let (base_symbol, quote_symbol) = tokio::join!(
        crate::preflight::token_symbol(&state.client, base),
        crate::preflight::token_symbol(&state.client, quote),
    );
    let found = match (base_symbol, quote_symbol) {
        (Some(base_symbol), Some(quote_symbol)) => {
            crate::discover::discover(
                &state.http,
                &state.lookups,
                &state.rest,
                &base_symbol,
                &quote_symbol,
            )
            .await
        }
        _ => Err(eyre!(
            "could not read symbol() from both tokens on chain, so their names are unknown"
        )),
    };
    // A lookup that could not be made is an error like any other here, and not a 200 a
    // client has to open to find out: what it asks (the chain, the venues) did not answer.
    let found = match found {
        Ok(found) => found,
        Err(err) => return ApiError::upstream(format!("{err:#}")).into_response(),
    };
    let venues: Vec<serde_json::Value> = VenueId::ALL
        .iter()
        .map(|venue| {
            let row = found.row(*venue);
            serde_json::json!({
                "venue": venue.as_str(),
                "listed": row.is_some(),
                "unreachable": found.unreachable.contains(venue),
                "symbol": row.map(|r| r.symbol.clone()),
                "example": venue.expected_symbol("ETH", "USDC"),
                "weight": row.map(|r| r.weight.clone()),
                "last": row.and_then(|r| r.last),
                "volume_usd": row.and_then(|r| r.volume_usd),
                "note": row.map(|r| r.note.clone()).unwrap_or_else(|| match venue {
                    VenueId::Mexc => "polled every second".to_owned(),
                    _ => String::new(),
                }),
                "stand_in": row.is_some_and(|r| r.note.starts_with("quoted in")),
            })
        })
        .collect();
    // `ok` and `error` are what a failed lookup used to answer with a 200; kept, constant,
    // for a client written against that.
    Json(serde_json::json!({
        "ok": true,
        "error": null,
        "swapped": found.swapped,
        "base": found.base_symbol,
        "quote": found.quote_symbol,
        "notes": found.notes,
        "venues": venues,
    }))
    .into_response()
}

/// A message from the preview's client: tick or re-weight a venue, or untick it.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PreviewCommand {
    Set {
        venue: String,
        symbol: String,
        weight: String,
    },
    Remove {
        venue: String,
    },
}

/// Most previews open at once; one past it is refused. With one connection per
/// venue per page, previews hold at most `PREVIEW_PAGES × venues` venue connections.
const PREVIEW_PAGES: usize = 4;

/// Least time between two connections to the same venue from one page, whatever the page
/// sends: a symbol edited letter by letter, or a venue ticked and unticked over and over,
/// connects at most this often, with whatever the page asked for last.
const PREVIEW_REDIAL_GAP: std::time::Duration = std::time::Duration::from_secs(2);

/// One ticked venue of a preview page. `rx` is `None` until the venue is connected to
/// `source.symbol`: just ticked, or its symbol just changed, and waiting out the redial gap.
struct PreviewVenue {
    source: config::Source,
    rx: Option<tokio::sync::watch::Receiver<Option<crate::feed::PriceSample>>>,
}

/// A pair's live prices before it is added, over one websocket per open preview. The
/// client sends which venues are ticked, one at a time as they change, and the server
/// connects to exactly those, with the pusher's own feed code: ticking a venue connects
/// only it, unticking disconnects only it, and a new weight reconnects nothing. Twice a
/// second the server sends each venue's mid and the weighted composite, computed the way
/// the composite that would publish computes it. Closing the socket closes every venue it
/// opened.
async fn preview_socket(
    State(state): State<Backoffice>,
    Query(tokens): Query<Tokens>,
    headers: axum::http::HeaderMap,
    ws: axum::extract::WebSocketUpgrade,
) -> Response {
    let bad = |status: StatusCode, msg: &str| {
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    };
    if !origin_allowed(&headers, &state.origins) {
        return bad(
            StatusCode::FORBIDDEN,
            "the preview only opens from a page served under the backoffice's own address \
             or an origin --backoffice-cors-origin lists",
        );
    }
    let config = state.config.snapshot();
    let (Ok(base), Ok(quote)) = (
        config::parse_address(tokens.token0.trim()),
        config::parse_address(tokens.token1.trim()),
    ) else {
        return bad(StatusCode::BAD_REQUEST, "token addresses are not valid");
    };
    let endpoints = match crate::venue::Endpoints::resolve(
        config.settings.binance_ws.as_deref(),
        &config.settings.endpoints,
    ) {
        Ok(endpoints) => endpoints,
        Err(err) => return bad(StatusCode::BAD_REQUEST, &format!("{err:#}")),
    };
    let Ok(page) = Arc::clone(&state.preview_pages).try_acquire_owned() else {
        return bad(
            StatusCode::TOO_MANY_REQUESTS,
            "too many previews are open; close one and try again",
        );
    };
    // The composite prices the sorted lane; a declared base that sorts second is inverted,
    // and the preview turns it back so the numbers read as the venues quote them.
    let inverted = base > quote;
    ws.on_upgrade(move |socket| async move {
        preview_session(socket, endpoints, inverted).await;
        drop(page);
    })
}

/// Whether the request came from a page served from this same host: its `Origin` names
/// the address in its `Host`. Asked of every change by [`guard`] and of the preview
/// websocket by its handler, through [`origin_allowed`]. A browser opens a websocket from
/// any site, and unlike a fetch, does not stop another site's script from reading the
/// answer, so without this any page an operator visits could open the preview in their
/// name. A browser always sets `Origin` on a websocket and on a change, and a script cannot
/// change it; a reverse proxy such as Caddy, serving a front end and this API under one
/// address, passes both it and `Host` through unchanged.
fn same_origin(headers: &axum::http::HeaderMap) -> bool {
    let (Some(origin), Some(host)) = (
        headers.get(axum::http::header::ORIGIN),
        headers.get(axum::http::header::HOST),
    ) else {
        return false;
    };
    let (Ok(origin), Ok(host)) = (origin.to_str(), host.to_str()) else {
        return false;
    };
    url::Url::parse(origin).is_ok_and(|url| {
        let origin_host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        origin_host.eq_ignore_ascii_case(host)
    })
}

async fn preview_session(
    mut socket: axum::extract::ws::WebSocket,
    endpoints: crate::venue::Endpoints,
    inverted: bool,
) {
    use axum::extract::ws::Message;

    let Ok(metrics) = crate::metrics::Metrics::new() else {
        return;
    };
    let adopted = crate::feed::Adoption::new();
    adopted.adopt();
    let mut venues: std::collections::BTreeMap<VenueId, PreviewVenue> =
        std::collections::BTreeMap::new();
    // When each venue was last connected, kept after it is unticked so that ticking it
    // again does not skip the gap.
    let mut dialed: std::collections::BTreeMap<VenueId, std::time::Instant> =
        std::collections::BTreeMap::new();
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let text = match incoming {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                    Some(Ok(_)) => continue,
                };
                if let Err(err) = apply_preview_command(&mut venues, &text) {
                    let reply = serde_json::json!({"error": format!("{err:#}")}).to_string();
                    if socket.send(Message::Text(reply.into())).await.is_err() {
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                let now = std::time::Instant::now();
                for (venue, state) in &mut venues {
                    let due = dialed
                        .get(venue)
                        .is_none_or(|at| now.duration_since(*at) >= PREVIEW_REDIAL_GAP);
                    if state.rx.is_some() || !due {
                        continue;
                    }
                    state.rx = Some(crate::feed::spawn_feed(
                        endpoints.http(),
                        *venue,
                        endpoints.for_venue(*venue),
                        &state.source.symbol,
                        PREVIEW_DECIMALS,
                        inverted,
                        crate::feed::Gated::new(
                            metrics.for_venue("preview", venue.as_str()),
                            adopted.clone(),
                        ),
                        None,
                        Default::default(),
                    ));
                    dialed.insert(*venue, now);
                }
                let body = preview_snapshot(&venues, inverted);
                if socket.send(Message::Text(body.to_string().into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Applies one command from the client. A new weight changes only the average; a new symbol
/// drops that venue's connection at once and leaves it for the next tick to redial.
fn apply_preview_command(
    venues: &mut std::collections::BTreeMap<VenueId, PreviewVenue>,
    text: &str,
) -> Result<()> {
    match serde_json::from_str::<PreviewCommand>(text).wrap_err("not a preview command")? {
        PreviewCommand::Set {
            venue,
            symbol,
            weight,
        } => {
            let venue: VenueId = venue.parse()?;
            let symbol = symbol.trim().to_owned();
            // The symbol goes into the venue's URL or subscribe message, so only the
            // characters market names are spelled with.
            eyre::ensure!(
                !symbol.is_empty()
                    && symbol.len() <= 40
                    && symbol
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_/.".contains(c)),
                "{venue}: {symbol:?} is not a market name"
            );
            let weight = crate::feed::parse_decimal_scaled(
                if weight.trim().is_empty() {
                    "1"
                } else {
                    weight.trim()
                },
                config::WEIGHT_DECIMALS,
            )
            .ok()
            .filter(|w| !w.is_zero())
            .ok_or_else(|| eyre!("{venue}: weight must be a positive number"))?;
            // The same ceiling saving applies: above it `weight × mid` can overflow, and the
            // composite would read as "waiting for a fresh venue" with every venue fresh.
            eyre::ensure!(
                weight
                    <= ethrex_common::U256::from(config::MAX_WEIGHT)
                        * ethrex_common::U256::exp10(config::WEIGHT_DECIMALS as usize),
                "{venue}: weight is above {}; weights are relative, so scale them down",
                config::MAX_WEIGHT
            );
            match venues.get_mut(&venue) {
                Some(state) => {
                    state.source.weight = weight;
                    if symbol != state.source.symbol {
                        // Dropping the receiver is what closes the old connection.
                        state.source.symbol = symbol;
                        state.rx = None;
                    }
                }
                None => {
                    venues.insert(
                        venue,
                        PreviewVenue {
                            source: config::Source {
                                venue,
                                symbol,
                                weight,
                            },
                            rx: None,
                        },
                    );
                }
            }
        }
        PreviewCommand::Remove { venue } => {
            // Dropping the receiver is what closes that venue's connection.
            venues.remove(&venue.parse::<VenueId>()?);
        }
    }
    Ok(())
}

/// What the client is sent twice a second: each ticked venue's mid, in the venue's own
/// orientation, and the composite of the fresh ones, averaged the way the pusher averages
/// the number it publishes.
fn preview_snapshot(
    venues: &std::collections::BTreeMap<VenueId, PreviewVenue>,
    inverted: bool,
) -> serde_json::Value {
    let now = std::time::Instant::now();
    let wall = std::time::SystemTime::now();
    let market = |sample: Option<crate::feed::PriceSample>| -> Option<f64> {
        let sample = sample?;
        let mid = crate::feed::scaled_to_f64(sample.mid, PREVIEW_DECIMALS);
        if mid <= 0.0 {
            return None;
        }
        Some(if inverted { 1.0 / mid } else { mid })
    };
    let mut fresh = Vec::new();
    let rows: Vec<serde_json::Value> = venues
        .values()
        .map(|state| {
            let sample = state.rx.as_ref().and_then(|rx| *rx.borrow());
            let is_fresh =
                sample.is_some_and(|s| s.age_at(now, wall) <= crate::update::MAX_PRICE_AGE);
            if let (true, Some(sample)) = (is_fresh, sample) {
                fresh.push((&state.source, sample));
            }
            serde_json::json!({
                "venue": state.source.venue.as_str(),
                "symbol": state.source.symbol,
                "mid": market(sample),
                "age_ms": sample.map(|s| s.age_at(now, wall).as_millis() as u64),
                "fresh": is_fresh,
            })
        })
        .collect();
    let composite =
        crate::composite::weighted_average(&fresh).map(|(delta, mid)| crate::feed::PriceSample {
            delta,
            mid,
            at: now,
            wall,
        });
    serde_json::json!({
        "composite": market(composite),
        "fresh": fresh.len(),
        "venues": rows,
    })
}

/// The preview's price scale. Mids are displayed, never published, so this only has to be
/// fine enough to read; 18 is what production uses.
const PREVIEW_DECIMALS: u32 = 18;

// ---------------------------------------------------------------------------
// Halts
// ---------------------------------------------------------------------------

/// Sets `halted` on the pair named by `key_env`, or on every pair when it is `None`.
/// Refuses a change that would do nothing, so the answer never reports a halt that did
/// not happen.
///
/// A halt set here carries no `halt_reason`. One that has a reason was explained by
/// whoever set it: a binary's `UpdaterHandle::halt` always writes one, since that is its
/// kill switch, and an operator may write one by hand. The bulk resume (`key_env` `None`,
/// from `POST /api/reload`) leaves such a halt for that pair's own resume, so the call
/// made to bring back what was halted here cannot also lift a kill switch;
/// [`explained_halts`] is what the answer then says it left. A pair's own resume clears
/// either kind.
fn set_halted(
    config: &mut RawConfig,
    key_env: Option<&str>,
    halted: bool,
) -> std::result::Result<(), ApiError> {
    let mut found = false;
    let mut changed = false;
    for pair in &mut config.pairs {
        if key_env.is_some_and(|key| pair.key_env != key.trim()) {
            continue;
        }
        if key_env.is_none() && !halted && is_explained(pair) {
            continue;
        }
        found = true;
        if pair.halted != halted {
            changed = true;
            // The reason goes with the halt it explained, and a halt set here has none: a
            // stale one left beside a cleared flag would make it look explained.
            pair.halt_reason = None;
        }
        pair.halted = halted;
    }
    match key_env {
        Some(key) if !found => Err(no_pair(key)),
        None if !found => Err(ApiError::conflict("there are no pairs to halt")),
        _ if !changed && halted => Err(ApiError::conflict("already halted")),
        _ if !changed => Err(ApiError::conflict("not halted")),
        _ => Ok(()),
    }
}

/// A halt with a reason beside it: see [`set_halted`] for why the bulk resume skips it.
fn is_explained(pair: &RawPair) -> bool {
    pair.halted && pair.halt_reason.is_some()
}

/// The tail of the answer to a bulk restart, naming each halt it left and its reason;
/// empty when it left none. Said rather than left to be noticed, because the operator who
/// asked to restart halted pairs expects every halted one to come back.
fn explained_halts(config: &RawConfig) -> String {
    let kept: Vec<String> = config
        .pairs
        .iter()
        .filter(|pair| is_explained(pair))
        .map(|pair| {
            format!(
                "{} ({})",
                pair.key_env,
                pair.halt_reason.as_deref().unwrap_or_default()
            )
        })
        .collect();
    if kept.is_empty() {
        return String::new();
    }
    format!(
        ". Left halted, because each was halted with a reason (a binary's kill switch \
         writes one) that only its own resume clears: {}",
        kept.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ReloadRequest, tests::a_config};
    use serde_json::{Value, json};

    const WETH_USDC: &str = "UPDATER_KEY_WETH_USDC";
    /// A front end's origin, listed with `--backoffice-cors-origin` where a test says so.
    const UI: &str = "http://ui.example:3000";
    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

    /// The kinds a test binary registers: the three shipped ones, and `skewed`, a kind with
    /// no form fields, whose stanza is only written whole.
    fn test_kinds() -> Arc<crate::kinds::Kinds> {
        #[derive(Clone, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Skewed {
            #[allow(dead_code)]
            half_spread: f64,
        }
        struct SkewedPricer;
        impl crate::pricing::Pricer for SkewedPricer {
            fn price(
                &mut self,
                tick: &crate::pricing::TickCtx,
                _: &mut crate::pricing::Diagnostics,
            ) -> std::result::Result<crate::pricing::PricerOutput, crate::pricing::Refusal>
            {
                let market = tick.market()?;
                Ok(crate::pricing::PricerOutput::new(market.delta, market.mid))
            }
        }
        let mut kinds = crate::kinds::Kinds::default();
        kinds.insert("fixed", Arc::new(crate::pricing::Fixed));
        kinds.insert("feed", Arc::new(crate::pricing::Feed));
        kinds.insert("volatile", Arc::new(crate::pricing::Volatile));
        kinds.insert(
            "skewed",
            crate::kinds::fn_factory(|_: Skewed, _: &mut crate::pricing::BuildCtx| {
                Ok(SkewedPricer)
            }),
        );
        Arc::new(kinds)
    }

    fn test_client() -> ethrex_rpc::clients::eth::EthClient {
        ethrex_rpc::clients::eth::EthClient::new(url::Url::parse("http://127.0.0.1:1").unwrap())
            .unwrap()
    }

    /// A shared config over a fresh file holding `a_config` as `edit` leaves it, and the
    /// service end of its channel.
    fn shared(
        name: &str,
        edit: impl FnOnce(&mut RawConfig),
    ) -> (
        Arc<SharedConfig>,
        tokio::sync::mpsc::Receiver<ReloadRequest>,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "quote-updater-backoffice-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut config = a_config();
        edit(&mut config);
        config::write_raw_atomically(&path, &config).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        // No service here to retire a halted lane: the notice goes nowhere.
        let (halts, _) = tokio::sync::mpsc::unbounded_channel();
        (Arc::new(SharedConfig::new(path, config, tx, halts)), rx)
    }

    /// The service, answering every reload it is asked for with `verdict`. It keeps
    /// nothing itself: the shared config does that on the verdict.
    fn service(
        mut requests: tokio::sync::mpsc::Receiver<ReloadRequest>,
        verdict: std::result::Result<String, ReloadFailure>,
    ) {
        tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                let _ = request.reply.send(verdict.clone());
            }
        });
    }

    /// A backoffice on a free port over [`shared`], with a service answering `verdict`.
    async fn serve(
        name: &str,
        edit: impl FnOnce(&mut RawConfig),
        verdict: std::result::Result<String, ReloadFailure>,
    ) -> (SocketAddr, Arc<SharedConfig>) {
        serve_for(name, edit, verdict, &[]).await
    }

    /// [`serve`], answering CORS for `origins`.
    async fn serve_for(
        name: &str,
        edit: impl FnOnce(&mut RawConfig),
        verdict: std::result::Result<String, ReloadFailure>,
        origins: &[String],
    ) -> (SocketAddr, Arc<SharedConfig>) {
        let (config, requests) = shared(name, edit);
        service(requests, verdict);
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access {
                origins: origins.to_vec(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        (local, config)
    }

    fn accepted() -> std::result::Result<String, ReloadFailure> {
        Ok("reload: 1 changed".to_owned())
    }

    /// A request as a client would send a change (`Content-Type: application/json`, no
    /// `Origin`), through a real socket, so the routing, the guard, `ConnectInfo` and the
    /// JSON wiring are exercised too. Answered with its status and its body.
    async fn call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call_with(
            addr,
            method,
            path,
            body,
            &[("content-type", "application/json")],
        )
        .await
    }

    async fn call_with(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut request = reqwest::Client::new().request(
            method.parse::<reqwest::Method>().unwrap(),
            format!("http://{addr}{path}"),
        );
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        let bytes = response.bytes().await.unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, body)
    }

    #[test]
    fn halting_keeps_the_pair_and_refuses_a_change_that_does_nothing() {
        let mut config = a_config();
        // Left behind by a hand edit: the API's own halt must not inherit it, or it would
        // read as explained and the bulk restart would skip it.
        config.pairs[0].halt_reason = Some("stale".to_owned());
        set_halted(&mut config, Some(WETH_USDC), true).unwrap();
        assert_eq!(config.pairs.len(), 1, "a halt must not remove the pair");
        assert!(config.pairs[0].halted);
        assert_eq!(config.pairs[0].halt_reason, None);
        let again = set_halted(&mut config, Some(WETH_USDC), true).unwrap_err();
        assert_eq!(again.status, StatusCode::CONFLICT);
        let missing = set_halted(&mut config, Some("NO_SUCH_KEY"), true).unwrap_err();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        set_halted(&mut config, None, false).unwrap();
        assert!(!config.pairs[0].halted);
        assert!(set_halted(&mut config, None, false).is_err());

        // An explained halt is skipped by the bulk resume and cleared by its own.
        config.pairs[0].halted = true;
        config.pairs[0].halt_reason = Some("vault audit".to_owned());
        assert!(set_halted(&mut config, None, false).is_err());
        assert!(config.pairs[0].halted);
        set_halted(&mut config, Some(WETH_USDC), false).unwrap();
        assert!(!config.pairs[0].halted);
        assert_eq!(config.pairs[0].halt_reason, None);
    }

    /// Each pair says what the running pusher is doing with it, not only what the config
    /// asks for.
    #[tokio::test]
    async fn each_pair_says_what_the_pusher_is_doing_with_it() {
        let mut pair = a_config().pairs.remove(0);
        assert_eq!(pair_status(&pair, None), PairStatus::NotRunning);
        assert_eq!(pair_status(&pair, Some(false)), PairStatus::Live);
        assert_eq!(pair_status(&pair, Some(true)), PairStatus::BreakerTripped);
        pair.halted = true;
        assert_eq!(
            pair_status(&pair, Some(false)),
            PairStatus::Halted,
            "a halt in the config wins over whatever is running"
        );

        let (config, _requests) = shared("status", |_| {});
        let states = PairStates::default();
        let tripped = Arc::new(AtomicBool::new(false));
        states
            .lock()
            .unwrap()
            .insert(WETH_USDC.to_owned(), Arc::clone(&tripped));
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            config,
            test_client(),
            states,
            test_kinds(),
            Access::default(),
        )
        .await
        .unwrap();
        let (status, pairs) = call(local, "GET", "/api/pairs", None).await;
        assert_eq!(status, StatusCode::OK, "{pairs}");
        assert_eq!(pairs[0]["status"], "live", "{pairs}");
        assert_eq!(pairs[0]["pair"]["key_env"], WETH_USDC);
        assert!(
            pairs[0]["pricing"].as_str().unwrap().starts_with("feed"),
            "the kind's summary of the stanza: {pairs}"
        );
        tripped.store(true, Ordering::SeqCst);
        let (_, pair) = call(local, "GET", &format!("/api/pairs/{WETH_USDC}"), None).await;
        assert_eq!(pair["status"], "breaker_tripped", "{pair}");
    }

    /// An API that rewrites the config, with no login, on whatever the host faces.
    #[tokio::test]
    async fn an_unspecified_bind_is_refused() {
        assert!(is_unspecified_bind("0.0.0.0:8088".parse().unwrap()));
        assert!(is_unspecified_bind("[::]:8088".parse().unwrap()));
        assert!(!is_unspecified_bind("127.0.0.1:8088".parse().unwrap()));
        assert!(!is_unspecified_bind("100.64.1.2:8088".parse().unwrap()));

        let (config, _requests) = shared("unspecified", |_| {});
        let err = bind(
            "0.0.0.0:0".parse().unwrap(),
            config,
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access::default(),
        )
        .await
        .expect_err("an unspecified bind must be refused");
        assert!(format!("{err:#}").contains("tailnet"), "{err:#}");
    }

    /// The whole life of a pair through the API, each change kept in the shared config and
    /// written to the file, and the stanza kept exactly as sent: a number stays a number.
    #[tokio::test]
    async fn a_pair_is_added_edited_halted_resumed_and_removed() {
        let (local, config) = serve("crud", |_| {}, accepted()).await;
        let key = "UPDATER_KEY_USDC_USDT";
        let path = format!("/api/pairs/{key}");

        let (status, body) = call(
            local,
            "POST",
            "/api/pairs",
            Some(json!({
                "tokens": [USDC, USDT],
                "key_env": key,
                "sources": [
                    {"venue": "binance", "symbol": "USDCUSDT"},
                    {"venue": "kraken", "symbol": "USDC/USDT", "weight": "2"},
                ],
                "max_deviation": "0.02",
                "pricing": {"kind": "skewed", "half_spread": 0.0005},
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "applied", "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .starts_with(&format!("added pair {key}")),
            "{body}"
        );
        let written = config::load_raw(config.path()).unwrap();
        assert_eq!(written.pairs.len(), 2);
        assert_eq!(
            written.pairs[1].pricing.get("half_spread"),
            Some(&toml::Value::Float(0.0005))
        );
        assert_eq!(written.pairs[1].sources[1].weight.as_deref(), Some("2"));
        assert_eq!(config.snapshot().pairs[1], written.pairs[1]);

        // What a GET shows is what a PUT takes back.
        let (status, got) = call(local, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{got}");
        assert_eq!(got["status"], "not_running");
        let mut edited = got["pair"].clone();
        edited["max_deviation"] = json!("0.05");
        let (status, body) = call(local, "PUT", &path, Some(edited)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            config.snapshot().pairs[1].max_deviation.as_deref(),
            Some("0.05")
        );
        assert_eq!(
            config::load_raw(config.path()).unwrap().pairs[1]
                .max_deviation
                .as_deref(),
            Some("0.05")
        );

        let (status, body) = call(local, "POST", &format!("{path}/halt"), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(config.snapshot().pairs[1].halted);
        assert!(config::load_raw(config.path()).unwrap().pairs[1].halted);
        let (_, got) = call(local, "GET", &path, None).await;
        assert_eq!(got["status"], "halted", "{got}");
        let (status, body) = call(local, "POST", &format!("{path}/halt"), None).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a halt that does nothing: {body}"
        );
        let (status, body) = call(local, "POST", &format!("{path}/resume"), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!config.snapshot().pairs[1].halted);

        let (status, body) = call(local, "DELETE", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(config.snapshot().pairs.len(), 1);
        assert_eq!(config::load_raw(config.path()).unwrap().pairs.len(), 1);
        let (status, _) = call(local, "GET", &path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, body) = call(local, "DELETE", &path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body["error"].as_str().unwrap().contains(key), "{body}");
    }

    /// A change the service rejects answers 422 and changes nothing, in memory or on disk.
    #[tokio::test]
    async fn a_rejected_change_answers_422_and_changes_nothing() {
        let (local, config) = serve(
            "rejected",
            |_| {},
            Err(ReloadFailure::Rejected(
                "preflight failed for the new config".to_owned(),
            )),
        )
        .await;
        let before = std::fs::read_to_string(config.path()).unwrap();

        let (status, body) = call(local, "DELETE", &format!("/api/pairs/{WETH_USDC}"), None).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let error = body["error"].as_str().unwrap();
        assert!(error.contains("preflight failed"), "{error}");
        assert!(error.contains("nothing changed"), "{error}");
        assert_eq!(std::fs::read_to_string(config.path()).unwrap(), before);
        assert_eq!(config.snapshot().pairs.len(), 1);
    }

    /// One the service applied in part is kept, and says `partial` rather than `applied`.
    #[tokio::test]
    async fn a_partly_applied_change_is_kept_and_says_partial() {
        let (local, config) = serve(
            "partial",
            |_| {},
            Err(ReloadFailure::Partial(
                "reload: 1 halted, 1 failed".to_owned(),
            )),
        )
        .await;

        let (status, body) = call(local, "DELETE", &format!("/api/pairs/{WETH_USDC}"), None).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "partial", "{body}");
        assert!(
            body["message"].as_str().unwrap().contains("is kept"),
            "{body}"
        );
        assert!(config.snapshot().pairs.is_empty());
        assert!(config::load_raw(config.path()).unwrap().pairs.is_empty());
    }

    /// A halt is the kill switch, not a converged change (audit F-06): a service that would
    /// reject every change, as one with a pair failing its checks does, is not asked, and
    /// the halt is recorded in the config and the file all the same.
    #[tokio::test]
    async fn a_halt_is_not_refused_by_a_service_that_refuses_every_change() {
        let (local, config) = serve(
            "halt-not-refused",
            |_| {},
            Err(ReloadFailure::Rejected(
                "preflight failed: another pair is not authorized".to_owned(),
            )),
        )
        .await;

        let (status, body) =
            call(local, "POST", &format!("/api/pairs/{WETH_USDC}/halt"), None).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "applied", "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("withdrawn at every builder"),
            "{body}"
        );
        assert!(config.snapshot().pairs[0].halted);
        assert!(config::load_raw(config.path()).unwrap().pairs[0].halted);
        let (status, _) = call(local, "POST", &format!("/api/pairs/{WETH_USDC}/halt"), None).await;
        assert_eq!(status, StatusCode::CONFLICT, "already halted");
    }

    /// A change that could not be made through no fault of its own (here, a pusher that is
    /// stopping) is a 500, apart from the 422 of a change to fix, and leaves everything as
    /// it was.
    #[tokio::test]
    async fn a_fault_on_this_side_is_a_500_and_not_the_changes_mistake() {
        let (local, config) = serve(
            "fault",
            |_| {},
            Err(ReloadFailure::Fault("the pusher is stopping".to_owned())),
        )
        .await;
        let before = std::fs::read_to_string(config.path()).unwrap();

        let (status, body) = call(local, "DELETE", &format!("/api/pairs/{WETH_USDC}"), None).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        let error = body["error"].as_str().unwrap();
        assert!(error.contains("the pusher is stopping"), "{error}");
        assert_eq!(std::fs::read_to_string(config.path()).unwrap(), before);
        assert_eq!(config.snapshot().pairs.len(), 1);
    }

    /// A lookup that could not be made (here, no node to read the tokens' names from)
    /// answers an error status and `{"error"}`, like everything else this API refuses, and
    /// not a 200 to be opened.
    #[tokio::test]
    async fn a_lookup_that_cannot_be_made_is_an_error_and_not_a_200() {
        let (local, _config) = serve("lookup-fails", |_| {}, accepted()).await;

        let (status, body) = call(
            local,
            "GET",
            &format!("/api/lookup?token0={USDC}&token1={USDT}"),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains("symbol()"),
            "{body}"
        );
        assert!(body.get("ok").is_none(), "{body}");
    }

    /// The guard: a change only as JSON, and never from another site's page, whatever its
    /// method. A read is answered to anyone; a browser keeps another site's page from
    /// reading the answer.
    #[tokio::test]
    async fn a_change_is_taken_only_as_json_and_from_no_other_site() {
        let (local, config) = serve("guard", |_| {}, accepted()).await;
        let halt = format!("/api/pairs/{WETH_USDC}/halt");
        let pair = format!("/api/pairs/{WETH_USDC}");

        // What a form on another site posts: no JSON.
        for headers in [
            &[][..],
            &[("content-type", "application/x-www-form-urlencoded")][..],
            &[("content-type", "text/plain")][..],
        ] {
            let (status, body) = call_with(local, "POST", &halt, None, headers).await;
            assert_eq!(
                status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{headers:?}: {body}"
            );
        }
        // Another site's page, by any method.
        let evil = [
            ("content-type", "application/json"),
            ("origin", "https://evil.example"),
        ];
        for (method, path) in [("POST", &halt), ("DELETE", &pair), ("PUT", &pair)] {
            let (status, body) = call_with(local, method, path, Some(json!({})), &evil).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {body}");
        }
        assert_eq!(config.snapshot().pairs.len(), 1);
        assert!(!config.snapshot().pairs[0].halted, "nothing was changed");

        // A read, from anywhere.
        let (status, _) = call_with(local, "GET", "/api/pairs", None, &evil).await;
        assert_eq!(status, StatusCode::OK);
        // A page served under this address, as through a proxy that serves a front end
        // beside the API.
        let own = format!("http://{local}");
        let (status, body) = call_with(
            local,
            "POST",
            &halt,
            None,
            &[
                ("content-type", "application/json; charset=utf-8"),
                ("origin", &own),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(config.snapshot().pairs[0].halted);
    }

    /// `--backoffice-cors-origin` is written as a browser writes `Origin`, so a listed one
    /// matches byte for byte; anything that would answer for every page is refused.
    #[test]
    fn cors_origins_are_written_as_a_browser_sends_them() {
        let parsed = parse_origins(&[
            "HTTP://UI.Example:3000/".to_owned(),
            " https://ui.example:443 ".to_owned(),
            "http://[::1]:5173".to_owned(),
            String::new(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            [
                "http://ui.example:3000",
                "https://ui.example",
                "http://[::1]:5173"
            ]
        );
        for refused in [
            "*",
            "null",
            "ui.example:3000",
            "http://ui.example/app",
            "http://ui.example?x=1",
            "ftp://ui.example",
            "http://user@ui.example",
        ] {
            let err = parse_origins(&[refused.to_owned()]).expect_err(refused);
            let err = format!("{err:#}");
            assert!(err.contains("origin"), "{refused}: {err}");
        }
    }

    /// The CORS answers: a listed origin's preflight is approved for what the API takes,
    /// its change is applied and its page may read the answer. Any other origin gets no
    /// approval, and its change is still refused by the guard.
    #[tokio::test]
    async fn a_listed_origin_is_answered_with_cors_and_its_change_is_taken() {
        let (local, config) = serve_for("cors", |_| {}, accepted(), &[UI.to_owned()]).await;
        let halt = format!("http://{local}/api/pairs/{WETH_USDC}/halt");
        let client = reqwest::Client::new();
        let allow_origin = |response: &reqwest::Response| {
            response
                .headers()
                .get("access-control-allow-origin")
                .map(|value| value.to_str().unwrap().to_owned())
        };
        let preflight = |origin: &'static str| {
            client
                .request(reqwest::Method::OPTIONS, &halt)
                .header("origin", origin)
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type")
                .send()
        };

        let approved = preflight(UI).await.unwrap();
        assert!(approved.status().is_success(), "{}", approved.status());
        assert_eq!(allow_origin(&approved).as_deref(), Some(UI));
        let methods = approved
            .headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        for method in ["GET", "POST", "PUT", "DELETE"] {
            assert!(methods.contains(method), "{methods}");
        }
        let not_listed = preflight("https://evil.example").await.unwrap();
        assert_eq!(allow_origin(&not_listed), None);

        let evil = client
            .post(&halt)
            .header("origin", "https://evil.example")
            .header("content-type", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(evil.status().as_u16(), 403);
        assert_eq!(allow_origin(&evil), None);
        assert!(!config.snapshot().pairs[0].halted);

        let taken = client
            .post(&halt)
            .header("origin", UI)
            .header("content-type", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(taken.status().as_u16(), 200);
        assert_eq!(allow_origin(&taken).as_deref(), Some(UI));
        assert!(config.snapshot().pairs[0].halted);
        // Still JSON only: a listed origin's form post is no more welcome than anyone's.
        let form = client
            .post(format!("http://{local}/api/pairs/{WETH_USDC}/resume"))
            .header("origin", UI)
            .header("content-type", "application/x-www-form-urlencoded")
            .send()
            .await
            .unwrap();
        assert_eq!(form.status().as_u16(), 415);

        // With no origin listed there is no CORS at all.
        let (plain, _) = serve("no-cors", |_| {}, accepted()).await;
        let unanswered = client
            .request(
                reqwest::Method::OPTIONS,
                format!("http://{plain}/api/pairs"),
            )
            .header("origin", UI)
            .header("access-control-request-method", "POST")
            .send()
            .await
            .unwrap();
        assert_eq!(allow_origin(&unanswered), None);
    }

    /// A client that takes any certificate, keeps the one it was given, and opens a new
    /// connection for every request, so a renewed certificate is the one it sees next.
    fn https_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .pool_max_idle_per_host(0)
            .build()
            .unwrap()
    }

    /// The status of a `GET` of `url`, and the certificate the server presented for it.
    async fn presented(client: &reqwest::Client, url: &str) -> (u16, Vec<u8>) {
        let response = client.get(url).send().await.unwrap();
        let certificate = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|info| info.peer_certificate())
            .expect("an HTTPS answer carries the server's certificate")
            .to_vec();
        (response.status().as_u16(), certificate)
    }

    /// With a certificate the API is HTTPS: it presents that certificate, takes a change
    /// (the peer's address still reaching the guard and the log), turns plain HTTP away
    /// without falling over, and presents a renewed certificate once its files change.
    #[tokio::test]
    async fn the_api_is_served_over_https_and_a_renewal_is_picked_up() {
        use crate::tls::tests::{fixture, leaf};
        let dir = std::env::temp_dir().join(format!(
            "quote-updater-backoffice-certificate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("server.crt"), dir.join("server.key"));
        std::fs::copy(fixture("a.crt"), &cert).unwrap();
        std::fs::copy(fixture("a.key"), &key).unwrap();
        let (config, requests) = shared("https", |_| {});
        service(requests, accepted());
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access {
                tls: Some(crate::tls::Tls::load(&cert, &key).unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let client = https_client();
        let pairs = format!("https://{local}/api/pairs");

        let (status, certificate) = presented(&client, &pairs).await;
        assert_eq!(status, 200);
        assert_eq!(certificate, leaf("a.crt"));

        let halted = client
            .post(format!("https://{local}/api/pairs/{WETH_USDC}/halt"))
            .header("content-type", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(halted.status().as_u16(), 200);
        assert!(config.snapshot().pairs[0].halted);

        assert!(
            reqwest::get(format!("http://{local}/api/pairs"))
                .await
                .is_err(),
            "plain HTTP is not answered on the HTTPS port"
        );
        assert_eq!(presented(&client, &pairs).await.0, 200, "and still serves");

        std::fs::copy(fixture("b.crt"), &cert).unwrap();
        std::fs::copy(fixture("b.key"), &key).unwrap();
        let (status, renewed) = presented(&client, &pairs).await;
        assert_eq!(status, 200);
        assert_eq!(
            renewed,
            leaf("b.crt"),
            "the renewed certificate, with no restart"
        );
    }

    /// `--backoffice-host` is a bare name, as a `Host` header carries it without its port.
    #[test]
    fn backoffice_hosts_are_bare_names() {
        assert_eq!(
            parse_hosts(&[
                "Pusher.Example.ts.net.".to_owned(),
                " ".to_owned(),
                "ui_1.example".to_owned(),
            ])
            .unwrap(),
            ["pusher.example.ts.net", "ui_1.example"]
        );
        for refused in [
            "https://pusher.example",
            "pusher.example:8088",
            "pusher.example/api",
            "*",
            "*.example",
            "a..b",
            "[::1]",
        ] {
            let err = format!("{:#}", parse_hosts(&[refused.to_owned()]).unwrap_err());
            assert!(err.contains("not a hostname"), "{refused}: {err}");
        }
    }

    /// Answered: an IP address, `localhost`, a listed name, in any case, with or without its
    /// port or a trailing dot. Not: any other name, a listed name inside a longer one, or
    /// no name at all.
    #[test]
    fn only_an_ip_localhost_or_a_listed_name_is_answered() {
        let allowed = |host: Option<&str>, uri: &str| {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(host) = host {
                headers.insert("host", host.parse().unwrap());
            }
            host_allowed(
                &headers,
                &uri.parse().unwrap(),
                &["pusher.example.ts.net".to_owned()],
            )
        };
        for answered in [
            "100.64.1.2:8088",
            "127.0.0.1",
            "[::1]:8088",
            "localhost:8088",
            "LOCALHOST",
            "pusher.example.ts.net:8088",
            "Pusher.Example.TS.net",
            "pusher.example.ts.net.:8088",
        ] {
            assert!(allowed(Some(answered), "/api/pairs"), "{answered}");
        }
        for refused in [
            "evil.example:8088",
            "pusher.example.ts.net.evil.example",
            "localhost.evil.example",
            "100.64.1.2.nip.io",
            "",
        ] {
            assert!(!allowed(Some(refused), "/api/pairs"), "{refused}");
        }
        assert!(!allowed(None, "/api/pairs"), "no name at all");
        assert!(
            allowed(None, "http://pusher.example.ts.net:8088/api/pairs"),
            "the request line's own authority stands in for a missing Host"
        );
    }

    /// DNS rebinding as the backoffice sees it: its own routes, asked by a page whose name
    /// was pointed at this host, so `Host` and `Origin` both carry that name. Refused, reads
    /// (which would hand over the settings) and changes alike, the preview too. A listed
    /// name, and an IP address, are answered.
    #[tokio::test]
    async fn a_request_addressed_to_another_name_is_refused() {
        let (config, requests) = shared("hosts", |_| {});
        service(requests, accepted());
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access {
                hosts: vec!["Pusher.Example.ts.net".to_owned()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let halt = format!("/api/pairs/{WETH_USDC}/halt");
        let rebound = [
            ("host", "evil.example:8088"),
            ("origin", "http://evil.example:8088"),
            ("content-type", "application/json"),
        ];

        let (status, body) = call_with(local, "GET", "/api/settings", None, &rebound).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("--backoffice-host"),
            "{body}"
        );
        let (status, body) = call_with(local, "POST", &halt, None, &rebound).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!config.snapshot().pairs[0].halted, "nothing changed");
        let preview = http(
            local,
            "GET /api/preview?token0=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\
             &token1=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 HTTP/1.1\r\n\
             Host: evil.example:8088\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(preview.starts_with("HTTP/1.1 403"), "{preview}");

        // The listed name, as a page served under it sends it.
        let named = [
            ("host", "pusher.example.ts.net:8088"),
            ("origin", "http://pusher.example.ts.net:8088"),
            ("content-type", "application/json"),
        ];
        let (status, body) = call_with(local, "POST", &halt, None, &named).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(config.snapshot().pairs[0].halted);
        // And an IP address, which needs no listing.
        let (status, body) = call(local, "GET", "/api/pairs", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// An edit replaces the stanza and nothing that makes the pair what it is: not its key,
    /// not its tokens, and not its halt, which only the halt and resume routes change.
    #[tokio::test]
    async fn an_edit_keeps_the_pairs_identity_and_its_halt() {
        let (local, config) = serve(
            "identity",
            |config| {
                crate::updater::halt_line(&mut config.pairs[0], "vault audit").unwrap();
            },
            accepted(),
        )
        .await;
        let path = format!("/api/pairs/{WETH_USDC}");
        let (_, got) = call(local, "GET", &path, None).await;
        let pair = got["pair"].clone();
        assert_eq!(pair["halted"], true, "{pair}");

        let mut other_key = pair.clone();
        other_key["key_env"] = json!("UPDATER_KEY_OTHER");
        let (status, body) = call(local, "PUT", &path, Some(other_key)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let mut swapped = pair.clone();
        swapped["tokens"] = json!([pair["tokens"][1], pair["tokens"][0]]);
        let (status, body) = call(local, "PUT", &path, Some(swapped)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // A halt is not lifted by an edit that leaves the flag out.
        let mut unhalted = pair.clone();
        unhalted.as_object_mut().unwrap().remove("halted");
        unhalted.as_object_mut().unwrap().remove("halt_reason");
        let (status, body) = call(local, "PUT", &path, Some(unhalted)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // A misspelt key is refused by name rather than dropped.
        let mut typo = pair.clone();
        typo["max_deviaton"] = json!("0.02");
        let (status, body) = call(local, "PUT", &path, Some(typo)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains("max_deviaton"),
            "{body}"
        );

        let mut missing = pair.clone();
        missing["key_env"] = json!("NO_SUCH_KEY");
        let (status, body) = call(local, "PUT", "/api/pairs/NO_SUCH_KEY", Some(missing)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        assert_eq!(
            config.snapshot().pairs[0].max_deviation,
            None,
            "nothing changed"
        );

        let mut fine = pair.clone();
        fine["max_deviation"] = json!("0.03");
        let (status, body) = call(local, "PUT", &path, Some(fine)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let now = &config.snapshot().pairs[0];
        assert_eq!(now.max_deviation.as_deref(), Some("0.03"));
        assert!(now.halted, "the halt stays");
        assert_eq!(now.halt_reason.as_deref(), Some("vault audit"));

        // And a pair is added quoting, never halted.
        let mut halted = pair.clone();
        halted["key_env"] = json!("UPDATER_KEY_NEW");
        halted["tokens"] = json!([USDC, USDT]);
        let (status, body) = call(local, "POST", "/api/pairs", Some(halted)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    /// A key or a builder name already in use is a conflict, and nothing is written.
    #[tokio::test]
    async fn a_taken_key_or_builder_name_is_a_conflict() {
        let (local, config) = serve("taken", |_| {}, accepted()).await;
        let mut pair = serde_json::to_value(&a_config().pairs[0]).unwrap();
        pair["tokens"] = json!([USDC, USDT]);
        let (status, body) = call(local, "POST", "/api/pairs", Some(pair)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["error"].as_str().unwrap().contains("nonce"), "{body}");

        let builder =
            json!({"name": "titan-eu", "endpoint": "wss://us.example/ws", "api_key": "k2"});
        let (status, body) = call(local, "POST", "/api/builders", Some(builder)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, body) = call(local, "DELETE", "/api/builders/nobody", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(config.snapshot().pairs.len(), 1);
        assert_eq!(config.snapshot().builders.len(), 1);
    }

    /// A builder's API key goes in and never comes out: no answer carries one.
    #[tokio::test]
    async fn no_answer_carries_a_builder_api_key() {
        let (local, config) = serve(
            "secrets",
            |config| config.builders[0].api_key = "sekrit-one".to_owned(),
            accepted(),
        )
        .await;
        let (status, body) = call(
            local,
            "POST",
            "/api/builders",
            Some(json!({
                "name": "titan-us",
                "endpoint": "wss://us.example/ws",
                "api_key": "sekrit-two",
                "disable_cross_region": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert!(!body.to_string().contains("sekrit"), "{body}");
        assert_eq!(config.snapshot().builders[1].api_key, "sekrit-two");

        let mut answers = String::new();
        for path in ["/api/builders", "/api/settings", "/api/pairs", "/api/kinds"] {
            let (status, body) = call(local, "GET", path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            answers.push_str(&body.to_string());
        }
        assert!(!answers.contains("sekrit"), "{answers}");
        let (_, builders) = call(local, "GET", "/api/builders", None).await;
        assert_eq!(builders[1]["name"], "titan-us");
        assert_eq!(builders[1]["disable_cross_region"], true);

        let (status, body) = call(local, "DELETE", "/api/builders/titan-us", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(config.snapshot().builders.len(), 1);
    }

    /// A halt a binary's handle set is its kill switch: the bulk restart brings back what
    /// was halted through the API and leaves that one halted, saying which and why. That
    /// pair's own resume still clears it.
    #[tokio::test]
    async fn restarting_halted_pairs_leaves_a_handle_halt_alone() {
        let (local, config) = serve(
            "kill-switch",
            |config| {
                let mut second = config.pairs[0].clone();
                second.tokens = vec![USDC.to_owned(), USDT.to_owned()];
                second.symbol = Some("USDCUSDT".to_owned());
                second.key_env = "UPDATER_KEY_USDC_USDT".to_owned();
                config.pairs.push(second);
                // The first, halted exactly as `UpdaterHandle::halt` writes it.
                crate::updater::halt_line(&mut config.pairs[0], "vault audit").unwrap();
            },
            accepted(),
        )
        .await;

        let (status, body) =
            call(local, "POST", "/api/pairs/UPDATER_KEY_USDC_USDT/halt", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(local, "POST", "/api/reload", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "applied", "{body}");

        let now = config.snapshot();
        assert!(
            now.pairs[0].halted,
            "the handle's halt survives the bulk restart"
        );
        assert_eq!(now.pairs[0].halt_reason.as_deref(), Some("vault audit"));
        assert!(!now.pairs[1].halted, "the API's own halt is restarted");
        let message = body["message"].as_str().unwrap();
        assert!(
            message.contains(WETH_USDC) && message.contains("vault audit"),
            "the answer says which pair it left halted, and why: {message}"
        );
        assert_eq!(config::load_raw(config.path()).unwrap().pairs, now.pairs);

        // Again with only the handle's halt left: nothing to restart, and it says why that
        // pair is still down rather than "nothing was halted".
        let (status, body) = call(local, "POST", "/api/reload", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let message = body["message"].as_str().unwrap();
        assert!(message.contains(WETH_USDC), "{message}");
        assert!(!message.contains("nothing was halted"), "{message}");
        assert!(config.snapshot().pairs[0].halted);

        let (status, body) = call(
            local,
            "POST",
            &format!("/api/pairs/{WETH_USDC}/resume"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !config.snapshot().pairs[0].halted,
            "its own resume clears it"
        );
        assert_eq!(config.snapshot().pairs[0].halt_reason, None);
    }

    /// `[settings]` are shown and never changed: each is read once, at start.
    #[tokio::test]
    async fn settings_are_shown_and_not_changed() {
        let (local, config) = serve(
            "settings",
            |config| config.settings.requote_ms = Some(50),
            accepted(),
        )
        .await;
        let (status, body) = call(local, "GET", "/api/settings", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["settings"]["requote_ms"], 50, "{body}");
        assert_eq!(body["target"], a_config().target);
        assert_eq!(
            body["config_path"],
            config.path().display().to_string(),
            "{body}"
        );
        for method in ["PUT", "POST"] {
            let (status, _) = call(
                local,
                method,
                "/api/settings",
                Some(json!({"requote_ms": 25})),
            )
            .await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        }
        assert_eq!(config.snapshot().settings.requote_ms, Some(50));
    }

    /// What a front end needs to draw a pair form: the kinds with their fields, and the
    /// venues with how each spells a market.
    #[tokio::test]
    async fn the_kinds_and_the_venues_are_listed() {
        let (local, _config) = serve("lists", |_| {}, accepted()).await;
        let (status, kinds) = call(local, "GET", "/api/kinds", None).await;
        assert_eq!(status, StatusCode::OK, "{kinds}");
        let kind = |name: &str| {
            kinds
                .as_array()
                .unwrap()
                .iter()
                .find(|kind| kind["kind"] == name)
                .unwrap_or_else(|| panic!("{name} in {kinds}"))
                .clone()
        };
        let fixed = kind("fixed");
        assert!(
            fixed["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["name"] == "mid"),
            "{fixed}"
        );
        assert!(!fixed["help_html"].as_str().unwrap().is_empty());
        assert_eq!(
            kind("skewed")["fields"],
            json!([]),
            "a kind with no form fields"
        );

        let (status, venues) = call(local, "GET", "/api/venues", None).await;
        assert_eq!(status, StatusCode::OK, "{venues}");
        assert_eq!(venues.as_array().unwrap().len(), VenueId::ALL.len());
        assert_eq!(venues[0]["venue"], "binance");
        assert_eq!(venues[0]["example"], "ETHUSDC");

        let (status, body) = call(local, "GET", "/", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no pages are served: {body}");
        assert!(body["error"].as_str().unwrap().contains("/api"), "{body}");
    }

    /// Through a socket, for the tests that read the raw answer.
    async fn http(addr: SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The lookup a front end calls once both addresses are known: the token names read on
    /// chain, each exchange's own market list matched on base and quote, one entry per
    /// venue, and nothing saved. An exchange that cannot be asked is a note, not
    /// a failed lookup.
    #[tokio::test]
    async fn the_lookup_answers_one_entry_per_venue_and_saves_nothing() {
        use axum::{Router, routing::get};
        const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let rpc = crate::rpc_mock::MockRpc::spawn(1).await;
        rpc.set_symbol(config::parse_address(WETH).unwrap(), "WETH");
        rpc.set_symbol(config::parse_address(USDC).unwrap(), "USDC");
        // Three exchanges answer; the rest are missing from this mock, which is how an
        // exchange that is down looks. Binance lists ETH/USDC; Coinbase's ETH-USDC is
        // delisted, so its ETH-USD stands in; OKX has only a suspended ETH-USDT.
        let app = Router::new()
            .route(
                "/api/v3/exchangeInfo",
                get(|| async {
                    r#"{"symbols":[{"symbol":"ETHUSDC","status":"TRADING","baseAsset":"ETH","quoteAsset":"USDC"}]}"#
                }),
            )
            .route(
                "/api/v3/ticker/24hr",
                get(|| async { r#"{"lastPrice":"2500.5","quoteVolume":"300000000"}"# }),
            )
            .route(
                "/products",
                get(|| async {
                    r#"[{"id":"ETH-USDC","base_currency":"ETH","quote_currency":"USDC","status":"delisted","trading_disabled":true},
                        {"id":"ETH-USD","base_currency":"ETH","quote_currency":"USD","status":"online","trading_disabled":false}]"#
                }),
            )
            .route(
                "/products/ETH-USD/stats",
                get(|| async { r#"{"volume":"160000","last":"2500"}"# }),
            )
            .route(
                "/api/v5/public/instruments",
                get(|| async {
                    r#"{"code":"0","data":[{"instId":"ETH-USDT","baseCcy":"ETH","quoteCcy":"USDT","state":"suspend"}]}"#
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exchanges = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let (config, mut requests) = shared("lookup", |_| {});
        let before = std::fs::read_to_string(config.path()).unwrap();
        let (local, _task) = bind_with(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            ethrex_rpc::clients::eth::EthClient::new(url::Url::parse(&rpc.url).unwrap()).unwrap(),
            PairStates::default(),
            test_kinds(),
            Access::default(),
            crate::discover::Rest::all_at(&format!("http://{exchanges}")),
        )
        .await
        .unwrap();

        let page = http(
            local,
            &format!(
                "GET /api/lookup?token0={WETH}&token1={USDC} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Connection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(page.contains("200 OK"), "{page}");
        let body = page.split("\r\n\r\n").nth(1).expect("a body");
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["ok"], true, "{json}");
        assert_eq!(json["base"], "ETH", "WETH is read as its underlying");
        assert_eq!(json["quote"], "USDC");
        let venues = json["venues"].as_array().unwrap();
        assert_eq!(venues.len(), VenueId::ALL.len(), "one entry per venue");
        let by = |name: &str| venues.iter().find(|v| v["venue"] == name).unwrap().clone();
        assert_eq!(by("binance")["symbol"], "ETHUSDC");
        assert_eq!(
            by("binance")["weight"],
            "7.5",
            "300M against Coinbase's 400M"
        );
        assert_eq!(by("binance")["last"], 2500.5);
        assert_eq!(by("binance")["stand_in"], false);
        assert_eq!(
            by("coinbase")["symbol"],
            "ETH-USD",
            "the delisted ETH-USDC is skipped"
        );
        assert_eq!(by("coinbase")["weight"], "10");
        assert_eq!(by("coinbase")["stand_in"], true);
        assert_eq!(
            by("okx")["listed"],
            false,
            "a suspended market is not listed"
        );
        let notes: Vec<&str> = json["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert!(
            notes[0].starts_with("2 exchanges list ETH against USDC"),
            "{notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n.starts_with("bybit: could not read its markets")),
            "an exchange that did not answer is named: {notes:?}"
        );
        // And its row says so, rather than claiming it does not list the pair.
        assert_eq!(by("bybit")["unreachable"], true);
        assert_eq!(
            by("okx")["unreachable"],
            false,
            "okx answered; it just has no market"
        );
        // Nothing saved, nothing asked of the service.
        assert_eq!(std::fs::read_to_string(config.path()).unwrap(), before);
        assert!(requests.try_recv().is_err());
    }

    /// Two mock venues on one port, standing in for what the preview dials: Binance on any
    /// `/<symbol>@bookTicker` path, quoting 1999/2001, and Bybit on `/bybit`, quoting
    /// 2099/2101 once it is subscribed. Each socket is held until the other end drops it.
    /// Records the path of every connection ever accepted and how many are open per path.
    #[derive(Clone, Default)]
    struct MockVenues {
        accepted: Arc<std::sync::Mutex<Vec<String>>>,
        open: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    }

    impl MockVenues {
        #[allow(clippy::result_large_err)]
        async fn start() -> (Self, SocketAddr) {
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message;
            let mocks = Self::default();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let shared = mocks.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let mocks = shared.clone();
                    tokio::spawn(async move {
                        let mut path = String::new();
                        let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(
                            stream,
                            |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                             resp| {
                                path = req.uri().path().to_owned();
                                Ok(resp)
                            },
                        )
                        .await
                        else {
                            return;
                        };
                        mocks.accepted.lock().unwrap().push(path.clone());
                        *mocks.open.lock().unwrap().entry(path.clone()).or_default() += 1;
                        if path.ends_with("@bookTicker") {
                            let _ = ws
                                .send(Message::text(
                                    r#"{"u":1,"s":"X","b":"1999.0","B":"1","a":"2001.0","A":"1"}"#,
                                ))
                                .await;
                        } else if let Some(Ok(_subscribe)) = ws.next().await {
                            let _ = ws
                                .send(Message::text(
                                    r#"{"topic":"orderbook.1.ETHUSDC","ts":"1","type":"snapshot","data":{"s":"ETHUSDC","b":[["2099.0","1"]],"a":[["2101.0","1"]],"u":1,"seq":1}}"#,
                                ))
                                .await;
                        }
                        while let Some(Ok(_)) = ws.next().await {}
                        *mocks.open.lock().unwrap().get_mut(&path).unwrap() -= 1;
                    });
                }
            });
            (mocks, addr)
        }

        fn open(&self, path: &str) -> usize {
            self.open.lock().unwrap().get(path).copied().unwrap_or(0)
        }

        fn accepted(&self, path: &str) -> usize {
            self.accepted
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == path)
                .count()
        }

        /// Waits until `path` has `want` open connections.
        async fn until_open(&self, path: &str, want: usize) {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while self.open(path) != want {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{path}: {} open, expected {want}", self.open(path)));
        }
    }

    const BINANCE_ETH: &str = "/ethusdc@bookTicker";
    const BYBIT: &str = "/bybit";

    /// A backoffice whose Binance and Bybit endpoints are the mocks, answering CORS for
    /// [`UI`].
    async fn preview_backoffice(name: &str, venues: SocketAddr) -> SocketAddr {
        preview_backoffice_with(name, venues, None).await
    }

    /// [`preview_backoffice`], over HTTPS when given a certificate.
    async fn preview_backoffice_with(
        name: &str,
        venues: SocketAddr,
        tls: Option<crate::tls::Tls>,
    ) -> SocketAddr {
        let (config, _requests) = shared(name, |config| {
            config
                .settings
                .endpoints
                .insert("binance".to_owned(), format!("ws://{venues}"));
            config
                .settings
                .endpoints
                .insert("bybit".to_owned(), format!("ws://{venues}{BYBIT}"));
        });
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            config,
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access {
                origins: vec![UI.to_owned()],
                tls,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        local
    }

    type PreviewPage = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Opens the preview for WETH/USDC, declared base first, so the lane is inverted and
    /// the preview has to turn it back to read 2000 rather than 0.0005.
    async fn open_preview(
        local: SocketAddr,
    ) -> Result<PreviewPage, tokio_tungstenite::tungstenite::Error> {
        open_preview_from(local, &format!("http://{local}")).await
    }

    async fn open_preview_from(
        local: SocketAddr,
        origin: &str,
    ) -> Result<PreviewPage, tokio_tungstenite::tungstenite::Error> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = format!(
            "ws://{local}/api/preview?token0=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\
             &token1=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert("origin", origin.parse().unwrap());
        tokio_tungstenite::connect_async(request)
            .await
            .map(|(ws, _)| ws)
    }

    async fn send(page: &mut PreviewPage, command: serde_json::Value) {
        use futures_util::SinkExt;
        page.send(tokio_tungstenite::tungstenite::Message::text(
            command.to_string(),
        ))
        .await
        .unwrap();
    }

    /// Reads the page's messages until one satisfies `want`.
    async fn snapshot_where(
        page: &mut PreviewPage,
        want: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        use futures_util::StreamExt;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let msg = page.next().await.expect("the page stays open").unwrap();
                if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if want(&value) {
                        return value;
                    }
                }
            }
        })
        .await
        .expect("no such message within 10s")
    }

    /// The preview connects to the ticked venues with the pusher's own feed code and sends
    /// what they quote: each venue's mid and the composite, oriented the way the venues
    /// quote, averaged the way the pusher averages what it publishes.
    #[tokio::test]
    async fn the_preview_sends_the_venues_mids_and_the_composite() {
        let (_mocks, venues) = MockVenues::start().await;
        let local = preview_backoffice("preview", venues).await;
        let mut page = open_preview(local).await.unwrap();
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "1"}),
        )
        .await;
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "bybit", "symbol": "ETHUSDC", "weight": ""}),
        )
        .await;
        let found = snapshot_where(&mut page, |v| v["fresh"] == 2).await;
        assert_eq!(found["venues"][0]["venue"], "binance");
        assert!((found["venues"][0]["mid"].as_f64().unwrap() - 2000.0).abs() < 0.01);
        assert_eq!(found["venues"][1]["venue"], "bybit");
        assert!((found["venues"][1]["mid"].as_f64().unwrap() - 2100.0).abs() < 0.01);
        // The inverted lane averages 1/2000 and 1/2100, so read back the way the venues
        // quote it the composite is their harmonic mean, 2048.78, not 2050.
        let composite = found["composite"].as_f64().unwrap();
        assert!((composite - 2048.78).abs() < 0.01, "{found}");

        // Something that is not a command is answered with an error, and the page lives on.
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETH USDC?x=1", "weight": "1"}),
        )
        .await;
        let refused = snapshot_where(&mut page, |v| v.get("error").is_some()).await;
        assert!(
            refused["error"]
                .as_str()
                .unwrap()
                .contains("not a market name"),
            "{refused}"
        );
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "1000001"}),
        )
        .await;
        let refused = snapshot_where(&mut page, |v| v.get("error").is_some()).await;
        assert!(
            refused["error"].as_str().unwrap().contains("above 1000000"),
            "{refused}"
        );
        snapshot_where(&mut page, |v| v["fresh"] == 2).await;
    }

    /// The point of the websocket: unticking a venue closes that venue's connection and no
    /// other, a new weight reconnects nothing, and a new symbol reconnects only its venue.
    /// Closing the page closes everything it opened.
    #[tokio::test]
    async fn unticking_a_venue_disconnects_only_that_venue() {
        let (mocks, venues) = MockVenues::start().await;
        let local = preview_backoffice("preview-untick", venues).await;
        let mut page = open_preview(local).await.unwrap();
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "1"}),
        )
        .await;
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "bybit", "symbol": "ETHUSDC", "weight": "1"}),
        )
        .await;
        snapshot_where(&mut page, |v| v["fresh"] == 2).await;

        send(
            &mut page,
            serde_json::json!({"type": "remove", "venue": "bybit"}),
        )
        .await;
        mocks.until_open(BYBIT, 0).await;
        let after = snapshot_where(&mut page, |v| v["venues"].as_array().unwrap().len() == 1).await;
        assert_eq!(after["venues"][0]["venue"], "binance");
        assert_eq!(after["fresh"], 1);
        assert_eq!(mocks.open(BINANCE_ETH), 1, "binance stays connected");
        assert_eq!(mocks.accepted(BINANCE_ETH), 1, "and was never redialled");

        // A new weight changes the average and nothing else.
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "3"}),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        assert_eq!(
            mocks.accepted(BINANCE_ETH),
            1,
            "a weight is not a reconnect"
        );

        // A new symbol closes the old market's connection and opens the new one.
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "BTCUSDC", "weight": "3"}),
        )
        .await;
        mocks.until_open(BINANCE_ETH, 0).await;
        mocks.until_open("/btcusdc@bookTicker", 1).await;

        drop(page);
        mocks.until_open("/btcusdc@bookTicker", 0).await;
    }

    /// Ticking and unticking the same venue over and over connects it at most once per
    /// PREVIEW_REDIAL_GAP, however fast the page sends.
    #[tokio::test]
    async fn a_venue_ticked_and_unticked_fast_is_not_redialled_fast() {
        let (mocks, venues) = MockVenues::start().await;
        let local = preview_backoffice("preview-flap", venues).await;
        let mut page = open_preview(local).await.unwrap();
        let tick = serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "1"});
        let untick = serde_json::json!({"type": "remove", "venue": "binance"});
        send(&mut page, tick.clone()).await;
        mocks.until_open(BINANCE_ETH, 1).await;
        let started = std::time::Instant::now();
        while started.elapsed() < PREVIEW_REDIAL_GAP - std::time::Duration::from_millis(500) {
            send(&mut page, untick.clone()).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            send(&mut page, tick.clone()).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(mocks.accepted(BINANCE_ETH), 1, "redialled inside the gap");
        // Once the gap has passed, the venue the page last ticked is connected again.
        mocks.until_open(BINANCE_ETH, 1).await;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while mocks.accepted(BINANCE_ETH) != 2 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("redialled once the gap passed");
    }

    /// A page on another site cannot open the preview; one served under the backoffice's
    /// own address can, whether reached by its tailnet address or by name, and so can a
    /// client that is not a browser.
    #[tokio::test]
    async fn no_other_sites_page_can_open_the_preview() {
        let (_mocks, venues) = MockVenues::start().await;
        let local = preview_backoffice("preview-origin", venues).await;
        for origin in ["https://evil.example", "http://127.0.0.1:1", "null"] {
            match open_preview_from(local, origin).await {
                Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                    assert_eq!(response.status(), 403, "{origin}")
                }
                other => panic!("{origin}: expected a 403, got {:?}", other.map(|_| ())),
            }
        }
        open_preview(local)
            .await
            .expect("a page under its own address opens it");
        open_preview_from(local, UI)
            .await
            .expect("so does a page from an origin --backoffice-cors-origin lists");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "backoffice.example.com".parse().unwrap());
        headers.insert("origin", "https://backoffice.example.com".parse().unwrap());
        assert!(same_origin(&headers));
        headers.insert("origin", "https://grafana.example.com".parse().unwrap());
        assert!(!same_origin(&headers));
        assert!(!origin_allowed(&headers, &[]));
        assert!(origin_allowed(
            &headers,
            &["https://grafana.example.com".to_owned()]
        ));
        headers.remove("origin");
        assert!(!same_origin(&headers));
        assert!(
            origin_allowed(&headers, &[]),
            "no origin is not a browser page, so no other site's"
        );
    }

    /// Over HTTPS the preview is a `wss://` socket: the websocket upgrade runs on the TLS
    /// connection the backoffice's own listener accepted, and the venues come through.
    #[tokio::test]
    async fn the_preview_opens_over_wss() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (_mocks, venues) = MockVenues::start().await;
        let tls = crate::tls::Tls::load(
            &crate::tls::tests::fixture("a.crt"),
            &crate::tls::tests::fixture("a.key"),
        )
        .unwrap();
        let local = preview_backoffice_with("preview-wss", venues, Some(tls)).await;
        let mut request = format!(
            "wss://{local}/api/preview?token0=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\
             &token1=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert("origin", format!("https://{local}").parse().unwrap());
        let connector = tokio_tungstenite::Connector::NativeTls(
            native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        );
        let (mut page, _) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .expect("the preview opens over wss://");
        send(
            &mut page,
            serde_json::json!({"type": "set", "venue": "binance", "symbol": "ETHUSDC", "weight": "1"}),
        )
        .await;
        let found = snapshot_where(&mut page, |v| v["fresh"] == 1).await;
        assert!((found["venues"][0]["mid"].as_f64().unwrap() - 2000.0).abs() < 0.01);
    }

    /// At most PREVIEW_PAGES pages at once; one more is refused before it opens anything,
    /// and closing a page frees its place.
    #[tokio::test]
    async fn the_number_of_open_preview_pages_is_capped() {
        let (_mocks, venues) = MockVenues::start().await;
        let local = preview_backoffice("preview-cap", venues).await;
        let mut pages = Vec::new();
        for _ in 0..PREVIEW_PAGES {
            pages.push(open_preview(local).await.unwrap());
        }
        match open_preview(local).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), 429)
            }
            other => panic!("expected a 429, got {:?}", other.map(|_| ())),
        }
        drop(pages.pop());
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while open_preview(local).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("a closed page frees its place");
    }

    /// Anything that is not an address is refused before it can reach CoinGecko's URL.
    #[tokio::test]
    async fn the_lookup_refuses_what_is_not_an_address() {
        let (config, _requests) = shared("lookup-validation", |_| {});
        let (local, _task) = bind(
            "127.0.0.1:0".parse().unwrap(),
            config,
            test_client(),
            PairStates::default(),
            test_kinds(),
            Access::default(),
        )
        .await
        .unwrap();
        for token0 in [
            "0xabc%3Fx%3D1",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2%23x",
            "weth",
        ] {
            let answer = http(
                local,
                &format!(
                    "GET /api/lookup?token0={token0}&token1=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
                     HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                ),
            )
            .await;
            assert!(answer.contains("400 Bad Request"), "{token0}: {answer}");
            assert!(answer.contains("not valid"), "{token0}: {answer}");
        }
    }
}

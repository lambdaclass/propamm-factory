//! The command line and the settings precedence behind it: flag, then environment
//! variable, then the config file's `[settings]`, then the built-in default. Also the
//! startup refusals that depend only on what was asked for (`--mode` against the flags and
//! the config that only make sense in the other mode).

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::{CommandFactory, FromArgMatches, Parser, builder::FalseyValueParser};
use ethrex_common::Address;
use eyre::{Result, WrapErr, bail, ensure};

use crate::{PRICE_DECIMALS, config, venue};

/// Mainnet PrioUpdateRegistry (MAX_UPDATE_AGE = 0, MAX_UPDATE_LEAD_TIME = 0). The
/// deployment PropAMM reads from since 2026-09-15. The first one, at
/// 0xDa7AfeeD01fe625CF15d187a19f94B45f00b8C5F, has a known vulnerability and must never be
/// the default again: a config with no `registry` line falls back to this constant, so a
/// wrong value here is a pusher that pushes to the wrong contract without saying so.
const MAINNET_REGISTRY: &str = "0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81";

/// The backoffice's address when a flag or `[settings] backoffice_addr` names only its port:
/// this host alone, which is never the wrong place to have bound an API with no login.
const DEFAULT_BACKOFFICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The backoffice's port when a flag names only its address: the one every doc and the
/// compose file use.
const DEFAULT_BACKOFFICE_PORT: u16 = 8088;

/// Variables that used to configure the single-builder mode. Kept only to refuse them.
const REMOVED_VARS: [&str; 2] = ["TITAN_WS", "TITAN_API_KEY"];

/// Where updates go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Mode {
    /// Sign each pair's per-block update locally and stream it to every builder in
    /// `--builders` as a protobuf quote update. The RPC is still used for reads.
    Builder,
    /// Submit `updateState` transactions to `--rpc-url`: an anvil for local testing, a
    /// fork, or a real network.
    Node,
}

/// The updater's command line. [`Args::from_env`] parses this process's; a binary with
/// flags of its own flattens these into them (`#[command(flatten)]`, through the
/// [`clap::Args`] impl) and parses the whole with its own `Parser`. Every path through clap
/// records which values were given and reads a variable that is set but blank as unset,
/// so the flag > variable > `[settings]` > default precedence holds however the flags were
/// parsed:
///
/// ```
/// use quote_updater::{Args, clap::{self, Parser}};
///
/// #[derive(Parser)]
/// struct Cli {
///     #[command(flatten)]
///     updater: Args,
///     /// This binary's own flag.
///     #[arg(long)]
///     strategy: String,
/// }
///
/// let cli = Cli::try_parse_from(["bin", "--config", "c.toml", "--strategy", "carry"]).unwrap();
/// // `cli.updater` is what `Updater::builder().run(..)` takes.
/// # drop(cli);
/// ```
pub struct Args {
    /// The flags, as clap filled them in.
    pub(crate) flags: Flags,
    /// Which of them the command line or the environment gave, read off the matches at
    /// parse time. `apply_file_settings` fills in only the rest from the file's
    /// `[settings]`, which is the flag > env > file > default precedence; carried here so
    /// a caller never has to hand clap's matches back in.
    pub(crate) given: Given,
}

/// Quote one or more asset pairs, streaming each pair's price from Binance and publishing
/// it as a priority update on its own lane of a single PropAMM. Every pair carries its own
/// updater key, so their nonces stay independent and each lane lands on its own.
///
/// By default (--mode builder) each pair's per-block update is signed locally and streamed
/// to every builder in --builders; --mode node submits updateState transactions to the
/// PrioUpdateRegistry over --rpc-url instead, verifying each push by reading it back as
/// the target.
// The derive lives on this private struct rather than on `Args` because it would also
// derive `FromArgMatches`, and that impl cannot record what was given: `Args` wraps it to
// add exactly that, on every parse path.
#[derive(Parser)]
pub(crate) struct Flags {
    /// Path to the config file: target, settings, pairs and builders; see
    /// config.example.toml
    #[arg(long, env = "CONFIG")]
    pub(crate) config: PathBuf,

    /// Validate the config, the keys and the chain, print what each pair would publish,
    /// then exit without sending anything
    #[arg(long, env = "CHECK", value_parser = FalseyValueParser::new())]
    pub(crate) check: bool,

    /// JSON-RPC endpoint (an anvil node for local testing)
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub(crate) rpc_url: String,

    /// WebSocket JSON-RPC endpoint (ws:// or wss://) for a newHeads subscription; builder
    /// mode only. Without it the chain head is polled over --rpc-url every --requote-ms
    /// (at least 250ms) and each new block fetched; with it the node pushes every new
    /// block's header the moment it has it, and the poll drops to a slow liveness check.
    /// Polling covers any spell the subscription is down.
    #[arg(long, env = "RPC_WS_URL")]
    pub(crate) rpc_ws_url: Option<String>,

    /// Registry address
    #[arg(long, env = "REGISTRY", default_value = MAINNET_REGISTRY, value_parser = parse_address)]
    pub(crate) registry: Address,

    /// Decimal places the published mid and delta are scaled by. PropAMM reads both at
    /// 1e18 (its PRICE_SCALE and SPREAD_SCALE), so 18 is the default and the only value
    /// accepted: there is nothing to set here.
    #[arg(long, env = "PRICE_DECIMALS", default_value_t = PRICE_DECIMALS)]
    #[arg(value_parser = parse_price_decimals)]
    pub(crate) price_decimals: u32,

    /// Binance WebSocket base endpoint (overridable for binance.us or a mock)
    #[arg(
        long,
        env = "BINANCE_WS",
        default_value = venue::VenueId::Binance.default_endpoint()
    )]
    pub(crate) binance_ws: String,

    /// Seconds between pushes on the RPC path (--mode node)
    #[arg(long, env = "INTERVAL", default_value_t = 12)]
    pub(crate) interval: u64,

    /// Push (or quote) a single update per pair and exit instead of running as a service
    #[arg(long, env = "ONCE", value_parser = FalseyValueParser::new())]
    pub(crate) once: bool,

    /// Skip pinning the next block timestamp (evm_setNextBlockTimestamp, anvil-only);
    /// required on real networks. The mainnet registry accepts an update only if its
    /// timestamp equals the including block's timestamp exactly, so without pinning an
    /// update (stamped one block time ahead) lands only when included in the very next
    /// block: a missed slot or delayed inclusion reverts the push, and the service
    /// retries with a fresh timestamp on the next tick.
    #[arg(long, env = "NO_PIN", value_parser = FalseyValueParser::new())]
    pub(crate) no_pin: bool,

    /// Mine a block after each send (anvil_mine, anvil-only). Required against a
    /// no-mining anvil like the one `make local` starts, where a sent transaction
    /// waits in the pool forever and its receipt never arrives on its own.
    #[arg(long, env = "MINE", value_parser = FalseyValueParser::new())]
    pub(crate) mine: bool,

    /// Where updates go: `builder` (the default) signs each pair's per-block update and
    /// streams it to every builder listed in --builders; `node` submits updateState
    /// transactions to --rpc-url instead. Builder mode rules out the anvil-only
    /// --mine/--no-pin.
    #[arg(long, env = "MODE", value_enum, default_value_t = Mode::Builder)]
    pub(crate) mode: Mode,

    /// Read the [[builder]] entries from this file instead of from --config. Builder mode
    /// only, and an override rather than an addition: the config file's own list is
    /// ignored entirely when this is given, so one list is in force, from one place.
    // An Option with the default applied in code, rather than clap's `default_value`, so an
    // explicitly configured path stays distinguishable from the fallback — clap cannot tell
    // a default it filled in from a value someone set, which would make validate_mode's
    // "ignored in node mode" note fire on every node-mode run.
    #[arg(long, env = "BUILDERS")]
    pub(crate) builders: Option<String>,

    /// Milliseconds between requotes of the current block's update (builder mode). A quote
    /// left idle for too long is evicted (~400ms in Titan's protocol), so keep this well
    /// under that; Titan's own guidance is a ~50ms cadence.
    #[arg(long, env = "REQUOTE_MS", default_value_t = 50)]
    pub(crate) requote_ms: u64,

    /// Serve Prometheus metrics at this address (e.g. 127.0.0.1:9464). Unset disables the
    /// exporter. Ignored under --check and --once, which are not long-running services.
    #[arg(long, env = "METRICS_ADDR")]
    pub(crate) metrics_addr: Option<SocketAddr>,

    /// Serve the backoffice API on this address: this host's tailnet address, say
    /// (100.64.1.2). The address half of [settings] backoffice_addr, which this overrides;
    /// with only --backoffice-port given, 127.0.0.1. Either flag alone turns the backoffice
    /// on. An unspecified address (0.0.0.0, ::) is refused: the API has no login, and that
    /// would bind every interface. Builder mode only
    #[arg(long, env = "BACKOFFICE_IP")]
    pub(crate) backoffice_ip: Option<IpAddr>,

    /// Serve the backoffice API on this port. The port half of [settings] backoffice_addr,
    /// which this overrides; with only --backoffice-ip given, 8088
    #[arg(long, env = "BACKOFFICE_PORT")]
    pub(crate) backoffice_port: Option<u16>,

    /// A name the backoffice is reached by, besides an IP address and localhost, which it
    /// always answers to: this host's tailnet name (the one its HTTPS certificate names), or a
    /// reverse proxy's. A request addressed to any other name is refused, which stops a site
    /// that points its own domain at this host (DNS rebinding). The name alone, with no scheme
    /// or port; repeat the flag, or comma-separate the variable, for more than one. Replaces
    /// [settings] backoffice_hosts. Not a front end's address: that is
    /// --backoffice-cors-origin
    #[arg(
        long = "backoffice-host",
        env = "BACKOFFICE_HOSTS",
        value_delimiter = ','
    )]
    pub(crate) backoffice_hosts: Vec<String>,

    /// Let a browser page served from this origin (scheme://host[:port], e.g.
    /// http://100.64.1.2:3000) call the backoffice API: it is answered with CORS headers
    /// and its changes are taken. Repeat the flag, or comma-separate the variable, for more
    /// than one. `*` is refused: the API has no login, so any site an operator's browser
    /// visits could then drive it. Without this only a page served under the API's own
    /// address, or a client that is not a browser, can make a change
    #[arg(
        long = "backoffice-cors-origin",
        env = "BACKOFFICE_CORS_ORIGINS",
        value_delimiter = ','
    )]
    pub(crate) backoffice_cors_origins: Vec<String>,

    /// Serve the backoffice API over HTTPS with this certificate: a PEM file holding the
    /// certificate and any intermediates, the server's own first (what `tailscale cert`
    /// writes as <name>.crt). Needs --backoffice-tls-key. Read again whenever it changes,
    /// so a renewal needs no restart. Without both, the backoffice is plain HTTP
    #[arg(long, env = "BACKOFFICE_TLS_CERT")]
    pub(crate) backoffice_tls_cert: Option<PathBuf>,

    /// The private key of --backoffice-tls-cert: one unencrypted PEM key, PKCS#8, SEC1
    /// (what `tailscale cert` writes as <name>.key) or PKCS#1
    #[arg(long, env = "BACKOFFICE_TLS_KEY")]
    pub(crate) backoffice_tls_key: Option<PathBuf>,

    /// Keep builder quote updates in the region they were submitted to
    #[arg(long, env = "DISABLE_CROSS_REGION", value_parser = FalseyValueParser::new())]
    pub(crate) disable_cross_region: bool,

    /// Record the Binance mid of every symbol and each pair's vault balances into this
    /// Postgres (e.g. postgresql://ponder:pass@127.0.0.1:5432/ponder), the indexer's
    /// database, for the P&L dashboard. Unset disables recording. Ignored under --check and
    /// --once. Flag or environment only, deliberately not a `[settings]` key: the URL
    /// carries a password, and the backoffice API shows `[settings]` to anyone who reaches
    /// it, so it belongs in `.env` beside the updater keys. See record.rs.
    #[arg(long, env = "RECORD_DB_URL")]
    pub(crate) record_db_url: Option<String>,

    /// How many days of recorded history to keep. Rows older than this are deleted from
    /// the tables that grow with time (feed.mids, feed.quotes, feed.vault_balances), once
    /// at startup and hourly after; the config history is never deleted. Unset keeps
    /// everything, and the database then grows for as long as the updater runs. Beside
    /// --record-db-url, and like it a flag or environment variable only.
    #[arg(long, env = "RECORD_RETENTION_DAYS")]
    #[arg(value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) record_retention_days: Option<u32>,
}

impl Flags {
    /// Where the backoffice is served, once [`apply_file_settings`] has filled in what the
    /// command line left to `[settings] backoffice_addr`: `None` when nothing asks for one,
    /// and a missing half defaulted when only the other was given.
    pub(crate) fn backoffice_addr(&self) -> Option<SocketAddr> {
        match (self.backoffice_ip, self.backoffice_port) {
            (None, None) => None,
            (ip, port) => Some(SocketAddr::new(
                ip.unwrap_or(DEFAULT_BACKOFFICE_IP),
                port.unwrap_or(DEFAULT_BACKOFFICE_PORT),
            )),
        }
    }

    /// The backoffice's certificate and key files, `None` when it is plain HTTP. One
    /// without the other is refused: half a TLS setup is a mistake, and serving plain HTTP
    /// over it would hide that.
    pub(crate) fn backoffice_tls(&self) -> Result<Option<(&std::path::Path, &std::path::Path)>> {
        match (&self.backoffice_tls_cert, &self.backoffice_tls_key) {
            (Some(cert), Some(key)) => Ok(Some((cert, key))),
            (None, None) => Ok(None),
            (Some(_), None) => bail!(
                "--backoffice-tls-cert is set without --backoffice-tls-key; HTTPS needs the \
                 certificate's private key too"
            ),
            (None, Some(_)) => bail!(
                "--backoffice-tls-key is set without --backoffice-tls-cert; HTTPS needs the \
                 certificate the key belongs to"
            ),
        }
    }
}

/// The argument ids a parse took from the command line or the environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Given(std::collections::BTreeSet<String>);

impl Given {
    /// Read off the matches: every id whose value came from the command line or a
    /// variable, rather than clap's default or nothing, which both mean the file may
    /// answer. A flattened parse's matches carry the binary's own ids as well; they are
    /// kept and never asked about.
    fn from_matches(matches: &clap::ArgMatches) -> Given {
        use clap::parser::ValueSource;
        Given(
            matches
                .ids()
                .filter(|id| {
                    matches!(
                        matches.value_source(id.as_str()),
                        Some(ValueSource::CommandLine | ValueSource::EnvVariable)
                    )
                })
                .map(|id| id.as_str().to_owned())
                .collect(),
        )
    }

    pub(crate) fn contains(&self, id: &str) -> bool {
        self.0.contains(id)
    }
}

/// Parse with [`Args::from_env`] or [`Args::try_parse_from`], or flatten `Args` into a
/// command line of your own. There is deliberately no `clap::Parser` impl: its `parse`
/// exits the process on `--help` or a usage error, and a library leaves that to the binary.
impl Args {
    /// This process's command line and environment, parsed. A variable that is set but
    /// empty reads as unset, so a `.env` that documents every knob by listing it blank
    /// falls through to the defaults. Returns clap's error (including `--help`, which is
    /// an "error" that prints the help) rather than exiting: the caller decides.
    pub fn from_env() -> Result<Args, clap::Error> {
        Self::try_parse_from(std::env::args_os())
    }

    /// [`Args::from_env`] over an explicit command line; the environment is still read
    /// for the `env = ...` bindings.
    pub fn try_parse_from<I, T>(args: I) -> Result<Args, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // `try_get_matches_from` rather than a derived parse: the matches say whether a
        // value was given or clap filled in its default, which `from_arg_matches` records.
        let matches = Self::command().try_get_matches_from(args)?;
        Self::from_arg_matches(&matches)
    }

    /// Whether the command line or the environment gave `id`, rather than clap's default
    /// or nothing, which both mean the file may answer.
    pub(crate) fn given(&self, id: &str) -> bool {
        self.given.contains(id)
    }

    /// The config file, as `--config` or `CONFIG` named it: for a binary that keeps a file
    /// of its own beside the updater's. The only setting read back, because it is the only
    /// one the file cannot change; every other flag may still be filled in from the file's
    /// `[settings]` when the run starts.
    pub fn config_path(&self) -> &std::path::Path {
        &self.flags.config
    }
}

impl FromArgMatches for Args {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        Ok(Args {
            flags: Flags::from_arg_matches(matches)?,
            given: Given::from_matches(matches),
        })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        self.flags.update_from_arg_matches(matches)?;
        // `given` follows what the update did to each value: a flag it wrote its default
        // over is no longer given, one it left alone (no default, not mentioned) still is,
        // and one it gave now is.
        use clap::parser::ValueSource;
        self.given
            .0
            .retain(|id| !matches!(matches.value_source(id), Some(ValueSource::DefaultValue)));
        self.given.0.extend(Given::from_matches(matches).0);
        Ok(())
    }
}

/// How a binary's own `Parser` mounts these flags: `#[command(flatten)]`.
impl clap::Args for Args {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        mounted(cmd, Flags::augment_args)
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        mounted(cmd, Flags::augment_args_for_update)
    }
}

impl CommandFactory for Args {
    fn command() -> clap::Command {
        ignore_blank_env(Flags::command(), blank_in_process_env)
    }

    fn command_for_update() -> clap::Command {
        ignore_blank_env(Flags::command_for_update(), blank_in_process_env)
    }
}

/// Whether the process has `name` set to nothing at all.
fn blank_in_process_env(name: &std::ffi::OsStr) -> bool {
    std::env::var_os(name).is_some_and(|value| value.is_empty())
}

/// Adds this crate's flags to a binary's `cmd` through `augment`, with two corrections to
/// what the derive does. The binary's description stays its own: clap gives a command that
/// states no `about` the flattened struct's doc comment, and ours describes the updater,
/// not the binary these flags are mounted in, so whatever `cmd` had (nothing included) is
/// put back. And every one of *our* variables that is set but blank loses its binding, the
/// way [`Args::command`] does for a parse of our own. Ours by variable name, not by flag:
/// the binary's flags keep whatever env semantics it chose, unless one binds the same
/// variable as ours, which then reads as unset for both, since it is one variable.
fn mounted(cmd: clap::Command, augment: fn(clap::Command) -> clap::Command) -> clap::Command {
    let theirs: std::collections::BTreeSet<clap::Id> = cmd
        .get_arguments()
        .map(|arg| arg.get_id().clone())
        .collect();
    let (about, long_about) = (cmd.get_about().cloned(), cmd.get_long_about().cloned());
    let cmd = augment(cmd)
        .about(clap::builder::Resettable::from(about))
        .long_about(clap::builder::Resettable::from(long_about));
    let ours: std::collections::BTreeSet<std::ffi::OsString> = cmd
        .get_arguments()
        .filter(|arg| !theirs.contains(arg.get_id()))
        .filter_map(|arg| arg.get_env().map(ToOwned::to_owned))
        .collect();
    ignore_blank_env(cmd, |name| {
        ours.contains(name) && blank_in_process_env(name)
    })
}

/// Drops the environment binding of every argument whose variable `is_blank` says is set
/// but empty. clap takes a present variable as an explicit value whatever it holds, so
/// `INTERVAL=` would reach the parser and fail there ("invalid digit found in string")
/// instead of defaulting. This used to remove the variables from the process environment,
/// which is undefined behaviour once any other thread exists; `Arg::env` reads the variable
/// when the command is built and `Arg::env(None)` resets the binding, so nothing outside
/// this command changes. The cost: `--help` omits `[env: X=]` for a variable that is set
/// but blank when it runs.
pub(crate) fn ignore_blank_env(
    command: clap::Command,
    is_blank: impl Fn(&std::ffi::OsStr) -> bool,
) -> clap::Command {
    command.mut_args(|arg| {
        let blank = arg.get_env().is_some_and(&is_blank);
        if blank { arg.env(None::<&str>) } else { arg }
    })
}

/// Fills in whatever the command line left alone from `[settings]`. Command line, then
/// file, then the built-in default: the local `make` targets drive everything from flags
/// against a file with no settings table, and the unit passes only `--config`.
/// `given` is a predicate rather than the `ArgMatches` so the precedence rules are testable
/// without the ambient environment leaking in through clap's `env` attributes.
pub(crate) fn apply_file_settings(
    args: &mut Args,
    given: &dyn Fn(&str) -> bool,
    settings: &config::FileSettings,
) -> Result<()> {
    if let Some(mode) = &settings.mode
        && !given("mode")
    {
        args.flags.mode = match mode.as_str() {
            "builder" => Mode::Builder,
            "node" => Mode::Node,
            other => bail!(
                "[settings] mode is {other:?}; the modes are \"builder\" (quote to the \
                 builders in [[builder]]) and \"node\" (send updateState over rpc_url)"
            ),
        };
    }
    if let Some(url) = &settings.rpc_url
        && !given("rpc_url")
    {
        args.flags.rpc_url = url.clone();
    }
    if let Some(url) = &settings.rpc_ws_url
        && !given("rpc_ws_url")
    {
        args.flags.rpc_ws_url = Some(url.clone());
    }
    if let Some(registry) = &settings.registry
        && !given("registry")
    {
        args.flags.registry = config::parse_address(registry).wrap_err("[settings] registry")?;
    }
    if let Some(decimals) = settings.price_decimals
        && !given("price_decimals")
    {
        // The check clap runs on --price-decimals, repeated because its parser cannot be
        // reached from here.
        crate::ensure_price_decimals(decimals, "[settings] price_decimals")?;
        args.flags.price_decimals = decimals;
    }
    if let Some(url) = &settings.binance_ws
        && !given("binance_ws")
    {
        args.flags.binance_ws = url.clone();
    }
    if let Some(interval) = settings.interval
        && !given("interval")
    {
        args.flags.interval = interval;
    }
    if let Some(requote_ms) = settings.requote_ms
        && !given("requote_ms")
    {
        args.flags.requote_ms = requote_ms;
    }
    if let Some(addr) = &settings.metrics_addr
        && !given("metrics_addr")
    {
        args.flags.metrics_addr = Some(
            addr.parse()
                .wrap_err_with(|| format!("[settings] metrics_addr {addr:?} is not host:port"))?,
        );
    }
    if let Some(disable) = settings.disable_cross_region
        && !given("disable_cross_region")
    {
        args.flags.disable_cross_region = disable;
    }
    // A list given on the command line replaces the file's, as every other setting does.
    if !settings.backoffice_hosts.is_empty() && !given("backoffice_hosts") {
        args.flags.backoffice_hosts = settings.backoffice_hosts.clone();
    }
    // Each half on its own, so `--backoffice-port` moves the port of an address the file
    // gives and keeps its IP.
    if let Some(addr) = &settings.backoffice_addr {
        let addr: SocketAddr = addr
            .parse()
            .wrap_err_with(|| format!("[settings] backoffice_addr {addr:?} is not host:port"))?;
        if !given("backoffice_ip") {
            args.flags.backoffice_ip = Some(addr.ip());
        }
        if !given("backoffice_port") {
            args.flags.backoffice_port = Some(addr.port());
        }
    }
    Ok(())
}

/// clap's parser for `--price-decimals`, which needs a `String` error. Delegates so the
/// one rule about the scale (and its message) is the one `[settings]` is held to.
fn parse_price_decimals(s: &str) -> Result<u32, String> {
    let decimals: u32 = s
        .parse()
        .map_err(|_| format!("{s:?} is not a number of decimal places"))?;
    crate::ensure_price_decimals(decimals, "--price-decimals")
        .map(|()| decimals)
        .map_err(|e| format!("{e:#}"))
}

/// clap's parser, which needs a `String` error. Delegates so the one address-parsing
/// rule (and its message) lives in `config`.
fn parse_address(s: &str) -> Result<Address, String> {
    config::parse_address(s).map_err(|e| format!("{e:#}"))
}

/// The removed variables that are still set to something non-empty.
pub(crate) fn removed_vars_present() -> Vec<&'static str> {
    REMOVED_VARS
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .collect()
}

/// Why a leftover variable is refused rather than ignored. A removed clap argument means
/// the variable is silently inert, and someone whose service starts and quotes with an
/// API key that is no longer read has no way to find out.
pub(crate) fn removed_vars_error(present: &[&str]) -> String {
    format!(
        "{} still set, but no longer read: the endpoint and key now live in the config \
         file as a [[builder]] entry (see config.example.toml). Move them there and unset \
         these, so nothing runs on an authentication that is not being used.",
        present.join(" and "),
    )
}

/// Every change the backoffice API makes is a reload, and the reload path belongs to the
/// `Service`, which node mode never builds. A backoffice there would serve an API whose
/// every change failed, so it is refused at startup rather than bound and left inert.
pub(crate) fn refuse_backoffice_in_node_mode(
    mode: Mode,
    backoffice_addr: Option<SocketAddr>,
) -> Result<()> {
    ensure!(
        mode != Mode::Node || backoffice_addr.is_none(),
        "a backoffice is configured (--backoffice-ip, --backoffice-port or [settings] \
         backoffice_addr), but --mode node has no config reload for it to drive: the \
         convergence it would trigger belongs to builder mode, which node mode does not run. \
         Drop it, or use --mode builder (see the mock-builder recipe in the README for a \
         local run)."
    );
    Ok(())
}

/// Refuses a pair config that arms a circuit breaker under `--mode node`.
///
/// Kept out of `validate_mode` because the setting is no longer a flag: it lives per pair
/// in the config, which is read after the mode is validated. Same intent, later moment.
///
/// The breaker's entire response to a trip is to withdraw the live quote, and node mode
/// has none to withdraw — it sends `updateState` straight to `--rpc-url`, and an update
/// that landed cannot be recalled. Accepting the key there would leave exactly the pairs
/// the operator took the most care over running with no protection at all, which for a
/// safety feature is the worst failure mode there is.
pub(crate) fn refuse_breakers_in_node_mode(mode: Mode, config: &config::Config) -> Result<()> {
    if mode != Mode::Node {
        return Ok(());
    }
    // Named by `key_env`, the way the duplicate-address refusal in `config` names pairs:
    // the on-chain `symbol()` labels come from preflight, which has not run yet.
    let armed: Vec<&str> = config
        .pairs
        .iter()
        .filter(|pair| pair.breaker.is_some())
        .map(|pair| pair.key_env.as_str())
        .collect();
    ensure!(
        armed.is_empty(),
        "max_deviation is builder-mode only, but {} sets it: node mode pushes updateState \
         straight to --rpc-url and has no live quote to withdraw, so those pairs would run \
         unprotected; drop the setting, or use --mode builder",
        armed.join(", ")
    );
    // A registered guard, for the same reason: it can only withdraw or halt, and node mode
    // has nothing to withdraw.
    let guarded: Vec<&str> = config
        .pairs
        .iter()
        .filter(|pair| !pair.guards.is_empty())
        .map(|pair| pair.key_env.as_str())
        .collect();
    ensure!(
        guarded.is_empty(),
        "[[pairs.guards]] is builder-mode only, but {} has one: node mode pushes updateState \
         straight to --rpc-url and has no live quote for a guard to withdraw; drop the \
         guards, or use --mode builder",
        guarded.join(", ")
    );
    Ok(())
}

/// Checks the mode against the options that only apply to the other one.
///
/// Checked on parsed values rather than through clap's `conflicts_with`, for the same
/// reason as the rest of `run`: clap counts anything that came from the environment as
/// explicitly present whatever it holds, so a .env documenting every knob (`MINE=false`)
/// would fail these relations on variables that are switched off.
pub(crate) fn validate_mode(
    mode: Mode,
    mine: bool,
    no_pin: bool,
    builders_set: bool,
) -> Result<()> {
    match mode {
        Mode::Builder => {
            ensure!(
                !mine && !no_pin,
                "--mine and --no-pin are anvil cheatcodes (anvil_mine, \
                 evm_setNextBlockTimestamp) and do nothing in builder mode, where each \
                 update is streamed to builders instead of sent to the RPC; drop them, or \
                 pass --mode node to submit transactions to --rpc-url"
            );
        }
        Mode::Node => {
            if builders_set {
                tracing::warn!(
                    "note: --builders (BUILDERS) is ignored with --mode node, which \
                     submits updateState transactions to --rpc-url"
                );
            }
        }
    }
    Ok(())
}

/// Whether to bind the metrics listener, and where.
///
/// A free function so the three "not here" cases have tests. `--check` is the important
/// one: `.env` is sourced for it as well, so an unconditional bind would make `--check`
/// fail with "address in use" whenever the service was already running — breaking the one
/// command an operator reaches for to diagnose it.
pub(crate) fn should_serve_metrics(
    addr: Option<SocketAddr>,
    check: bool,
    once: bool,
) -> Option<SocketAddr> {
    if check || once { None } else { addr }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_well_formed() {
        Args::command().debug_assert();
    }

    /// An `Args` with nothing but the required `--config`, i.e. every setting sitting on
    /// its clap default, which is the state `apply_file_settings` is meant to fill in.
    fn defaulted_args() -> Args {
        Args::try_parse_from(["quote-updater", "--config", "config.toml"]).expect("parses")
    }

    /// The file supplies whatever the command line left alone. This is what makes the
    /// systemd unit's bare `--config` a complete configuration.
    #[test]
    fn the_config_file_fills_in_settings_the_command_line_did_not_give() {
        let mut args = defaulted_args();
        let settings = config::FileSettings {
            mode: Some("node".to_owned()),
            rpc_url: Some("https://from-the-file.example".to_owned()),
            requote_ms: Some(25),
            interval: Some(3),
            metrics_addr: Some("127.0.0.1:9464".to_owned()),
            price_decimals: Some(18),
            disable_cross_region: Some(true),
            ..Default::default()
        };
        apply_file_settings(&mut args, &|_| false, &settings).unwrap();

        assert_eq!(args.flags.mode, Mode::Node);
        assert_eq!(args.flags.rpc_url, "https://from-the-file.example");
        assert_eq!(args.flags.requote_ms, 25);
        assert_eq!(args.flags.interval, 3);
        assert_eq!(args.flags.price_decimals, 18);
        assert!(args.flags.disable_cross_region);
        assert_eq!(
            args.flags.metrics_addr,
            Some("127.0.0.1:9464".parse::<SocketAddr>().unwrap())
        );
    }

    /// And does not touch what it did. The local `make` targets drive everything from
    /// flags against a file that may well carry a settings table meant for the server.
    #[test]
    fn a_setting_given_on_the_command_line_beats_the_file() {
        let mut args = defaulted_args();
        args.flags.requote_ms = 10;
        args.flags.mode = Mode::Node;
        let settings = config::FileSettings {
            mode: Some("builder".to_owned()),
            requote_ms: Some(25),
            ..Default::default()
        };
        apply_file_settings(&mut args, &|_| true, &settings).unwrap();
        assert_eq!(args.flags.requote_ms, 10);
        assert_eq!(args.flags.mode, Mode::Node);
    }

    /// A value the file can hold that the flag's parser would have refused must be refused
    /// here too, naming the key: the file is the only place these are set on a server.
    #[test]
    fn a_malformed_setting_is_rejected_by_name() {
        let cases: Vec<(&str, config::FileSettings, &str)> = vec![
            (
                "mode",
                config::FileSettings {
                    mode: Some("builders".to_owned()),
                    ..Default::default()
                },
                "mode",
            ),
            (
                "metrics_addr",
                config::FileSettings {
                    metrics_addr: Some("not-a-socket".to_owned()),
                    ..Default::default()
                },
                "metrics_addr",
            ),
            (
                "registry",
                config::FileSettings {
                    registry: Some("0xnothex".to_owned()),
                    ..Default::default()
                },
                "registry",
            ),
            (
                "price_decimals",
                config::FileSettings {
                    // Inside the old ceiling, and the dangerous side of 18: a mid a
                    // trillionth of the price.
                    price_decimals: Some(6),
                    ..Default::default()
                },
                "price_decimals is 6",
            ),
            (
                "backoffice_addr",
                config::FileSettings {
                    backoffice_addr: Some("tailnet:8088".to_owned()),
                    ..Default::default()
                },
                "backoffice_addr",
            ),
        ];
        for (case, settings, expected) in cases {
            let mut args = defaulted_args();
            let err = match apply_file_settings(&mut args, &|_| false, &settings) {
                Ok(()) => panic!("{case}: expected a rejection"),
                Err(err) => format!("{err:#}"),
            };
            assert!(err.contains(expected), "{case}: {err}");
        }
    }

    /// The backoffice's address, a half at a time: the file's `backoffice_addr` fills in
    /// whichever of `--backoffice-ip` and `--backoffice-port` the command line left alone,
    /// and a half nothing gives is defaulted when the other is given.
    #[test]
    fn the_backoffice_address_is_resolved_a_half_at_a_time() {
        let addr = |argv: &[&str], file: Option<&str>| {
            let mut full = vec!["quote-updater", "--config", "config.toml"];
            full.extend_from_slice(argv);
            let mut args = Args::try_parse_from(full).unwrap();
            let settings = config::FileSettings {
                backoffice_addr: file.map(str::to_owned),
                ..Default::default()
            };
            let given = args.given.clone();
            apply_file_settings(&mut args, &|id| given.contains(id), &settings).unwrap();
            args.flags.backoffice_addr().map(|addr| addr.to_string())
        };
        assert_eq!(addr(&[], None), None, "nothing asks for one");
        assert_eq!(
            addr(&[], Some("100.64.1.2:8088")).as_deref(),
            Some("100.64.1.2:8088")
        );
        assert_eq!(
            addr(&["--backoffice-port", "9000"], Some("100.64.1.2:8088")).as_deref(),
            Some("100.64.1.2:9000"),
            "the flag moves the port and keeps the file's address"
        );
        assert_eq!(
            addr(&["--backoffice-ip", "100.64.9.9"], Some("100.64.1.2:8088")).as_deref(),
            Some("100.64.9.9:8088")
        );
        assert_eq!(
            addr(&["--backoffice-port", "9000"], None).as_deref(),
            Some("127.0.0.1:9000"),
            "a port alone is this host alone"
        );
        assert_eq!(
            addr(&["--backoffice-ip", "100.64.9.9"], None).as_deref(),
            Some("100.64.9.9:8088")
        );
        assert_eq!(
            addr(&["--backoffice-ip", "::1", "--backoffice-port", "0"], None).as_deref(),
            Some("[::1]:0")
        );
    }

    /// The backoffice's names: the file's list unless the command line gives one, which
    /// replaces it rather than adding to it.
    #[test]
    fn backoffice_hosts_come_from_the_file_unless_given() {
        let hosts = |argv: &[&str]| {
            let mut full = vec!["quote-updater", "--config", "config.toml"];
            full.extend_from_slice(argv);
            let mut args = Args::try_parse_from(full).unwrap();
            let settings = config::FileSettings {
                backoffice_hosts: vec!["from-file.example".to_owned()],
                ..Default::default()
            };
            let given = args.given.clone();
            apply_file_settings(&mut args, &|id| given.contains(id), &settings).unwrap();
            args.flags.backoffice_hosts
        };
        assert_eq!(hosts(&[]), ["from-file.example"]);
        assert_eq!(
            hosts(&["--backoffice-host", "a.example,b.example"]),
            ["a.example", "b.example"]
        );
    }

    /// The CORS origins: the flag repeated, or one value split on commas, which is how the
    /// variable lists more than one.
    #[test]
    fn cors_origins_are_repeated_or_comma_separated() {
        let args = Args::try_parse_from([
            "quote-updater",
            "--config",
            "config.toml",
            "--backoffice-cors-origin",
            "http://a.example,http://b.example",
            "--backoffice-cors-origin",
            "http://c.example",
        ])
        .unwrap();
        assert_eq!(
            args.flags.backoffice_cors_origins,
            ["http://a.example", "http://b.example", "http://c.example"]
        );
        assert!(defaulted_args().flags.backoffice_cors_origins.is_empty());
    }

    /// The TLS files go together: both, or neither for plain HTTP.
    #[test]
    fn the_tls_certificate_and_key_go_together() {
        let tls = |argv: &[&str]| {
            let mut full = vec!["quote-updater", "--config", "config.toml"];
            full.extend_from_slice(argv);
            let args = Args::try_parse_from(full).unwrap();
            args.flags
                .backoffice_tls()
                .map(|files| files.map(|(c, k)| (c.to_owned(), k.to_owned())))
                .map_err(|err| format!("{err:#}"))
        };
        assert_eq!(tls(&[]), Ok(None));
        assert_eq!(
            tls(&[
                "--backoffice-tls-cert",
                "s.crt",
                "--backoffice-tls-key",
                "s.key"
            ]),
            Ok(Some((PathBuf::from("s.crt"), PathBuf::from("s.key"))))
        );
        let err = tls(&["--backoffice-tls-cert", "s.crt"]).unwrap_err();
        assert!(err.contains("--backoffice-tls-key"), "{err}");
        let err = tls(&["--backoffice-tls-key", "s.key"]).unwrap_err();
        assert!(err.contains("--backoffice-tls-cert"), "{err}");
    }

    /// A backoffice bound in a mode with no reload would serve an API whose every change
    /// failed. Refused at startup rather than discovered at the moment it was needed.
    #[test]
    fn a_backoffice_in_node_mode_is_refused() {
        let addr: SocketAddr = "100.64.1.2:8088".parse().unwrap();
        refuse_backoffice_in_node_mode(Mode::Node, None).expect("node mode without one is fine");
        refuse_backoffice_in_node_mode(Mode::Builder, Some(addr))
            .expect("builder mode is what it is for");

        let err = format!(
            "{:#}",
            refuse_backoffice_in_node_mode(Mode::Node, Some(addr)).unwrap_err()
        );
        assert!(err.contains("backoffice_addr"), "{err}");
        assert!(err.contains("--mode builder"), "{err}");
    }

    /// A .env is only a complete configuration if nothing is flag-only, so a new argument
    /// added without an `env = ...` fails here rather than silently becoming unreachable
    /// from the file. It would also be invisible to `ignore_blank_env`, which reads the bindings.
    #[test]
    fn every_argument_reads_from_the_environment() {
        let command = Args::command();
        let flag_only: Vec<_> = command
            .get_arguments()
            .filter(|arg| arg.get_env().is_none() && arg.get_id() != "help")
            .map(|arg| arg.get_id().as_str())
            .collect();
        assert!(
            flag_only.is_empty(),
            "arguments with no env var: {flag_only:?}"
        );

        let mut names: Vec<_> = command
            .get_arguments()
            .filter_map(|arg| arg.get_env())
            .collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total, "two arguments share an env var");
    }

    #[test]
    fn parse_address_accepts_prefixed_hex() {
        assert_eq!(
            parse_address(MAINNET_REGISTRY).unwrap(),
            Address::from_slice(&hex::decode("Da7AfEeD021EAFC1c1Af9C362dE477DaD0396B81").unwrap())
        );
        assert!(parse_address("0x123").is_err());
    }

    /// The scale is not a choice: PropAMM reads 1e18, and a flag naming anything else used
    /// to be taken and every pair published a power of ten off.
    #[test]
    fn the_price_decimals_flag_takes_18_and_nothing_else() {
        assert_eq!(parse_price_decimals("18"), Ok(18));
        for wrong in ["0", "6", "17", "19", "38", "59"] {
            let err = parse_price_decimals(wrong).unwrap_err();
            assert!(err.contains("1e18"), "{wrong}: {err}");
        }
        assert!(parse_price_decimals("eighteen").is_err());
        // Through clap: the default stands, 18 said aloud is fine, anything else is refused
        // before the config is even read.
        let with = |decimals: &str| {
            Args::try_parse_from([
                "quote-updater",
                "--config",
                "config.toml",
                "--price-decimals",
                decimals,
            ])
        };
        assert_eq!(defaulted_args().flags.price_decimals, 18);
        assert_eq!(with("18").expect("parses").flags.price_decimals, 18);
        assert!(with("6").is_err());
    }

    /// The removed variables must not silently become inert: someone whose service starts
    /// quoting with an API key that is no longer read has no way to tell.
    #[test]
    fn the_removed_variable_error_names_what_is_still_set() {
        let both = removed_vars_error(&["TITAN_WS", "TITAN_API_KEY"]);
        assert!(
            both.contains("TITAN_WS") && both.contains("TITAN_API_KEY"),
            "{both}"
        );
        assert!(both.contains("[[builder]]"), "{both}");
        assert!(both.contains("config.example.toml"), "{both}");
        let one = removed_vars_error(&["TITAN_API_KEY"]);
        assert!(
            one.contains("TITAN_API_KEY") && !one.contains("TITAN_WS"),
            "{one}"
        );
    }

    /// The anvil cheatcodes have no meaning when the update is streamed to builders
    /// instead of sent to an RPC.
    #[test]
    fn builder_mode_rejects_the_anvil_only_flags() {
        for (mine, no_pin) in [(true, false), (false, true), (true, true)] {
            let err = validate_mode(Mode::Builder, mine, no_pin, false)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("--mode node"),
                "must point at the way out: {err}"
            );
        }
        // Node mode is exactly where they belong, and builder mode without them is fine.
        assert!(validate_mode(Mode::Node, true, true, false).is_ok());
        assert!(validate_mode(Mode::Builder, false, false, true).is_ok());
    }

    #[test]
    fn mode_parses_its_two_values_and_nothing_else() {
        use clap::ValueEnum;
        assert_eq!(Mode::from_str("builder", false).unwrap(), Mode::Builder);
        assert_eq!(Mode::from_str("node", false).unwrap(), Mode::Node);
        // Nothing is named after a builder any more, least of all a mode.
        assert!(Mode::from_str("titan", false).is_err());
    }

    #[test]
    /// A guard stanza is refused in node mode the way `max_deviation` is, for the same
    /// reason: nothing there can withdraw a landed update.
    fn node_mode_refuses_a_pair_with_guards() {
        const TARGET: &str = "0x1234567890123456789012345678901234567890";
        const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let guarded = format!(
            "target = \"{TARGET}\"\n\n\
             [[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"USDCUSDT\"\n\
             key_env = \"K_USDC\"\npricing = {{ kind = \"feed\" }}\n[[pairs.guards]]\nkind = \"cap\"\n"
        );
        let config = config::parse_config(&guarded, 18).expect("config must parse");
        let err = refuse_breakers_in_node_mode(Mode::Node, &config)
            .unwrap_err()
            .to_string();
        assert!(err.contains("K_USDC") && err.contains("guards"), "{err}");
        refuse_breakers_in_node_mode(Mode::Builder, &config).expect("builder mode runs them");
    }

    #[test]
    fn node_mode_refuses_a_pair_that_arms_the_breaker() {
        const TARGET: &str = "0x1234567890123456789012345678901234567890";
        const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        const WBTC: &str = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";

        let armed = format!(
            "target = \"{TARGET}\"\n\n\
             [[pairs]]\ntokens = [\"{WBTC}\", \"{USDC}\"]\nsymbol = \"BTCUSDC\"\n\
             key_env = \"K_WBTC\"\npricing = {{ kind = \"feed\" }}\n\n\
             [[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"USDCUSDT\"\n\
             key_env = \"K_USDC\"\nmax_deviation = \"0.002\"\npricing = {{ kind = \"feed\" }}\n"
        );
        let config = config::parse_config(&armed, 18).expect("config must parse");

        let err = refuse_breakers_in_node_mode(Mode::Node, &config)
            .unwrap_err()
            .to_string();
        // Names the pair to edit and the way out, not just the rule.
        assert!(err.contains("K_USDC"), "must name the pair: {err}");
        assert!(
            !err.contains("K_WBTC"),
            "must not blame an unarmed pair: {err}"
        );
        assert!(
            err.contains("--mode builder"),
            "must offer the way out: {err}"
        );

        // Builder mode is exactly where it belongs.
        assert!(refuse_breakers_in_node_mode(Mode::Builder, &config).is_ok());
        // And node mode is fine as long as no pair arms one.
        let unarmed = format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\n\
             symbol = \"USDCUSDT\"\nkey_env = \"K_USDC\"\npricing = {{ kind = \"feed\" }}\n"
        );
        let unarmed = config::parse_config(&unarmed, 18).expect("config must parse");
        assert!(refuse_breakers_in_node_mode(Mode::Node, &unarmed).is_ok());
    }

    #[test]
    fn metrics_serve_only_on_a_long_running_service_run() {
        let addr: std::net::SocketAddr = "127.0.0.1:9464".parse().unwrap();
        assert_eq!(should_serve_metrics(Some(addr), false, false), Some(addr));
    }

    #[test]
    fn metrics_are_off_when_no_address_is_given() {
        assert_eq!(should_serve_metrics(None, false, false), None);
    }

    #[test]
    fn check_does_not_bind_even_with_an_address_set() {
        // `.env` is sourced for --check too. Binding here would make --check fail with
        // "address in use" whenever the service was up, breaking the diagnostic path outright.
        let addr: std::net::SocketAddr = "127.0.0.1:9464".parse().unwrap();
        assert_eq!(should_serve_metrics(Some(addr), true, false), None);
    }

    #[test]
    fn once_does_not_bind() {
        // A batch invocation with a script waiting on it: a scrape endpoint that lives for one
        // block is never scraped, and binding costs the run a port conflict for nothing.
        let addr: std::net::SocketAddr = "127.0.0.1:9464".parse().unwrap();
        assert_eq!(should_serve_metrics(Some(addr), false, true), None);
    }

    /// A blank variable must read as unset without the environment being touched: the
    /// binding is dropped from the command instead, so this needs no `unsafe` and no
    /// single-thread precondition.
    #[test]
    fn a_blank_variable_loses_its_binding_and_nothing_else_does() {
        let command = ignore_blank_env(Args::command(), |name| name == "INTERVAL");
        let interval = command
            .get_arguments()
            .find(|arg| arg.get_id() == "interval")
            .expect("interval is an argument");
        assert_eq!(
            interval.get_env(),
            None,
            "a blank variable's binding is dropped"
        );
        let config = command
            .get_arguments()
            .find(|arg| arg.get_id() == "config")
            .expect("config is an argument");
        assert_eq!(config.get_env(), Some(std::ffi::OsStr::new("CONFIG")));
    }

    /// Parsing returns clap's error instead of exiting, so a library caller decides what
    /// an unknown flag means for its own process.
    #[test]
    fn a_parse_error_is_returned_not_exited() {
        let err = Args::try_parse_from(["quote-updater", "--config", "c.toml", "--no-such-flag"])
            .err()
            .expect("an unknown flag is an error");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        let help = Args::try_parse_from(["quote-updater", "--help"])
            .err()
            .expect("help");
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// What the command line gave is remembered on `Args` itself, so precedence (flag > env
    /// > [settings] > default) no longer needs clap's matches carried beside it.
    #[test]
    fn args_remember_what_the_command_line_gave() {
        let args = Args::try_parse_from(["quote-updater", "--config", "c.toml", "--interval", "5"])
            .expect("parses");
        assert!(args.given("interval"));
        assert!(args.given("config"));
        assert!(!args.given("requote_ms"));
    }

    /// Flattened into a binary's own command line and parsed by that binary's `Parser`,
    /// the flags still record what was given: precedence cannot depend on which parse
    /// path a binary took, because `[settings]` would otherwise override its flags. The
    /// binary's own about and flags are untouched by the mounting.
    #[test]
    fn flattened_into_another_command_line_the_flags_still_know_what_was_given() {
        #[derive(Parser)]
        #[command(name = "strategy", about = "the binary's own about")]
        struct Cli {
            #[command(flatten)]
            updater: Args,
            #[arg(long, env = "STRATEGY")]
            strategy: String,
        }
        let cli = Cli::try_parse_from([
            "strategy",
            "--config",
            "c.toml",
            "--interval",
            "5",
            "--rpc-ws-url",
            "ws://first",
            "--strategy",
            "carry",
        ])
        .expect("parses");
        assert!(cli.updater.given("interval"));
        assert!(cli.updater.given("config"));
        assert!(!cli.updater.given("requote_ms"));
        assert_eq!(cli.strategy, "carry");
        let command = Cli::command();
        command.clone().debug_assert();
        assert_eq!(
            command.get_about().map(ToString::to_string).as_deref(),
            Some("the binary's own about")
        );
        let strategy = command
            .get_arguments()
            .find(|arg| arg.get_id() == "strategy")
            .expect("the binary's flag is there");
        assert_eq!(strategy.get_env(), Some(std::ffi::OsStr::new("STRATEGY")));

        // A parent that states no about of its own gets none from the flags either: the
        // updater's description must not become a binary's.
        #[derive(Parser)]
        struct Bare {
            #[command(flatten)]
            updater: Args,
        }
        assert!(Bare::command().get_about().is_none());

        // An update layers a second command line over the first, and `given` follows what
        // clap did to each value: a flag with a default goes back to it (no longer given),
        // one without keeps the first parse's value (still given), and the update's own
        // flags are given.
        let mut cli = cli;
        cli.update_from(["strategy", "--requote-ms", "10"]);
        assert_eq!(cli.updater.flags.interval, 12);
        assert!(!cli.updater.given("interval"));
        assert_eq!(cli.updater.flags.rpc_ws_url.as_deref(), Some("ws://first"));
        assert!(cli.updater.given("rpc_ws_url"));
        assert_eq!(cli.updater.flags.requote_ms, 10);
        assert!(cli.updater.given("requote_ms"));
    }
}

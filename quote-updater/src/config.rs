//! Pusher configuration, from two TOML files: the pair config (`pairs.toml`), parsed
//! into the lanes, price sources and updater keys the pusher quotes, and — in builder
//! mode — the builder config (`builders.toml`), the maker endpoints every update is
//! streamed to. The pair config holds no secrets (a pair names the environment variable
//! carrying its key, and resolution happens separately; see `resolve_keys`); the builder
//! config holds live API keys and is gitignored.

use std::{collections::HashSet, fs, path::Path, time::Duration};

use ethrex_common::{Address, U256, utils::keccak};
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use eyre::{Result, WrapErr, bail, ensure, eyre};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    breaker::{BreakerConfig, WindowConfig, percent},
    feed::{format_scaled, parse_decimal_scaled, reciprocal_scaled},
    venue::VenueId,
    volatile::{RawKnobs, VolatileParams},
};

/// Squaring the price scale during inversion must fit a uint256: 10^(2d) < 2^256.
const MAX_INVERTED_PRICE_DECIMALS: u32 = 38;

/// The largest window a pair may configure, in blocks — a day at `BLOCK_TIME_SECS`.
///
/// Not a memory limit so much as a typo limit: the buffer is one bucket a second, so even
/// this ceiling is single-digit megabytes. What it catches is an extra digit, which would
/// otherwise arm a guard measuring over days and looking like it measured over hours.
pub const MAX_BREAKER_WINDOW_BLOCKS: u64 = 7200;

/// The config file as written on disk. `Serialize` too, because the backoffice edits it by
/// reading it into this and writing it back: one type for both directions, so a field the
/// writer forgot fails to compile rather than vanishing from someone's config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub target: String,
    /// Read by `parse_file_settings`, not here: `price_decimals` is one of these and the
    /// pairs cannot be parsed until it is known. Declared so `deny_unknown_fields` accepts
    /// the table.
    #[serde(default, skip_serializing_if = "FileSettings::is_empty")]
    pub settings: FileSettings,
    pub pairs: Vec<RawPair>,
    /// The builders to quote, previously their own `builders.toml`. Empty is allowed here
    /// and rejected later, but only in builder mode: node mode quotes to nobody.
    #[serde(default, rename = "builder", skip_serializing_if = "Vec::is_empty")]
    pub builders: Vec<BuilderConfig>,
}

/// Everything that used to be an environment variable and is not a key. Each mirrors a CLI
/// flag, and a flag or variable that was actually given wins over the file.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileSettings {
    /// `builder` or `node`; see `--mode`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_ws_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_decimals: Option<u32>,
    /// The Binance endpoint; the older spelling of `endpoints.binance`, kept because
    /// existing files and the `--binance-ws` flag use it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binance_ws: Option<String>,
    /// Per-venue endpoint overrides, `[settings.endpoints]`, keyed by venue name: for a
    /// mock, or a regional endpoint such as binance.us. Unlisted venues use their default.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub endpoints: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requote_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cross_region: Option<bool>,
    /// Where the backoffice listens, e.g. `100.x.y.z:8088`. Unset disables it, which is the
    /// default: a service that listens on nothing is the one that cannot be reached wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoffice_addr: Option<String>,
}

impl FileSettings {
    /// So the writer can leave the table out rather than emit an empty `[settings]` header.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The keys that differ, so a refused reload can name the one that changed.
    pub fn changed_keys(&self, other: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        let mut check = |name, differs| {
            if differs {
                changed.push(name);
            }
        };
        check("mode", self.mode != other.mode);
        check("rpc_url", self.rpc_url != other.rpc_url);
        check("rpc_ws_url", self.rpc_ws_url != other.rpc_ws_url);
        check("registry", self.registry != other.registry);
        check(
            "price_decimals",
            self.price_decimals != other.price_decimals,
        );
        check("binance_ws", self.binance_ws != other.binance_ws);
        check("endpoints", self.endpoints != other.endpoints);
        check("interval", self.interval != other.interval);
        check("requote_ms", self.requote_ms != other.requote_ms);
        check("metrics_addr", self.metrics_addr != other.metrics_addr);
        check(
            "disable_cross_region",
            self.disable_cross_region != other.disable_cross_region,
        );
        check(
            "backoffice_addr",
            self.backoffice_addr != other.backoffice_addr,
        );
        changed
    }
}

/// A serde round-trip cannot keep comments, so a rewritten file says where they went.
fn written_header() -> String {
    format!(
        "\
# The pusher's configuration. Rewritten in full whenever the backoffice changes it, which
# is why it carries no comments: see quote-updater/config.example.toml for what every key
# means. Editing it by hand is fine ({} applies the
# [[pairs]]), but the next backoffice write reformats whatever you leave here.
#
# It holds the builder API keys, so it stays mode 0600.
",
        crate::hints::reload_in_prose()
    )
}

/// Reads the file exactly as written, for a caller that is about to change one entry.
pub fn load_raw(path: &Path) -> Result<RawConfig> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read config {}", path.display()))?;
    toml::from_str(&text).wrap_err_with(|| format!("invalid config {}", path.display()))
}

/// Renders a config back to TOML, header and all.
pub fn render_raw(config: &RawConfig) -> Result<String> {
    let body = toml::to_string_pretty(config).wrap_err("failed to render the config as TOML")?;
    Ok(format!("{}\n{body}", written_header()))
}

/// Write-then-rename into the same directory, so a reload racing this sees the whole old
/// file or the whole new one. 0600 throughout: it holds the builder API keys.
pub fn write_raw_atomically(path: &Path, config: &RawConfig) -> Result<()> {
    let rendered = render_raw(config)?;

    // A round-trip failure here would leave a file the loader cannot read. Cheap to catch
    // now, expensive at the next reload.
    parse_file_settings(&rendered).wrap_err("the rendered config does not parse back")?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config.toml".to_owned())
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options
            .open(&tmp)
            .wrap_err_with(|| format!("failed to open {}", tmp.display()))?;
        file.write_all(rendered.as_bytes())
            .wrap_err_with(|| format!("failed to write {}", tmp.display()))?;
        // Before the rename: otherwise a crash could leave an empty file at the real path.
        file.sync_all()
            .wrap_err_with(|| format!("failed to flush {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).wrap_err_with(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .wrap_err_with(|| format!("failed to chmod 600 {}", path.display()))?;
    }
    Ok(())
}

/// Reads just the `[settings]` table. Separate from `parse_config` because
/// `price_decimals` is one of these and every pair is parsed at that scale.
pub fn parse_file_settings(toml_text: &str) -> Result<FileSettings> {
    #[derive(Deserialize, Default)]
    struct Probe {
        #[serde(default)]
        settings: FileSettings,
    }
    let probe: Probe = toml::from_str(toml_text).wrap_err("could not parse TOML")?;
    Ok(probe.settings)
}

/// Same, from a path, so a caller reading the file for its settings reports a missing or
/// unreadable file the way `load_config` does.
pub fn load_file_settings(path: &Path) -> Result<FileSettings> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read config {}", path.display()))?;
    parse_file_settings(&text).wrap_err_with(|| format!("invalid config {}", path.display()))
}

/// One `[[pairs]]` stanza, as written. See `RawConfig` for why this is serializable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawPair {
    pub tokens: Vec<String>,
    pub key_env: String,
    /// One Binance market, weight 1. The short form of a single-entry `sources`; the two
    /// keys are exclusive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// The venues this pair's mid is averaged over. See [`Feeds`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<RawSource>,
    /// How many of `sources` must have a fresh price for the pair to publish. Default 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_sources: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_deviation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_deviation_window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_deviation_window_blocks: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_symbol_mismatch: bool,
    /// Kept in the file with all its settings but not quoting: the pusher treats a halted
    /// pair as if it were absent, so halting it withdraws its quote at every builder the way
    /// removing it would. It stays halted across reloads and restarts until the flag is
    /// cleared. Parsed and validated like any other pair, so resuming one cannot surprise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub halted: bool,
    /// Why, when a binary's `UpdaterHandle::halt` set the flag: the backoffice shows it and
    /// the reload logs it when it stops the lane. Cleared with the flag by a resume. The
    /// quoting never acts on it; the backoffice does, once: its "Restart halted pairs"
    /// leaves a halt with a reason for that pair's own Resume, so a kill switch outlives
    /// the button. One written by hand beside `halted = true` makes that halt as sticky.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_reason: Option<String>,
    // Volatile pricing (see `volatile.rs`). Setting any of the first three puts the pair on
    // the computed spread; the other four then have defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gamma: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kappa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_share: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_secs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_delay_secs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volatility_window_secs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_aversion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_band_lower: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_band_upper: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_aversion_hard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_band_hard_lower: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_band_hard_upper: Option<String>,
    /// A custom pricer's stanza: `kind` names a pricer the binary registered, and the rest
    /// is that kind's own config. Kept as the table it was written as, so the backoffice's
    /// round-trip preserves a stanza it cannot interpret, and reload compares it as written.
    /// Excludes every built-in model's key (mid, delta, gamma, ...). Last, and a table, so
    /// the serializer writes it after the pair's plain keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<toml::Table>,
    /// The pair's registered guards, `[[pairs.guards]]` stanzas in file order: each names a
    /// `kind` the binary registered and carries that kind's own config. Kept as written for
    /// the same reasons `pricing` is. An array of tables, so last of all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<toml::Table>,
}

/// One entry of a pair's `sources`, as written.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawSource {
    pub venue: String,
    pub symbol: String,
    /// A positive decimal; blank is 1. Relative to the other entries' weights, so `2` and
    /// `1` mean the same as `0.667` and `0.333`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<String>,
}

/// Weights are relative, so their scale cancels out of the average; six decimals is more
/// resolution than anyone tunes a weight to, and keeps `weight × mid` far inside a uint256
/// at 18 price decimals.
pub const WEIGHT_DECIMALS: u32 = 6;

/// The largest weight a source may carry. Relative weights never need more than this
/// range, and without a ceiling a weight like 1e70 parses, overflows `weight × mid` on
/// every tick, and the pair silently never publishes.
pub const MAX_WEIGHT: u64 = 1_000_000;

/// One venue's market that a pair's mid is read from, with its share of the average.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub venue: VenueId,
    pub symbol: String,
    /// Scaled by 10^[`WEIGHT_DECIMALS`].
    pub weight: U256,
}

/// Where a streamed pair's mid comes from: one or more venues, averaged by weight over the
/// ones with a fresh price, published only while at least `min_sources` of them have one.
///
/// A single Binance source with weight 1 is exactly what a `symbol` pair was before
/// `sources` existed, and is what the `symbol` key still means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feeds {
    pub sources: Vec<Source>,
    pub min_sources: usize,
}

impl Feeds {
    /// What a `symbol = "..."` stanza means: one Binance market, weight 1.
    pub fn single_binance(symbol: &str) -> Self {
        Self {
            sources: vec![Source {
                venue: VenueId::Binance,
                symbol: symbol.to_owned(),
                weight: U256::exp10(WEIGHT_DECIMALS as usize),
            }],
            min_sources: 1,
        }
    }

    /// The one-line description the report and the backoffice print: `binance:ETHUSDC`, or
    /// `binance:ETHUSDC ×2 + coinbase:ETH-USD ×1` when there is more than one.
    pub fn describe(&self) -> String {
        if let [only] = self.sources.as_slice() {
            return format!("{}:{}", only.venue, only.symbol);
        }
        let parts: Vec<String> = self
            .sources
            .iter()
            .map(|s| {
                format!(
                    "{}:{} ×{}",
                    s.venue,
                    s.symbol,
                    format_scaled(s.weight, WEIGHT_DECIMALS)
                )
            })
            .collect();
        let mut text = parts.join(" + ");
        if self.min_sources > 1 {
            text.push_str(&format!(" (min {})", self.min_sources));
        }
        text
    }

    /// What identifies the market these sources describe, weights aside: the key a
    /// volatile pair's σ history is shared under, so two pairs (or two generations of one)
    /// reading the same venues pool their samples. Order-independent and case-insensitive
    /// in the symbol, the way venues themselves are.
    pub fn history_key(&self) -> String {
        let mut keys: Vec<String> = self
            .sources
            .iter()
            .map(|s| format!("{}:{}", s.venue, s.symbol.to_uppercase()))
            .collect();
        keys.sort();
        keys.join("+")
    }
}

/// Bounds a pair's published mid must fall inside: the guard against a feed that has gone
/// wrong, or an orientation that came out backwards. A mid outside the band is refused
/// rather than published, which withdraws the quote instead of letting fills be priced
/// from a number nobody vouched for.
///
/// Per pair rather than per process, because the magnitudes are not comparable: one band
/// covering both ETHUSDC (~4000) and USDCUSDT (~1) would have to be so wide it bounds
/// nothing. Declared in **lane** orientation — the number the lane publishes, which is what
/// `--check`'s mid column prints — so the band can be read straight off that report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MidBand {
    pub min: Option<U256>,
    pub max: Option<U256>,
}

impl MidBand {
    /// Whether this band constrains anything at all, for the warning a pair with no bounds
    /// earns: nothing being set is the default, and silence would make it invisible.
    pub fn is_unset(&self) -> bool {
        self.min.is_none() && self.max.is_none()
    }

    pub fn check(&self, mid: U256) -> Result<(), crate::update::Unusable> {
        use crate::update::{Unusable, UnusableKind};
        if let Some(min) = self.min
            && mid < min
        {
            return Err(Unusable::new(
                UnusableKind::OutOfBand,
                format!("mid {mid} is below this pair's min_mid {min}; refusing to publish it"),
            ));
        }
        if let Some(max) = self.max
            && mid > max
        {
            return Err(Unusable::new(
                UnusableKind::OutOfBand,
                format!("mid {mid} is above this pair's max_mid {max}; refusing to publish it"),
            ));
        }
        Ok(())
    }
}

/// Where a pair's `[delta, mid]` comes from, with orientation already resolved: a
/// `Static` mid is the value the lane publishes, and a `Feed` is inverted on arrival
/// using the pair's `invert` (see `quote_from_ticker`). Both are declared in market
/// orientation; neither carries it any further than this module.
#[derive(Clone, Debug, PartialEq)]
pub enum SourceSpec {
    Feed {
        feeds: Feeds,
        /// The half-spread to publish. `None` publishes the book's own
        /// `(ask - bid) / (ask + bid)`, which is the default and is only allowed for a
        /// single source: there is one book to copy.
        delta: Option<U256>,
    },
    Static {
        delta: U256,
        mid: U256,
    },
    /// A feed whose spread is computed every tick from the recent volatility and the
    /// vault's inventory, and whose mid is shifted by the inventory tilt. See `volatile.rs`.
    Volatile {
        feeds: Feeds,
        params: VolatileParams,
    },
    /// A pricer registered by the binary (`Updater::builder().pricer(...)`), named by the
    /// pair's `[pairs.pricing] kind`. `config` is the stanza as written, `kind` included:
    /// `kinds::Kinds` deserializes it into the kind's own type, and reload compares it as
    /// written. `feeds` is the pair's reference market, if it sets `symbol` or `sources`.
    Custom {
        kind: String,
        config: toml::Table,
        feeds: Option<Feeds>,
    },
}

impl SourceSpec {
    /// The venues this pair streams from, if it streams.
    pub fn feeds(&self) -> Option<&Feeds> {
        match self {
            SourceSpec::Feed { feeds, .. } | SourceSpec::Volatile { feeds, .. } => Some(feeds),
            SourceSpec::Custom { feeds, .. } => feeds.as_ref(),
            SourceSpec::Static { .. } => None,
        }
    }

    /// The half-spread to publish for a feed sample: this pair's own `delta` when it
    /// states one, otherwise the book's.
    ///
    /// Resolved here rather than at each call site so the service path and `--check`
    /// cannot disagree about what a pair would publish - a `--check` that prints a spread
    /// the run does not charge is worse than no report at all.
    ///
    /// `spread_scale` is one whole unit at the price scale in use. A book-derived spread
    /// is refused at or above it: PropAMM subtracts the spread as a fraction of the mid,
    /// so a whole unit leaves the taker nothing and anything beyond reverts
    /// `SpreadTooWide`. A book that gapes that wide is not one to quote against anyway,
    /// and refusing routes it through the same unusable-price path a stale feed takes:
    /// node mode skips the push, builder mode withdraws the live quote, rather than every
    /// taker reverting. A configured `delta` needs no check here, having been bounded at
    /// parse time.
    pub fn published_delta(&self, feed_delta: U256, spread_scale: U256) -> Result<U256> {
        match self {
            SourceSpec::Feed {
                delta: Some(delta), ..
            } => Ok(*delta),
            SourceSpec::Feed { delta: None, .. } => {
                ensure!(
                    feed_delta < spread_scale,
                    "the book's half-spread {feed_delta} is not below one whole unit \
                     ({spread_scale}); refusing to publish a spread that leaves the taker \
                     nothing"
                );
                Ok(feed_delta)
            }
            // A static pair publishes the delta it declared, whatever it is handed.
            SourceSpec::Static { delta, .. } => Ok(*delta),
            // Needs σ and the vault balance as well as the sample; `VolatilePricer` computes
            // it, and `--check` prints it from there.
            SourceSpec::Volatile { .. } => {
                eyre::bail!("a volatile pair's delta is computed per tick, not taken from the feed")
            }
            SourceSpec::Custom { .. } => eyre::bail!("a custom pair's delta comes from its pricer"),
        }
    }
}

/// One `[[pairs.guards]]` stanza: the registered kind it names, and the stanza as written
/// (`kind` included), which `kinds::Kinds` deserializes into the kind's own config and a
/// reload compares as text.
#[derive(Clone, Debug, PartialEq)]
pub struct GuardStanza {
    pub kind: String,
    pub config: toml::Table,
}

/// The pair's `[[pairs.guards]]` stanzas, checked for shape: each has a string `kind`
/// that is not the deviation guard's (that one is configured with `max_deviation`, so a
/// reserved name never reads as an unknown kind) and no kind appears twice on one pair.
/// Whether a kind is registered is the binary's to say, once `Kinds` sees the file.
fn parse_guards(raw: &RawPair, at: &str) -> Result<Vec<GuardStanza>> {
    let mut guards: Vec<GuardStanza> = Vec::with_capacity(raw.guards.len());
    for table in &raw.guards {
        let kind = match table.get("kind") {
            Some(toml::Value::String(kind)) => kind.clone(),
            Some(other) => eyre::bail!(
                "{at}: [[pairs.guards]] kind must be a string, not {}",
                other.type_str()
            ),
            None => eyre::bail!(
                "{at}: a [[pairs.guards]] stanza needs kind = \"...\", the name the binary \
                 registered its guard under"
            ),
        };
        ensure!(
            kind != "deviation",
            "{at}: the deviation guard is configured with max_deviation (and \
             max_deviation_window), not a [[pairs.guards]] stanza"
        );
        ensure!(
            !guards.iter().any(|g| g.kind == kind),
            "{at}: guard kind `{kind}` is listed twice; one stanza per kind per pair"
        );
        guards.push(GuardStanza {
            kind,
            config: table.clone(),
        });
    }
    Ok(guards)
}

/// One whole unit at `price_decimals`, the 100% mark a published spread must stay below.
pub fn spread_scale(price_decimals: u32) -> U256 {
    U256::exp10(price_decimals as usize)
}

/// Builds one pair's venue list, or `None` when it streams from nothing (a static pair).
///
/// `symbol` is the short form of one Binance source and the two keys are exclusive, so a
/// stanza cannot say two different things about where its price comes from.
fn parse_feeds(raw: &RawPair, at: &str) -> Result<Option<Feeds>> {
    let mut sources = Vec::with_capacity(raw.sources.len() + 1);
    match (&raw.symbol, raw.sources.is_empty()) {
        (Some(_), false) => bail!(
            "{at}: set symbol or sources, not both; symbol is the short form of one binance \
             source"
        ),
        (Some(symbol), true) => {
            ensure!(
                raw.min_sources.is_none(),
                "{at}: min_sources needs sources to count"
            );
            return Ok(Some(Feeds::single_binance(symbol)));
        }
        (None, true) => {
            ensure!(
                raw.min_sources.is_none(),
                "{at}: min_sources needs sources to count"
            );
            return Ok(None);
        }
        (None, false) => {}
    }
    for (i, source) in raw.sources.iter().enumerate() {
        let venue: VenueId = source
            .venue
            .parse()
            .wrap_err_with(|| format!("{at}: sources[{i}]"))?;
        ensure!(
            !source.symbol.trim().is_empty(),
            "{at}: sources[{i}] ({venue}) has no symbol"
        );
        let weight = match &source.weight {
            None => U256::exp10(WEIGHT_DECIMALS as usize),
            Some(text) => {
                let weight = parse_decimal_scaled(text, WEIGHT_DECIMALS)
                    .wrap_err_with(|| format!("{at}: sources[{i}] ({venue}) invalid weight"))?;
                ensure!(
                    !weight.is_zero(),
                    "{at}: sources[{i}] ({venue}) weight {text} is zero (or below \
                     10^-{WEIGHT_DECIMALS}); drop the source instead"
                );
                ensure!(
                    weight <= U256::from(MAX_WEIGHT) * U256::exp10(WEIGHT_DECIMALS as usize),
                    "{at}: sources[{i}] ({venue}) weight {text} is above {MAX_WEIGHT}; weights \
                     are relative, so scale them down"
                );
                weight
            }
        };
        ensure!(
            !sources.iter().any(|s: &Source| {
                s.venue == venue && s.symbol.eq_ignore_ascii_case(&source.symbol)
            }),
            "{at}: sources[{i}] repeats {venue}:{}; one entry per market",
            source.symbol
        );
        sources.push(Source {
            venue,
            symbol: source.symbol.clone(),
            weight,
        });
    }
    let min_sources = match &raw.min_sources {
        None => 1,
        Some(text) => {
            let n: usize = text
                .parse()
                .wrap_err_with(|| format!("{at}: min_sources {text:?} is not a whole number"))?;
            ensure!(
                (1..=sources.len()).contains(&n),
                "{at}: min_sources is {n} but there are {} sources; it must be between 1 and \
                 that",
                sources.len()
            );
            n
        }
    };
    Ok(Some(Feeds {
        sources,
        min_sources,
    }))
}

/// Builds one pair's volatile pricing knobs, or `None` when it declares none.
///
/// The three without a default (γ, k, κ) come as a set: a pair with some of them is a pair
/// whose operator stopped half way, not one that wants the missing ones defaulted to a
/// guess. The timings default because the chain fixes them, and the target share defaults
/// to half and half.
fn parse_volatile(raw: &RawPair, at: &str) -> Result<Option<VolatileParams>> {
    let required = [("gamma", &raw.gamma), ("k", &raw.k), ("kappa", &raw.kappa)];
    let optional = [
        ("target_share", &raw.target_share),
        ("hold_secs", &raw.hold_secs),
        ("fill_delay_secs", &raw.fill_delay_secs),
        ("volatility_window_secs", &raw.volatility_window_secs),
    ];
    let set: Vec<&str> = required
        .iter()
        .chain(&optional)
        .filter(|(_, value)| value.is_some())
        .map(|(name, _)| *name)
        .collect();
    if set.is_empty() {
        return Ok(None);
    }
    let missing: Vec<&str> = required
        .iter()
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| *name)
        .collect();
    ensure!(
        missing.is_empty(),
        "{at}: volatile pricing needs gamma, k and kappa together; {} set but {} missing",
        set.join(", "),
        missing.join(", ")
    );
    fn get(value: &Option<String>) -> &str {
        value.as_deref().expect("checked above")
    }
    VolatileParams::parse(
        at,
        RawKnobs {
            gamma: get(&raw.gamma),
            k: get(&raw.k),
            kappa: get(&raw.kappa),
            target_share: raw.target_share.as_deref(),
            hold_secs: raw.hold_secs.as_deref(),
            fill_delay_secs: raw.fill_delay_secs.as_deref(),
            volatility_window_secs: raw.volatility_window_secs.as_deref(),
            inventory_aversion: raw.inventory_aversion.as_deref(),
            inventory_band_lower: raw.inventory_band_lower.as_deref(),
            inventory_band_upper: raw.inventory_band_upper.as_deref(),
            inventory_aversion_hard: raw.inventory_aversion_hard.as_deref(),
            inventory_band_hard_lower: raw.inventory_band_hard_lower.as_deref(),
            inventory_band_hard_upper: raw.inventory_band_hard_upper.as_deref(),
        },
    )
    .map(Some)
}

/// Parses one threshold fraction, applying every check that makes a threshold trustworthy.
/// Shared by both thresholds so they cannot drift apart: a guard whose windowed limit was
/// validated less carefully than its tick limit is a guard with a soft edge.
fn parse_threshold(fraction: &str, price_decimals: u32, key: &str, at: &str) -> Result<U256> {
    let threshold_scaled = parse_decimal_scaled(fraction, price_decimals)
        .wrap_err_with(|| format!("{at}: invalid {key}"))?;
    // Catches a threshold too fine to express at this scale as well as a literal zero:
    // either way the pair would trip on its second sample and halt, so the run would end
    // up quoting nothing while looking configured.
    ensure!(
        !threshold_scaled.is_zero(),
        "{at}: {key} {fraction} is zero at {price_decimals} decimals, so the second \
         price would trip it and halt the pair"
    );
    // Digits beyond `--price-decimals` are dropped by `parse_decimal_scaled`, which
    // quietly tightens the guard: 0.0000015 at 6 decimals reads as 0.000001. A threshold
    // that is not what the config says is the misconfiguration the zero and upper-bound
    // checks exist to prevent, so it is refused the same way. Trailing zeros are not
    // precision and are not counted.
    let fraction_digits = fraction
        .split_once('.')
        .map_or(0, |(_, digits)| digits.trim_end_matches('0').len());
    ensure!(
        fraction_digits <= price_decimals as usize,
        "{at}: {key} {fraction} has more decimal digits than the {price_decimals} \
         decimals of --price-decimals can hold, so it would be read as {read}; use at most \
         {price_decimals} decimals, or raise --price-decimals",
        read = format_scaled(threshold_scaled, price_decimals)
    );
    // Bounded above as well as below, and for the same reason. Every line of prose about
    // this setting talks in percentages ("a 2% move is a depeg"), so `max_deviation = "2"`
    // meaning 2% is the natural slip — and it parses as 200%, a threshold the mid would
    // have to triple to cross. The pair would run effectively unguarded while its config
    // says otherwise, which is the failure mode the zero check above already exists to
    // prevent; refusing only one end of the range would be arbitrary.
    let scale = U256::exp10(price_decimals as usize);
    ensure!(
        threshold_scaled < scale,
        "{at}: {key} {fraction} is a fraction of the mid, not a percentage, so this is \
         {percent} — a threshold the price could scarcely reach. Write 0.02 for 2%.",
        percent = percent(threshold_scaled, scale)
    );
    Ok(threshold_scaled)
}

/// Builds one pair's circuit-breaker settings, or `None` when it declares no threshold.
///
/// Per pair for the same reason as [`MidBand`]: a deviation is a fraction, but what counts
/// as an implausible one is not shared. 2% is a quiet hour on BTCUSDC and a depeg on
/// USDCUSDT, so a single process-wide threshold would have to be loose enough for the
/// most volatile pair configured — which is exactly the pair the guard exists for.
///
/// It lives here rather than as a flag because this is a decision about *what* a pair
/// publishes, which `pairs.toml` owns; flags and the environment carry only *where* the
/// pusher runs, so no setting has two homes.
fn parse_breaker(
    max_deviation: Option<&str>,
    max_deviation_window: Option<&str>,
    max_deviation_window_blocks: Option<&str>,
    source: &SourceSpec,
    price_decimals: u32,
    at: &str,
) -> Result<Option<BreakerConfig>> {
    if max_deviation.is_none()
        && max_deviation_window.is_none()
        && max_deviation_window_blocks.is_none()
    {
        return Ok(None);
    }
    // A fixed mid is the same number every tick, so no check could ever trip on it.
    // Silently accepting that would leave a pair the operator believes is guarded.
    ensure!(
        source.feeds().is_some(),
        "{at}: the circuit breaker watches a streamed price for a move, and this pair \
         publishes a fixed mid, which cannot deviate; drop its breaker keys, or give the \
         pair a symbol"
    );

    let threshold_scaled = max_deviation
        .map(|fraction| parse_threshold(fraction, price_decimals, "max_deviation", at))
        .transpose()?;

    let window = match (max_deviation_window, max_deviation_window_blocks) {
        (None, None) => None,
        (Some(fraction), Some(blocks)) => {
            let threshold_scaled =
                parse_threshold(fraction, price_decimals, "max_deviation_window", at)?;
            let blocks: u64 = blocks.parse().wrap_err_with(|| {
                format!("{at}: max_deviation_window_blocks {blocks} is not a whole number")
            })?;
            ensure!(
                blocks > 0,
                "{at}: max_deviation_window_blocks is zero, so the window has no span"
            );
            ensure!(
                blocks <= MAX_BREAKER_WINDOW_BLOCKS,
                "{at}: max_deviation_window_blocks {blocks} is above the \
                 {MAX_BREAKER_WINDOW_BLOCKS} block ceiling (a day); check for an extra digit"
            );
            Some(WindowConfig {
                threshold_scaled,
                blocks,
                span: Duration::from_secs(blocks * crate::update::BLOCK_TIME_SECS),
            })
        }
        (Some(_), None) => bail!(
            "{at}: max_deviation_window needs max_deviation_window_blocks to say over how \
             long it applies"
        ),
        (None, Some(_)) => bail!(
            "{at}: max_deviation_window_blocks needs max_deviation_window to say how far \
             the mid may move over it"
        ),
    };

    Ok(Some(BreakerConfig {
        threshold_scaled,
        window,
        decimals: price_decimals,
    }))
}

/// One configured pair, parsed and validated but with its key not yet resolved.
///
/// `PartialEq` is what a config reload diffs on: two specs comparing equal means that
/// lane's stanza did not change and its pair can be left running untouched. Sound because
/// this type is the *whole* parsed stanza and holds nothing else — no key (that is
/// `key_env`, a name, resolved later), no live handle, no runtime state — so equality here
/// is equality of what the operator wrote, and the diff never touches a secret.
#[derive(Clone, Debug, PartialEq)]
pub struct PairSpec {
    /// Address-sorted, matching `PropAMM._pairKey` ordering.
    pub tokens: (Address, Address),
    pub lane: U256,
    /// True when the declared `[base, quote]` order is the reverse of the sorted order,
    /// so the feed must publish the reciprocal price.
    pub invert: bool,
    pub source: SourceSpec,
    pub band: MidBand,
    /// Trip/recovery settings for this pair's price circuit breaker; `None` leaves the
    /// pair unguarded, which is the default.
    pub breaker: Option<BreakerConfig>,
    /// The registered guards this pair runs, after the deviation guard, in file order.
    pub guards: Vec<GuardStanza>,
    pub key_env: String,
    pub allow_symbol_mismatch: bool,
    /// Why the file halts this pair, when it says: only a spec in [`Config::halted`] has one,
    /// whatever the stanza carries, so a running pair's diff never turns on it.
    pub halt_reason: Option<String>,
}

impl Config {
    /// Every pair in the file, halted or not, in file order and numbered from one as errors
    /// count its `[[pairs]]` tables, with whether it is halted.
    pub fn in_file_order(&self) -> impl Iterator<Item = (usize, &PairSpec, bool)> + '_ {
        self.file_order
            .iter()
            .enumerate()
            .filter_map(|(i, &(halted, at))| {
                let list = if halted { &self.halted } else { &self.pairs };
                list.get(at).map(|spec| (i + 1, spec, halted))
            })
    }

    /// The scale the file was parsed at, which every price in it is read in.
    pub fn price_decimals(&self) -> u32 {
        self.price_decimals
    }

    /// The token pairs whose vaults are watched: every pair in the file, halted or not.
    pub fn vault_pairs(&self) -> Vec<(Address, Address)> {
        self.pairs
            .iter()
            .chain(&self.halted)
            .map(|spec| spec.tokens)
            .collect()
    }
}

impl PairSpec {
    /// The pair as it was declared, `(base, quote)` — recovered from `invert` so the
    /// Binance symbol cross-check can compare against the market's own orientation.
    pub fn declared_base_quote(&self) -> (Address, Address) {
        if self.invert {
            (self.tokens.1, self.tokens.0)
        } else {
            (self.tokens.0, self.tokens.1)
        }
    }
}

pub struct Config {
    pub target: Address,
    /// The pairs to run: every pair in the file that is not halted.
    pub pairs: Vec<PairSpec>,
    /// The pairs the file marks `halted`. Not run, but their vaults are still watched, since
    /// a halted pair's inventory is exactly what an operator wants to look at.
    pub halted: Vec<PairSpec>,
    /// The `[[builder]]` entries from the same file. Validated here for shape (names,
    /// endpoints, keys) but not for being non-empty: whether zero builders is an error
    /// depends on the mode, which the config file does not decide on its own.
    pub builders: Vec<BuilderConfig>,
    /// Where each `[[pairs]]` table of the file went: `(halted, index)` into `halted` or
    /// `pairs`, in file order, which splitting the two lists loses.
    file_order: Vec<(bool, usize)>,
    /// The scale the file was parsed at.
    price_decimals: u32,
}

/// The stand-in label for a pair whose ERC-20 `symbol()` calls could not be read, used
/// until preflight replaces it with something like `USDC/USDT`.
///
/// Deliberately short. A full 32-byte lane is 66 characters, which as a log prefix buries
/// the message after it and in the `--check` table overflows the pair column and knocks
/// every later column out of alignment — and the table prints the lane in its own column
/// anyway. Eight hex digits identify a lane uniquely enough to cross-check by eye, which is
/// all a label is for. This is reached more often than it looks: `make local` writes the
/// mock token's code without its constructor storage, so `symbol()` reads empty there.
pub fn lane_label(lane: U256) -> String {
    // Sliced from the rendered string rather than shifted-and-padded: U256's LowerHex does
    // not zero-pad, so a lane with leading zero bytes would render short either way, and
    // `min` handles that without pretending the padding worked.
    let full = format!("{lane:#x}");
    format!("lane {}", &full[..full.len().min(10)])
}

/// The registry convention for a pair's lane: keccak256(token0 ++ token1), tokens
/// address-sorted. Byte-identical to `PropAMM._pairKey`.
pub fn lane_of(token0: Address, token1: Address) -> U256 {
    let mut buf = [0u8; 40];
    buf[..20].copy_from_slice(token0.as_bytes());
    buf[20..].copy_from_slice(token1.as_bytes());
    U256::from_big_endian(keccak(buf).as_bytes())
}

/// The one place a hex address string becomes an `Address`. Also backs clap's
/// `--registry` parser via `cli::parse_address`, so a malformed address reads the same
/// way whether it came from the config or the command line.
pub fn parse_address(s: &str) -> Result<Address> {
    s.parse().map_err(|e| eyre!("invalid address {s:?}: {e:?}"))
}

pub fn load_config(path: &Path, price_decimals: u32, allow_no_pairs: bool) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read config {}", path.display()))?;
    parse_config_with(&text, price_decimals, allow_no_pairs)
        .wrap_err_with(|| format!("invalid config {}", path.display()))
}

/// The strict parse: a config with no pairs is a mistake. Used by the tests, which are
/// where every parse rule is pinned down; the binary goes through `load_config`.
#[cfg(test)]
pub fn parse_config(toml_text: &str, price_decimals: u32) -> Result<Config> {
    parse_config_with(toml_text, price_decimals, false)
}

/// A `[pairs.pricing]` stanza, as its pair's source. The stanza computes the whole
/// `[delta, mid]`, so no built-in model's key may stand beside it, and a built-in kind is
/// configured with its own keys rather than named in one. `symbol`/`sources` stay: they are
/// the pair's reference market, which the core's freshness gate and backstop judge.
fn custom_source(raw: &RawPair, stanza: &toml::Table, at: &str) -> Result<SourceSpec> {
    let kind = match stanza.get("kind") {
        Some(toml::Value::String(kind)) => kind.clone(),
        Some(other) => eyre::bail!(
            "{at}: [pairs.pricing] kind must be a string, not {}",
            other.type_str()
        ),
        None => eyre::bail!(
            "{at}: [pairs.pricing] needs kind = \"...\", the name the binary registered its \
             pricer under"
        ),
    };
    ensure!(
        !crate::pricing::BUILT_IN_KINDS.contains(&kind.as_str()),
        "{at}: pricing kind `{kind}` is built in; configure it with the pair's own keys (mid \
         and delta, symbol or sources, gamma/k/kappa), not a [pairs.pricing] stanza"
    );
    let built_in = [
        ("mid", raw.mid.is_some()),
        ("delta", raw.delta.is_some()),
        ("gamma", raw.gamma.is_some()),
        ("k", raw.k.is_some()),
        ("kappa", raw.kappa.is_some()),
        ("target_share", raw.target_share.is_some()),
        ("hold_secs", raw.hold_secs.is_some()),
        ("fill_delay_secs", raw.fill_delay_secs.is_some()),
        (
            "volatility_window_secs",
            raw.volatility_window_secs.is_some(),
        ),
        ("inventory_aversion", raw.inventory_aversion.is_some()),
        ("inventory_band_lower", raw.inventory_band_lower.is_some()),
        ("inventory_band_upper", raw.inventory_band_upper.is_some()),
    ];
    if let Some((key, _)) = built_in.iter().find(|(_, set)| *set) {
        eyre::bail!(
            "{at}: set [pairs.pricing] or {key}, not both: a custom pricer computes the whole \
             [delta, mid]"
        );
    }
    Ok(SourceSpec::Custom {
        kind,
        config: stanza.clone(),
        feeds: parse_feeds(raw, at)?,
    })
}

/// `allow_no_pairs` is for a server whose pairs are going to arrive through the
/// backoffice. Otherwise an empty `[[pairs]]` is a config that failed to say what it
/// meant, and is refused.
pub fn parse_config_with(
    toml_text: &str,
    price_decimals: u32,
    allow_no_pairs: bool,
) -> Result<Config> {
    let raw: RawConfig = toml::from_str(toml_text).wrap_err("could not parse TOML")?;
    ensure!(
        allow_no_pairs || !raw.pairs.is_empty(),
        "no pairs configured; at least one is required"
    );
    let target = parse_address(&raw.target).wrap_err("invalid target")?;
    // The zero address is what config.example.toml ships, so it is the value an unedited
    // template carries. It parses fine, and every later check then fails for a reason that
    // does not name the cause: `isUpdater(0x0, …)` answers false, so every row reports "not
    // an authorized updater" and points the operator at `addUpdater` on the zero address
    // rather than at the one field they did not fill in.
    ensure!(
        !target.is_zero(),
        "target is the zero address; set `target` to the PropAMM these lanes belong to"
    );

    // One whole unit at this scale. `delta` is a fraction of the mid, and this is the
    // 100% mark PropAMM's own `SPREAD_SCALE` measures it against.
    let spread_scale = spread_scale(price_decimals);

    let mut pairs = Vec::with_capacity(raw.pairs.len());
    let mut halted = Vec::new();
    let mut file_order = Vec::with_capacity(raw.pairs.len());
    let mut seen_lanes = HashSet::new();
    let mut seen_key_envs = HashSet::new();

    for (i, raw_pair) in raw.pairs.iter().enumerate() {
        // Errors are indexed rather than named: the label comes from an on-chain
        // symbol() call, which has not happened yet at parse time. From one, as a person
        // counts the file's `[[pairs]]` tables.
        let at = format!("pair {}", i + 1);

        ensure!(
            raw_pair.tokens.len() == 2,
            "{at}: tokens must have exactly two entries (base, quote), got {}",
            raw_pair.tokens.len()
        );
        let declared0 = parse_address(&raw_pair.tokens[0]).wrap_err_with(|| at.clone())?;
        let declared1 = parse_address(&raw_pair.tokens[1]).wrap_err_with(|| at.clone())?;
        ensure!(declared0 != declared1, "{at}: tokens must differ");

        // PropAMM sorts by uint160, which for H160 is byte-wise order.
        let invert = declared0 > declared1;
        let tokens = if invert {
            (declared1, declared0)
        } else {
            (declared0, declared1)
        };
        // Checked here rather than after the loop, because everything below that inverts a
        // price depends on it: with the bound enforced first, squaring the scale cannot
        // overflow, so an inversion failure downstream is impossible rather than handled.
        // Attributing it to the pair that inverts also beats a whole-config error.
        if invert {
            ensure!(
                price_decimals <= MAX_INVERTED_PRICE_DECIMALS,
                "{at}: price-decimals {price_decimals} is too large for an inverted pair: \
                 inverting squares the scale, so at most {MAX_INVERTED_PRICE_DECIMALS} fits \
                 a uint256"
            );
        }
        let lane = lane_of(tokens.0, tokens.1);
        ensure!(
            seen_lanes.insert(lane),
            "{at}: lane {lane:#x} is already configured; two pairs on one lane means one \
             silently overwrites the other every block"
        );

        ensure!(
            !raw_pair.key_env.is_empty()
                && raw_pair
                    .key_env
                    .starts_with(|c: char| c.is_ascii_uppercase())
                && raw_pair
                    .key_env
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
            "{at}: key_env {:?} must match ^[A-Z][A-Z0-9_]*$",
            raw_pair.key_env
        );
        ensure!(
            seen_key_envs.insert(raw_pair.key_env.clone()),
            "{at}: key_env {:?} is already used by another pair; each pair needs its own key",
            raw_pair.key_env
        );

        // `delta` means the same thing wherever it appears: the half-spread to publish,
        // as a fraction of the mid. Parsed in one place so a feed's and a static pair's
        // are bounded identically.
        let parse_delta = |text: &str| -> Result<U256> {
            let delta = parse_decimal_scaled(text, price_decimals)
                .wrap_err_with(|| format!("{at}: invalid delta"))?;
            // PropAMM subtracts the spread as a fraction of the mid, so at one whole unit
            // the fill is zero and beyond it `_quote` reverts `SpreadTooWide`. Rejected
            // here rather than on-chain, where it would surface as an unrelated revert on
            // every fill the lane takes.
            ensure!(
                delta < spread_scale,
                "{at}: delta {text} is not below 1; the spread is a fraction of the mid, \
                 so a whole unit leaves the taker nothing and more than that reverts \
                 on-chain"
            );
            crate::ensure_fits_216_bits(delta).wrap_err_with(|| at.clone())?;
            Ok(delta)
        };

        let source = if let Some(stanza) = &raw_pair.pricing {
            custom_source(raw_pair, stanza, &at)?
        } else {
            let volatile = parse_volatile(raw_pair, &at)?;
            let feeds = parse_feeds(raw_pair, &at)?;
            match (feeds, &raw_pair.mid, &raw_pair.delta) {
                (Some(feeds), None, None) if volatile.is_some() => SourceSpec::Volatile {
                    feeds,
                    params: volatile.expect("checked above"),
                },
                // The computed spread replaces the declared one; both at once would leave the
                // operator guessing which the lane charges.
                _ if volatile.is_some() => eyre::bail!(
                    "{at}: gamma/k/kappa price a streamed pair, so set symbol and leave mid and \
                 delta blank"
                ),
                // A feed without a delta publishes the book's own half-spread. With several
                // venues there is no single book to copy, and a made-up average of their
                // spreads is not a number anyone asked to charge.
                (Some(feeds), None, None) => {
                    ensure!(
                        feeds.sources.len() == 1,
                        "{at}: a pair with more than one source needs a delta (or gamma/k/kappa); \
                     only a single source can copy its venue's spread"
                    );
                    SourceSpec::Feed { feeds, delta: None }
                }
                // With one, that delta is published instead. The book's half-spread is what a
                // venue charges a taker it can quote away from in milliseconds; a published
                // quote cannot be pulled that way, since it stands for the whole block and the
                // maker wears every move that happens inside it.
                (Some(feeds), None, Some(delta_text)) => SourceSpec::Feed {
                    feeds,
                    delta: Some(parse_delta(delta_text)?),
                },
                (None, Some(mid_text), Some(delta_text)) => {
                    let declared_mid = parse_decimal_scaled(mid_text, price_decimals)
                        .wrap_err_with(|| format!("{at}: invalid mid"))?;
                    ensure!(
                        !declared_mid.is_zero(),
                        "{at}: mid must be nonzero; PropAMM rejects a zero mid"
                    );
                    // A static `mid` is declared in the same market orientation as `tokens`,
                    // so an inverted lane publishes its reciprocal — byte-for-byte the rule a
                    // feed follows in `quote_from_ticker`. Without this, `symbol` and `mid` would
                    // mean different things behind the same `tokens` array: the one setting that is
                    // deliberately derived rather than stated would be back, only silent, because
                    // nothing downstream can tell a market-oriented mid from a lane-oriented one.
                    let mid = if invert {
                        // Cannot fail: `price_decimals <= MAX_INVERTED_PRICE_DECIMALS` was
                        // enforced above for this pair, and the mid is nonzero.
                        reciprocal_scaled(declared_mid, price_decimals).ok_or_else(|| {
                        eyre!("{at}: mid {declared_mid} has no reciprocal at {price_decimals} decimals")
                    })?
                    } else {
                        declared_mid
                    };
                    // Truncation, not overflow: inverting a mid far above the scale floors to
                    // zero, and PropAMM rejects a zero mid. Reported against the number the
                    // operator actually wrote, not against the inverted zero.
                    ensure!(
                        !mid.is_zero(),
                        "{at}: mid {mid_text} inverts to zero at {price_decimals} decimals; this \
                     lane is {t0:#x} priced in {t1:#x}, so it publishes 1/{mid_text}, which is \
                     too small to represent at this scale",
                        t0 = tokens.0,
                        t1 = tokens.1,
                    );
                    // Not inverted, and that is not an oversight: `delta` is the half-spread as
                    // a fraction of the mid, and (ask-bid)/(ask+bid) is invariant under
                    // inversion — the 1/(bid·ask) factors cancel. Same reason `quote_from_ticker`
                    // computes it from the original sides in both orientations.
                    let delta = parse_delta(delta_text)?;
                    SourceSpec::Static { delta, mid }
                }
                _ => eyre::bail!(
                    "{at}: set exactly one price source: either symbol or sources, on their own \
                 or with a delta, or both mid and delta"
                ),
            }
        };

        // Bounds are read in lane orientation, so they need no inversion: they describe the
        // number this lane publishes, which is the one the check below has in hand.
        let bound = |text: &Option<String>, what: &str| -> Result<Option<U256>> {
            text.as_deref()
                .map(|value| {
                    parse_decimal_scaled(value, price_decimals)
                        .wrap_err_with(|| format!("{at}: invalid {what}"))
                })
                .transpose()
        };
        let band = MidBand {
            min: bound(&raw_pair.min_mid, "min_mid")?,
            max: bound(&raw_pair.max_mid, "max_mid")?,
        };
        if let (Some(min), Some(max)) = (band.min, band.max) {
            ensure!(
                min <= max,
                "{at}: min_mid {min} is above max_mid {max}, so no mid could ever be published"
            );
        }
        // A static price is fixed, so a band it already violates can only be a mistake — and
        // one that would otherwise surface as every push refusing to publish, at run time.
        if let SourceSpec::Static { mid, .. } = &source {
            band.check(*mid)
                .wrap_err_with(|| format!("{at}: the configured mid is outside its own band"))?;
        }

        let breaker = parse_breaker(
            raw_pair.max_deviation.as_deref(),
            raw_pair.max_deviation_window.as_deref(),
            raw_pair.max_deviation_window_blocks.as_deref(),
            &source,
            price_decimals,
            &at,
        )?;

        let guards = parse_guards(raw_pair, &at)?;

        let spec = PairSpec {
            tokens,
            lane,
            invert,
            source,
            band,
            breaker,
            guards,
            key_env: raw_pair.key_env.clone(),
            allow_symbol_mismatch: raw_pair.allow_symbol_mismatch,
            // Only a halted pair's: the reason explains a halt, and a running pair's spec is
            // what a reload diffs, so a stale one left beside a cleared flag would otherwise
            // restart a quoting lane (a withdraw and a redial) for a line nothing acts on.
            halt_reason: raw_pair.halt_reason.clone().filter(|_| raw_pair.halted),
        };
        if raw_pair.halted {
            file_order.push((true, halted.len()));
            halted.push(spec);
        } else {
            file_order.push((false, pairs.len()));
            pairs.push(spec);
        }
    }

    // Shape only. Whether an empty list is fatal is the mode's call, not the file's, and
    // is decided where the mode is known.
    validate_builders(&raw.builders)?;

    Ok(Config {
        target,
        pairs,
        halted,
        builders: raw.builders,
        file_order,
        price_decimals,
    })
}

/// A configured pair with its updater key resolved: everything the send path needs and
/// nothing more. `label` starts as the lane and is replaced with the on-chain ERC-20
/// symbol pair by preflight. `key_env` and `allow_symbol_mismatch` end their usefulness
/// at resolution (duplicate-key detection and the pre-run symbol check, both against
/// `PairSpec`, run before this type exists), so neither is carried into this struct — and
/// neither is the price source, which [`ResolvedPair`] holds only until a live feed
/// replaces it.
///
/// Derives `Debug` for test ergonomics (`unwrap_err` on a `Result<Vec<_>, _>`); this is
/// safe because `Signer`'s `Debug` never prints the raw key, only a fingerprint hash or a
/// redaction placeholder (see `secp256k1::SecretKey`'s `impl_display_secret!`).
#[derive(Clone, Debug)]
pub struct Pair {
    pub tokens: (Address, Address),
    pub lane: U256,
    pub signer: Signer,
    pub label: String,
    /// Checked against every mid before it is published; see [`MidBand`].
    pub band: MidBand,
}

/// A [`Pair`] plus what it needs to *start* its price source, which the caller converts
/// into a live one and then discards. Kept separate so the running pair carries no field
/// nothing reads: `invert` is consumed by the feed it spawns, and `source` by the
/// `ValueSource` built from it.
#[derive(Clone, Debug)]
pub struct ResolvedPair {
    pub pair: Pair,
    pub source: SourceSpec,
    /// Only the feed path needs this — a static mid was already inverted at parse time.
    pub invert: bool,
    /// The settings a live breaker is built from, which the caller does exactly once.
    ///
    /// Deliberately here and not on [`Pair`]: `Pair` is cloned on every supervised restart,
    /// and a copy of the settings riding along with it is an invitation to rebuild the
    /// breaker inside the restarted loop — which would hand it a guard that has forgotten
    /// both its reference and its trip, the precise hole `SharedBreaker` exists to close.
    /// Ending its life at resolution means there is nothing to rebuild from.
    pub breaker: Option<BreakerConfig>,
    /// The registered guards' stanzas, built once with the lane for the same reason.
    pub guards: Vec<GuardStanza>,
}

impl ResolvedPair {
    /// The pair as it was declared, `(base, quote)`; see [`PairSpec::declared_base_quote`].
    pub fn declared_base_quote(&self) -> (Address, Address) {
        if self.invert {
            (self.pair.tokens.1, self.pair.tokens.0)
        } else {
            (self.pair.tokens.0, self.pair.tokens.1)
        }
    }
}

/// Reads the process environment. Passed as `lookup` in production; tests inject their
/// own closure instead, since `std::env::set_var` is unsafe in edition 2024 and process
/// env is shared across test threads.
pub fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Where a run reads updater keys from: [`env_lookup`] in production, a closure in tests,
/// shared by `run` and the `Service` it builds so both read keys the same way.
pub(crate) type KeyLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Resolves each pair's key independently, so a caller reporting a half-configured
/// deployment (`--check`) can show every row. Errors never contain the key value.
pub fn resolve_keys<F: Fn(&str) -> Option<String>>(
    config: &Config,
    lookup: F,
) -> Vec<Result<Signer>> {
    config
        .pairs
        .iter()
        .map(|pair| {
            let name = &pair.key_env;
            let raw = lookup(name).ok_or_else(|| eyre!("{name} is not set in the environment"))?;
            let secret: SecretKey = raw
                .strip_prefix("0x")
                .unwrap_or(&raw)
                .parse()
                // Deliberately not wrapping the parse error: it can quote the input.
                .map_err(|_| eyre!("{name} does not hold a valid secp256k1 private key"))?;
            Ok(Signer::from(LocalSigner::new(secret)))
        })
        .collect()
}

/// Resolves every key and rejects duplicate signer addresses. Used to start a run: a
/// missing or invalid key is fatal, because a pair that cannot sign cannot quote.
pub fn resolve_pairs<F: Fn(&str) -> Option<String>>(
    config: Config,
    lookup: F,
) -> Result<Vec<ResolvedPair>> {
    let signers = resolve_keys(&config, lookup);
    let mut seen: Vec<(Address, String)> = Vec::with_capacity(signers.len());
    let mut pairs = Vec::with_capacity(signers.len());

    for (spec, signer) in config.pairs.into_iter().zip(signers) {
        let signer = signer?;
        let address = signer.address();
        if let Some((_, other)) = seen.iter().find(|(seen, _)| *seen == address) {
            // Sharing an address means sharing a nonce, so only one of the two lanes
            // could ever land per block and the other would be starved.
            eyre::bail!(
                "{} and {other} resolve to the same address {address:#x}; each pair needs \
                 its own key so their nonces stay independent",
                spec.key_env
            );
        }
        seen.push((address, spec.key_env.clone()));

        pairs.push(ResolvedPair {
            pair: Pair {
                tokens: spec.tokens,
                lane: spec.lane,
                signer,
                label: lane_label(spec.lane),
                band: spec.band,
            },
            source: spec.source,
            invert: spec.invert,
            guards: spec.guards,
            breaker: spec.breaker,
        });
    }
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// Builder configuration (`builders.toml`)
// ---------------------------------------------------------------------------
// The builders the pusher quotes to in builder mode: a name, an endpoint and an API key
// each. They live in the main config file as `[[builder]]` entries (see
// `config.example.toml`), which is why that file holds secrets and is kept 0600. The
// separate-file form below is what `--builders` reads, and it is the same shape.
//
// Everything here is validated at load time rather than at first connect, so a typo, a
// pasted `https://` URL or a key with a stray newline fails at startup naming the builder
// that carries it.

/// One builder's maker endpoint.
///
/// `PartialEq` so a reload can tell whether the builder list in the file is still the one
/// the process connected with; see `refuse_builders_change`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuilderConfig {
    /// How this builder is named in logs. Unique across the file.
    pub name: String,
    /// The maker WebSocket endpoint, `ws://` or `wss://`.
    pub endpoint: String,
    /// Sent verbatim as the `Authorization` header.
    pub api_key: String,
    /// Overrides the global `--disable-cross-region` for this builder. Builders differ in
    /// whether they run regions at all, and one that does not simply ignores the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cross_region: Option<bool>,
}

impl BuilderConfig {
    /// The per-builder override, falling back to the global `--disable-cross-region`.
    /// Named `_or` rather than after the field it reads, so a call site cannot be misread
    /// as a field access.
    pub fn disable_cross_region_or(&self, global: bool) -> bool {
        self.disable_cross_region.unwrap_or(global)
    }
}

/// Every configured builder. `deny_unknown_fields` is load-bearing rather than tidiness:
/// in a file whose fields are secrets and destinations, a misspelling that resolved to a
/// default would leave a key empty or a region unpinned with no diagnostic at all.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildersConfig {
    /// One `[[builder]]` table per builder.
    #[serde(default, rename = "builder")]
    pub builders: Vec<BuilderConfig>,
}

impl BuildersConfig {
    /// Reads and validates the file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .wrap_err_with(|| format!("failed to read builders config {}", path.display()))?;

        // The file holds live API keys. Not fatal (a container may mount it 0644), but
        // worth saying out loud, the way startup already warns about an unset mid band.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    "note: {} is readable beyond its owner (mode {:03o}) and holds live API \
                     keys; consider chmod 600",
                    path.display(),
                    fs::metadata(path)?.permissions().mode() & 0o777,
                );
            }
        }

        Self::parse(&text).wrap_err_with(|| format!("invalid builders config {}", path.display()))
    }

    /// Parses and validates TOML text. Split from `load` so every validation rule is
    /// testable without touching the filesystem.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).wrap_err("failed to parse TOML")?;
        ensure!(
            !config.builders.is_empty(),
            "expected at least one [[builder]] entry; builder mode has nothing to quote to \
             without one (pass --mode node to send updateState transactions to --rpc-url \
             instead)"
        );
        validate_builders(&config.builders)?;
        Ok(config)
    }
}

/// Shape only, and deliberately not "there is at least one": whether an empty list is
/// fatal depends on the mode, which the file does not know.
pub fn validate_builders(builders: &[BuilderConfig]) -> Result<()> {
    let mut seen = HashSet::new();
    for builder in builders {
        ensure!(
            !builder.name.trim().is_empty(),
            "a [[builder]] has an empty name; the name is how it is identified in logs"
        );
        ensure!(
            seen.insert(builder.name.as_str()),
            "two [[builder]] entries are both named {:?}; names identify a builder in \
             the logs, so they must be unique (try {:?}-eu and {:?}-us)",
            builder.name,
            builder.name,
            builder.name,
        );
        let url = Url::parse(&builder.endpoint)
            .wrap_err_with(|| format!("builder {:?} has an unparseable endpoint", builder.name))?;
        ensure!(
            matches!(url.scheme(), "ws" | "wss"),
            "builder {:?} has a {:?} endpoint; a maker endpoint is a WebSocket URL, so \
             the scheme must be ws or wss",
            builder.name,
            url.scheme(),
        );
        ensure!(
            !builder.api_key.is_empty(),
            "builder {:?} has an empty api_key; it is sent as the Authorization header \
             and an empty one is rejected at connect",
            builder.name,
        );
        // Checked here rather than at first connect so the builder carrying a malformed
        // key is named, at startup. The predicate lives in builder.rs, next to the code
        // whose requirement it mirrors.
        ensure!(
            crate::builder::is_valid_api_key(&builder.api_key),
            "builder {:?} has an api_key that is not a valid HTTP header value; check \
             for a stray newline or a non-ASCII character",
            builder.name,
        );
    }
    Ok(())
}

/// Config fixtures other modules' tests share.
#[cfg(test)]
pub(crate) mod tests_support {
    /// One WETH/USDC pair priced by the custom kind `skewed`, with ETHUSDC as its market.
    pub(crate) const CUSTOM: &str = r#"
target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
[[pairs]]
tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol  = "ETHUSDC"
key_env = "UPDATER_KEY_WETH_USDC"
[pairs.pricing]
kind = "skewed"
half_spread = 0.0005
[[builder]]
name = "b"
endpoint = "wss://b.example/ws"
api_key = "k"
"#;

    /// One WETH/USDC feed pair with one `[[pairs.guards]]` stanza naming `kind`.
    pub(crate) fn guarded(kind: &str) -> String {
        CUSTOM.replace(
            "[pairs.pricing]\nkind = \"skewed\"\nhalf_spread = 0.0005\n",
            &format!("[[pairs.guards]]\nkind = \"{kind}\"\n"),
        )
    }

    /// [`CUSTOM`] naming `kind` instead.
    pub(crate) fn custom(kind: &str) -> String {
        CUSTOM.replace("kind = \"skewed\"", &format!("kind = \"{kind}\""))
    }

    /// [`CUSTOM`] with `line` added to its stanza.
    pub(crate) fn custom_with(kind: &str, line: &str) -> String {
        custom(kind).replace(
            "half_spread = 0.0005",
            &format!("half_spread = 0.0005\n{line}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const WBTC: &str = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";
    const TARGET: &str = "0x1234567890123456789012345678901234567890";

    fn three_pair_toml() -> String {
        format!(
            r#"
target = "{TARGET}"

[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
key_env = "K_WETH_USDC"

[[pairs]]
tokens  = ["{WBTC}", "{USDC}"]
symbol  = "BTCUSDC"
key_env = "K_WBTC_USDC"

[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
symbol  = "USDCUSDT"
key_env = "K_USDC_USDT"
"#
        )
    }

    fn u256_hex(s: &str) -> U256 {
        U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
    }

    #[test]
    fn parses_three_pairs_with_golden_lanes() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        assert_eq!(config.pairs.len(), 3);
        // Golden values read from the live registry probe: keccak256 of the two
        // address-sorted tokens concatenated, i.e. PropAMM._pairKey.
        assert_eq!(
            config.pairs[0].lane,
            u256_hex("0x85053f65cd1ece2bb37b70c13d66eadebf2779df5ddd68cf12f3ccfdc6bfe760")
        );
        assert_eq!(
            config.pairs[1].lane,
            u256_hex("0x49ac7cf15ee63cfb424f6c6960feac21491b6a71bd520d5acc60b88454052cf3")
        );
        assert_eq!(
            config.pairs[2].lane,
            u256_hex("0x4aafb64a36177dc82e7ace74cf60cc655659bc049da9533b5f7a6881bea995c6")
        );
    }

    #[test]
    fn derives_invert_from_the_sort_order() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        // WETH/USDC sorts to USDC/WETH, so the declared order was flipped.
        assert!(config.pairs[0].invert, "WETH/USDC must invert");
        assert!(!config.pairs[1].invert, "WBTC/USDC must not invert");
        assert!(!config.pairs[2].invert, "USDC/USDT must not invert");
        // tokens are stored address-sorted regardless of how they were declared.
        assert!(config.pairs[0].tokens.0 < config.pairs[0].tokens.1);
        // The declared orientation is still recoverable for the symbol cross-check.
        let (base, quote) = config.pairs[0].declared_base_quote();
        assert_eq!(base, config.pairs[0].tokens.1); // WETH
        assert_eq!(quote, config.pairs[0].tokens.0); // USDC
    }

    #[test]
    fn accepts_static_mid_and_delta_instead_of_a_symbol() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
mid     = "0.9998"
delta   = "0.0005"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        match &config.pairs[0].source {
            SourceSpec::Static { delta, mid } => {
                assert_eq!(*mid, U256::from_dec_str("999800000000000000").unwrap());
                assert_eq!(*delta, U256::from_dec_str("500000000000000").unwrap());
            }
            _ => panic!("expected a static source"),
        }
    }

    /// A static price is declared in market orientation, exactly like `symbol`, so an
    /// inverted lane publishes its reciprocal.
    ///
    /// This is the one case where a wrong answer is silent and catastrophic: nothing
    /// downstream can tell a market-oriented mid from a lane-oriented one, `check_symbol`
    /// does not run for static pairs, and publishing 4001.98 where 0.000249… belongs is
    /// wrong by a factor of 1.6e7 on a lane a taker can trade.
    #[test]
    fn a_static_mid_on_an_inverted_lane_publishes_the_reciprocal() {
        // WETH, USDC declared in market order; sorts to USDC/WETH, so the lane carries
        // USDC priced in WETH and 4001.98 USDC-per-WETH must publish as its reciprocal.
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
mid     = "4001.98"
delta   = "0.00025"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        assert!(config.pairs[0].invert, "WETH/USDC must invert");
        match &config.pairs[0].source {
            SourceSpec::Static { delta, mid } => {
                // Golden: 10^36 / 4001.98e18, the same floor division the feed path takes.
                assert_eq!(*mid, U256::from_dec_str("249876311225943").unwrap());
                // Not the declared value — the whole point.
                assert_ne!(*mid, U256::from_dec_str("4001980000000000000000").unwrap());
                // Delta is a fraction of the mid, and (ask-bid)/(ask+bid) is invariant
                // under inversion, so it must pass through untouched.
                assert_eq!(*delta, U256::from_dec_str("250000000000000").unwrap());
            }
            _ => panic!("expected a static source"),
        }

        // And `--check`'s reciprocal line reads it back as the number the operator wrote,
        // which is the only reason an inverted lane is auditable by eye at all.
        let published = match &config.pairs[0].source {
            SourceSpec::Static { mid, .. } => *mid,
            _ => unreachable!(),
        };
        let back = reciprocal_scaled(published, 18).expect("a nonzero mid inverts back");
        assert_eq!(
            crate::feed::format_scaled(back, 18),
            "4001.980000000002532693",
            "the reciprocal line must land back on the declared price (two truncations)"
        );

        // The same declared pair the other way round does not invert, so the identical mid
        // publishes verbatim. Same numbers, opposite handling — only orientation differs.
        let flipped = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{WETH}"]
mid     = "4001.98"
delta   = "0.00025"
key_env = "K"
"#
        );
        let config = parse_config(&flipped, 18).unwrap();
        assert!(!config.pairs[0].invert);
        match &config.pairs[0].source {
            SourceSpec::Static { mid, .. } => {
                assert_eq!(*mid, U256::from_dec_str("4001980000000000000000").unwrap())
            }
            _ => panic!("expected a static source"),
        }
    }

    /// Carried over from the single-pair CLI's `--min-mid`/`--max-mid`, now per pair.
    #[test]
    fn a_mid_band_rejects_values_outside_it() {
        let band = MidBand {
            min: Some(U256::from(100u64)),
            max: Some(U256::from(200u64)),
        };
        assert!(band.check(U256::from(99u64)).is_err());
        assert!(band.check(U256::from(201u64)).is_err());
        // The bounds themselves are inside the band.
        for inside in [100u64, 150, 200] {
            assert!(band.check(U256::from(inside)).is_ok(), "{inside} is inside");
        }
        assert!(!band.is_unset());
    }

    #[test]
    fn a_mid_band_bounds_only_the_side_that_was_given() {
        let floor = MidBand {
            min: Some(U256::from(100u64)),
            max: None,
        };
        assert!(floor.check(U256::from(99u64)).is_err());
        assert!(floor.check(U256::MAX).is_ok());
        assert!(!floor.is_unset());

        let ceiling = MidBand {
            min: None,
            max: Some(U256::from(100u64)),
        };
        assert!(ceiling.check(U256::from(101u64)).is_err());
        assert!(ceiling.check(U256::zero()).is_ok());

        let unbounded = MidBand::default();
        assert!(unbounded.check(U256::zero()).is_ok());
        assert!(unbounded.check(U256::MAX).is_ok());
        // Drives the report warning: a pair nothing bounds must not be silent about it.
        assert!(unbounded.is_unset());
    }

    /// Bounds are declared in lane orientation, so an inverted pair's band is compared
    /// against what the lane publishes — the number `--check`'s mid column prints — not
    /// against the market-oriented mid the operator wrote.
    #[test]
    fn a_bands_bounds_are_read_in_lane_orientation() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
mid     = "4000"
delta   = "0.0001"
min_mid = "0.0002"
max_mid = "0.0003"
key_env = "K"
"#
        );
        // 4000 market-oriented publishes 0.00025 on the lane, which is inside [0.0002,
        // 0.0003]. Had the band been compared against 4000 it would have been rejected.
        let config = parse_config(&text, 18).unwrap();
        let band = config.pairs[0].band;
        assert_eq!(band.min, Some(parse_decimal_scaled("0.0002", 18).unwrap()));
        match &config.pairs[0].source {
            SourceSpec::Static { mid, .. } => band.check(*mid).expect("0.00025 is inside"),
            _ => panic!("expected a static source"),
        }
    }

    /// The three knobs without defaults switch a streamed pair to the computed spread; the
    /// timings default to the chain's and the target share to half and half.
    #[test]
    fn gamma_k_and_kappa_make_a_volatile_pair() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
gamma   = "0.1"
k       = "700"
kappa   = "1"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        match &config.pairs[0].source {
            SourceSpec::Volatile { feeds, params } => {
                assert_eq!(feeds, &Feeds::single_binance("ETHUSDC"));
                assert_eq!(params.gamma.get(), 0.1);
                assert_eq!(params.k.get(), 700.0);
                assert_eq!(params.kappa.get(), 1.0);
                assert_eq!(params.target_share.get(), 0.5);
                assert_eq!(params.hold_secs.get(), 12.0);
                assert_eq!(params.fill_delay_secs.get(), 6.0);
                assert_eq!(
                    params.volatility_window,
                    std::time::Duration::from_secs(600)
                );
            }
            _ => panic!("expected a volatile source"),
        }
        assert_eq!(
            config.pairs[0].source.feeds(),
            Some(&Feeds::single_binance("ETHUSDC"))
        );
        // A volatile pair streams, so it may carry a breaker like any feed.
        let text = text.replace(
            "key_env = \"K\"",
            "key_env = \"K\"\nmax_deviation = \"0.02\"",
        );
        assert!(parse_config(&text, 18).unwrap().pairs[0].breaker.is_some());
    }

    /// Half a set of knobs is a pair someone stopped configuring, not one that wants the
    /// rest guessed; and the computed spread cannot sit beside a declared one or a fixed mid.
    #[test]
    fn volatile_knobs_come_as_a_set_and_exclude_a_fixed_price() {
        let base = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
key_env = "K"
"#
        );
        let err = |extra: &str| match parse_config(&format!("{base}{extra}"), 18) {
            Ok(_) => panic!("{extra:?} should have been refused"),
            Err(err) => err.to_string(),
        };
        let partial = err("symbol = \"ETHUSDC\"\ngamma = \"0.1\"\nk = \"700\"");
        assert!(
            partial.contains("gamma, k set but kappa missing"),
            "{partial}"
        );
        let timing_only = err("symbol = \"ETHUSDC\"\nhold_secs = \"12\"");
        assert!(timing_only.contains("hold_secs set but"), "{timing_only}");
        let full = "gamma = \"0.1\"\nk = \"700\"\nkappa = \"1\"\n";
        let with_delta = err(&format!("symbol = \"ETHUSDC\"\ndelta = \"0.0005\"\n{full}"));
        assert!(
            with_delta.contains("leave mid and delta blank"),
            "{with_delta}"
        );
        let with_mid = err(&format!("mid = \"4000\"\ndelta = \"0.0005\"\n{full}"));
        assert!(with_mid.contains("leave mid and delta blank"), "{with_mid}");
        let no_symbol = err(full);
        assert!(
            no_symbol.contains("leave mid and delta blank"),
            "{no_symbol}"
        );
        let bad_gamma = err(&format!(
            "symbol = \"ETHUSDC\"\n{}",
            full.replace("\"0.1\"", "\"0\"")
        ));
        assert!(
            bad_gamma.contains("gamma must be above zero"),
            "{bad_gamma}"
        );
    }

    /// The knobs round-trip through the file the backoffice writes, and a change to one is
    /// a change a reload sees.
    #[test]
    fn volatile_knobs_round_trip_and_diff() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
gamma   = "0.1"
k       = "700"
kappa   = "1"
key_env = "K"
"#
        );
        let raw: RawConfig = toml::from_str(&text).unwrap();
        let written = toml::to_string(&raw).unwrap();
        assert!(written.contains("gamma = \"0.1\""));
        assert!(
            !written.contains("hold_secs"),
            "an unset default is not written back"
        );
        assert_eq!(
            parse_config(&written, 18).unwrap().pairs,
            parse_config(&text, 18).unwrap().pairs
        );

        let retuned = text.replace("gamma   = \"0.1\"", "gamma   = \"0.2\"");
        assert_ne!(
            parse_config(&retuned, 18).unwrap().pairs,
            parse_config(&text, 18).unwrap().pairs
        );
    }

    /// A feed that states no `delta` publishes the book's own half-spread, so stating one
    /// is opt-in and leaving it out is the behaviour that existed before.
    #[test]
    fn a_feed_without_a_delta_publishes_the_book_half_spread() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
symbol  = "USDCUSDT"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        let source = &config.pairs[0].source;
        match source {
            SourceSpec::Feed { delta, .. } => assert!(delta.is_none()),
            _ => panic!("expected a feed source"),
        }
        let book = parse_decimal_scaled("0.000002", 18).unwrap();
        assert_eq!(
            source.published_delta(book, spread_scale(18)).unwrap(),
            book,
            "an unstated delta must publish the book's own half-spread"
        );
    }

    /// A feed pair may state a `delta` and take only the mid from the stream. The number
    /// means what it means everywhere else: the half-spread to publish. Binance's ETHUSDC
    /// half-spread is ~0.02bp, far too tight for a quote that stands for a whole block and
    /// cannot be pulled inside it.
    fn pair_with(body: &str) -> String {
        format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
key_env = "K"
{body}
"#
        )
    }

    #[test]
    fn sources_parse_with_weights_and_a_minimum() {
        let text = pair_with(
            r#"
delta = "0.0005"
min_sources = "2"
sources = [
  { venue = "binance", symbol = "ETHUSDC", weight = "2" },
  { venue = "BINANCE", symbol = "ETHUSDT" },
  { venue = "binance", symbol = "ETHFDUSD", weight = "0.5" },
]
"#,
        );
        let config = parse_config(&text, 18).unwrap();
        let feeds = config.pairs[0].source.feeds().expect("a streamed pair");
        assert_eq!(feeds.min_sources, 2);
        let weights: Vec<String> = feeds
            .sources
            .iter()
            .map(|s| {
                format!(
                    "{}:{} {}",
                    s.venue,
                    s.symbol,
                    format_scaled(s.weight, WEIGHT_DECIMALS)
                )
            })
            .collect();
        assert_eq!(
            weights,
            [
                "binance:ETHUSDC 2",
                "binance:ETHUSDT 1",
                "binance:ETHFDUSD 0.5"
            ]
        );
        assert_eq!(
            feeds.describe(),
            "binance:ETHUSDC ×2 + binance:ETHUSDT ×1 + binance:ETHFDUSD ×0.5 (min 2)"
        );
        // Weights aside, the same markets in any order share a history.
        let text2 = pair_with(
            r#"
delta = "0.0005"
sources = [
  { venue = "binance", symbol = "ethfdusd" },
  { venue = "binance", symbol = "ETHUSDT", weight = "9" },
  { venue = "binance", symbol = "ETHUSDC" },
]
"#,
        );
        let other = parse_config(&text2, 18).unwrap();
        assert_eq!(
            feeds.history_key(),
            other.pairs[0].source.feeds().unwrap().history_key()
        );
    }

    #[test]
    fn symbol_is_one_binance_source_with_weight_one() {
        let text = pair_with(r#"symbol = "ETHUSDC""#);
        let config = parse_config(&text, 18).unwrap();
        let feeds = config.pairs[0].source.feeds().unwrap();
        assert_eq!(feeds, &Feeds::single_binance("ETHUSDC"));
        assert_eq!(feeds.describe(), "binance:ETHUSDC");
        assert_eq!(feeds.history_key(), "binance:ETHUSDC");
        let text = pair_with(
            r#"
symbol = "ETHUSDC"
sources = [{ venue = "binance", symbol = "ETHUSDT" }]
"#,
        );
        let err = parse_config(&text, 18).map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn sources_refuse_what_cannot_be_averaged() {
        let cases = [
            (
                r#"sources = [{ venue = "nasdaq", symbol = "ETH" }]"#,
                "unknown venue",
            ),
            (
                r#"sources = [{ venue = "binance", symbol = "" }]"#,
                "has no symbol",
            ),
            (
                r#"sources = [{ venue = "binance", symbol = "ETHUSDC", weight = "0" }]"#,
                "weight 0 is zero",
            ),
            (
                r#"sources = [{ venue = "binance", symbol = "ETHUSDC", weight = "-1" }]"#,
                "invalid weight",
            ),
            (
                r#"sources = [{ venue = "binance", symbol = "ETHUSDC", weight = "1000001" }]"#,
                "is above 1000000",
            ),
            (
                r#"
sources = [{ venue = "binance", symbol = "ETHUSDC" }, { venue = "binance", symbol = "ethusdc" }]
delta = "0.0005"
"#,
                "repeats binance:ethusdc",
            ),
            (
                r#"
sources = [{ venue = "binance", symbol = "ETHUSDC" }, { venue = "binance", symbol = "ETHUSDT" }]
delta = "0.0005"
min_sources = "3"
"#,
                "min_sources is 3 but there are 2",
            ),
            (
                r#"
sources = [{ venue = "binance", symbol = "ETHUSDC" }]
delta = "0.0005"
min_sources = "0"
"#,
                "min_sources is 0",
            ),
            (
                r#"
mid = "4000"
delta = "0.0005"
min_sources = "1"
"#,
                "min_sources needs sources",
            ),
            // No delta with two venues: there is no single book whose spread to copy.
            (
                r#"sources = [{ venue = "binance", symbol = "ETHUSDC" }, { venue = "binance", symbol = "ETHUSDT" }]"#,
                "needs a delta",
            ),
        ];
        for (body, expected) in cases {
            let err = format!(
                "{:#}",
                parse_config(&pair_with(body), 18).map(|_| ()).unwrap_err()
            );
            assert!(
                err.contains(expected),
                "{body}\n  expected {expected:?} in: {err}"
            );
        }
        // One venue may still copy its own spread, as before.
        let one = pair_with(r#"sources = [{ venue = "binance", symbol = "ETHUSDC" }]"#);
        assert!(matches!(
            parse_config(&one, 18).unwrap().pairs[0].source,
            SourceSpec::Feed { delta: None, .. }
        ));
    }

    #[test]
    fn the_endpoints_table_is_a_setting_a_reload_refuses_to_change() {
        let a = FileSettings {
            endpoints: [("binance".to_owned(), "wss://a".to_owned())].into(),
            ..FileSettings::default()
        };
        let b = FileSettings {
            endpoints: [("binance".to_owned(), "wss://b".to_owned())].into(),
            ..FileSettings::default()
        };
        assert_eq!(a.changed_keys(&b), ["endpoints"]);
        assert!(a.changed_keys(&a.clone()).is_empty());
        // Round trip through TOML as a sub-table.
        let text = toml::to_string(&a).unwrap();
        assert!(text.contains("[endpoints]"), "{text}");
        let back: FileSettings = toml::from_str(&text).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn a_feed_delta_replaces_the_book_half_spread() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
delta   = "0.0005"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        let source = &config.pairs[0].source;
        match source {
            SourceSpec::Feed { feeds, delta } => {
                assert_eq!(feeds, &Feeds::single_binance("ETHUSDC"));
                // 5bp at 18 decimals.
                assert_eq!(*delta, Some(U256::from_dec_str("500000000000000").unwrap()));
            }
            _ => panic!("expected a feed source"),
        }
        // The book's own half-spread is handed in and ignored: 5bp, not 5.02bp.
        let book = parse_decimal_scaled("0.000002", 18).unwrap();
        assert_eq!(
            source.published_delta(book, spread_scale(18)).unwrap(),
            parse_decimal_scaled("0.0005", 18).unwrap()
        );
    }

    /// A stated `delta` is not reoriented for an inverted lane, exactly like a static
    /// pair's: `(ask - bid) / (ask + bid)` is unchanged by inversion, so a fraction
    /// standing in for it is too. Being a fraction it also means 5bp on any pair whatever
    /// that pair trades at.
    #[test]
    fn a_feed_delta_is_not_reoriented_on_an_inverted_lane() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
delta   = "0.0005"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        assert!(config.pairs[0].invert, "WETH/USDC must invert");
        match &config.pairs[0].source {
            SourceSpec::Feed { delta, .. } => {
                assert_eq!(*delta, Some(U256::from_dec_str("500000000000000").unwrap()))
            }
            _ => panic!("expected a feed source"),
        }
    }

    /// A book wide enough to reach a whole unit must not be published: PropAMM subtracts
    /// the spread from the mid fill, so the taker would get nothing, and past that
    /// `_quote` reverts `SpreadTooWide` for every fill on the lane. Refusing routes it
    /// through the unusable-price path instead, which withdraws the quote.
    #[test]
    fn a_book_half_spread_reaching_one_whole_unit_is_refused() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
symbol  = "USDCUSDT"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        let source = &config.pairs[0].source;
        let scale = spread_scale(18);
        let wide = parse_decimal_scaled("0.8", 18).unwrap();
        assert_eq!(source.published_delta(wide, scale).unwrap(), wide);
        assert!(source.published_delta(scale, scale).is_err());
    }

    /// A stated `delta` is bounded at parse time, so a book that gapes cannot make it
    /// unusable at runtime: the book's number is discarded rather than compared against.
    #[test]
    fn a_stated_delta_ignores_a_gaping_book() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
symbol  = "USDCUSDT"
delta   = "0.0005"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        let scale = spread_scale(18);
        assert_eq!(
            config.pairs[0]
                .source
                .published_delta(scale, scale)
                .unwrap(),
            parse_decimal_scaled("0.0005", 18).unwrap()
        );
    }

    /// A static pair's `delta` is published exactly as declared, through the same function.
    #[test]
    fn a_static_delta_is_published_unchanged() {
        let text = format!(
            r#"
target = "{TARGET}"
[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
mid     = "0.9998"
delta   = "0.0005"
key_env = "K"
"#
        );
        let config = parse_config(&text, 18).unwrap();
        assert_eq!(
            config.pairs[0]
                .source
                .published_delta(U256::zero(), spread_scale(18))
                .unwrap(),
            parse_decimal_scaled("0.0005", 18).unwrap()
        );
    }

    /// The shipped template must parse. `RawPair` is `deny_unknown_fields`, so a key
    /// documented in the example but never added to the struct — or renamed in one place
    /// and not the other — makes the file every operator starts from fail to load.
    #[test]
    fn the_example_config_parses() {
        let example = include_str!("../config.example.toml");
        // The template ships the zero address on purpose, which `parse_config` refuses;
        // substitute a real one so the rest of the file is what is under test.
        let text = example.replace(
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
        );
        let config = parse_config(&text, 18).expect("config.example.toml must parse");
        assert_eq!(config.pairs.len(), 3);
        // The builders moved into this file, so the template's own [[builder]] has to
        // survive the same strict parse the pairs do.
        assert_eq!(config.builders.len(), 1);
        assert_eq!(config.builders[0].name, "titan-eu");
        // And its [settings] table, which is read by a different pass and would otherwise
        // never be exercised by this test at all.
        let settings = parse_file_settings(&text).expect("[settings] must parse");
        assert_eq!(settings.mode.as_deref(), Some("builder"));
        assert_eq!(settings.requote_ms, Some(50));
        assert_eq!(settings.metrics_addr.as_deref(), Some("127.0.0.1:9464"));

        // The commented-out volatile pair is the documentation of those keys, so it has to
        // parse too.
        let with_volatile = with_example_pair(&text, "# The same pair priced as a volatile one");
        let config = parse_config(&with_volatile, 18).expect("the volatile example must parse");
        let volatile = config
            .pairs
            .iter()
            .find(|pair| matches!(pair.source, SourceSpec::Volatile { .. }))
            .expect("one pair is volatile");
        assert_eq!(
            volatile.source.feeds(),
            Some(&Feeds::single_binance("ETHUSDC"))
        );
        assert!(volatile.breaker.is_some());
    }

    /// The template with the commented-out `[[pairs]]` example that follows `marker`
    /// uncommented (one level; its own commented defaults stay comments), in place of the
    /// live WETH/USDC pair it duplicates.
    fn with_example_pair(text: &str, marker: &str) -> String {
        let start = text
            .find(marker)
            .unwrap_or_else(|| panic!("the template has no {marker:?} example"));
        let block_start = start + text[start..].find("# [[pairs]]").unwrap();
        let block_end = block_start + text[block_start..].find("\n\n").unwrap();
        let uncommented: String = text[block_start..block_end]
            .lines()
            .map(|line| format!("{}\n", line.strip_prefix("# ").unwrap_or(line)))
            .collect();
        let live_start = text.find("\n[[pairs]]\n").unwrap() + 1;
        let live_end = live_start + text[live_start..].find("\n\n").unwrap();
        format!(
            "{}{}{}",
            &text[..live_start],
            uncommented,
            &text[live_end..]
        )
    }

    /// The commented-out custom pair documents `[pairs.pricing]`, so it parses: into a
    /// custom source naming its kind, holding its stanza, and keeping its reference market.
    #[test]
    fn the_example_custom_pair_parses() {
        let text = include_str!("../config.example.toml").replace(
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
        );
        let with_custom = with_example_pair(
            &text,
            "# A pair priced by a pricing kind a binary registered",
        );
        let config = parse_config(&with_custom, 18).expect("the custom example must parse");
        let (kind, stanza, feeds) = config
            .pairs
            .iter()
            .find_map(|pair| match &pair.source {
                SourceSpec::Custom {
                    kind,
                    config,
                    feeds,
                } => Some((kind, config, feeds)),
                _ => None,
            })
            .expect("one pair is custom");
        assert_eq!(kind, "skewed");
        assert_eq!(stanza.get("half_spread"), Some(&toml::Value::Float(0.0005)));
        assert_eq!(feeds.as_ref(), Some(&Feeds::single_binance("ETHUSDC")));
    }

    /// The writer's whole promise: what it renders, the loader reads back identically. A
    /// field added to a raw type and forgotten by the writer would silently drop an
    /// operator's setting on the next backoffice edit; this is what catches that.
    #[test]
    fn a_rendered_config_round_trips() {
        let text = format!(
            r#"
target = "{TARGET}"

[settings]
mode = "builder"
rpc_url = "https://rpc.example"
requote_ms = 25
metrics_addr = "127.0.0.1:9464"
backoffice_addr = "100.1.2.3:8088"
disable_cross_region = true

[[pairs]]
tokens  = ["{WETH}", "{USDC}"]
symbol  = "ETHUSDC"
delta   = "0.0005"
min_mid = "0.0001"
max_mid = "0.001"
max_deviation = "0.02"
key_env = "K_WETH_USDC"

[[pairs]]
tokens  = ["{USDC}", "{USDT}"]
mid     = "1"
delta   = "0"
key_env = "K_USDC_USDT"
allow_symbol_mismatch = true

[[builder]]
name = "titan-eu"
endpoint = "wss://eu.example/ws"
api_key = "k"
disable_cross_region = false
"#
        );
        let original: RawConfig = toml::from_str(&text).unwrap();
        let rendered = render_raw(&original).unwrap();
        let again: RawConfig = toml::from_str(&rendered).unwrap();

        assert_eq!(original.target, again.target);
        assert_eq!(original.settings, again.settings);
        assert_eq!(original.pairs, again.pairs);
        assert_eq!(original.builders, again.builders);
        // And what it renders is still a config the real loader accepts, not merely one
        // that deserializes into the raw types.
        parse_config(&rendered, 18).expect("a rendered config must load");
    }

    /// An unset optional key must be absent from the output, not present and empty. TOML
    /// has no null, so the difference is between a file that loads and one that does not.
    #[test]
    fn the_writer_omits_what_was_never_set() {
        let text = format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\nkey_env = \"K\"\n"
        );
        let rendered = render_raw(&toml::from_str::<RawConfig>(&text).unwrap()).unwrap();
        for absent in [
            "[settings]",
            "[[builder]]",
            "min_mid",
            "max_mid",
            "max_deviation",
            "mid =",
            "allow_symbol_mismatch",
        ] {
            assert!(!rendered.contains(absent), "{absent} in:\n{rendered}");
        }
        parse_config(&rendered, 18).expect("a minimal rendered config must load");
    }

    /// A halted pair is kept and validated but not run, and its vault is still watched.
    #[test]
    fn a_halted_pair_is_parsed_but_not_run() {
        let text = format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\nkey_env = \"A\"\nhalted = true\n\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"1\"\ndelta = \"0\"\nkey_env = \"B\"\n"
        );
        let config = parse_config(&text, 18).unwrap();
        assert_eq!(config.pairs.len(), 1);
        assert_eq!(config.pairs[0].key_env, "B");
        assert_eq!(config.halted.len(), 1);
        assert_eq!(config.halted[0].key_env, "A");
        assert_eq!(config.vault_pairs().len(), 2);

        // The flag round-trips, and an unhalted pair writes no `halted` key at all.
        let rendered = render_raw(&toml::from_str::<RawConfig>(&text).unwrap()).unwrap();
        assert_eq!(rendered.matches("halted = true").count(), 1, "{rendered}");
        assert!(!rendered.contains("halted = false"), "{rendered}");
    }

    /// A `halt_reason` left on a pair that is not halted (a hand edit, or a resume that kept
    /// it) says nothing the pair acts on, so it is not part of what a reload diffs: adding
    /// or removing one must not restart a quoting lane, withdrawing it and redialling.
    #[test]
    fn a_running_pairs_stale_halt_reason_restarts_nothing() {
        let stanza = |tail: &str| {
            format!(
                "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"1\"\ndelta = \"0\"\nkey_env = \"B\"\n{tail}"
            )
        };
        let running = parse_config(&stanza("halt_reason = \"desk\"\n"), 18).unwrap();
        let desired = parse_config(&stanza(""), 18).unwrap();
        let running: std::collections::BTreeMap<U256, PairSpec> = running
            .pairs
            .into_iter()
            .map(|spec| (spec.lane, spec))
            .collect();
        let actions = crate::reload::plan(
            &running,
            &desired.pairs,
            &std::collections::BTreeSet::new(),
            false,
        );
        assert!(actions.is_empty(), "{actions:?}");
        assert!(running.values().all(|spec| spec.halt_reason.is_none()));

        // A halted pair keeps its reason, for the reload line that stops it.
        let halted = parse_config(&stanza("halted = true\nhalt_reason = \"desk\"\n"), 18).unwrap();
        assert_eq!(halted.halted[0].halt_reason.as_deref(), Some("desk"));
    }

    /// A halted pair still counts against its lane and key: resuming it must not produce a
    /// config the loader would then refuse.
    #[test]
    fn a_halted_pair_still_claims_its_lane() {
        let text = format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\nkey_env = \"A\"\nhalted = true\n\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\nkey_env = \"B\"\n"
        );
        assert!(parse_config(&text, 18).is_err());
    }

    /// A fresh host whose configuration is going to arrive through the backoffice starts
    /// from a file with no pairs in it. Refusing that would leave the operator with no page
    /// to add the pairs on, which is the one thing the exception exists to prevent.
    #[test]
    fn an_empty_pair_list_loads_only_when_it_is_allowed() {
        let text = format!("target = \"{TARGET}\"\npairs = []\n");

        let err = parse_err(&text, 18);
        assert!(err.contains("no pairs configured"), "{err}");

        let config = parse_config_with(&text, 18, true).expect("allowed, for a fresh host");
        assert!(config.pairs.is_empty());
        assert!(config.builders.is_empty());
        // And the target is still checked: an empty config is a starting point, not an
        // unvalidated one.
        assert!(!config.target.is_zero());
    }

    /// The exception is about the pair list and nothing else. A zero target in an otherwise
    /// empty file is still the unedited template, and still refused.
    #[test]
    fn allowing_an_empty_pair_list_does_not_relax_anything_else() {
        let zero = "target = \"0x0000000000000000000000000000000000000000\"\npairs = []\n";
        let err = match parse_config_with(zero, 18, true) {
            Ok(_) => panic!("the zero target must still be refused"),
            Err(err) => format!("{err:#}"),
        };
        assert!(err.contains("zero address"), "{err}");
    }

    /// A file with no `[settings]` table must still load, because that is exactly what the
    /// local `make` targets pass: they drive every setting from the command line.
    #[test]
    fn a_config_without_settings_reads_as_all_defaults() {
        let settings = parse_file_settings(&three_pair_toml()).unwrap();
        assert_eq!(settings, FileSettings::default());
    }

    /// The settings table is read by its own pass, so a typo there would be invisible to
    /// `parse_config`'s strict parse unless this one is strict too.
    #[test]
    fn a_misspelled_setting_is_rejected() {
        let text = format!("{}\n[settings]\nrequote_millis = 50\n", three_pair_toml());
        let err = format!("{:#}", parse_file_settings(&text).unwrap_err());
        assert!(err.contains("requote_millis"), "{err}");
    }

    /// Builders live in the same file as the pairs now. The shape rules that used to run
    /// over `builders.toml` have to run over this list too, or a typo in the merged file
    /// reaches a connect attempt instead of failing at load.
    #[test]
    fn builders_in_the_config_file_are_validated() {
        let good = format!(
            "{}\n[[builder]]\nname = \"titan-eu\"\nendpoint = \"wss://eu.example/ws\"\napi_key = \"k\"\n",
            three_pair_toml()
        );
        let config = parse_config(&good, 18).unwrap();
        assert_eq!(config.builders.len(), 1);
        assert_eq!(config.builders[0].endpoint, "wss://eu.example/ws");

        let cases = [
            (
                "https endpoint",
                "https://eu.example/ws",
                "k",
                "must be ws or wss",
            ),
            ("empty api_key", "wss://eu.example/ws", "", "empty api_key"),
        ];
        for (case, endpoint, api_key, expected) in cases {
            let text = format!(
                "{}\n[[builder]]\nname = \"b\"\nendpoint = \"{endpoint}\"\napi_key = \"{api_key}\"\n",
                three_pair_toml()
            );
            let err = parse_err(&text, 18);
            assert!(err.contains(expected), "{case}: {err}");
        }
    }

    /// Node mode has no builders and must not be forced to declare any: whether an empty
    /// list is fatal is the mode's call, made where the mode is known.
    #[test]
    fn a_config_with_no_builders_parses() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        assert!(config.builders.is_empty());
    }

    /// The reload path refuses a changed setting by naming the key. That message is only
    /// as good as this diff.
    #[test]
    fn changed_keys_names_every_setting_that_moved() {
        let running = FileSettings {
            requote_ms: Some(50),
            rpc_url: Some("https://a.example".to_owned()),
            ..Default::default()
        };
        assert!(running.changed_keys(&running).is_empty());

        let desired = FileSettings {
            requote_ms: Some(25),
            rpc_url: Some("https://b.example".to_owned()),
            metrics_addr: Some("127.0.0.1:9464".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            running.changed_keys(&desired),
            vec!["rpc_url", "requote_ms", "metrics_addr"]
        );
    }

    /// Each rejection is a config mistake that would otherwise publish wrong prices or
    /// silently quote fewer pairs than the operator believes.
    #[test]
    fn rejects_malformed_configs() {
        let cases: Vec<(&str, String)> = vec![
            (
                "empty pairs list",
                format!("target = \"{TARGET}\"\npairs = []\n"),
            ),
            (
                "one token",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "three tokens",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\", \"{WETH}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "identical tokens",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDC}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "duplicate lane across pairs (declared in opposite orders)",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"A\"\nkey_env = \"K1\"\n[[pairs]]\ntokens = [\"{USDT}\", \"{USDC}\"]\nsymbol = \"B\"\nkey_env = \"K2\"\n"
                ),
            ),
            (
                "both symbol and mid",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nmid = \"1\"\ndelta = \"0\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "neither symbol nor mid",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nkey_env = \"K\"\n"
                ),
            ),
            (
                // A whole unit of spread leaves the taker nothing, and beyond it PropAMM
                // reverts SpreadTooWide on every fill.
                "feed delta of one whole unit",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\ndelta = \"1\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "static delta of one whole unit",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"1\"\ndelta = \"1\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "feed delta that is not a number",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\ndelta = \"wide\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "mid without delta",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"1\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "zero static mid",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"0\"\ndelta = \"0\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // A valid mid isolates this from the zero-mid rule above: at
                // price_decimals = 18, this delta scales to 1e66, which exceeds
                // 2^216 (~1.05e65) — slot 0 shares its storage word with the
                // timestamp and slot count, leaving only 216 bits for delta.
                "delta exceeding 216 bits",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"1\"\ndelta = \"1000000000000000000000000000000000000000000000000\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // Otherwise a completely valid pair, plus one unknown key — isolating
                // deny_unknown_fields from any other rejection reason.
                "unknown key",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"K\"\nextra = 1\n"
                ),
            ),
            (
                // Same isolation, but the stray key sits beside `target`, not inside
                // the pair — exercising RawConfig's deny_unknown_fields specifically
                // rather than RawPair's (covered by "unknown key" above).
                "unknown key at top level",
                format!(
                    "target = \"{TARGET}\"\nextra = 1\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "missing key_env",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\n"
                ),
            ),
            (
                // Present but empty, unlike "missing key_env" above: serde is happy
                // with an empty String, so this must fail our own ensure!, not
                // deserialization.
                "empty key_env",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"\"\n"
                ),
            ),
            (
                "lowercase key_env name",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"k_usdc\"\n"
                ),
            ),
            (
                "duplicate key_env across pairs",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"A\"\nkey_env = \"K\"\n[[pairs]]\ntokens = [\"{WBTC}\", \"{USDC}\"]\nsymbol = \"B\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                "bad target address",
                format!(
                    "target = \"0x123\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // Nothing could ever be published, so this can only be a transposition.
                "min_mid above max_mid",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nmin_mid = \"2\"\nmax_mid = \"1\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // A fixed price its own band forbids would otherwise fail at run time, on
                // every push, rather than at load.
                "static mid outside its own band",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nmid = \"5\"\ndelta = \"0\"\nmin_mid = \"10\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // Parses as an address, so only an explicit rule rejects it — and it is
                // what config.example.toml ships, so it is the value an unedited template
                // carries into a run.
                "zero-address target",
                format!(
                    "target = \"0x0000000000000000000000000000000000000000\"\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // An inverted lane publishes 1/mid, and a mid this far above the scale
                // floors to zero — which PropAMM rejects. Declared WETH-first so it
                // inverts; the same mid on the flipped pair is perfectly valid.
                "static mid that inverts to zero",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nmid = \"100000000000000000000000\"\ndelta = \"0\"\nkey_env = \"K\"\n"
                ),
            ),
            (
                // Only the target address was covered above; this exercises
                // parse_address on the token path instead.
                "malformed token address",
                format!(
                    "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"0x123\", \"{USDT}\"]\nsymbol = \"X\"\nkey_env = \"K\"\n"
                ),
            ),
        ];
        for (name, text) in cases {
            assert!(
                parse_config(&text, 18).is_err(),
                "expected rejection for: {name}"
            );
        }
    }

    #[test]
    fn bounds_price_decimals_only_when_a_pair_inverts() {
        // WETH/USDC inverts, so squaring the scale must fit a uint256: d <= 38.
        let inverting = three_pair_toml();
        assert!(parse_config(&inverting, 38).is_ok());
        assert!(parse_config(&inverting, 39).is_err());

        // With no inverted pair the looser existing cap applies.
        let direct = format!(
            "target = \"{TARGET}\"\n[[pairs]]\ntokens = [\"{WBTC}\", \"{USDC}\"]\nsymbol = \"BTCUSDC\"\nkey_env = \"K\"\n"
        );
        assert!(parse_config(&direct, 39).is_ok());
    }

    // Well-known anvil test keys (public, not secrets): mnemonic indices 0, 2 and 3.
    const KEY0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const KEY2: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    const KEY3: &str = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
    const ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn resolves_one_distinct_key_per_pair() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        let pairs = resolve_pairs(config, |name| match name {
            "K_WETH_USDC" => Some(KEY0.to_owned()),
            "K_WBTC_USDC" => Some(KEY2.to_owned()),
            "K_USDC_USDT" => Some(KEY3.to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(
            format!("{:#x}", pairs[0].pair.signer.address()),
            ADDR0.to_lowercase()
        );
        // Every pair has its own address, which is what keeps their nonces independent.
        let mut addresses: Vec<_> = pairs.iter().map(|p| p.pair.signer.address()).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), 3);
        // The feed's orientation rides alongside the pair, for the feed it spawns.
        assert!(pairs[0].invert, "WETH/USDC inverts");
        match &pairs[0].source {
            SourceSpec::Feed { feeds, .. } => assert_eq!(feeds, &Feeds::single_binance("ETHUSDC")),
            _ => panic!("expected a feed source"),
        }
    }

    #[test]
    fn rejects_two_pairs_resolving_to_the_same_address() {
        // Distinct variable names, same key: still a nonce collision, so still rejected.
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        let err = resolve_pairs(config, |_| Some(KEY0.to_owned())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("same address"), "unexpected error: {msg}");
        // The key value itself must never appear in an error.
        assert!(
            !msg.contains(KEY0.trim_start_matches("0x")),
            "error leaked a key"
        );
    }

    #[test]
    fn reports_unset_and_invalid_keys_per_pair_without_aborting() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        let results = resolve_keys(&config, |name| match name {
            "K_WETH_USDC" => Some(KEY0.to_owned()),
            "K_WBTC_USDC" => Some("not-a-key".to_owned()),
            _ => None,
        });
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        let invalid = format!("{:#}", results[1].as_ref().unwrap_err());
        assert!(
            invalid.contains("K_WBTC_USDC"),
            "unexpected error: {invalid}"
        );
        let unset = format!("{:#}", results[2].as_ref().unwrap_err());
        assert!(unset.contains("not set"), "unexpected error: {unset}");
    }

    #[test]
    fn a_run_refuses_to_start_when_any_key_is_unset() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        let err = resolve_pairs(config, |_| None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not set"), "unexpected error: {msg}");
        // Pins the failure to the specific pair, not just to the "unset" rule in the
        // abstract — catches a future change that resolved pairs out of order or
        // reported a different one first.
        assert!(
            msg.contains("K_WETH_USDC"),
            "should name the first unresolved pair: {msg}"
        );
    }

    #[test]
    fn key_errors_never_leak_the_value() {
        let config = parse_config(&three_pair_toml(), 18).unwrap();
        let secret = "0xdeadbeef";
        let results = resolve_keys(&config, |_| Some(secret.to_owned()));
        for result in &results {
            let msg = format!("{:#}", result.as_ref().unwrap_err());
            assert!(!msg.contains("deadbeef"), "error leaked a key: {msg}");
        }
    }

    // ---------------------------------------------------------------------
    // Per-pair circuit breaker (`max_deviation`)
    // ---------------------------------------------------------------------

    /// `parse_config`'s error, rendered with its context chain. A helper because `Config`
    /// does not derive `Debug`, so `unwrap_err` is unavailable on its `Result`.
    fn parse_err(toml_text: &str, price_decimals: u32) -> String {
        match parse_config(toml_text, price_decimals) {
            Ok(_) => panic!("expected a parse error, got a config"),
            Err(err) => format!("{err:#}"),
        }
    }

    /// One pair, with whatever breaker keys the test is about.
    fn breaker_toml(keys: &str) -> String {
        format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\n\
             symbol = \"USDCUSDT\"\nkey_env = \"K\"\n{keys}"
        )
    }

    /// The reason the threshold is per pair and not per process: a run quoting both a
    /// stablecoin and a volatile pair needs two different numbers, and one global setting
    /// would have to be loose enough for the looser pair — which is the pair the guard is
    /// for. Each row's own value must survive parsing independently.
    #[test]
    fn each_pair_carries_its_own_deviation_threshold() {
        let toml = format!(
            "target = \"{TARGET}\"\n\n\
             [[pairs]]\ntokens = [\"{WBTC}\", \"{USDC}\"]\nsymbol = \"BTCUSDC\"\n\
             key_env = \"K_WBTC\"\nmax_deviation = \"0.02\"\n\n\
             [[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"USDCUSDT\"\n\
             key_env = \"K_USDC\"\nmax_deviation = \"0.002\"\n\n\
             [[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\n\
             key_env = \"K_WETH\"\n"
        );
        let config = parse_config(&toml, 6).unwrap();

        let volatile = config.pairs[0].breaker.unwrap();
        assert_eq!(volatile.threshold_scaled, Some(U256::from(20_000))); // 0.02 at 1e6
        let stable = config.pairs[1].breaker.unwrap();
        assert_eq!(stable.threshold_scaled, Some(U256::from(2_000))); // 0.002 at 1e6
        assert_eq!(stable.scale(), U256::exp10(6));
        // Unset is the default: a pair that declares nothing is simply unguarded.
        assert!(config.pairs[2].breaker.is_none());
    }

    /// A zero threshold trips on the second price and halts the pair, so a run that
    /// looks configured would quote nothing. Includes the case that matters more in
    /// practice: a nonzero fraction too fine to express at the configured decimals.
    #[test]
    fn a_zero_max_deviation_is_refused() {
        let err = parse_err(&breaker_toml("max_deviation = \"0\"\n"), 18);
        assert!(err.contains("zero"), "{err}");
        let err = parse_err(&breaker_toml("max_deviation = \"0.0000001\"\n"), 6);
        assert!(err.contains("zero"), "{err}");
    }

    /// Regression test for the missing upper bound found in review. Every doc about this
    /// setting speaks in percentages, so `"2"` for 2% is the natural slip — and it means
    /// 200%, leaving the pair unguarded while its config claims otherwise. The error has
    /// to say what the number was read as, or the operator just retypes it.
    #[test]
    fn a_max_deviation_of_one_or_more_is_refused() {
        let err = parse_err(&breaker_toml("max_deviation = \"2\"\n"), 6);
        assert!(err.contains("200.00%"), "must show how it was read: {err}");
        assert!(err.contains("0.02"), "must show the intended form: {err}");
        // 100% exactly is refused too: a mid cannot move more than that downwards, so the
        // guard would only ever fire on a price more than doubling.
        assert!(parse_err(&breaker_toml("max_deviation = \"1\"\n"), 6).contains("100.00%"));
        // Just below the boundary is a legitimate, if very loose, threshold.
        assert!(parse_config(&breaker_toml("max_deviation = \"0.99\"\n"), 6).is_ok());
    }

    /// A threshold with more digits than `--price-decimals` can hold would be silently
    /// truncated — `0.0000015` at 6 decimals becomes 0.000001, a third tighter than
    /// configured — and a guard whose real threshold differs from its configured one is
    /// the misconfiguration this setting's other refusals exist to prevent.
    #[test]
    fn a_max_deviation_finer_than_the_price_decimals_is_refused() {
        let err = parse_err(&breaker_toml("max_deviation = \"0.0000015\"\n"), 6);
        assert!(
            err.contains("6 decimals"),
            "must name the scale it cannot fit: {err}"
        );
        // Trailing zeros are not precision: this is exactly representable.
        assert!(parse_config(&breaker_toml("max_deviation = \"0.0200000000\"\n"), 6).is_ok());
    }

    /// A fixed mid is the same number every tick, so a breaker on it is a contradiction —
    /// and one that would otherwise leave the operator believing the pair is guarded.
    #[test]
    fn max_deviation_requires_a_streamed_price() {
        let toml = format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\n\
             mid = \"0.9998\"\ndelta = \"0.0005\"\nkey_env = \"K\"\nmax_deviation = \"0.02\"\n"
        );
        let err = parse_err(&toml, 6);
        assert!(err.contains("symbol"), "must say what to do instead: {err}");
    }

    /// The breaker no longer re-arms on a timer, so the window that used to configure
    /// that is gone. A config still carrying it must fail rather than start with a key
    /// that silently does nothing — `deny_unknown_fields` is what makes that automatic.
    #[test]
    fn a_leftover_stability_window_is_refused() {
        let err = parse_err(
            &breaker_toml("max_deviation = \"0.02\"\nbreaker_stability_secs = 30\n"),
            6,
        );
        assert!(err.contains("breaker_stability_secs"), "{err}");
    }

    /// The errors are indexed like every other pair error, from one as a person counts
    /// `[[pairs]]` tables, so a file with several rows says which one to edit.
    #[test]
    fn a_breaker_error_names_the_pair_it_came_from() {
        let toml = format!(
            "target = \"{TARGET}\"\n\n\
             [[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\nsymbol = \"ETHUSDC\"\n\
             key_env = \"K_WETH\"\n\n\
             [[pairs]]\ntokens = [\"{USDC}\", \"{USDT}\"]\nsymbol = \"USDCUSDT\"\n\
             key_env = \"K_USDC\"\nmax_deviation = \"nope\"\n"
        );
        let err = parse_err(&toml, 6);
        assert!(err.contains("pair 2"), "{err}");
        assert!(err.contains("max_deviation"), "{err}");
    }

    /// The window is written in blocks and resolved to seconds at parse time, because the
    /// feed task that judges samples has no block awareness.
    #[test]
    fn a_window_is_resolved_from_blocks_to_seconds() {
        let text = breaker_toml(
            "max_deviation = \"0.02\"\nmax_deviation_window = \"0.20\"\n\
             max_deviation_window_blocks = \"1000\"\n",
        );
        let window = parse_config(&text, 18).unwrap().pairs[0]
            .breaker
            .unwrap()
            .window
            .expect("both window keys set");
        assert_eq!(window.blocks, 1000);
        assert_eq!(
            window.span,
            std::time::Duration::from_secs(1000 * crate::update::BLOCK_TIME_SECS)
        );
    }

    /// A threshold with no length, or a length with no threshold, is a guard that cannot
    /// fire — the same failure the zero check refuses.
    #[test]
    fn the_two_window_keys_are_required_together() {
        let err = parse_err(&breaker_toml("max_deviation_window = \"0.20\"\n"), 18);
        assert!(err.contains("max_deviation_window_blocks"), "{err}");
        let err = parse_err(
            &breaker_toml("max_deviation_window_blocks = \"1000\"\n"),
            18,
        );
        assert!(err.contains("max_deviation_window"), "{err}");
    }

    /// A pair with only the window keys still gets a breaker. Without the gate change the
    /// old early return leaves it unguarded while its config says otherwise.
    #[test]
    fn a_window_alone_still_builds_a_breaker() {
        let text = breaker_toml(
            "max_deviation_window = \"0.20\"\nmax_deviation_window_blocks = \"1000\"\n",
        );
        let breaker = parse_config(&text, 18).unwrap().pairs[0]
            .breaker
            .expect("a window alone arms the breaker");
        assert_eq!(breaker.threshold_scaled, None);
        assert!(breaker.window.is_some());
    }

    /// The cap catches an extra digit before it allocates an hours-long buffer.
    #[test]
    fn an_implausible_block_count_is_refused() {
        let err = parse_err(
            &breaker_toml(
                "max_deviation_window = \"0.20\"\nmax_deviation_window_blocks = \"100000\"\n",
            ),
            18,
        );
        assert!(err.contains("7200"), "{err}");
    }

    /// The windowed threshold inherits every check the tick threshold already has.
    #[test]
    fn the_window_threshold_is_validated_like_the_tick_threshold() {
        for (keys, expected) in [
            ("max_deviation_window = \"0\"\n", "zero"),
            ("max_deviation_window = \"20\"\n", "fraction"),
        ] {
            let text = breaker_toml(&format!("{keys}max_deviation_window_blocks = \"1000\"\n"));
            let err = parse_err(&text, 18);
            assert!(err.contains(expected), "{keys} gave {err}");
        }
    }

    /// A feed pair with `guards` written after its keys, the way an operator would.
    fn with_guards(guards: &str) -> String {
        format!(
            "target = \"{TARGET}\"\n\n[[pairs]]\ntokens = [\"{WETH}\", \"{USDC}\"]\n\
             symbol = \"ETHUSDC\"\nkey_env = \"K_WETH_USDC\"\n{guards}\n\
             [[builder]]\nname = \"b\"\nendpoint = \"wss://b.example/ws\"\napi_key = \"k\"\n"
        )
    }

    /// Guard stanzas are kept as written, `kind` included, in file order: the order they
    /// run in after the deviation guard, and what a reload compares.
    #[test]
    fn a_guards_stanza_parses_in_order() {
        let config = parse_config(
            &with_guards(
                "[[pairs.guards]]\nkind = \"dispersion\"\nmax_spread = \"0.003\"\n\
                 [[pairs.guards]]\nkind = \"cap\"\nlimit = 2\n",
            ),
            18,
        )
        .expect("parses");
        let guards = &config.pairs[0].guards;
        assert_eq!(
            guards.iter().map(|g| g.kind.as_str()).collect::<Vec<_>>(),
            ["dispersion", "cap"]
        );
        assert_eq!(
            guards[0].config.get("max_spread").and_then(|v| v.as_str()),
            Some("0.003")
        );
        assert_eq!(
            guards[0].config.get("kind").and_then(|v| v.as_str()),
            Some("dispersion"),
            "kept as written, kind included"
        );
        assert_eq!(
            guards[1].config.get("limit").and_then(|v| v.as_integer()),
            Some(2)
        );
        let none = parse_config(&with_guards(""), 18).expect("parses");
        assert!(none.pairs[0].guards.is_empty());
    }

    #[test]
    fn a_guard_stanza_without_kind_is_refused() {
        let err = format!(
            "{:#}",
            parse_config(
                &with_guards("[[pairs.guards]]\nmax_spread = \"0.003\"\n"),
                18
            )
            .err()
            .expect("refused")
        );
        assert!(
            err.contains("[[pairs.guards]]") && err.contains("kind"),
            "{err}"
        );
        let err = format!(
            "{:#}",
            parse_config(&with_guards("[[pairs.guards]]\nkind = 7\n"), 18)
                .err()
                .expect("refused")
        );
        assert!(err.contains("must be a string"), "{err}");
    }

    /// The deviation guard is configured with its own keys; naming it in a stanza is refused
    /// pointing at them, so a reserved name never reads as an unknown kind.
    #[test]
    fn the_deviation_guard_cannot_be_a_stanza() {
        let err = format!(
            "{:#}",
            parse_config(&with_guards("[[pairs.guards]]\nkind = \"deviation\"\n"), 18)
                .err()
                .expect("refused")
        );
        assert!(err.contains("max_deviation"), "{err}");
    }

    #[test]
    fn a_guard_kind_repeated_on_one_pair_is_refused() {
        let err = format!(
            "{:#}",
            parse_config(
                &with_guards(
                    "[[pairs.guards]]\nkind = \"cap\"\n[[pairs.guards]]\nkind = \"cap\"\n"
                ),
                18
            )
            .err()
            .expect("refused")
        );
        assert!(err.contains("`cap`") && err.contains("twice"), "{err}");
    }

    /// The backoffice's serde round-trip keeps a stanza it cannot interpret, so an operator
    /// editing an unrelated field through the page does not lose a guard.
    #[test]
    fn the_backoffice_round_trip_keeps_a_guards_stanza() {
        let text = with_guards("[[pairs.guards]]\nkind = \"dispersion\"\nmax_spread = \"0.003\"\n");
        let original: RawConfig = toml::from_str(&text).unwrap();
        let rendered = render_raw(&original).unwrap();
        let again: RawConfig = toml::from_str(&rendered).unwrap();
        assert_eq!(original.pairs[0].guards, again.pairs[0].guards);
        assert_eq!(
            parse_config(&rendered, 18)
                .expect("a rendered config must load")
                .pairs[0]
                .guards
                .len(),
            1
        );
    }

    #[test]
    fn a_pricing_stanza_names_a_custom_kind_and_keeps_its_market() {
        let config = parse_config(tests_support::CUSTOM, 18).expect("parses");
        match &config.pairs[0].source {
            SourceSpec::Custom {
                kind,
                config: table,
                feeds,
            } => {
                assert_eq!(kind, "skewed");
                assert_eq!(
                    table.get("half_spread").and_then(|v| v.as_float()),
                    Some(0.0005)
                );
                assert!(feeds.is_some(), "symbol stays the reference market");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_stanza_refuses_the_built_in_keys_and_the_built_in_kinds() {
        let mixed = tests_support::CUSTOM.replace(
            "key_env = \"UPDATER_KEY_WETH_USDC\"",
            "key_env = \"UPDATER_KEY_WETH_USDC\"\ndelta = \"0.001\"",
        );
        let err = format!("{:#}", parse_config(&mixed, 18).err().expect("refused"));
        assert!(
            err.contains("[pairs.pricing]") && err.contains("delta"),
            "{err}"
        );
        for builtin in ["fixed", "feed", "volatile"] {
            let err = format!(
                "{:#}",
                parse_config(&tests_support::custom(builtin), 18)
                    .err()
                    .expect("refused")
            );
            assert!(err.contains("built in"), "{builtin}: {err}");
        }
        let err = format!(
            "{:#}",
            parse_config(
                &tests_support::CUSTOM.replace("kind = \"skewed\"\n", ""),
                18
            )
            .err()
            .expect("refused")
        );
        assert!(err.contains("kind"), "{err}");
    }
}

#[cfg(test)]
mod builders_tests {
    use super::*;

    const TWO: &str = r#"
        [[builder]]
        name = "titan"
        endpoint = "wss://eu.rpc.titanbuilder.xyz/ws/sendquoteupdate"
        api_key = "tb_live_key"

        [[builder]]
        name = "buildernet"
        endpoint = "wss://relay.buildernet.org/ws/sendquoteupdate"
        api_key = "bn_key"
        disable_cross_region = true
    "#;

    #[test]
    fn parses_several_builders() {
        let config = BuildersConfig::parse(TWO).unwrap();
        assert_eq!(config.builders.len(), 2);
        assert_eq!(config.builders[0].name, "titan");
        assert_eq!(
            config.builders[0].endpoint,
            "wss://eu.rpc.titanbuilder.xyz/ws/sendquoteupdate"
        );
        assert_eq!(config.builders[0].api_key, "tb_live_key");
        assert_eq!(config.builders[0].disable_cross_region, None);
        assert_eq!(config.builders[1].disable_cross_region, Some(true));
    }

    /// The per-builder field wins where it is set; elsewhere the global flag governs.
    #[test]
    fn per_builder_cross_region_overrides_the_global_default() {
        let config = BuildersConfig::parse(TWO).unwrap();
        assert!(!config.builders[0].disable_cross_region_or(false));
        assert!(config.builders[0].disable_cross_region_or(true));
        // Set explicitly, so the global cannot turn it off.
        assert!(config.builders[1].disable_cross_region_or(false));
        assert!(config.builders[1].disable_cross_region_or(true));
    }

    /// The whole point of deny_unknown_fields: in a file of secrets and destinations, a
    /// typo must be an error, never a silent default. `api-key` would leave the key empty
    /// and `disable_cross_regoin` would quote cross-region at a builder meant to be pinned.
    #[test]
    fn rejects_misspelled_fields() {
        for bad in [
            r#"[[builder]]
               name = "a"
               endpoint = "wss://e/x"
               api-key = "k""#,
            r#"[[builder]]
               name = "a"
               endpoint = "wss://e/x"
               apikey = "k""#,
            r#"[[builder]]
               name = "a"
               endpoint = "wss://e/x"
               api_key = "k"
               disable_cross_regoin = true"#,
            // A misspelled table name yields no builders at all rather than one.
            r#"[[bulider]]
               name = "a"
               endpoint = "wss://e/x"
               api_key = "k""#,
        ] {
            assert!(BuildersConfig::parse(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn rejects_an_empty_builder_list() {
        let err = BuildersConfig::parse("").unwrap_err().to_string();
        assert!(err.contains("at least one"), "unhelpful error: {err}");
    }

    #[test]
    fn rejects_duplicate_names_and_names_the_duplicate() {
        let dup = r#"
            [[builder]]
            name = "titan"
            endpoint = "wss://eu.example/x"
            api_key = "k1"

            [[builder]]
            name = "titan"
            endpoint = "wss://us.example/x"
            api_key = "k2"
        "#;
        let err = BuildersConfig::parse(dup).unwrap_err().to_string();
        assert!(
            err.contains("titan"),
            "error must name the duplicate: {err}"
        );
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(
            BuildersConfig::parse(
                r#"[[builder]]
                   name = ""
                   endpoint = "wss://e/x"
                   api_key = "k""#
            )
            .is_err()
        );
    }

    /// An https:// endpoint is the mistake a docs page invites; it must not reach connect.
    #[test]
    fn rejects_an_endpoint_that_is_not_a_websocket_url() {
        for bad in ["https://eu.example/x", "eu.example/x", "not a url", ""] {
            let toml = format!(
                r#"[[builder]]
                   name = "quasar"
                   endpoint = "{bad}"
                   api_key = "k""#
            );
            let err = BuildersConfig::parse(&toml).unwrap_err().to_string();
            assert!(err.contains("quasar"), "error must name the builder: {err}");
        }
        // Both WebSocket schemes are accepted; ws:// is what the local mock serves.
        for good in [
            "ws://127.0.0.1:8560/ws/sendquoteupdate",
            "wss://eu.example/x",
        ] {
            let toml = format!(
                r#"[[builder]]
                   name = "a"
                   endpoint = "{good}"
                   api_key = "k""#
            );
            assert!(BuildersConfig::parse(&toml).is_ok(), "rejected: {good}");
        }
    }

    #[test]
    fn rejects_an_empty_api_key() {
        let err = BuildersConfig::parse(
            r#"[[builder]]
               name = "quasar"
               endpoint = "wss://e/x"
               api_key = """#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("quasar"), "error must name the builder: {err}");
    }

    /// BuilderClient::connect parses the key into a header value. Checking it here means a
    /// key with a stray newline names the builder that carries it, at startup, instead of
    /// failing anonymously on the first connect.
    #[test]
    fn rejects_an_api_key_that_is_not_a_valid_header_value() {
        let err = BuildersConfig::parse(
            "[[builder]]\nname = \"quasar\"\nendpoint = \"wss://e/x\"\napi_key = \"line\\nbreak\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("quasar"), "error must name the builder: {err}");
    }

    #[test]
    fn load_reports_a_missing_file_with_its_path() {
        let err = BuildersConfig::load(Path::new("/nonexistent/builders.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/builders.toml"), "{err}");
    }
}

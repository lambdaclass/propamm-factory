//! Records, into the indexer's Postgres, what nothing on chain provides and the P&L work
//! needs: the Binance mid of every symbol we price from, each pair's vault balances, the
//! working behind every update we publish (the feed mid, the spread terms, σ, the skew),
//! and every configuration the pusher has run. The feed task hands over every tick, the
//! vault exporter every reading, the quote loop every signed update and the reload path
//! every config; one writer task decides what is worth a row and writes it, so quoting
//! never waits on the database. See README.md ("Recording the feed") for the tables and
//! their rules.
//!
//! Two halves. [`Recorder`] is the handle the producers hold: a mutex around the latest
//! mid per symbol and bounded lists of everything else, so `book()` costs a lock and a map
//! insert on the feed's hot path. [`spawn`] is the writer: once a second it
//! takes what the producers left, keeps the rows the cadence rule says to keep, and writes
//! them in one statement per table. The rule and the row shapes are plain data, tested
//! without a database; the database is only in `Writer`.
//!
//! Failure never reaches quoting. No database, a refused connection, a full disk: the
//! writer logs it, keeps a bounded backlog, and retries with backoff. What is lost when the
//! backlog overflows is dashboard history, which the backfill (indexer/backfill) can
//! reconstruct from Binance's public candles; what is never lost is a quote.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use ethrex_common::{Address, U256};
use tokio_postgres::NoTls;

use crate::supervisor::Shutdown;

/// A mid row at least this often while the price sits still, so a gap in the table means
/// the recorder was down rather than the market was quiet. A row is otherwise written only
/// when the mid changed, which bounds the table by how often the price moves (about 3 GB a
/// year for two pairs, measured on the backfill) and not by the tick rate.
pub const MID_HEARTBEAT_SECS: i64 = 60;
/// Same for balances: the exporter reads every 12s, a row lands when a balance changed or
/// this long has passed.
pub const BALANCE_HEARTBEAT_SECS: i64 = 300;
/// How often the writer looks at what the producers left.
const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// Rows kept while the database is unreachable, before the oldest are dropped: an hour of
/// two symbols changing every second.
const MAX_BACKLOG: usize = 7_200;
/// Balance readings kept between flushes. The exporter leaves a handful every 12s; this
/// only matters if the writer is stuck for a very long time.
const MAX_PENDING_BALANCES: usize = 4_096;
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// The latest book a feed reported for one symbol, in market orientation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Book {
    pub mid: f64,
    pub bid: f64,
    pub ask: f64,
}

/// A vault balance as the exporter read it: raw token units, read AT `block` (not merely
/// after it), so the P&L join ("the inventory during fill i" is the newest row for the pair's
/// vault with `block_number <= the fill's block`) lines up with the swaps table. `ts` is that
/// block's own timestamp, the same meaning the backfill gives the column. Keyed by vault as
/// well as token: with vaults per pair, one token can sit in two vaults of one pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceReading {
    pub prop_amm: Address,
    pub vault: Address,
    pub token: Address,
    pub block: u64,
    pub ts: i64,
    pub balance: U256,
}

/// A token's on-chain symbol and decimals, for `feed.tokens`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRow {
    pub address: Address,
    pub symbol: String,
    pub decimals: u32,
}

/// The working behind one published update, as `ValueSource::current_detailed` decided it,
/// in lane orientation and human units (`scaled_to_f64`; the exact integers are on chain in
/// `price_updates`). `pricing` is `None` for a fixed-spread pair.
#[derive(Clone, Debug, PartialEq)]
pub struct QuoteRow {
    pub prop_amm: Address,
    pub lane: U256,
    pub label: String,
    pub block: u64,
    /// Wall clock when the update was signed, in both modes: when the feed mid was read.
    pub ts: i64,
    pub feed_mid: f64,
    pub published_mid: f64,
    pub delta: f64,
    pub pricing: Option<crate::update::Pricing>,
    /// A registered pricer's declared diagnostics as of this update, by name: the row's
    /// `terms` jsonb. `None` for the built-ins, whose volatile working has columns of its
    /// own (`pricing`), so the data API falls back to those.
    pub terms: Option<serde_json::Value>,
}

/// The `terms` map for a row: a pricer's declared diagnostics by name, or `None` when it
/// declared none, so a built-in's row carries `null` rather than `{}`. A diagnostic with no
/// reading (NaN: blanked when the lane was adopted, and not set by any tick since) is left
/// out of the map rather than written as a `null` among the numbers.
pub(crate) fn terms_from(diagnostics: &[(String, f64)]) -> Option<serde_json::Value> {
    if diagnostics.is_empty() {
        return None;
    }
    Some(serde_json::Value::Object(
        diagnostics
            .iter()
            .filter(|(_, value)| value.is_finite())
            .map(|(name, value)| (name.clone(), serde_json::json!(value)))
            .collect(),
    ))
}

/// One configuration the pusher ran: the file as JSON, secrets redacted, and why it was
/// read (`startup`, or `reload`). The writer keeps a row when the file changed since the
/// last one this process recorded, judged on the file itself (`unredacted`), or else when
/// the JSON differs from the newest row, so a restart on an unchanged file adds nothing and
/// the newest row's `ts` is when the running config last changed.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigSnapshot {
    pub ts: i64,
    pub source: String,
    pub config: serde_json::Value,
    pub unredacted: Unredacted,
}

impl ConfigSnapshot {
    pub fn new(ts: i64, source: &str, raw: &crate::config::RawConfig) -> ConfigSnapshot {
        ConfigSnapshot {
            ts,
            source: source.to_owned(),
            config: redacted_config(raw),
            unredacted: Unredacted(serde_json::to_value(raw).unwrap_or(serde_json::Value::Null)),
        }
    }
}

/// The config as the file says it, secrets and all: what decides whether a snapshot is a
/// change, held in this process's memory beside the parsed config it came from and never
/// written. Its `Debug` prints nothing of it.
#[derive(Clone, PartialEq)]
pub struct Unredacted(serde_json::Value);

impl std::fmt::Debug for Unredacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unredacted(..)")
    }
}

/// Whether `next` is a change from `last`, the newest config this process recorded, judged
/// on the files rather than on the redacted JSON: a change only inside a redacted value (a
/// rotated key, or `token_decimals`, which the name rule blanks beside the credentials)
/// leaves the JSON identical, and the database's rule alone would record nothing.
///
/// `Some` with the position, from one as `feed.pairs.ord` counts them, of every pair whose
/// stanza changed, so its `config_changed_at` can move even where its recorded stanza did
/// not; `None` when nothing changed, or when there is no `last`: the first config a process
/// records has only the stored row to be compared with, which is redacted, so the database
/// decides that one, and a change made only to a secret while the process was down is the
/// one change this cannot see.
fn change_since(last: Option<&Unredacted>, next: &Unredacted) -> Option<Vec<i32>> {
    let last = last?;
    if *last == *next {
        return None;
    }
    let pairs = |config: &Unredacted| -> Vec<serde_json::Value> {
        config.0["pairs"].as_array().cloned().unwrap_or_default()
    };
    // A pair is its two tokens, case and order aside, as `feed.apply_config` keys it.
    let identity = |pair: &serde_json::Value| -> Option<(String, String)> {
        let tokens = pair["tokens"].as_array()?;
        let mut tokens: Vec<String> = tokens
            .iter()
            .map(|token| token.as_str().unwrap_or_default().to_ascii_lowercase())
            .collect();
        tokens.sort();
        Some((tokens.first()?.clone(), tokens.get(1)?.clone()))
    };
    let before = pairs(last);
    let changed = pairs(next)
        .iter()
        .enumerate()
        .filter(|(_, pair)| {
            // A pair that is new here starts its own run in `feed.pairs` already.
            before
                .iter()
                .find(|old| identity(old).is_some() && identity(old) == identity(pair))
                .is_some_and(|old| old != *pair)
        })
        .filter_map(|(i, _)| i32::try_from(i + 1).ok())
        .collect();
    Some(changed)
}

/// Published updates kept between flushes: one per block per pair, so this is minutes of
/// stall for a handful of pairs.
const MAX_PENDING_QUOTES: usize = 4_096;

/// A pair's vault holdings as the vault exporter last read them, keyed by the pair's lane:
/// token0 and token1 in address order, whole tokens, with the symbols the exporter read,
/// which say which of the two a quote's label names as its base.
#[derive(Clone, Debug, PartialEq)]
pub struct Holdings {
    pub amount0: f64,
    pub amount1: f64,
    pub symbol0: String,
    pub symbol1: String,
}

/// A quote with what a spread panel needs beside it, stamped when it was signed:
/// `feed.quotes`' `balance0`, `balance1` and `ref_mid` (see feed.sql).
#[derive(Clone, Debug, PartialEq)]
struct RecordedQuote {
    row: QuoteRow,
    balance0: Option<f64>,
    balance1: Option<f64>,
    ref_mid: Option<f64>,
}

/// The newest of everything, kept across flushes (unlike `Pending`, which the writer empties
/// every second), for stamping quotes.
#[derive(Default)]
struct Latest {
    /// The newest mid per `feed.mids` key.
    mids: HashMap<String, f64>,
    holdings: HashMap<(Address, U256), Holdings>,
}

impl Latest {
    /// The stamp for `row`: its pair's holdings, and the Binance mid of its market, the one
    /// `feed.marked_fills` marks against: the base's name in exchange markets followed by the
    /// quote's (`ETHUSDC` for WETH/USDC), base and quote as the label declares them. That mid
    /// is quote per base; the row is in lane orientation, so it is turned over when the base
    /// is token1, the same test the dashboard makes (the label's first symbol is token1's).
    fn stamp(&self, row: QuoteRow) -> RecordedQuote {
        let holdings = self.holdings.get(&(row.prop_amm, row.lane));
        let ref_mid = holdings.and_then(|h| {
            let base_is_token1 = row.label.split('/').next() == Some(h.symbol1.as_str());
            let (base, quote) = if base_is_token1 {
                (&h.symbol1, &h.symbol0)
            } else {
                (&h.symbol0, &h.symbol1)
            };
            let market = |sym: &str| crate::venues::unwrap_alias(&sym.to_uppercase()).to_owned();
            let mid = *self
                .mids
                .get(&format!("{}{}", market(base), market(quote)))?;
            Some(if base_is_token1 { 1.0 / mid } else { mid })
        });
        RecordedQuote {
            balance0: holdings.map(|h| h.amount0),
            balance1: holdings.map(|h| h.amount1),
            ref_mid,
            row,
        }
    }
}

#[derive(Default)]
struct Pending {
    books: HashMap<String, Book>,
    balances: Vec<BalanceReading>,
    dropped_balances: u64,
    quotes: Vec<RecordedQuote>,
    dropped_quotes: u64,
    configs: Vec<ConfigSnapshot>,
    tokens: Vec<TokenRow>,
    latest: Latest,
}

/// What the feed and the vault exporter hold. Cheap to clone; every clone feeds one writer.
#[derive(Clone, Default)]
pub struct Recorder(Arc<Mutex<Pending>>);

impl Recorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The key a venue's market is recorded under. Binance markets keep their bare symbol:
    /// the whole of `feed.mids` before venues were plural is Binance data under that key,
    /// the backfill (`indexer/backfill`) still fills it from Binance candles under it, and
    /// the P&L queries join on it. Every other venue is `VENUE:SYMBOL`, and a pair's
    /// composite is recorded under its label by `composite.rs`.
    pub fn mid_key(venue: crate::venue::VenueId, symbol: &str) -> String {
        if venue == crate::venue::VenueId::Binance {
            symbol.to_uppercase()
        } else {
            format!(
                "{}:{}",
                venue.as_str().to_uppercase(),
                symbol.to_uppercase()
            )
        }
    }

    /// The latest book for `symbol`: the market mid (whichever way the lane carries it, so
    /// two lanes on one symbol record one series) and the half-spread as a fraction of it.
    /// Overwrites the previous tick: the writer samples once a second, and only the last
    /// book of that second can become a row.
    pub fn book(&self, symbol: &str, mid: f64, half_spread: f64) {
        if mid <= 0.0 || !mid.is_finite() || !half_spread.is_finite() {
            return;
        }
        let book = Book {
            mid,
            bid: mid * (1.0 - half_spread),
            ask: mid * (1.0 + half_spread),
        };
        // Upper case, whatever the config wrote: the backfill and the dashboard use the
        // Binance spelling, and two spellings would be two series for one market.
        let key = symbol.to_uppercase();
        let mut pending = lock(&self.0);
        pending.latest.mids.insert(key.clone(), mid);
        pending.books.insert(key, book);
    }

    /// One balance the exporter just read. Bounded: past `MAX_PENDING_BALANCES` the oldest
    /// reading goes, counted so the writer can say so.
    pub fn balance(&self, reading: BalanceReading) {
        let mut pending = lock(&self.0);
        if pending.balances.len() >= MAX_PENDING_BALANCES {
            pending.balances.remove(0);
            pending.dropped_balances += 1;
        }
        pending.balances.push(reading);
    }

    /// One update the quote loop just signed and sent, stamped with the holdings and the
    /// Binance mid as they stand right now. Bounded like balances.
    pub fn quote(&self, row: QuoteRow) {
        let mut pending = lock(&self.0);
        if pending.quotes.len() >= MAX_PENDING_QUOTES {
            pending.quotes.remove(0);
            pending.dropped_quotes += 1;
        }
        let stamped = pending.latest.stamp(row);
        pending.quotes.push(stamped);
    }

    /// A pair's vault holdings, as the vault exporter just read them, for stamping the
    /// quotes signed from now on.
    pub fn holdings(&self, prop_amm: Address, lane: U256, holdings: Holdings) {
        lock(&self.0)
            .latest
            .holdings
            .insert((prop_amm, lane), holdings);
    }

    /// A token's name and decimals, as the vault exporter read them. Once per token per
    /// process, so unbounded.
    pub fn token(&self, row: TokenRow) {
        lock(&self.0).tokens.push(row);
    }

    /// The configuration the pusher is running from now on. Rare, so unbounded.
    pub fn config(&self, snapshot: ConfigSnapshot) {
        lock(&self.0).configs.push(snapshot);
    }

    /// Everything left since the last call, keeping only `latest`, which outlives flushes.
    fn take(&self) -> Pending {
        let mut pending = lock(&self.0);
        let latest = std::mem::take(&mut pending.latest);
        let taken = std::mem::take(&mut *pending);
        pending.latest = latest;
        taken
    }
}

/// What a key's name contains when its value is a credential, matched anywhere in the
/// lowercased name: `api_key`, `X-Api-Key`, `client_secret`, `access_token`,
/// `Authorization`, `credentials`, `passphrase`, `private_pem`, `seed_phrase`. A substring
/// rule over-matches (`token_decimals`, `max_tokens`, `reference_token` are blanked with
/// the credentials), which costs a reader that value and nothing else: whether the config
/// changed is judged on the file itself ([`change_since`]). Under-matching would publish a
/// key, so the list errs this way.
const CREDENTIAL_WORDS: &[&str] = &[
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "auth",
    "credential",
    "bearer",
    "private",
    "mnemonic",
    "seed",
    "cookie",
    "session",
    "jwt",
];

/// Replaces the value of every key (at any depth) whose name suggests a credential, and
/// scrubs every string left under the other names ([`redact_text`]).
fn redact_secrets(table: &mut toml::Table) {
    for (key, value) in table.iter_mut() {
        let name = key.to_ascii_lowercase();
        if CREDENTIAL_WORDS.iter().any(|word| name.contains(word)) {
            *value = toml::Value::String("<redacted>".to_owned());
        } else {
            redact_within(value);
        }
    }
}

/// Into every table a value holds, at any depth: `[[pairs.pricing.venues]]` is an array of
/// tables, and an array's elements have no key of their own for the name check above.
fn redact_within(value: &mut toml::Value) {
    match value {
        toml::Value::Table(inner) => redact_secrets(inner),
        toml::Value::Array(items) => items.iter_mut().for_each(redact_within),
        toml::Value::String(text) => redact_text(text),
        _ => {}
    }
}

/// A string whose key's name said nothing can still hold a credential in its value: an
/// authorization header's `Bearer …`/`Basic …` is dropped, and a URL is cut to scheme and
/// host as `rpc_url` is, since a provider's key rides in the path (`/v2/<key>`), the query
/// (`?apikey=`) or the userinfo, whatever the scheme. A string with no host (`BINANCE:X`,
/// an address) is not a URL and stays.
fn redact_text(text: &mut String) {
    let lower = text.trim_start().to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") {
        *text = "<redacted>".to_owned();
    } else if let Ok(url) = url::Url::parse(text)
        && let Some(host) = url.host_str()
    {
        *text = format!("{}://{host}", url.scheme());
    }
}

/// `RawConfig` as the `feed.config_changes` row stores it: the file, minus what must not be
/// readable by everything that reads the indexer. Every builder's `api_key` is replaced,
/// and the two RPC URLs are cut to scheme and host: a provider URL carries its key in the
/// path (`.../v2/<key>`) or the query, and the host is all a reader needs to know.
pub fn redacted_config(raw: &crate::config::RawConfig) -> serde_json::Value {
    let mut raw = raw.clone();
    for builder in &mut raw.builders {
        builder.api_key = "<redacted>".to_owned();
    }
    // A custom pricer's stanza is recorded as written, and its keys are the pricer's own, so
    // nothing here knows which one is a credential: anything named like one is dropped, and
    // a URL anywhere in it is cut to its host. `EnvSecret` (`{ env = "NAME" }`) is how a
    // stanza takes a secret without holding it; this catches the ones typed in anyway.
    // Residual risk stays with a bare key under a name none of `CREDENTIAL_WORDS` is in.
    for pair in &mut raw.pairs {
        if let Some(stanza) = &mut pair.pricing {
            redact_secrets(stanza);
        }
    }
    raw.settings.rpc_url = raw.settings.rpc_url.as_deref().map(host_only);
    raw.settings.rpc_ws_url = raw.settings.rpc_ws_url.as_deref().map(host_only);
    serde_json::to_value(&raw).unwrap_or(serde_json::Value::Null)
}

/// `https://eth-mainnet.g.alchemy.com/v2/abc123` → `https://eth-mainnet.g.alchemy.com`.
/// Something that is not a URL is not echoed either: it might be the key alone.
fn host_only(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => match parsed.host_str() {
            Some(host) => format!("{}://{host}", parsed.scheme()),
            None => "<redacted>".to_owned(),
        },
        Err(_) => "<redacted>".to_owned(),
    }
}

fn lock(pending: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A row of `feed.mids`.
#[derive(Clone, Debug, PartialEq)]
pub struct MidRow {
    pub symbol: String,
    pub ts: i64,
    pub book: Book,
}

/// The change-or-heartbeat rule, per key, as plain state: "write this if it differs from
/// the last row written, or if the last row is older than the heartbeat". The same rule
/// governs both tables, keyed by symbol for mids and by (pool, token) for balances.
#[derive(Default)]
pub struct Cadence<K, V> {
    last: HashMap<K, (i64, V)>,
}

impl<K: std::hash::Hash + Eq, V: PartialEq + Clone> Cadence<K, V> {
    /// Whether a row for `key` with `value` at `ts` is due, recording it as written if so.
    pub fn due(&mut self, key: K, ts: i64, value: &V, heartbeat_secs: i64) -> bool {
        let due = match self.last.get(&key) {
            Some((last_ts, last_value)) => {
                last_value != value || ts.saturating_sub(*last_ts) >= heartbeat_secs
            }
            None => true,
        };
        if due {
            self.last.insert(key, (ts, value.clone()));
        }
        due
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Turns what the producers left into the rows the cadence rule keeps. Pure, so the whole
/// decision is testable: given these books and these readings after that history, these
/// rows. `now` is the second every mid row is stamped with; balances carry their own block.
fn select_rows(
    pending: Pending,
    now: i64,
    mids: &mut Cadence<String, f64>,
    balances: &mut Cadence<(Address, Address, Address), U256>,
) -> (Vec<MidRow>, Vec<BalanceReading>) {
    let mut mid_rows = Vec::new();
    for (symbol, book) in pending.books {
        if mids.due(symbol.clone(), now, &book.mid, MID_HEARTBEAT_SECS) {
            mid_rows.push(MidRow {
                symbol,
                ts: now,
                book,
            });
        }
    }
    let mut balance_rows = Vec::new();
    for reading in pending.balances {
        if balances.due(
            (reading.prop_amm, reading.vault, reading.token),
            now,
            &reading.balance,
            BALANCE_HEARTBEAT_SECS,
        ) {
            balance_rows.push(reading);
        }
    }
    (mid_rows, balance_rows)
}

/// Runs the writer for the life of the process. Returns once `shutdown` is set and the last
/// rows have been written (or given up on, after one attempt).
#[must_use = "await this at shutdown, or the last second of rows is lost"]
pub fn spawn(
    url: String,
    recorder: Recorder,
    mut shutdown: Shutdown,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut writer = Writer::new(url);
        let mut mids = Cadence::default();
        let mut balances = Cadence::default();
        let mut ticker = tokio::time::interval(FLUSH_EVERY);
        loop {
            // The shutdown signal ends the wait at once rather than at the next tick, so
            // the final flush starts the moment the operator asks to stop. The caller
            // awaits the handle before the process exits (see `finish_recording`).
            let stopping = tokio::select! {
                _ = ticker.tick() => shutdown.is_set(),
                _ = shutdown.wait() => true,
            };
            let mut pending = recorder.take();
            if pending.dropped_balances > 0 {
                tracing::warn!(
                    "[record] {} balance readings dropped before they could be written",
                    pending.dropped_balances
                );
            }
            if pending.dropped_quotes > 0 {
                tracing::warn!(
                    "[record] {} published updates dropped before they could be written",
                    pending.dropped_quotes
                );
            }
            // Quotes and configs have no cadence rule: every one is a row.
            let quote_rows = std::mem::take(&mut pending.quotes);
            let config_rows = std::mem::take(&mut pending.configs);
            writer.tokens.append(&mut pending.tokens);
            let (mid_rows, balance_rows) =
                select_rows(pending, now_secs(), &mut mids, &mut balances);
            writer.queue(mid_rows, balance_rows, quote_rows, config_rows);
            writer.flush().await;
            if stopping {
                return;
            }
        }
    })
}

/// The database side: one connection, made lazily and remade after any error, and the
/// rows waiting for it.
struct Writer {
    url: String,
    client: Option<tokio_postgres::Client>,
    mids: Vec<MidRow>,
    balances: Vec<BalanceReading>,
    quotes: Vec<RecordedQuote>,
    configs: Vec<ConfigSnapshot>,
    tokens: Vec<TokenRow>,
    /// The newest config this writer has put in, unredacted, which the next one is judged a
    /// change against ([`change_since`]). Memory only: a restart starts without one.
    last_config: Option<Unredacted>,
    /// When the next connection attempt may happen, and how long to wait after that one.
    retry_at: Option<tokio::time::Instant>,
    backoff: Duration,
    /// Rows dropped for the backlog cap since the last time it was said.
    dropped: usize,
    /// Writes that failed in a row. Past `MAX_WRITE_FAILURES` the queued rows are dropped:
    /// a batch Postgres rejects for what it contains would otherwise be replayed forever.
    write_failures: u32,
}

/// Consecutive failed writes before the queue is abandoned. Three at the growing backoff
/// spans well over a minute, long enough for a connection blip to have passed; what is
/// still failing then is the statement itself.
const MAX_WRITE_FAILURES: u32 = 3;

impl Writer {
    fn new(url: String) -> Self {
        Self {
            url,
            client: None,
            mids: Vec::new(),
            balances: Vec::new(),
            quotes: Vec::new(),
            configs: Vec::new(),
            tokens: Vec::new(),
            last_config: None,
            retry_at: None,
            backoff: RECONNECT_MIN,
            dropped: 0,
            write_failures: 0,
        }
    }

    fn queue(
        &mut self,
        mids: Vec<MidRow>,
        balances: Vec<BalanceReading>,
        quotes: Vec<RecordedQuote>,
        configs: Vec<ConfigSnapshot>,
    ) {
        // One row per key per batch, the newest winning. Two flushes can land in the same
        // second after a stall (the ticker catches up), and a batch holding the same
        // (symbol, ts) twice is one Postgres rejects whole ("cannot affect row a second
        // time"), so the duplicate is resolved here, where it is cheap, not there.
        for row in mids {
            match self
                .mids
                .iter_mut()
                .find(|r| r.symbol == row.symbol && r.ts == row.ts)
            {
                Some(existing) => *existing = row,
                None => self.mids.push(row),
            }
        }
        for row in balances {
            match self.balances.iter_mut().find(|r| {
                r.prop_amm == row.prop_amm
                    && r.vault == row.vault
                    && r.token == row.token
                    && r.block == row.block
            }) {
                Some(existing) => *existing = row,
                None => self.balances.push(row),
            }
        }
        for row in quotes {
            match self.quotes.iter_mut().find(|r| {
                r.row.prop_amm == row.row.prop_amm
                    && r.row.lane == row.row.lane
                    && r.row.block == row.row.block
            }) {
                Some(existing) => *existing = row,
                None => self.quotes.push(row),
            }
        }
        self.configs.extend(configs);
        for queue_len in [self.mids.len(), self.balances.len(), self.quotes.len()] {
            if queue_len > MAX_BACKLOG {
                self.dropped += queue_len - MAX_BACKLOG;
            }
        }
        if self.mids.len() > MAX_BACKLOG {
            let excess = self.mids.len() - MAX_BACKLOG;
            self.mids.drain(..excess);
        }
        if self.balances.len() > MAX_BACKLOG {
            let excess = self.balances.len() - MAX_BACKLOG;
            self.balances.drain(..excess);
        }
        if self.quotes.len() > MAX_BACKLOG {
            let excess = self.quotes.len() - MAX_BACKLOG;
            self.quotes.drain(..excess);
        }
    }

    fn is_empty(&self) -> bool {
        self.mids.is_empty()
            && self.balances.is_empty()
            && self.quotes.is_empty()
            && self.configs.is_empty()
            && self.tokens.is_empty()
    }

    async fn flush(&mut self) {
        if self.is_empty() {
            return;
        }
        if self.client.is_none() {
            if let Some(at) = self.retry_at
                && tokio::time::Instant::now() < at
            {
                return;
            }
            match self.connect().await {
                Ok(client) => {
                    self.client = Some(client);
                    self.backoff = RECONNECT_MIN;
                    self.retry_at = None;
                    if self.dropped > 0 {
                        tracing::warn!(
                            "[record] connected to postgres; {} rows were dropped while it was unreachable",
                            self.dropped
                        );
                        self.dropped = 0;
                    } else {
                        tracing::info!("[record] connected to postgres");
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "[record] cannot reach postgres ({err:#}); {} mid and {} balance rows waiting, retrying in {:?}",
                        self.mids.len(),
                        self.balances.len(),
                        self.backoff
                    );
                    self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(RECONNECT_MAX);
                    return;
                }
            }
        }
        let Some(client) = self.client.as_mut() else {
            return;
        };
        let result = async {
            if !self.mids.is_empty() {
                insert_mids(client, &self.mids).await?;
                self.mids.clear();
            }
            if !self.balances.is_empty() {
                insert_balances(client, &self.balances).await?;
                self.balances.clear();
            }
            if !self.quotes.is_empty() {
                insert_quotes(client, &self.quotes).await?;
                self.quotes.clear();
            }
            if !self.tokens.is_empty() {
                insert_tokens(client, &self.tokens).await?;
                self.tokens.clear();
            }
            // One at a time, each removed only once it is in: a failure leaves the rest
            // queued for the next flush, like every other row here. Judged against the last
            // one written rather than the last one queued, so a snapshot dropped with a
            // failing batch does not hide the change it carried from the one after it.
            while let Some(snapshot) = self.configs.first() {
                let change = change_since(self.last_config.as_ref(), &snapshot.unredacted);
                insert_config(client, snapshot, change.as_deref()).await?;
                self.last_config = Some(snapshot.unredacted.clone());
                self.configs.remove(0);
            }
            Ok::<(), tokio_postgres::Error>(())
        }
        .await;
        match result {
            Ok(()) => self.write_failures = 0,
            Err(err) => {
                // Drop the connection and let the next flush redial, later each time: a broken
                // socket looks exactly like a rejected statement from here, and redialling
                // costs nothing. A batch that keeps failing is abandoned rather than replayed
                // forever, with the count said out loud; the backfill can refill the gap.
                self.write_failures += 1;
                self.client = None;
                self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
                let wait = self.backoff;
                self.backoff = (self.backoff * 2).min(RECONNECT_MAX);
                if self.write_failures >= MAX_WRITE_FAILURES {
                    tracing::warn!(
                        "[record] write failed {} times in a row ({err}); dropping {} mid, {} balance, {} quote and {} config rows",
                        self.write_failures,
                        self.mids.len(),
                        self.balances.len(),
                        self.quotes.len(),
                        self.configs.len()
                    );
                    self.mids.clear();
                    self.balances.clear();
                    self.quotes.clear();
                    self.configs.clear();
                    self.write_failures = 0;
                } else {
                    tracing::warn!("[record] write failed ({err}); reconnecting in {wait:?}");
                }
            }
        }
    }

    /// Dials, runs the connection on its own task, and makes sure the tables exist.
    async fn connect(&self) -> eyre::Result<tokio_postgres::Client> {
        // Plain TCP: the database is on this host (loopback), see the deploy. A URL asking
        // for TLS is refused here rather than silently downgraded.
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls).await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::warn!("[record] postgres connection ended: {err}");
            }
        });
        migrate(&client).await?;
        Ok(client)
    }
}

/// The schema, created if missing: `indexer/backfill/feed.sql`, the one definition both
/// writers run, compiled in the way the alert rules are (`include_str!` across the repo) so
/// the two can never disagree. Idempotent, and cheap enough to run on every connect.
async fn migrate(client: &tokio_postgres::Client) -> Result<(), tokio_postgres::Error> {
    client.batch_execute(include_str!("../sql/feed.sql")).await
}

/// One statement for the batch. A live row replaces a backfilled one for the same second
/// (the live book is the better measurement); nothing else is ever overwritten.
async fn insert_mids(
    client: &tokio_postgres::Client,
    rows: &[MidRow],
) -> Result<(), tokio_postgres::Error> {
    let symbols: Vec<&str> = rows.iter().map(|r| r.symbol.as_str()).collect();
    let ts: Vec<i64> = rows.iter().map(|r| r.ts).collect();
    let mids: Vec<f64> = rows.iter().map(|r| r.book.mid).collect();
    let bids: Vec<f64> = rows.iter().map(|r| r.book.bid).collect();
    let asks: Vec<f64> = rows.iter().map(|r| r.book.ask).collect();
    client
        .execute(
            "insert into feed.mids (symbol, ts, mid, bid, ask, source)
               select s, t, m, b, a, 'book'
               from unnest($1::text[], $2::int8[], $3::float8[], $4::float8[], $5::float8[]) as r(s, t, m, b, a)
               on conflict (symbol, ts) do update
                 set mid = excluded.mid, bid = excluded.bid, ask = excluded.ask, source = excluded.source
                 where feed.mids.source = 'kline'",
            &[&symbols, &ts, &mids, &bids, &asks],
        )
        .await?;
    Ok(())
}

async fn insert_balances(
    client: &tokio_postgres::Client,
    rows: &[BalanceReading],
) -> Result<(), tokio_postgres::Error> {
    let pools: Vec<String> = rows.iter().map(|r| format!("{:#x}", r.prop_amm)).collect();
    let vaults: Vec<String> = rows.iter().map(|r| format!("{:#x}", r.vault)).collect();
    let tokens: Vec<String> = rows.iter().map(|r| format!("{:#x}", r.token)).collect();
    let blocks: Vec<i64> = rows.iter().map(|r| r.block as i64).collect();
    let ts: Vec<i64> = rows.iter().map(|r| r.ts).collect();
    // As text and cast in SQL: a uint256 has no native Postgres type on this side.
    let balances: Vec<String> = rows.iter().map(|r| r.balance.to_string()).collect();
    client
        .execute(
            "insert into feed.vault_balances (prop_amm, vault, token, block_number, ts, balance)
               select p, v, k, b, t, n::numeric
               from unnest($1::text[], $2::text[], $3::text[], $4::int8[], $5::int8[], $6::text[]) as r(p, v, k, b, t, n)
               on conflict do nothing",
            &[&pools, &vaults, &tokens, &blocks, &ts, &balances],
        )
        .await?;
    Ok(())
}

/// A token already there is overwritten: a symbol can change (a proxy upgrade), and the
/// newest reading is the one to show.
async fn insert_tokens(
    client: &tokio_postgres::Client,
    rows: &[TokenRow],
) -> Result<(), tokio_postgres::Error> {
    // One row per address, or Postgres refuses the whole statement.
    let mut unique: Vec<&TokenRow> = Vec::new();
    for row in rows.iter().rev() {
        if !unique.iter().any(|u| u.address == row.address) {
            unique.push(row);
        }
    }
    let addresses: Vec<String> = unique.iter().map(|r| format!("{:#x}", r.address)).collect();
    let symbols: Vec<&str> = unique.iter().map(|r| r.symbol.as_str()).collect();
    let decimals: Vec<i32> = unique.iter().map(|r| r.decimals as i32).collect();
    client
        .execute(
            "insert into feed.tokens (address, symbol, decimals)
               select a, s, d from unnest($1::text[], $2::text[], $3::int4[]) as r(a, s, d)
               on conflict (address) do update set symbol = excluded.symbol, decimals = excluded.decimals",
            &[&addresses, &symbols, &decimals],
        )
        .await?;
    Ok(())
}

/// One statement for the batch. Builder mode re-signs a block's update every time the feed
/// moves inside the block's window, so the same block can arrive across several flushes;
/// the newest wins, as it does inside one flush, and the row is the last quote sent for
/// that block. What landed is `price_updates`, on chain.
async fn insert_quotes(
    client: &tokio_postgres::Client,
    quotes: &[RecordedQuote],
) -> Result<(), tokio_postgres::Error> {
    let rows: Vec<&QuoteRow> = quotes.iter().map(|q| &q.row).collect();
    let pools: Vec<String> = rows.iter().map(|r| format!("{:#x}", r.prop_amm)).collect();
    // As text and cast in SQL, like balances: a uint256 has no native Postgres type here.
    let lanes: Vec<String> = rows.iter().map(|r| r.lane.to_string()).collect();
    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
    let blocks: Vec<i64> = rows.iter().map(|r| r.block as i64).collect();
    let ts: Vec<i64> = rows.iter().map(|r| r.ts).collect();
    let feed_mids: Vec<f64> = rows.iter().map(|r| r.feed_mid).collect();
    let published: Vec<f64> = rows.iter().map(|r| r.published_mid).collect();
    let deltas: Vec<f64> = rows.iter().map(|r| r.delta).collect();
    let term = |pick: fn(&crate::update::Pricing) -> f64| -> Vec<Option<f64>> {
        rows.iter().map(|r| r.pricing.as_ref().map(pick)).collect()
    };
    let skews = term(|p| p.skew);
    let sigmas = term(|p| p.sigma);
    let holds = term(|p| p.hold);
    let edges = term(|p| p.edge);
    let stales = term(|p| p.stale);
    // A registered pricer's diagnostics, as one jsonb per row (`with-serde_json-1`).
    let terms: Vec<Option<serde_json::Value>> = rows.iter().map(|r| r.terms.clone()).collect();
    let balance0: Vec<Option<f64>> = quotes.iter().map(|q| q.balance0).collect();
    let balance1: Vec<Option<f64>> = quotes.iter().map(|q| q.balance1).collect();
    let ref_mids: Vec<Option<f64>> = quotes.iter().map(|q| q.ref_mid).collect();
    client
        .execute(
            "insert into feed.quotes (prop_amm, lane, label, block_number, ts, feed_mid, published_mid, delta, skew, sigma, hold, edge, stale, balance0, balance1, ref_mid, terms)
               select p, l::numeric, n, b, t, f, m, d, k, s, h, e, a, b0, b1, r, j
               from unnest($1::text[], $2::text[], $3::text[], $4::int8[], $5::int8[], $6::float8[], $7::float8[], $8::float8[], $9::float8[], $10::float8[], $11::float8[], $12::float8[], $13::float8[], $14::float8[], $15::float8[], $16::float8[], $17::jsonb[])
                 as r(p, l, n, b, t, f, m, d, k, s, h, e, a, b0, b1, r, j)
               on conflict (prop_amm, lane, block_number) do update
                 set label = excluded.label, ts = excluded.ts, feed_mid = excluded.feed_mid,
                     published_mid = excluded.published_mid, delta = excluded.delta,
                     skew = excluded.skew, sigma = excluded.sigma, hold = excluded.hold,
                     edge = excluded.edge, stale = excluded.stale,
                     balance0 = excluded.balance0, balance1 = excluded.balance1,
                     ref_mid = excluded.ref_mid, terms = excluded.terms",
            &[
                &pools, &lanes, &labels, &blocks, &ts, &feed_mids, &published, &deltas, &skews,
                &sigmas, &holds, &edges, &stales, &balance0, &balance1, &ref_mids, &terms,
            ],
        )
        .await?;
    Ok(())
}

/// A row when `change` says this process saw the file change ([`change_since`]), or else
/// when the config differs from the newest one stored, so the newest row's `ts` is when the
/// running configuration last changed and a restart on the same file is not a change.
/// `jsonb` equality ignores key order and whitespace.
///
/// `change`'s pairs are the ones whose stanza changed, some perhaps only inside a redacted
/// value: `feed.apply_config` keeps a pair's `config_changed_at` when its recorded stanza is
/// the same, so theirs is moved here, in the same transaction as the row.
async fn insert_config(
    client: &mut tokio_postgres::Client,
    snapshot: &ConfigSnapshot,
    change: Option<&[i32]>,
) -> Result<(), tokio_postgres::Error> {
    let tx = client.transaction().await?;
    tx.execute(
        // `feed.pairs` follows in the same statement, so the two never disagree.
        "with added as (
           insert into feed.config_changes (ts, source, config)
             select $1, $2, $3::jsonb
             where $4 or not exists (
               select 1 from feed.config_changes
               where id = (select max(id) from feed.config_changes) and config = $3::jsonb
             )
             returning id, ts, config
         )
         select feed.apply_config(id, ts, config) from added",
        &[
            &snapshot.ts,
            &snapshot.source,
            &snapshot.config,
            &change.is_some(),
        ],
    )
    .await?;
    if let Some(pairs) = change.filter(|pairs| !pairs.is_empty()) {
        // The row was added (`$4` above), so the newest row is this config's, and `ord` is
        // each pair's position in it.
        tx.execute(
            "update feed.pairs set config_changed_at = $1
               where active and ord = any($2::int4[])
                 and last_config_id = (select max(id) from feed.config_changes)",
            &[&snapshot.ts, &pairs],
        )
        .await?;
    }
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book(mid: f64) -> Book {
        Book {
            mid,
            bid: mid,
            ask: mid,
        }
    }

    #[test]
    fn a_changed_mid_is_due_and_a_flat_one_waits_for_the_heartbeat() {
        let mut c: Cadence<String, f64> = Cadence::default();
        assert!(
            c.due("ETHUSDC".into(), 0, &2500.0, MID_HEARTBEAT_SECS),
            "first ever"
        );
        assert!(
            !c.due("ETHUSDC".into(), 1, &2500.0, MID_HEARTBEAT_SECS),
            "same mid, 1s later"
        );
        assert!(
            c.due("ETHUSDC".into(), 2, &2500.5, MID_HEARTBEAT_SECS),
            "moved"
        );
        assert!(
            !c.due("ETHUSDC".into(), 61, &2500.5, MID_HEARTBEAT_SECS),
            "59s, not yet"
        );
        assert!(
            c.due("ETHUSDC".into(), 62, &2500.5, MID_HEARTBEAT_SECS),
            "heartbeat at 60s"
        );
        // Symbols are independent.
        assert!(c.due("USDCUSDT".into(), 62, &1.0, MID_HEARTBEAT_SECS));
    }

    #[test]
    fn the_recorder_keeps_only_the_last_book_of_a_second_per_symbol() {
        let r = Recorder::new();
        r.book("ETHUSDC", 2500.0, 0.0001);
        r.book("ETHUSDC", 2501.0, 0.0001);
        r.book("USDCUSDT", 1.0, 0.00005);
        let pending = r.take();
        assert_eq!(pending.books.len(), 2);
        let eth = pending.books["ETHUSDC"];
        assert_eq!(eth.mid, 2501.0);
        assert!((eth.bid - 2501.0 * 0.9999).abs() < 1e-9);
        assert!((eth.ask - 2501.0 * 1.0001).abs() < 1e-9);
        // Taking empties it.
        assert!(r.take().books.is_empty());
    }

    #[test]
    fn the_symbol_is_stored_in_binance_spelling() {
        let r = Recorder::new();
        r.book("ethusdc", 2500.0, 0.0001);
        assert!(r.take().books.contains_key("ETHUSDC"));
    }

    #[test]
    fn a_batch_never_holds_one_key_twice() {
        let mut w = Writer::new(String::new());
        let row = |ts: i64, mid: f64| MidRow {
            symbol: "ETHUSDC".into(),
            ts,
            book: book(mid),
        };
        w.queue(vec![row(1, 1.0)], Vec::new(), Vec::new(), Vec::new());
        // A second flush in the same second (the ticker catching up after a stall): the
        // newer book replaces the older row instead of sitting beside it.
        w.queue(vec![row(1, 2.0)], Vec::new(), Vec::new(), Vec::new());
        assert_eq!(w.mids.len(), 1);
        assert_eq!(w.mids[0].book.mid, 2.0);
        w.queue(vec![row(2, 3.0)], Vec::new(), Vec::new(), Vec::new());
        assert_eq!(w.mids.len(), 2);
    }

    #[test]
    fn a_bad_book_is_ignored() {
        let r = Recorder::new();
        r.book("ETHUSDC", 0.0, 0.0001);
        r.book("ETHUSDC", f64::NAN, 0.0001);
        r.book("ETHUSDC", 2500.0, f64::INFINITY);
        assert!(r.take().books.is_empty());
    }

    /// A published update is a row per block per lane, the newest winning if a block is
    /// queued twice, and never more than the backlog.
    #[test]
    fn quotes_queue_one_row_per_block_per_lane() {
        let row = |lane: u64, block: u64, mid: f64| QuoteRow {
            prop_amm: Address::zero(),
            lane: U256::from(lane),
            label: "A/B".into(),
            block,
            ts: 1,
            feed_mid: mid,
            published_mid: mid,
            delta: 0.0005,
            pricing: None,
            terms: None,
        };
        let stamp = |row: QuoteRow| Latest::default().stamp(row);
        let mut writer = Writer::new(String::new());
        writer.queue(
            Vec::new(),
            Vec::new(),
            vec![
                stamp(row(1, 10, 1.0)),
                stamp(row(1, 11, 2.0)),
                stamp(row(2, 10, 3.0)),
            ],
            Vec::new(),
        );
        writer.queue(
            Vec::new(),
            Vec::new(),
            vec![stamp(row(1, 10, 1.5))],
            Vec::new(),
        );
        assert_eq!(writer.quotes.len(), 3);
        assert_eq!(
            writer.quotes[0].row.published_mid, 1.5,
            "the newer row for a block wins"
        );
        assert!(!writer.is_empty());

        let recorder = Recorder::new();
        for block in 0..(MAX_PENDING_QUOTES as u64 + 5) {
            recorder.quote(row(1, block, 1.0));
        }
        let pending = recorder.take();
        assert_eq!(pending.quotes.len(), MAX_PENDING_QUOTES);
        assert_eq!(pending.dropped_quotes, 5);
        assert_eq!(pending.quotes[0].row.block, 5, "the oldest are what goes");
    }

    /// A quote carries its pair's holdings and the Binance mid of its market in lane
    /// orientation: as is when the base is token0, turned over when it is token1.
    #[test]
    fn a_quote_is_stamped_with_holdings_and_the_market_mid() {
        let pool = Address::from_low_u64_be(1);
        let usdc = Address::from_low_u64_be(2);
        let weth = Address::from_low_u64_be(3);
        let usdt = Address::from_low_u64_be(4);
        let weth_lane = crate::config::lane_of(usdc, weth);
        let usdt_lane = crate::config::lane_of(usdc, usdt);
        let quote = |lane: U256, label: &str| QuoteRow {
            prop_amm: pool,
            lane,
            label: label.into(),
            block: 1,
            ts: 1,
            feed_mid: 1.0,
            published_mid: 1.0,
            delta: 0.0005,
            pricing: None,
            terms: None,
        };
        let r = Recorder::new();
        // Nothing read yet: the quote goes out bare.
        r.quote(quote(weth_lane, "WETH/USDC"));
        r.book("ETHUSDC", 2500.0, 0.0001);
        r.book("USDCUSDT", 1.0002, 0.00005);
        r.holdings(
            pool,
            weth_lane,
            Holdings {
                amount0: 10_000.0,
                amount1: 4.0,
                symbol0: "USDC".into(),
                symbol1: "WETH".into(),
            },
        );
        r.holdings(
            pool,
            usdt_lane,
            Holdings {
                amount0: 500.0,
                amount1: 700.0,
                symbol0: "USDC".into(),
                symbol1: "USDT".into(),
            },
        );
        // A flush in between: what quotes are stamped with outlives it.
        let first = r.take();
        assert_eq!(first.quotes[0].balance0, None);
        assert_eq!(first.quotes[0].ref_mid, None);
        r.quote(quote(weth_lane, "WETH/USDC"));
        r.quote(quote(usdt_lane, "USDC/USDT"));
        let pending = r.take();
        let weth = &pending.quotes[0];
        assert_eq!((weth.balance0, weth.balance1), (Some(10_000.0), Some(4.0)));
        // WETH is token1 here, so the lane carries WETH per USDC.
        assert_eq!(weth.ref_mid, Some(1.0 / 2500.0));
        let usdt = &pending.quotes[1];
        assert_eq!((usdt.balance0, usdt.balance1), (Some(500.0), Some(700.0)));
        assert_eq!(usdt.ref_mid, Some(1.0002));
    }

    /// A custom lane's declared diagnostics ride with its row as one JSON map, by name,
    /// bound as `jsonb`; a lane that declared none (every built-in) sends `null`, and the
    /// data API falls back to the volatile columns for it. The map is what the row queued
    /// keeps, the newest per block winning as for every other column.
    #[test]
    fn a_custom_lanes_diagnostics_become_its_terms_json() {
        assert_eq!(terms_from(&[]), None, "no diagnostics, no map");
        let terms = terms_from(&[("edge".to_owned(), 0.25), ("tilt".to_owned(), -0.5)]);
        assert_eq!(
            terms,
            Some(serde_json::json!({ "edge": 0.25, "tilt": -0.5 }))
        );
        // A gauge the lane's adoption blanked and no tick has set yet reads NaN: no reading,
        // left out rather than written as a `null` the API's numbers would have to expect.
        assert_eq!(
            terms_from(&[("edge".to_owned(), f64::NAN), ("tilt".to_owned(), -0.5)]),
            Some(serde_json::json!({ "tilt": -0.5 }))
        );

        let row = |block: u64, terms: Option<serde_json::Value>| QuoteRow {
            prop_amm: Address::zero(),
            lane: U256::from(1),
            label: "A/B".into(),
            block,
            ts: 1,
            feed_mid: 1.0,
            published_mid: 1.0,
            delta: 0.0005,
            pricing: None,
            terms,
        };
        let stamp = |row: QuoteRow| Latest::default().stamp(row);
        let mut writer = Writer::new(String::new());
        writer.queue(
            Vec::new(),
            Vec::new(),
            vec![stamp(row(10, None)), stamp(row(10, terms.clone()))],
            Vec::new(),
        );
        assert_eq!(writer.quotes.len(), 1);
        assert_eq!(
            writer.quotes[0].row.terms, terms,
            "the newer row's map wins"
        );
    }

    /// The config row is the file, minus what must not be readable by everything that reads
    /// the indexer.
    #[test]
    fn a_recorded_config_has_no_builder_keys() {
        let raw: crate::config::RawConfig = toml::from_str(
            r#"
target = "0x1111111111111111111111111111111111111111"
[settings]
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/rpc-key"
rpc_ws_url = "wss://mainnet.infura.io/ws/v3/ws-key"
[[pairs]]
tokens = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol = "ETHUSDC"
key_env = "K"
[[builder]]
name = "titan"
endpoint = "wss://x"
api_key = "very-secret"
"#,
        )
        .unwrap();
        let json = redacted_config(&raw);
        let text = json.to_string();
        assert!(!text.contains("very-secret"), "{text}");
        assert!(!text.contains("rpc-key"), "{text}");
        assert!(!text.contains("ws-key"), "{text}");
        assert_eq!(json["builder"][0]["api_key"], "<redacted>");
        assert_eq!(
            json["settings"]["rpc_url"],
            "https://eth-mainnet.g.alchemy.com"
        );
        assert_eq!(json["settings"]["rpc_ws_url"], "wss://mainnet.infura.io");
        assert_eq!(host_only("not a url"), "<redacted>");
        assert_eq!(json["pairs"][0]["symbol"], "ETHUSDC");
        assert_eq!(json["builder"][0]["name"], "titan");
    }

    #[test]
    fn select_rows_applies_both_rules() {
        let mut mids = Cadence::default();
        let mut balances = Cadence::default();
        let pool = Address::from_low_u64_be(1);
        let vault = Address::from_low_u64_be(2);
        let weth = Address::from_low_u64_be(3);
        let reading = |block: u64, balance: u64| BalanceReading {
            prop_amm: pool,
            vault,
            token: weth,
            block,
            ts: block as i64 * 12,
            balance: U256::from(balance),
        };
        let mut pending = Pending::default();
        pending.books.insert("ETHUSDC".into(), book(2500.0));
        pending.balances.push(reading(100, 5));
        let (m, b) = select_rows(pending, 1_000, &mut mids, &mut balances);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].ts, 1_000);
        assert_eq!(b.len(), 1);

        // Twelve seconds on, nothing moved: no rows.
        let mut pending = Pending::default();
        pending.books.insert("ETHUSDC".into(), book(2500.0));
        pending.balances.push(reading(101, 5));
        let (m, b) = select_rows(pending, 1_012, &mut mids, &mut balances);
        assert!(m.is_empty() && b.is_empty());

        // The balance changed, the mid did not.
        let mut pending = Pending::default();
        pending.books.insert("ETHUSDC".into(), book(2500.0));
        pending.balances.push(reading(102, 6));
        let (m, b) = select_rows(pending, 1_024, &mut mids, &mut balances);
        assert!(m.is_empty());
        assert_eq!(b, vec![reading(102, 6)]);

        // Five minutes on, flat: the balance heartbeat lands (the mid's did at 60s).
        let mut pending = Pending::default();
        pending.balances.push(reading(130, 6));
        let (_, b) = select_rows(pending, 1_324, &mut mids, &mut balances);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn the_backlog_is_bounded_and_counts_what_it_dropped() {
        let mut w = Writer::new(String::new());
        let rows: Vec<MidRow> = (0..MAX_BACKLOG as i64 + 10)
            .map(|i| MidRow {
                symbol: "ETHUSDC".into(),
                ts: i,
                book: book(1.0),
            })
            .collect();
        w.queue(rows, Vec::new(), Vec::new(), Vec::new());
        assert_eq!(w.mids.len(), MAX_BACKLOG);
        assert_eq!(w.dropped, 10);
        // The oldest went, the newest stayed.
        assert_eq!(w.mids[0].ts, 10);
    }

    #[test]
    fn a_recorded_stanza_has_no_secrets() {
        let raw: crate::config::RawConfig = toml::from_str(
            r#"target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
[[pairs]]
tokens  = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
key_env = "K"
[pairs.pricing]
kind = "funding"
api_key = "abc"
weight = 0.5
oracle = { env = "ORACLE" }
[pairs.pricing.feed]
token = "t"
url = "https://x.example"
[[builder]]
name = "b"
endpoint = "wss://b.example/ws"
api_key = "k"
"#,
        )
        .unwrap();
        let json = redacted_config(&raw);
        let pricing = &json["pairs"][0]["pricing"];
        assert_eq!(pricing["api_key"], "<redacted>");
        assert_eq!(pricing["feed"]["token"], "<redacted>");
        assert_eq!(pricing["feed"]["url"], "https://x.example");
        assert_eq!(pricing["weight"], 0.5);
        assert_eq!(pricing["kind"], "funding");
        assert_eq!(
            pricing["oracle"]["env"], "ORACLE",
            "a variable's name is not a secret"
        );
    }

    /// `[[pairs.pricing.venues]]` is an array of tables, one level the table walk alone never
    /// entered: the credential in each element must be dropped like the one beside `kind`.
    #[test]
    fn a_secret_in_an_array_of_tables_is_redacted_too() {
        let raw: crate::config::RawConfig = toml::from_str(
            r#"target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
[[pairs]]
tokens  = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
key_env = "K"
[pairs.pricing]
kind = "funding"
[[pairs.pricing.venues]]
name = "a"
api_key = "SECRET-A"
[[pairs.pricing.venues]]
name = "b"
extra = [{ token = "SECRET-B" }]
[[builder]]
name = "b"
endpoint = "wss://b.example/ws"
api_key = "k"
"#,
        )
        .unwrap();
        let json = redacted_config(&raw);
        let venues = &json["pairs"][0]["pricing"]["venues"];
        assert_eq!(venues[0]["api_key"], "<redacted>");
        assert_eq!(venues[0]["name"], "a");
        assert_eq!(
            venues[1]["extra"][0]["token"], "<redacted>",
            "arrays nest too"
        );
        assert!(!json.to_string().contains("SECRET"), "{json}");
    }

    /// A credential goes by many names, and a URL carries one in its path or query whatever
    /// its key is called: neither may reach `feed.config_changes`, `feed.pairs`, Grafana or
    /// the data API.
    #[test]
    fn a_stanza_credential_by_any_common_name_or_inside_a_url_is_redacted() {
        let raw: crate::config::RawConfig = toml::from_str(
            r#"target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
[[pairs]]
tokens  = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
key_env = "K"
[pairs.pricing]
kind = "funding"
passphrase = "SECRET-1"
auth = "SECRET-2"
credentials = "SECRET-3"
bearer = "SECRET-4"
signer_private_pem = "SECRET-5"
mnemonic = "SECRET-6"
seed_phrase = "SECRET-7"
cookie = "SECRET-8"
rpc = "https://eth.example/v2/SECRET-9"
feed = "wss://feed.example/ws?apikey=SECRET-10"
mirrors = ["https://user:SECRET-11@a.example:8443/x"]
note = "Bearer SECRET-12"
weight = 0.5
market = "BINANCE:ETHUSDC"
[pairs.pricing.headers]
Authorization = "Basic SECRET-13"
X-Custom = "plain"
[[builder]]
name = "b"
endpoint = "wss://b.example/ws"
api_key = "k"
"#,
        )
        .unwrap();
        let json = redacted_config(&raw);
        assert!(!json.to_string().contains("SECRET"), "{json}");
        let pricing = &json["pairs"][0]["pricing"];
        assert_eq!(pricing["rpc"], "https://eth.example");
        assert_eq!(pricing["feed"], "wss://feed.example");
        assert_eq!(pricing["mirrors"][0], "https://a.example");
        assert_eq!(pricing["headers"]["Authorization"], "<redacted>");
        assert_eq!(pricing["headers"]["X-Custom"], "plain");
        assert_eq!(pricing["weight"], 0.5);
        assert_eq!(
            pricing["market"], "BINANCE:ETHUSDC",
            "a scheme without a host is not a URL anything is hidden in"
        );
    }

    /// A stanza as `change_since` compares them: the first pair's `token_decimals` and
    /// `api_key` are both blanked in what is recorded, the second pair has nothing redacted.
    fn snapshot(decimals: u32, api_key: &str, builder_key: &str) -> ConfigSnapshot {
        let raw: crate::config::RawConfig = toml::from_str(&format!(
            r#"target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
[[pairs]]
tokens  = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
key_env = "K"
[pairs.pricing]
kind = "funding"
token_decimals = {decimals}
api_key = "{api_key}"
[[pairs]]
tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol  = "ETHUSDC"
key_env = "L"
[[builder]]
name = "b"
endpoint = "wss://b.example/ws"
api_key = "{builder_key}"
"#
        ))
        .unwrap();
        ConfigSnapshot::new(1_755_000_000, "reload", &raw)
    }

    /// The row is written when the config changed, not when its redacted JSON did: a change
    /// only inside a redacted value (a rotated key, or `token_decimals`, which the name rule
    /// blanks beside the credentials) leaves the JSON identical and is still a change, of
    /// the pair it was in.
    #[test]
    fn a_change_only_to_a_redacted_value_is_still_a_change() {
        let first = snapshot(6, "a", "k");
        for (changed, pairs) in [
            (snapshot(18, "a", "k"), vec![1]),
            (snapshot(6, "b", "k"), vec![1]),
            (snapshot(6, "a", "k2"), vec![]),
        ] {
            assert_eq!(
                first.config, changed.config,
                "invisible in what is recorded"
            );
            assert_eq!(
                change_since(Some(&first.unredacted), &changed.unredacted),
                Some(pairs)
            );
        }
        // The same file again is no change. The first config a process records has only the
        // stored row to be compared with, which is redacted: the database decides that one.
        assert_eq!(
            change_since(Some(&first.unredacted), &snapshot(6, "a", "k").unredacted),
            None
        );
        assert_eq!(change_since(None, &first.unredacted), None);
    }

    #[test]
    fn a_snapshot_never_prints_the_config_it_was_taken_from() {
        let printed = format!("{:?}", snapshot(6, "very-secret", "builder-secret"));
        assert!(
            !printed.contains("very-secret") && !printed.contains("builder-secret"),
            "{printed}"
        );
    }
}

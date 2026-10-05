//! What the vault holds, read straight off the chain.
//!
//! Each pair of the PropAMM fills from its own vault, `target.vaultFor(token0, token1)`,
//! and two things want to know those vaults' balances: a volatile pair, whose skew tilts
//! off the share of its two tokens (`volatile::spawn_inventory` reads them through
//! [`read_balance`]), and the operator, who wants every vault's balance of every token on
//! a dashboard regardless of which pair prices off it ([`spawn_vault_exporter`]). Both are
//! here so the ERC-20 plumbing lives in one place.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethrex_common::{Address, U256};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_sdk::calldata::encode_calldata;
use ethrex_rpc::clients::eth::EthClient;
use ethrex_rpc::types::block_identifier::BlockIdentifier;
use eyre::{Result, WrapErr, eyre};

use crate::{
    call_view,
    feed::scaled_to_f64,
    metrics::Metrics,
    preflight::{decode_one, token_symbol},
    volatile::INVENTORY_REFRESH,
};

/// One vault's live reader, held by every lane that reads the vault. The poller behind
/// the receiver stops when the last holder drops this, since the channel's sender sees no
/// receiver left.
pub(crate) struct SharedReader {
    pub(crate) rx: tokio::sync::watch::Receiver<crate::volatile::Inventory>,
}

/// One vault, as the readers are keyed: `(target, base, quote)`.
type VaultKey = (Address, Address, Address);

/// The live readers, weakly: see [`InventoryReaders`].
type Registry = std::collections::HashMap<VaultKey, std::sync::Weak<SharedReader>>;

/// The process's inventory readers, one per `(target, base, quote)`: a volatile lane and a
/// custom lane on the same vault, or two lanes across a reload's hand-over, share one
/// poller rather than each polling the chain every 12s. Weak entries, so the registry
/// keeps no reader alive: a vault nobody reads any more is not polled.
#[derive(Clone)]
pub(crate) struct InventoryReaders {
    inner: Arc<std::sync::Mutex<Registry>>,
    /// How often a reader re-reads its vault: [`INVENTORY_REFRESH`], or what a test set.
    refresh: std::time::Duration,
}

impl Default for InventoryReaders {
    fn default() -> Self {
        InventoryReaders {
            inner: Arc::default(),
            refresh: INVENTORY_REFRESH,
        }
    }
}

impl InventoryReaders {
    /// The readers' refresh interval, for a test that cannot wait out the real one.
    #[cfg(test)]
    pub(crate) fn with_refresh(mut self, refresh: std::time::Duration) -> Self {
        self.refresh = refresh;
        self
    }

    /// How often a reader started through this registry re-reads its vault.
    pub(crate) fn refresh(&self) -> std::time::Duration {
        self.refresh
    }

    /// The live reader for this vault, if a lane holds one.
    pub(crate) fn get(&self, key: VaultKey) -> Option<Arc<SharedReader>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .and_then(std::sync::Weak::upgrade)
    }

    /// Registers a reader just started for this vault, and hands back the handle the
    /// caller keeps. Two lanes that both missed the registry while connecting (each read
    /// the vault and started a poller) leave the later one registered; the earlier one
    /// polls until its own lane drops it, a transient double read rather than a lock held
    /// across the chain round trip.
    pub(crate) fn register(
        &self,
        key: VaultKey,
        rx: tokio::sync::watch::Receiver<crate::volatile::Inventory>,
    ) -> Arc<SharedReader> {
        let reader = Arc::new(SharedReader { rx });
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, Arc::downgrade(&reader));
        reader
    }
}

const BALANCE_OF_SIG: &str = "balanceOf(address)";
const VAULT_FOR_SIG: &str = "vaultFor(address,address)";
const GET_PAIRS_SIG: &str = "getPairs()";
const DECIMALS_SIG: &str = "decimals()";

/// How often the vault's tokens are priced in USD.
pub const PRICE_REFRESH: Duration = Duration::from_secs(60);

/// A price older than this is not used: a token's USD value disappears rather than being
/// computed from a price that stopped updating, so the dashboard shows a gap, not a number
/// quietly going stale.
const PRICE_MAX_AGE: Duration = Duration::from_secs(600);

/// Where the vault's tokens get their USD prices: CoinGecko's price by contract address,
/// with the plan's key (`COINGECKO_API_KEY`) when there is one.
pub struct UsdPricing {
    /// The run's shared client (`feed::http_client`): one pool, and a User-Agent CoinGecko
    /// accepts.
    pub http: Arc<reqwest::Client>,
    /// CoinGecko's API base: the `coingecko` endpoint setting, or its default.
    pub endpoint: String,
    /// CoinGecko's name for the chain the tokens live on.
    pub platform: &'static str,
}

impl UsdPricing {
    /// CoinGecko's name for `chain_id`, if it prices tokens there.
    pub fn platform(chain_id: u64) -> Option<&'static str> {
        match chain_id {
            1 | 31337 => Some("ethereum"),
            8453 => Some("base"),
            _ => None,
        }
    }

    /// The USD price of each of `tokens` CoinGecko knows. One request for all of them;
    /// CoinGecko allows only one address per request without an API key, so if it refuses
    /// the batch for that reason, one request per token instead.
    async fn prices(&self, tokens: &[Address]) -> Result<HashMap<Address, f64>> {
        if tokens.is_empty() {
            return Ok(HashMap::new());
        }
        match self.request(tokens).await {
            Err(err) if tokens.len() > 1 && format!("{err:#}").contains("10012") => {
                let mut out = HashMap::new();
                for token in tokens {
                    out.extend(self.request(std::slice::from_ref(token)).await?);
                }
                Ok(out)
            }
            other => other,
        }
    }

    async fn request(&self, tokens: &[Address]) -> Result<HashMap<Address, f64>> {
        let addresses: Vec<String> = tokens.iter().map(|t| format!("{t:#x}")).collect();
        let url = format!(
            "{}/simple/token_price/{}?contract_addresses={}&vs_currencies=usd&precision=full",
            crate::venues::coingecko::url_base(&self.endpoint),
            self.platform,
            addresses.join(",")
        );
        let mut request = self.http.get(&url);
        if let Some((name, key)) = crate::venues::coingecko::key_header() {
            request = request.header(name, key);
        }
        let body = request
            .send()
            .await
            .wrap_err("coingecko price request failed")?
            .text()
            .await
            .wrap_err("coingecko price answer unreadable")?;
        parse_token_prices(&body)
    }
}

/// `{"0xc02a…":{"usd":2685.06}}`, keyed by lower-case address. An error body
/// (`{"status":{"error_code":10012,…}}`) is an error carrying its code.
fn parse_token_prices(body: &str) -> Result<HashMap<Address, f64>> {
    let value: serde_json::Value =
        serde_json::from_str(body).wrap_err("coingecko price answer is not JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| eyre!("coingecko price answer is not an object"))?;
    if let Some(code) = value
        .get("error_code")
        .or_else(|| value["status"].get("error_code"))
    {
        return Err(eyre!(
            "coingecko refused the price request ({code}): {}",
            value["status"]["error_message"].as_str().unwrap_or("")
        ));
    }
    let mut out = HashMap::new();
    for (address, entry) in object {
        let (Ok(token), Some(usd)) = (crate::config::parse_address(address), entry["usd"].as_f64())
        else {
            continue;
        };
        if usd.is_finite() && usd > 0.0 {
            out.insert(token, usd);
        }
    }
    Ok(out)
}

/// One side of the pair as the inventory task reads it.
#[derive(Clone, Copy, Debug)]
pub struct Side {
    pub token: Address,
    pub decimals: u32,
}

/// Spawns the task that exports every pair's vault balances as
/// `quote_updater_vault_balance{token=<symbol>, vault=<address>}`, re-read every
/// [`INVENTORY_REFRESH`].
///
/// Independent of any pair's pricing. The per-pair inventory gauges are written by the
/// volatile pricing tick and so exist only on volatile pairs, which left a stable pair's
/// tokens (USDT beside WETH/USDC) invisible on the dashboard even though they sit in the
/// same account. Vaults are per pair and the owner can move one with `setPairVault`, so
/// each pair's vault is resolved with `vaultFor` on every tick, not once: a balance read
/// off an account the pair no longer fills from would be a wrong number with nothing
/// saying so. Two pairs on one vault read each shared token once. A (vault, token) series
/// that stops being read, because a pair moved, is dropped rather than left reporting its
/// last value, so a `sum` over a token on the dashboard never double counts.
///
/// Each token's symbol and decimals are resolved inside the task, once, the first tick the
/// token appears. A failure anywhere here is a printed warning and a missing series, never
/// a pair that does not start, because this is observability and not quoting.
///
/// Every tick it also asks the target for its own pairs (`getPairs()`) and watches those
/// too. The vaults hold our inventory whether or not this pusher quotes a pair: a token whose
/// only pair was removed from the config, or halted, or never configured here, is still
/// money in the vault, and the dashboard's totals need it. If the target does not answer,
/// the configured pairs are watched on their own.
///
/// With `pricing`, every [`PRICE_REFRESH`] it also prices every token it has seen in USD
/// and exports `quote_updater_token_price_usd{token}` and, per balance,
/// `quote_updater_vault_value_usd{token, vault}`: what the vault is worth in dollars without
/// reading any pair's metrics, so the dashboard's totals and shares survive the pair that
/// used to price WETH for them not running.
///
/// The pair set is read from `pairs` every tick rather than fixed at spawn. Startup seeds it
/// and every reload replaces it, so a pair added from the backoffice is watched from the
/// next tick, and a pusher that started with no pairs does not stay blind to the ones
/// added after. Before this, the set was fixed at spawn and a reload-added pair only
/// appeared after the next restart.
pub fn spawn_vault_exporter(
    tasks: &mut crate::tasks::Tasks,
    client: EthClient,
    target: Address,
    pairs: tokio::sync::watch::Receiver<Vec<(Address, Address)>>,
    metrics: Arc<Metrics>,
    recorder: Option<crate::record::Recorder>,
    pricing: Option<UsdPricing>,
) {
    tasks.spawn(async move {
        // The latest USD price per token, with when it was fetched.
        let mut prices: HashMap<Address, (Instant, f64)> = HashMap::new();
        let mut priced_at: Option<Instant> = None;
        let mut pricing_failing = false;
        let mut tokens: Vec<(Address, String, u32)> = Vec::new();
        // Tokens already looked up, resolved or not, so a token whose decimals() failed
        // warns once rather than every tick.
        let mut looked_up: Vec<Address> = Vec::new();
        // Whether the last `getPairs()` failed, so a target that stops answering warns once
        // rather than every tick, and says so again when it comes back.
        let mut target_pairs_failing = false;

        // The (vault, symbol) series exported last tick, to drop the ones that went away
        // (a pair's vault moved, a pair was removed). Dropped only after a tick where every
        // read answered: since the reads are pinned to one block, an RPC behind a load
        // balancer can hand out a block number from one node and then fail every read on a
        // node that has not seen that block yet, and a failed read must not look like a
        // vault that went away, or the whole set of gauges disappears for a tick.
        let mut exported: Vec<(Address, String)> = Vec::new();
        let mut ticker = tokio::time::interval(INVENTORY_REFRESH);
        loop {
            ticker.tick().await;
            let mut pairs = pairs.borrow().clone();
            match read_target_pairs(&client, target).await {
                Ok(served) => {
                    if target_pairs_failing {
                        // WARN, though it is good news, as the head watcher's "recovered"
                        // line is: the operator layer puts WARN and above on stderr, where
                        // the failure line went, so the outage ends in the stream it began.
                        tracing::warn!("[vault] getPairs() on {target:#x} answers again");
                        target_pairs_failing = false;
                    }
                    for pair in served {
                        let same = |&(a, b): &(Address, Address)| (a, b) == pair || (b, a) == pair;
                        if !pairs.iter().any(same) {
                            pairs.push(pair);
                        }
                    }
                }
                Err(err) => {
                    if !target_pairs_failing {
                        tracing::warn!("[vault] {err:#}; watching only the configured pairs' vaults");
                        target_pairs_failing = true;
                    }
                }
            }
            for token in pairs.iter().flat_map(|&(a, b)| [a, b]) {
                if looked_up.contains(&token) {
                    continue;
                }
                looked_up.push(token);
                let read_symbol = token_symbol(&client, token).await;
                let symbol = read_symbol.clone().unwrap_or_else(|| format!("{token:#x}"));
                match read_decimals(&client, token).await {
                    Ok(decimals) => {
                        // For the dashboard's names and decimals (`feed.tokens`); only a
                        // symbol the token actually answered, never the address stand-in.
                        if let (Some(recorder), Some(read_symbol)) = (&recorder, read_symbol) {
                            recorder.token(crate::record::TokenRow {
                                address: token,
                                symbol: read_symbol,
                                decimals,
                            });
                        }
                        tokens.push((token, symbol, decimals))
                    }
                    Err(err) => {
                        tracing::warn!("[vault] {symbol}: {err:#}; balance will not be exported")
                    }
                }
            }
            if let Some(pricing) = &pricing
                && priced_at.is_none_or(|at| at.elapsed() >= PRICE_REFRESH)
            {
                priced_at = Some(Instant::now());
                let known: Vec<Address> = tokens.iter().map(|(t, _, _)| *t).collect();
                match pricing.prices(&known).await {
                    Ok(fetched) => {
                        if pricing_failing {
                            // On stderr beside its failure line; see getPairs() above.
                            tracing::warn!("[vault] coingecko prices answer again");
                            pricing_failing = false;
                        }
                        let now = Instant::now();
                        for (token, usd) in fetched {
                            prices.insert(token, (now, usd));
                        }
                    }
                    Err(err) => {
                        if !pricing_failing {
                            tracing::warn!(
                                "[vault] {err:#}; USD values keep the last price for up to 10 minutes"
                            );
                            pricing_failing = true;
                        }
                    }
                }
                for (token, symbol, _) in &tokens {
                    match prices.get(token) {
                        Some((at, usd)) if at.elapsed() <= PRICE_MAX_AGE => {
                            metrics.token_price_usd(symbol).set(*usd)
                        }
                        _ => metrics.drop_token_price_usd(symbol),
                    }
                }
            }
            let fresh_price = |token: Address| {
                prices
                    .get(&token)
                    .filter(|(at, _)| at.elapsed() <= PRICE_MAX_AGE)
                    .map(|(_, usd)| *usd)
            };
            let side_of = |token: Address| {
                tokens
                    .iter()
                    .find(|(t, _, _)| *t == token)
                    .map(|(t, symbol, decimals)| {
                        (
                            Side {
                                token: *t,
                                decimals: *decimals,
                            },
                            symbol.as_str(),
                        )
                    })
            };
            // The block every balance below is read AT, for the recorder's rows: the P&L
            // join needs "the inventory during fill i" to be the newest row at or before the
            // fill's block, so a reading has to say which block it describes, and describe
            // it truthfully. Pinning every read to this number is what makes a swap landing
            // between the calls harmless: the reads still answer for the block they name.
            // The block's own timestamp goes with it, the same meaning the backfill writes.
            // No block, no recording this tick; the gauges do not need it.
            let at = match &recorder {
                Some(_) => match block_and_time(&client).await {
                    Ok(at) => Some(at),
                    Err(err) => {
                        tracing::warn!("[vault] {err:#}; balances are not recorded this tick");
                        None
                    }
                },
                None => None,
            };
            let pin = at.map(|(block, _)| BlockIdentifier::Number(block));
            let mut every_read_answered = true;
            let mut wanted: Vec<(Address, Address)> = Vec::new();
            let mut pair_vaults: Vec<(Address, Address, Address)> = Vec::new();
            for &(a, b) in &pairs {
                match read_pair_vault(&client, target, a, b, pin.clone()).await {
                    Ok(vault) => {
                        pair_vaults.push((a, b, vault));
                        for token in [a, b] {
                            if !wanted.contains(&(vault, token)) {
                                wanted.push((vault, token));
                            }
                        }
                    }
                    Err(err) => {
                        every_read_answered = false;
                        tracing::warn!(
                            "[vault] {err:#}; this pair's balances keep last tick's value"
                        );
                    }
                }
            }
            let mut current: Vec<(Address, String)> = Vec::new();
            let mut read: HashMap<(Address, Address), f64> = HashMap::new();
            for (vault, token) in wanted {
                let Some((side, symbol)) = side_of(token) else {
                    continue;
                };
                let vault_hex = format!("{vault:#x}");
                match read_balance_raw(&client, vault, side.token, pin.clone()).await {
                    Ok(raw) => {
                        let balance = scaled_to_f64(raw, side.decimals);
                        read.insert((vault, side.token), balance);
                        metrics.vault_balance(symbol, &vault_hex).set(balance);
                        match fresh_price(side.token) {
                            Some(usd) => metrics
                                .vault_value_usd(symbol, &vault_hex)
                                .set(balance * usd),
                            None => metrics.drop_vault_value_usd(symbol, &vault_hex),
                        }
                        current.push((vault, symbol.to_owned()));
                        if let (Some(recorder), Some((block, ts))) = (&recorder, at) {
                            recorder.balance(crate::record::BalanceReading {
                                prop_amm: target,
                                vault,
                                token: side.token,
                                block,
                                ts,
                                balance: raw,
                            });
                        }
                    }
                    Err(err) => {
                        every_read_answered = false;
                        tracing::warn!(
                            "[vault] balance read failed: {err:#}; keeping last tick's value"
                        );
                    }
                }
            }
            // Each pair's holdings, for the recorder to stamp on the quotes it signs next
            // (the inventory panel). Only a pair whose two balances both answered.
            if let Some(recorder) = &recorder {
                for &(a, b, vault) in &pair_vaults {
                    let (token0, token1) = if a < b { (a, b) } else { (b, a) };
                    let (Some(&amount0), Some(&amount1), Some((_, symbol0)), Some((_, symbol1))) = (
                        read.get(&(vault, token0)),
                        read.get(&(vault, token1)),
                        side_of(token0),
                        side_of(token1),
                    ) else {
                        continue;
                    };
                    recorder.holdings(
                        target,
                        crate::config::lane_of(token0, token1),
                        crate::record::Holdings {
                            amount0,
                            amount1,
                            symbol0: symbol0.to_owned(),
                            symbol1: symbol1.to_owned(),
                        },
                    );
                }
            }
            if !every_read_answered {
                continue;
            }
            for (vault, symbol) in &exported {
                if !current.contains(&(*vault, symbol.clone())) {
                    metrics.drop_vault_balance(symbol, &format!("{vault:#x}"));
                    metrics.drop_vault_value_usd(symbol, &format!("{vault:#x}"));
                }
            }
            exported = current;
        }
    });
}

/// The latest block and its timestamp, for readings that must say which block they are of.
async fn block_and_time(client: &EthClient) -> Result<(u64, i64)> {
    let block = client
        .get_block_number()
        .await
        .wrap_err("eth_blockNumber failed")?;
    let header = client
        .get_block_by_number(BlockIdentifier::Number(block), false)
        .await
        .wrap_err_with(|| format!("eth_getBlockByNumber({block}) failed"))?;
    Ok((block, header.header.timestamp as i64))
}

/// `token.balanceOf(vault)` as whole tokens, at the latest block.
pub async fn read_balance(
    client: &EthClient,
    vault: Address,
    token: Address,
    decimals: u32,
) -> Result<f64> {
    Ok(scaled_to_f64(
        read_balance_raw(client, vault, token, None).await?,
        decimals,
    ))
}

/// `token.balanceOf(vault)` in the token's own raw units, the number the chain holds, at
/// `block` (the latest when `None`).
pub async fn read_balance_raw(
    client: &EthClient,
    vault: Address,
    token: Address,
    block: Option<BlockIdentifier>,
) -> Result<U256> {
    let calldata = encode_calldata(BALANCE_OF_SIG, &[Value::Address(vault)])?;
    let answer = call_view(client, token, calldata, None, block)
        .await
        .wrap_err_with(|| format!("balanceOf({vault:#x}) on {token:#x} failed"))?;
    match decode_one("r(uint256)", Some(&answer)) {
        Some(Value::Uint(balance)) => Ok(balance),
        _ => Err(eyre!(
            "balanceOf({vault:#x}) on {token:#x} returned no uint256"
        )),
    }
}

/// Where a pair's PropAMM fills from: `target.vaultFor(tokenA, tokenB)`. Token order does
/// not matter; the contract canonicalizes. The call reverts, and so this errors, for a pair
/// the target does not list. Vaults are per pair and the owner can move one, so callers
/// resolve this on every read rather than once.
pub async fn read_pair_vault(
    client: &EthClient,
    target: Address,
    token_a: Address,
    token_b: Address,
    block: Option<BlockIdentifier>,
) -> Result<Address> {
    let calldata = encode_calldata(
        VAULT_FOR_SIG,
        &[Value::Address(token_a), Value::Address(token_b)],
    )?;
    let answer = call_view(client, target, calldata, None, block)
        .await
        .wrap_err_with(|| format!("vaultFor({token_a:#x}, {token_b:#x}) on {target:#x} failed"))?;
    match decode_one("r(address)", Some(&answer)) {
        Some(Value::Address(vault)) => Ok(vault),
        _ => Err(eyre!(
            "vaultFor({token_a:#x}, {token_b:#x}) on {target:#x} returned no address"
        )),
    }
}

/// Every pair the target serves, `target.getPairs()`, as `(token0, token1)`.
async fn read_target_pairs(client: &EthClient, target: Address) -> Result<Vec<(Address, Address)>> {
    let answer = call_view(
        client,
        target,
        encode_calldata(GET_PAIRS_SIG, &[])?,
        None,
        None,
    )
    .await
    .wrap_err_with(|| format!("getPairs() on {target:#x} failed"))?;
    decode_token_pairs(&answer)
        .ok_or_else(|| eyre!("getPairs() on {target:#x} returned no (address, address)[]"))
}

/// The ABI encoding of a `(address, address)[]` return: an offset to the array, its length,
/// then two words per pair. `None` for anything that is not exactly that.
fn decode_token_pairs(data: &[u8]) -> Option<Vec<(Address, Address)>> {
    let word = |i: usize| data.get(i * 32..(i + 1) * 32);
    let as_usize = |w: &[u8]| -> Option<usize> {
        // An offset or length has no business above a few thousand; the high bytes must be
        // zero or this is not the array we asked for.
        w[..24]
            .iter()
            .all(|b| *b == 0)
            .then(|| usize::try_from(u64::from_be_bytes(w[24..].try_into().ok()?)).ok())?
    };
    let as_address = |w: &[u8]| -> Option<Address> {
        w[..12]
            .iter()
            .all(|b| *b == 0)
            .then(|| Address::from_slice(&w[12..]))
    };
    let offset = as_usize(word(0)?)?;
    if offset % 32 != 0 {
        return None;
    }
    let start = offset / 32;
    let len = as_usize(word(start)?)?;
    if data.len() != (start + 1 + 2 * len) * 32 {
        return None;
    }
    (0..len)
        .map(|i| {
            Some((
                as_address(word(start + 1 + 2 * i)?)?,
                as_address(word(start + 2 + 2 * i)?)?,
            ))
        })
        .collect()
}

/// `token.decimals()`, so the balance can be read in whole tokens.
pub async fn read_decimals(client: &EthClient, token: Address) -> Result<u32> {
    let answer = call_view(
        client,
        token,
        encode_calldata(DECIMALS_SIG, &[])?,
        None,
        None,
    )
    .await
    .wrap_err_with(|| format!("decimals() on {token:#x} failed"))?;
    match decode_one("r(uint8)", Some(&answer)) {
        Some(Value::Uint(decimals)) => Ok(decimals.low_u32()),
        _ => Err(eyre!("decimals() on {token:#x} returned no uint8")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A target that answers again is said where its failure was, on stderr, as when both
    /// lines were `eprintln!`: an operator reading one stream sees the outage end there.
    /// Real time for the RPC (paused time would fire its timeout while the mock answers),
    /// with the clock moved past one refresh by hand instead of waiting it out.
    #[tokio::test]
    async fn the_target_answering_again_is_said_on_the_stream_its_failure_was() {
        let (_guard, captured) = crate::output::capture();
        let rpc = crate::rpc_mock::MockRpc::spawn(100).await;
        let mut tasks = crate::tasks::Tasks::default();
        let (_pairs, pairs) = tokio::sync::watch::channel(Vec::new());
        spawn_vault_exporter(
            &mut tasks,
            EthClient::new(url::Url::parse(&rpc.url).unwrap()).unwrap(),
            Address::repeat_byte(0x70),
            pairs,
            Arc::new(Metrics::new().unwrap()),
            None,
            None,
        );
        let said = |needle: &str| {
            captured
                .lines()
                .into_iter()
                .find(|(_, line)| line.contains(needle))
                .map(|(stream, _)| stream)
        };
        let until = async |needle: &str| {
            for _ in 0..500 {
                if said(needle).is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        // The first tick is at once, and the mock's answer does not decode as pairs.
        let failing = "watching only the configured pairs";
        until(failing).await;
        assert!(said(failing).is_some(), "{:?}", captured.lines());

        rpc.set_target_pairs(Vec::new());
        tokio::time::pause();
        tokio::time::advance(INVENTORY_REFRESH).await;
        tokio::time::resume();
        let again = "answers again";
        until(again).await;
        assert_eq!(
            said(again),
            Some(crate::output::Stream::Stderr),
            "{:?}",
            captured.lines()
        );
        assert_eq!(said(again), said(failing));
    }

    /// What prod's target answered to `getPairs()` on 2026-09-24: USDC/WETH and USDC/USDT.
    const PROD_GET_PAIRS: &str = "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_targets_pairs_decode_from_what_prod_answered() {
        let usdc: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let weth: Address = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
            .parse()
            .unwrap();
        let usdt: Address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse()
            .unwrap();
        assert_eq!(
            decode_token_pairs(&hex(PROD_GET_PAIRS)),
            Some(vec![(usdc, weth), (usdc, usdt)])
        );
    }

    #[test]
    fn token_prices_are_read_by_address_and_an_error_carries_its_code() {
        let weth =
            crate::config::parse_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        // What CoinGecko answered for WETH.
        let prices = parse_token_prices(
            r#"{"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2":{"usd":2685.0644586641197}}"#,
        )
        .unwrap();
        assert_eq!(prices.get(&weth), Some(&2685.0644586641197));
        // A token it does not price is simply absent.
        assert!(
            parse_token_prices(r#"{"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2":{}}"#)
                .unwrap()
                .is_empty()
        );
        // What it answered, keyless, to three addresses at once.
        let refused = r#"{"timestamp":"2026-09-24T22:14:22.530+00:00","error_code":10012,"status":{"error_message":"Number of contract addresses in the request exceeds the allowed limit of 1 contract address."}}"#;
        let err = format!("{:#}", parse_token_prices(refused).unwrap_err());
        assert!(err.contains("10012"), "{err}");
    }

    /// One request for every token; when CoinGecko refuses a batch (no API key), one per
    /// token instead.
    #[tokio::test]
    async fn prices_fall_back_to_one_request_per_token_when_the_batch_is_refused() {
        use axum::{Router, extract::Query, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let app = Router::new().route(
            "/simple/token_price/ethereum",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let addresses: Vec<&str> = q["contract_addresses"].split(',').collect();
                    if addresses.len() > 1 {
                        return r#"{"error_code":10012,"status":{"error_message":"limit of 1"}}"#
                            .to_owned();
                    }
                    format!(r#"{{"{}":{{"usd":2.5}}}}"#, addresses[0])
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let pricing = UsdPricing {
            http: Arc::new(reqwest::Client::new()),
            endpoint: format!("http://{addr}"),
            platform: "ethereum",
        };
        let a = Address::from_low_u64_be(0xa);
        let b = Address::from_low_u64_be(0xb);
        let prices = pricing.prices(&[a, b]).await.unwrap();
        assert_eq!(prices.get(&a), Some(&2.5));
        assert_eq!(prices.get(&b), Some(&2.5));
        assert_eq!(
            requests.load(Ordering::SeqCst),
            3,
            "the refused batch, then one each"
        );
        assert!(pricing.prices(&[]).await.unwrap().is_empty());
    }

    #[test]
    fn anything_but_a_pair_array_decodes_to_none() {
        let good = hex(PROD_GET_PAIRS);
        // Truncated, one word too many, and an empty answer.
        assert_eq!(decode_token_pairs(&good[..good.len() - 32]), None);
        assert_eq!(
            decode_token_pairs(&[good.clone(), vec![0; 32]].concat()),
            None
        );
        assert_eq!(decode_token_pairs(&[]), None);
        // An empty array is a valid answer.
        let empty = hex(&format!("{:064x}{:064x}", 32, 0));
        assert_eq!(decode_token_pairs(&empty), Some(vec![]));
    }
}

//! Pricing for a volatile pair: the spread and the inventory tilt, computed off-chain
//! every tick from the recent Binance history and the vault's balance.
//!
//! A stable pair publishes a fixed spread. That is wrong for WETH/USDC, because the pool
//! is stuck with whatever it bought until the next block, and the price moves meanwhile.
//! The spread here is the sum of three costs (Avellaneda-Stoikov for the first two,
//! Glosten-Milgrom for the third), all as fractions of the mid:
//!
//! ```text
//! hold  = γ·σ²·τ               holding what you bought for τ seconds while the price moves
//! edge  = (2/γ)·ln(1 + γ/k)    the profit margin routing competition leaves you
//! stale = κ·σ·√Δ               a bot filling your Δ-seconds-old price after the market moved
//!
//! spread = hold + edge + stale
//! delta  = spread / 2           what is published: the half-spread, one per side
//! skew   = q·γ·σ·√τ            q = (share of vault value in base − target_share) / target_share
//! ```
//!
//! With σ = 0 (a stable pair) `hold` and `stale` vanish and `spread` is `edge` alone: the
//! constant spread a stable pair publishes today. So this is one formula for both cases.
//!
//! The tilt scales with the standard deviation of the move over the hold, σ·√τ, while `hold`
//! scales with the variance σ²·τ. At the σ this feed measures the variance form is ~1e-8 of the
//! mid, too small to steer inventory at a sane γ, so the tilt uses the stdev instead. See `price`.
//!
//! The skew is published as a mid shift, not as two spreads. When too much of the vault's
//! value is in the base asset (q > 0) both prices should drop: sell cheaper so takers buy it off us,
//! bid lower so fewer sell us more. With two spreads that is `mid + (delta − skew)` on the
//! sell side and `mid − (delta + skew)` on the buy side. Both are `(mid − skew) ± delta`,
//! so publishing `mid' = mid·(1 − skew)` with the one `delta` gives PropAMM the same two
//! prices through the `[delta, mid]` slots it already reads. Nothing on chain changes, and
//! a stable pair (skew = 0) publishes exactly what it did before. The cost is that the mid
//! on chain is the market mid less the tilt, which `min_mid`/`max_mid` and the dashboards
//! then see; `skew` is a few bps at most, so a band wide enough to be useful is unaffected.
//!
//! Everything in the model's assumptions is a knob: γ, k, κ are guesses an operator tunes
//! from the backoffice while watching what the pool earns and loses; τ and Δ are timings
//! the chain fixes; the target share is a policy. σ is the only measured input.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ethrex_common::{Address, U256};
use ethrex_rpc::clients::eth::EthClient;
use eyre::{Result, WrapErr, ensure};
use tokio::sync::watch;

use crate::{
    feed::parse_decimal_scaled,
    vault::{Side, read_balance, read_pair_vault},
};

/// Longest window any pair may measure σ over, and so how much history is kept.
pub const MAX_WINDOW: Duration = Duration::from_secs(3600);

/// How much history σ needs before a pair prices off it. Fewer seconds than this and a
/// single tick dominates the estimate; the pair reports itself as warming up instead of
/// publishing off noise.
pub const MIN_HISTORY: Duration = Duration::from_secs(60);

/// How often the vault's balance is re-read. Fills land once a block, so reading faster
/// than that only costs RPC calls.
pub const INVENTORY_REFRESH: Duration = Duration::from_secs(12);

/// How old the vault balance may be before the pair refuses to price off it. Generous
/// against one slow RPC round-trip, tight enough that a dead RPC withdraws the quote rather
/// than tilting it off a balance from minutes ago.
pub const MAX_INVENTORY_AGE: Duration = Duration::from_secs(60);

/// Fractional digits `delta` and the mid factor are rounded to on their way from `f64` to
/// the published fixed-point value. `f64` carries ~16 significant digits, so rounding at 15
/// turns `1 − 0.001` back into exactly `0.999` rather than its binary neighbour, and a
/// spread of a few bps keeps a dozen significant digits: far below the noise in σ.
const F64_DIGITS: usize = 15;

/// A finite `f64` knob. `f64` is not `Eq` because of NaN; every value here is checked
/// finite at parse time, so equality is total and `PairSpec` keeps the derived `Eq` a
/// reload diffs on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Knob(f64);

impl Eq for Knob {}

impl Knob {
    pub fn get(self) -> f64 {
        self.0
    }
}

/// The volatile pricing knobs of one pair, as parsed from its config block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolatileParams {
    /// γ, risk aversion: how much to charge per unit of expected loss from holding.
    pub gamma: Knob,
    /// k, competition: how fast trades fall away as the price worsens.
    pub k: Knob,
    /// κ, how much of the expected stale-quote move to charge for.
    pub kappa: Knob,
    /// τ, seconds a position is held before the next block lets us requote.
    pub hold_secs: Knob,
    /// Δ, seconds a published price is typically old when it is filled.
    pub fill_delay_secs: Knob,
    /// The share of the vault's value that should be in the base asset, in (0, 1); q is
    /// measured against it. A share rather than an amount, so adding liquidity to the vault
    /// does not change what "balanced" means.
    pub target_share: Knob,
    /// λ, the inventory charge's own coefficient, independent of γ. Zero (the default) leaves
    /// pricing unchanged. Above zero, once the vault's base share leaves the band
    /// [`inventory_band_lower`, `inventory_band_upper`] (default [½·target_share,
    /// 2·target_share]), it worsens the price of the one trade that would push the vault
    /// further off target, in proportion to how far past the band it is. The trade that
    /// brings the vault back is priced as if the charge were off. Its own coefficient
    /// because one γ cannot drive both the tilt and this charge: they need values orders of
    /// magnitude apart (the tilt is right near γ ≈ 0.1–1, the charge would need γ ≈ 380).
    pub inventory_aversion: Knob,
    /// The band of base share inside which the inventory charge is zero, as two explicit
    /// base-share fractions (not q). The charge fires when base share drops below
    /// `inventory_band_lower` or rises above `inventory_band_upper`. Stated as base shares so
    /// both edges are reachable and target-independent: base share is capped at 1.0, so a band
    /// edge expressed as a multiple of the target (the old ±q formulation, edges 2·target /
    /// ½·target) put the upper edge past 1.0 and out of reach whenever target ≥ 0.5, making the
    /// charge one-sided. Default `½·target_share`; unchanged from before.
    pub inventory_band_lower: Knob,
    /// Upper edge of the no-charge band, as a base-share fraction (see `inventory_band_lower`).
    /// Default `2·target_share`, which reproduces the old band exactly — so behaviour is
    /// unchanged unless set. Note the default can exceed 1.0 (when target ≥ 0.5) and is then
    /// unreachable, as before; set this to a reachable value (e.g. 0.75) to arm the upper side.
    pub inventory_band_upper: Knob,
    /// How far back σ is measured over.
    pub volatility_window: Duration,
}

/// The knobs as written in a pair's config block, before parsing. `None` for the four
/// with defaults means "use the default"; the other three are required and checked by the
/// caller before this is built.
pub struct RawKnobs<'a> {
    pub gamma: &'a str,
    pub k: &'a str,
    pub kappa: &'a str,
    pub target_share: Option<&'a str>,
    pub hold_secs: Option<&'a str>,
    pub fill_delay_secs: Option<&'a str>,
    pub volatility_window_secs: Option<&'a str>,
    pub inventory_aversion: Option<&'a str>,
    pub inventory_band_lower: Option<&'a str>,
    pub inventory_band_upper: Option<&'a str>,
}

impl VolatileParams {
    /// Parses and bounds the knobs. Every failure names the field the operator wrote.
    pub fn parse(at: &str, raw: RawKnobs<'_>) -> Result<Self> {
        let knob = |name: &str, text: &str| -> Result<Knob> {
            let value: f64 = text
                .trim()
                .parse()
                .wrap_err_with(|| format!("{at}: invalid {name} {text:?}"))?;
            ensure!(
                value.is_finite(),
                "{at}: {name} {text:?} is not a finite number"
            );
            ensure!(value >= 0.0, "{at}: {name} {text:?} is negative");
            Ok(Knob(value))
        };
        let positive = |name: &str, text: &str| -> Result<Knob> {
            let knob = knob(name, text)?;
            ensure!(knob.0 > 0.0, "{at}: {name} must be above zero");
            Ok(knob)
        };
        let window_secs: u64 = match raw.volatility_window_secs {
            Some(text) => text
                .trim()
                .parse()
                .wrap_err_with(|| format!("{at}: invalid volatility_window_secs {text:?}"))?,
            None => 600,
        };
        let volatility_window = Duration::from_secs(window_secs);
        ensure!(
            volatility_window >= MIN_HISTORY,
            "{at}: volatility_window_secs {window_secs} is below the {} seconds σ needs",
            MIN_HISTORY.as_secs()
        );
        ensure!(
            volatility_window <= MAX_WINDOW,
            "{at}: volatility_window_secs {window_secs} is above the {} seconds of history kept",
            MAX_WINDOW.as_secs()
        );
        let target_share = positive("target_share", raw.target_share.unwrap_or("0.5"))?;
        ensure!(
            target_share.get() < 1.0,
            "{at}: target_share is the share of the vault's value in the base asset, so it must \
             be between 0 and 1 (0.5 is half and half)"
        );
        // The no-charge band's edges, as base-share fractions. Default to the old band
        // [½·target, 2·target] so behaviour is unchanged when unset; an operator can set either
        // edge to a reachable base share (base share ≤ 1.0) to arm that side.
        let inventory_band_lower = match raw.inventory_band_lower {
            Some(text) => knob("inventory_band_lower", text)?,
            None => Knob(0.5 * target_share.get()),
        };
        let inventory_band_upper = match raw.inventory_band_upper {
            Some(text) => knob("inventory_band_upper", text)?,
            None => Knob(2.0 * target_share.get()),
        };
        ensure!(
            inventory_band_lower.get() <= target_share.get()
                && target_share.get() <= inventory_band_upper.get(),
            "{at}: the inventory band [inventory_band_lower, inventory_band_upper] = [{}, {}] must \
             bracket target_share {} (both are base-share fractions)",
            inventory_band_lower.get(),
            inventory_band_upper.get(),
            target_share.get()
        );
        Ok(Self {
            // γ divides in the edge term, so zero is not a value it can take.
            gamma: positive("gamma", raw.gamma)?,
            k: positive("k", raw.k)?,
            kappa: knob("kappa", raw.kappa)?,
            hold_secs: knob("hold_secs", raw.hold_secs.unwrap_or("12"))?,
            fill_delay_secs: knob("fill_delay_secs", raw.fill_delay_secs.unwrap_or("6"))?,
            target_share,
            inventory_aversion: knob("inventory_aversion", raw.inventory_aversion.unwrap_or("0"))?,
            inventory_band_lower,
            inventory_band_upper,
            volatility_window,
        })
    }
}

/// The three terms, the published half-spread and the tilt, all as fractions of the mid,
/// for one tick. Returned whole so the metrics can show an operator which term is doing
/// the work when the spread moves.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Terms {
    /// σ, per √second.
    pub sigma: f64,
    pub hold: f64,
    pub edge: f64,
    pub stale: f64,
    /// The inventory charge once base share leaves the band [`inventory_band_lower`,
    /// `inventory_band_upper`] (default [½·target, 2·target]): the fraction the harmful side's
    /// price is worsened by. Zero inside the band and when `inventory_aversion` is zero.
    pub inventory_penalty: f64,
    /// The published half-spread. `(hold + edge + stale) / 2` while the charge is zero; with
    /// it, solved together with `skew` so the two prices come out one-sided (see `price`).
    /// Not capped: the volatility spread must be free to widen without limit in a crash. The
    /// pusher refuses to publish a half-spread that reaches one whole unit (see `update.rs`).
    pub delta: f64,
    /// `(base_share − target_share) / target_share`.
    pub q: f64,
    /// The published mid shift, `mid · (1 − skew)`. While the charge is zero it is the tilt,
    /// `q·γ·σ·√τ` capped at ±delta and at ±SKEW_LIMIT; with the charge it also carries the
    /// half of the charge that moves the mid toward the harmful side, never past
    /// [`skew_reach`].
    pub skew: f64,
}

/// Hard sanity bound on the tilt, so the published mid factor `1 − skew` can never flip sign
/// or double the price, whatever the spread does. The economic clamp is `±delta`; this is the
/// safety net beneath it. It bounds the tilt, before the inventory charge: the charge (at most
/// `MAX_DELTA`) moves the mid a little further, to exactly [`skew_reach`] rather than
/// `±SKEW_LIMIT`.
pub const SKEW_LIMIT: f64 = 0.5;

/// The widest the inventory charge alone is allowed to build, so the charge stays well below
/// the one-whole-unit ceiling that makes the pusher refuse to publish. Being far off target
/// should quote wide, not stop quoting (which would strand the inventory). It bounds only the
/// inventory penalty, not the whole half-spread: the volatility spread widens uncapped.
const MAX_DELTA: f64 = 0.05;

/// The furthest the published skew reaches either way, `(lowest, highest)`: the tilt at
/// `±SKEW_LIMIT` carried further by the inventory charge at its `MAX_DELTA` cap. Short the
/// base, the charge raises only our sell price, so the factor `1 − skew` is
/// `(1 − tilt)/√(1 − charge)` with the tilt at or below zero, at most
/// `(1 + SKEW_LIMIT)/√(1 − MAX_DELTA)` ≈ 1.539; long, it lowers only our buy price,
/// `(1 − tilt)·√(1 − charge)` with the tilt at or above zero, at least
/// `(1 − SKEW_LIMIT)·√(1 − MAX_DELTA)` ≈ 0.487. Without the charge the factor is `1 − tilt`,
/// inside both. Both ends are reached: a vault far enough off its band, at a σ that clamps
/// the tilt, sits on them.
///
/// One definition for two readers: [`price`] clamps its skew to it, and the core's backstop
/// (`pricing::backstop`) bounds every pricer's mid by the mids it gives, so the bound is the
/// model's reach and cannot drift from it.
pub fn skew_reach() -> (f64, f64) {
    let charge = (1.0 - MAX_DELTA).sqrt();
    (
        1.0 - (1.0 + SKEW_LIMIT) / charge,
        1.0 - (1.0 - SKEW_LIMIT) * charge,
    )
}

/// The module's formula, in one place, on plain numbers. `base_share` is the share of the
/// vault's value currently in the base asset, see [`Inventory::base_share`]. Everything
/// with a clock or a socket is upstream of this.
pub fn price(params: &VolatileParams, sigma: f64, base_share: f64) -> Terms {
    let gamma = params.gamma.get();
    let k = params.k.get();
    let variance = sigma * sigma * params.hold_secs.get();

    let hold = gamma * variance;
    let edge = (2.0 / gamma) * (1.0 + gamma / k).ln();
    let stale = params.kappa.get() * sigma * params.fill_delay_secs.get().sqrt();

    let q = (base_share - params.target_share.get()) / params.target_share.get();
    let move_over_hold = variance.sqrt();

    // The inventory charge. Inside the base-share band [inventory_band_lower,
    // inventory_band_upper] it is zero and pricing is unchanged. The band edges are configured
    // as base shares (default [½·target, 2·target]) and converted to q here, keeping q_excess
    // in the same q units as before so λ tunes the same magnitude: q_lower = (lower − t)/t and
    // q_upper = (upper − t)/t, which for the defaults are −0.5 and +1.0. Past the band the
    // charge worsens the harmful side's price by λ·σ·√τ per unit of q beyond the edge, so
    // pushing the vault further off target costs the taker progressively more. σ·√τ, not σ²·τ, so it is
    // not numerically dead; its own coefficient λ, independent of γ (see VolatileParams).
    // Capped at MAX_DELTA so an extreme inventory quotes very wide rather than tripping the
    // one-whole-unit refuse guard and quoting nothing at all.
    let target = params.target_share.get();
    let q_lower = (params.inventory_band_lower.get() - target) / target;
    let q_upper = (params.inventory_band_upper.get() - target) / target;
    let q_excess = (q - q_upper).max(0.0) + (q_lower - q).max(0.0);
    let inventory_penalty =
        (params.inventory_aversion.get() * move_over_hold * q_excess).min(MAX_DELTA);
    // The half-spread before the charge. No cap here: capping it would chop the volatility
    // spread (hold + stale) in a crash, exactly when it should widen. The pusher's
    // refuse-to-publish guard (a half-spread reaching one whole unit) in `update.rs` is the
    // backstop.
    let spread_delta = (hold + edge + stale) / 2.0;

    // The tilt scales with the standard deviation of the price move over the hold, σ·√τ,
    // not its variance σ²·τ. Textbook Avellaneda-Stoikov ties the tilt to `hold`'s variance,
    // but at the σ this feed measures (fractions of a bp per √second) that variance tilt is
    // ~1e-8 of the mid: too small to steer inventory at any sane γ. Scaling by the stdev puts
    // the tilt on the order of the spread, so a γ near 1 controls inventory. `hold` keeps its
    // variance form; the adverse-selection charge stays in `stale`.
    //
    // Two bounds. The economic one, `±delta`, stops the tilt from carrying a side past the
    // market mid (a pool very long WETH would then sell it below Binance, a free fill for a
    // bot). The safety one, `±SKEW_LIMIT`, keeps the published factor `1 − skew` inside
    // `(0, 2)` no matter how wide the spread grows, so it can never flip the price's sign or
    // double it; the inventory charge below moves the mid a little past it, to `skew_reach`,
    // still well inside `(0, 2)`. skew stays signed: negative when the vault is short the base, to bid it back.
    let tilt = (q * gamma * move_over_hold)
        .clamp(-spread_delta, spread_delta)
        .clamp(-SKEW_LIMIT, SKEW_LIMIT);

    // The charge goes on one side only. We publish one mid and one half-spread, and PropAMM
    // takes the spread off the taker's output both ways, so as fractions of the market mid
    // we buy at `(1 − skew)·(1 − delta)` and sell at `(1 − skew) / (1 − delta)`. Any pair of
    // prices can be written that way: their product is `(1 − skew)²` and their ratio
    // `(1 − delta)²`. So work out the two prices we want, then solve for the mid and
    // half-spread that give them. Short the base, the harmful trade is a taker buying base
    // from us, so only our sell price rises; long the base, only our buy price drops. The
    // other price is exactly what it would be with the charge off, which the tilt's ±delta
    // clamp already keeps on its own side of the market mid. With no charge, or a spread
    // already at the refuse-to-publish ceiling, there is nothing to solve.
    let (delta, skew) = if inventory_penalty == 0.0 || spread_delta >= 1.0 {
        (spread_delta, tilt)
    } else {
        let mut buy = (1.0 - tilt) * (1.0 - spread_delta);
        let mut sell = (1.0 - tilt) / (1.0 - spread_delta);
        if q < q_lower {
            sell /= 1.0 - inventory_penalty;
        } else {
            buy *= 1.0 - inventory_penalty;
        }
        (1.0 - (buy / sell).sqrt(), 1.0 - (buy * sell).sqrt())
    };
    // Exactly, the solve lands inside `skew_reach`. Nothing proves f64 rounding cannot carry
    // it an ulp past an end (a million sampled spreads at both ends never did), so the clamp
    // takes any such ulp back, and the backstop's bound, computed from the same two numbers,
    // holds by construction rather than within a tolerance.
    let (lowest, highest) = skew_reach();
    let skew = skew.clamp(lowest, highest);

    Terms {
        sigma,
        hold,
        edge,
        stale,
        inventory_penalty,
        delta,
        q,
        skew,
    }
}

/// Renders a non-negative fraction as the fixed-point value the lane publishes.
pub fn fraction_scaled(value: f64, decimals: u32) -> Result<U256> {
    ensure!(
        value.is_finite() && value >= 0.0,
        "{value} is not a non-negative finite fraction"
    );
    parse_decimal_scaled(&format!("{value:.F64_DIGITS$}"), decimals)
}

/// The mid to publish: the market mid less the tilt, in lane orientation.
///
/// `mid` is what the feed published, already inverted for an inverted lane, so the shift
/// has to follow: a market mid scaled by `(1 − skew)` is a lane mid scaled by its
/// reciprocal when the lane carries the price the other way up. The scaling is done in
/// fixed point on the published mid itself, so the mid's precision is the feed's; only the
/// factor passes through `f64`.
pub fn shifted_mid(mid: U256, skew: f64, invert: bool, decimals: u32) -> Result<U256> {
    let factor = if invert {
        1.0 / (1.0 - skew)
    } else {
        1.0 - skew
    };
    let scale = U256::exp10(decimals as usize);
    let factor = fraction_scaled(factor, decimals)?;
    mid.checked_mul(factor)
        .map(|scaled| scaled / scale)
        .ok_or_else(|| eyre::eyre!("mid {mid} times factor {factor} overflows"))
}

/// The recent market mids of one symbol, one per second, from which σ is measured.
///
/// Kept per symbol at the process level and handed to every feed of that symbol, so a
/// reload that rebuilds a pair (and so redials its feed) leaves the history where it was:
/// the new feed appends to the same samples and σ carries on with no warm-up. During the
/// hand-over both feeds write here at once, which is why a second holds one sample and
/// the latest write wins: two feeds reporting the same book do not double the returns.
#[derive(Debug)]
pub struct PriceHistory {
    /// `(whole seconds since `epoch`, market mid)`, oldest first.
    samples: VecDeque<(u64, f64)>,
    epoch: Instant,
}

impl PriceHistory {
    pub fn new(epoch: Instant) -> Self {
        Self {
            samples: VecDeque::new(),
            epoch,
        }
    }

    fn second(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.epoch).as_secs()
    }

    /// Records the market mid seen at `at`. Non-positive mids are skipped: a log return
    /// needs a positive price, and the feed already refuses to publish such a book.
    pub fn record(&mut self, mid: f64, at: Instant) {
        if mid <= 0.0 || !mid.is_finite() {
            return;
        }
        let second = self.second(at);
        match self.samples.back_mut() {
            Some((last, value)) if *last == second => *value = mid,
            // A sample from before the latest second is a late write from a feed being
            // replaced; the newer feed's reading stands.
            Some((last, _)) if *last > second => {}
            _ => self.samples.push_back((second, mid)),
        }
        let keep_from = second.saturating_sub(MAX_WINDOW.as_secs());
        while matches!(self.samples.front(), Some((t, _)) if *t < keep_from) {
            self.samples.pop_front();
        }
    }

    /// σ over the last `window`, per √second, or the seconds of history there are when
    /// that is less than [`MIN_HISTORY`].
    ///
    /// The variance of one second's log return is `Σ r_i² / Σ dt_i` over consecutive
    /// samples: each return is weighted by the seconds it spans, so a quiet stretch with
    /// no ticks is one long return rather than a run of zeros, and the mean return is
    /// taken as zero, which over seconds it is.
    pub fn volatility(&self, now: Instant, window: Duration) -> std::result::Result<f64, Duration> {
        let from = self.second(now).saturating_sub(window.as_secs());
        let mut samples = self.samples.iter().filter(|(t, _)| *t >= from);
        let Some(&(first, mut last_mid)) = samples.next() else {
            return Err(Duration::ZERO);
        };
        let mut last_t = first;
        let mut sum_sq = 0.0;
        for &(t, mid) in samples {
            let r = (mid / last_mid).ln();
            sum_sq += r * r;
            last_t = t;
            last_mid = mid;
        }
        let covered = Duration::from_secs(last_t - first);
        if covered < MIN_HISTORY {
            return Err(covered);
        }
        Ok((sum_sq / covered.as_secs_f64()).sqrt())
    }
}

/// The process's histories, one per market (`Feeds::history_key`).
#[derive(Clone, Default)]
pub struct Histories {
    inner: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<PriceHistory>>>>>,
}

impl Histories {
    /// The history for `symbol`, created on first use and shared thereafter.
    pub fn for_symbol(&self, symbol: &str) -> Arc<Mutex<PriceHistory>> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(symbol.to_uppercase())
            .or_insert_with(|| Arc::new(Mutex::new(PriceHistory::new(Instant::now()))))
            .clone()
    }
}

/// Locks a history. The lock is held for a few arithmetic operations and never across an
/// await, so a poisoned lock (a panic while holding it) is recovered rather than spread.
pub fn lock(history: &Mutex<PriceHistory>) -> std::sync::MutexGuard<'_, PriceHistory> {
    history.lock().unwrap_or_else(|e| e.into_inner())
}

/// The vault's balances of both sides of the pair, in whole tokens, stamped when read, and
/// which vault they were read from. Public through `pricing::Inventory`, and
/// `#[non_exhaustive]` so a field can join it: a test builds one with `testing::inventory`.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Inventory {
    /// The account `target.vaultFor(base, quote)` named when this was read. Vaults are per
    /// pair and the owner can move one, so it is part of the reading rather than a constant.
    pub vault: Address,
    /// The base token held, in whole tokens: `balanceOf` scaled by the token's decimals.
    pub base: f64,
    /// The quote token held, in whole tokens.
    pub quote: f64,
    /// When the balances were read.
    pub at: Instant,
}

impl Inventory {
    /// The share of the vault's value held in the base asset, valuing it at `market_mid`
    /// (quote per base). 0.5 is half and half. An empty vault has no share and reads as
    /// balanced, so the skew stays out of a quote PropAMM will refuse anyway (EmptyVault).
    pub fn base_share(&self, market_mid: f64) -> f64 {
        let base_value = self.base * market_mid;
        let total = base_value + self.quote;
        if total > 0.0 { base_value / total } else { 0.5 }
    }
}

/// Spawns the task that keeps the pair's vault balances current, re-read every
/// [`INVENTORY_REFRESH`]. Seeded with `first`, the reading the caller already took to prove
/// the pair resolves, so the channel always holds a reading and, like the feed's, its age is
/// the consumer's health signal. The first re-read is one full interval out: a plain
/// `interval` fires its first tick immediately, which would repeat the three calls the
/// caller just made. The task exits when every receiver is gone.
pub fn spawn_inventory(
    client: EthClient,
    target: Address,
    base: Side,
    quote: Side,
    label: String,
    first: Inventory,
    every: Duration,
) -> watch::Receiver<Inventory> {
    let (tx, rx) = watch::channel(first);
    tokio::spawn(async move {
        tokio::select! {
            _ = tx.closed() => {}
            _ = async {
                let mut ticker = tokio::time::interval_at(
                    tokio::time::Instant::now() + every,
                    every,
                );
                loop {
                    ticker.tick().await;
                    match read_inventory(&client, target, base, quote).await {
                        Ok(inventory) => {
                            tx.send_replace(inventory);
                        }
                        Err(err) => tracing::warn!("[{label}] vault balance read failed: {err:#}"),
                    }
                }
            } => {}
        }
    });
    rx
}

/// The pair's vault, then both of its balances at once.
///
/// The vault is resolved on every read rather than once at pair start. The owner can move a
/// pair to another account with `setPairVault` while the pusher runs; a balance read off the
/// old account would tilt the skew with nothing saying so, and this crate's rule is that a
/// silently wrong price is the one failure it never allows. One extra `eth_call` per tick.
pub async fn read_inventory(
    client: &EthClient,
    target: Address,
    base: Side,
    quote: Side,
) -> Result<Inventory> {
    let vault = read_pair_vault(client, target, base.token, quote.token, None).await?;
    let (base, quote) = tokio::join!(
        read_balance(client, vault, base.token, base.decimals),
        read_balance(client, vault, quote.token, quote.decimals),
    );
    Ok(Inventory {
        vault,
        base: base?,
        quote: quote?,
        at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knobs<'a>(gamma: &'a str, k: &'a str, kappa: &'a str) -> RawKnobs<'a> {
        RawKnobs {
            gamma,
            k,
            kappa,
            target_share: None,
            hold_secs: None,
            fill_delay_secs: None,
            volatility_window_secs: None,
            inventory_aversion: None,
            inventory_band_lower: None,
            inventory_band_upper: None,
        }
    }

    fn params() -> VolatileParams {
        VolatileParams::parse("p", knobs("0.1", "700", "1")).unwrap()
    }

    #[test]
    fn with_no_volatility_the_spread_is_the_edge_term_alone() {
        let terms = price(&params(), 0.0, 0.5);
        assert_eq!(terms.hold, 0.0);
        assert_eq!(terms.stale, 0.0);
        assert_eq!(terms.skew, 0.0);
        let edge = (2.0 / 0.1) * (1.0 + 0.1 / 700.0f64).ln();
        assert_eq!(terms.edge, edge);
        assert_eq!(terms.delta, edge / 2.0);
    }

    #[test]
    fn volatility_widens_the_spread_through_hold_and_stale() {
        let quiet = price(&params(), 0.0, 0.5);
        let jumpy = price(&params(), 0.001, 0.5);
        assert!(jumpy.hold > 0.0 && jumpy.stale > 0.0);
        assert!(jumpy.delta > quiet.delta);
        assert_eq!(jumpy.hold, 0.1 * 0.001 * 0.001 * 12.0);
        assert_eq!(jumpy.stale, 0.001 * 6.0f64.sqrt());
    }

    #[test]
    fn excess_inventory_tilts_down_and_a_shortfall_up() {
        let long = price(&params(), 0.001, 0.75);
        let short = price(&params(), 0.001, 0.25);
        assert_eq!(long.q, 0.5);
        assert_eq!(short.q, -0.5);
        assert!(long.skew > 0.0);
        assert_eq!(long.skew, -short.skew);
        // skew = q·γ·σ·√τ: the stdev of the move over the hold, not the variance. Mirrors the
        // computation's operation order (σ²·τ, then √) so the float result matches to the bit.
        assert_eq!(long.skew, long.q * 0.1 * (0.001 * 0.001 * 12.0f64).sqrt());
    }

    #[test]
    fn the_inventory_charge_is_zero_in_band_and_widens_the_spread_outside_it() {
        // Default band: target 0.5, [½·target, 2·target] of share is [0.25, 1.0], q ∈ [−0.5, +1.0].
        let raw = |aversion: &'static str,
                   lower: Option<&'static str>,
                   upper: Option<&'static str>| RawKnobs {
            gamma: "0.1",
            k: "700",
            kappa: "1",
            target_share: Some("0.5"),
            hold_secs: None,
            fill_delay_secs: None,
            volatility_window_secs: None,
            inventory_aversion: Some(aversion),
            inventory_band_lower: lower,
            inventory_band_upper: upper,
        };
        let off = VolatileParams::parse("p", raw("0", None, None)).unwrap();
        // Small enough that the charge stays below the MAX_DELTA cap, so the formula is exact.
        let on = VolatileParams::parse("p", raw("10", None, None)).unwrap();
        let sigma_root_tau = (0.001 * 0.001 * 12.0f64).sqrt();

        // Inside the band (share 0.6 → q = 0.2): no charge, and aversion changes nothing.
        let inside = price(&on, 0.001, 0.6);
        assert_eq!(inside.inventory_penalty, 0.0);
        assert_eq!(inside.delta, price(&off, 0.001, 0.6).delta);

        // Below the default band's low edge (share 0.1 → q = −0.8, which is 0.3 below the −0.5 edge).
        let below = price(&on, 0.001, 0.1);
        assert!(below.q < -0.5);
        assert!(below.inventory_penalty > 0.0);
        assert!(below.delta > price(&off, 0.001, 0.1).delta);
        // The charge is λ·σ·√τ·(distance past the edge) = 10 · √(σ²τ) · (−0.5 − q).
        let expected = 10.0 * sigma_root_tau * (-0.5 - below.q);
        assert!((below.inventory_penalty - expected).abs() < 1e-12);

        // FIX 1: with target 0.5 the default upper edge is share 1.0 (unreachable). Set a
        // reachable upper edge (share 0.75 → q_upper = +0.5) so the upper side of the charge
        // fires. Units unchanged: q_excess is still measured in q, so λ tunes the same magnitude.
        let capped = VolatileParams::parse("p", raw("10", None, Some("0.75"))).unwrap();
        // Inside the tighter band (share 0.7 → q = 0.4 < 0.5): still no charge.
        assert_eq!(price(&capped, 0.001, 0.7).inventory_penalty, 0.0);
        // Above it (share 0.9 → q = 0.8, which is 0.3 past the q_upper = +0.5 edge): charge fires.
        let above = price(&capped, 0.001, 0.9);
        assert_eq!(above.q, 0.8);
        assert!(above.inventory_penalty > 0.0);
        let expected_above = 10.0 * sigma_root_tau * (above.q - 0.5);
        assert!((above.inventory_penalty - expected_above).abs() < 1e-12);
    }

    /// Our two prices as fractions of the market mid, the way PropAMM computes them from
    /// what we publish.
    fn buy_and_sell(t: &Terms) -> (f64, f64) {
        (
            (1.0 - t.skew) * (1.0 - t.delta),
            (1.0 - t.skew) / (1.0 - t.delta),
        )
    }

    #[test]
    fn the_inventory_charge_only_worsens_the_trade_that_pushes_us_further_off() {
        let raw = |aversion: &'static str| RawKnobs {
            gamma: "0.1",
            k: "700",
            kappa: "1",
            target_share: Some("0.5"),
            hold_secs: None,
            fill_delay_secs: None,
            volatility_window_secs: None,
            inventory_aversion: Some(aversion),
            inventory_band_lower: Some("0.25"),
            inventory_band_upper: Some("0.75"),
        };
        let off = VolatileParams::parse("p", raw("0")).unwrap();
        let on = VolatileParams::parse("p", raw("10")).unwrap();
        let close = |a: f64, b: f64| (a - b).abs() < 1e-12;

        // Short the base: our buy price is untouched, our sell price rises by the charge.
        let (short_off, short_on) = (price(&off, 0.001, 0.1), price(&on, 0.001, 0.1));
        let (buy_off, sell_off) = buy_and_sell(&short_off);
        let (buy_on, sell_on) = buy_and_sell(&short_on);
        assert!(short_on.inventory_penalty > 0.0);
        assert!(close(buy_on, buy_off), "{buy_on} vs {buy_off}");
        assert!(close(
            sell_on,
            sell_off / (1.0 - short_on.inventory_penalty)
        ));

        // Long the base: our sell price is untouched, our buy price drops by the charge.
        let (long_off, long_on) = (price(&off, 0.001, 0.9), price(&on, 0.001, 0.9));
        let (buy_off, sell_off) = buy_and_sell(&long_off);
        let (buy_on, sell_on) = buy_and_sell(&long_on);
        assert!(long_on.inventory_penalty > 0.0);
        assert!(close(sell_on, sell_off), "{sell_on} vs {sell_off}");
        assert!(close(buy_on, buy_off * (1.0 - long_on.inventory_penalty)));

        // Neither side crosses the market mid, and the half-spread stays positive.
        for t in [short_on, long_on] {
            let (buy, sell) = buy_and_sell(&t);
            assert!(buy < 1.0 && sell > 1.0 && t.delta > 0.0);
        }
    }

    #[test]
    fn the_tilt_never_flips_or_doubles_the_published_price() {
        // Even with an absurd inventory and a wide spread, skew stays within ±SKEW_LIMIT so
        // the factor 1 − skew stays in (0, 2).
        let params = VolatileParams::parse("p", knobs("1000", "700", "1")).unwrap();
        for &share in &[0.0, 0.01, 0.5, 0.99] {
            let t = price(&params, 0.05, share);
            assert!(t.skew.abs() <= SKEW_LIMIT, "skew {} out of bound", t.skew);
            assert!((1.0 - t.skew) > 0.0 && (1.0 - t.skew) < 2.0);
        }
    }

    /// `skew_reach` is the tilt limit carried by the full charge, and the model reaches each
    /// end and never passes it: short the base with the tilt clamped at −SKEW_LIMIT and the
    /// charge at MAX_DELTA, then long with both mirrored. σ = 0.11 makes the half-spread
    /// ≈ 0.86, so both clamps bind and the spread still publishes.
    #[test]
    fn the_skew_reaches_both_ends_of_its_reach_and_never_passes_them() {
        let (lowest, highest) = skew_reach();
        assert_eq!(lowest, 1.0 - 1.5 / 0.95f64.sqrt());
        assert_eq!(highest, 1.0 - 0.5 * 0.95f64.sqrt());
        assert!((lowest + 0.538_967_5).abs() < 1e-6 && (highest - 0.512_659_6).abs() < 1e-6);
        let raw = |gamma: &'static str, aversion: &'static str| RawKnobs {
            target_share: Some("0.5"),
            inventory_aversion: Some(aversion),
            inventory_band_lower: Some("0.25"),
            inventory_band_upper: Some("0.75"),
            ..knobs(gamma, "2000", "1")
        };
        let params = VolatileParams::parse("p", raw("10", "1")).unwrap();
        let short = price(&params, 0.11, 0.0);
        let long = price(&params, 0.11, 1.0);
        assert_eq!(short.inventory_penalty, MAX_DELTA);
        assert_eq!(long.inventory_penalty, MAX_DELTA);
        assert!(short.delta < 1.0 && long.delta < 1.0);
        assert!((short.skew - lowest).abs() < 1e-12, "{}", short.skew);
        assert!((long.skew - highest).abs() < 1e-12, "{}", long.skew);
        for gamma in ["0.1", "1", "10", "1000"] {
            for aversion in ["0", "1", "100"] {
                let params = VolatileParams::parse("p", raw(gamma, aversion)).unwrap();
                for sigma in [0.0, 0.001, 0.05, 0.08, 0.11, 0.2] {
                    for share in [0.0, 0.1, 0.2, 0.5, 0.8, 0.9, 1.0] {
                        let skew = price(&params, sigma, share).skew;
                        assert!(
                            (lowest..=highest).contains(&skew),
                            "γ {gamma}, λ {aversion}, σ {sigma}, share {share}: skew {skew}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_tilt_never_carries_a_side_past_the_mid() {
        // γ large, so the raw tilt (q·γ·σ·√τ) dwarfs the half-spread and the economic ±delta
        // clamp is the one that binds. γ is kept below the point where delta itself would reach
        // SKEW_LIMIT (0.5): at γ = 100, delta ≈ 0.06, well under 0.5, so ±delta binds before the
        // safety clamp and skew lands exactly on delta. (Since FIX 2 removed the MAX_DELTA cap on
        // delta, an even larger γ would push delta past SKEW_LIMIT and the safety net would bind
        // first — a different invariant, covered by the_tilt_never_flips_or_doubles test.)
        let params = VolatileParams::parse("p", knobs("100", "700", "0")).unwrap();
        let terms = price(&params, 0.01, 1.0);
        assert!(terms.delta < SKEW_LIMIT);
        assert_eq!(terms.skew, terms.delta);
        let terms = price(&params, 0.01, 0.0);
        assert_eq!(terms.skew, -terms.delta);
    }

    #[test]
    fn a_shifted_mid_moves_with_the_tilt_in_lane_orientation() {
        let mid = U256::from(4000u64) * U256::exp10(18);
        // q > 0 lowers the market price; on a direct lane the published mid drops.
        let down = shifted_mid(mid, 0.001, false, 18).unwrap();
        assert_eq!(down, U256::from(3996u64) * U256::exp10(18));
        // An inverted lane publishes 1/price, which rises when the price drops.
        let inverted = U256::exp10(36) / mid;
        let up = shifted_mid(inverted, 0.001, true, 18).unwrap();
        assert!(up > inverted);
        // And back within a rounding step of 1/3996.
        let expected = U256::exp10(36) / (U256::from(3996u64) * U256::exp10(18));
        assert!(up.abs_diff(expected) <= U256::from(1u64));
        // No tilt, no change.
        assert_eq!(shifted_mid(mid, 0.0, false, 18).unwrap(), mid);
    }

    #[test]
    fn fractions_render_at_the_published_scale() {
        assert_eq!(
            fraction_scaled(0.0005, 18).unwrap(),
            U256::from(5u64) * U256::exp10(14)
        );
        assert_eq!(fraction_scaled(0.0, 18).unwrap(), U256::zero());
        assert!(fraction_scaled(-0.1, 18).is_err());
        assert!(fraction_scaled(f64::NAN, 18).is_err());
    }

    #[test]
    fn history_needs_a_minute_before_it_reports_a_volatility() {
        let epoch = Instant::now();
        let mut history = PriceHistory::new(epoch);
        for s in 0..30 {
            history.record(4000.0, epoch + Duration::from_secs(s));
        }
        assert_eq!(
            history.volatility(epoch + Duration::from_secs(30), Duration::from_secs(600)),
            Err(Duration::from_secs(29))
        );
        for s in 30..=60 {
            history.record(4000.0, epoch + Duration::from_secs(s));
        }
        assert_eq!(
            history.volatility(epoch + Duration::from_secs(60), Duration::from_secs(600)),
            Ok(0.0)
        );
    }

    #[test]
    fn a_flat_price_has_no_volatility_and_a_moving_one_does() {
        let epoch = Instant::now();
        let mut history = PriceHistory::new(epoch);
        // Alternate ±0.1% every second for two minutes.
        for s in 0..120u64 {
            let mid = if s % 2 == 0 { 4000.0 } else { 4004.0 };
            history.record(mid, epoch + Duration::from_secs(s));
        }
        let sigma = history
            .volatility(epoch + Duration::from_secs(120), Duration::from_secs(600))
            .unwrap();
        // Each second's return is ±ln(1.001), so σ per √second is that.
        assert!((sigma - 1.001f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn one_sample_per_second_and_the_latest_wins() {
        let epoch = Instant::now();
        let mut history = PriceHistory::new(epoch);
        history.record(4000.0, epoch + Duration::from_millis(100));
        history.record(4100.0, epoch + Duration::from_millis(900));
        history.record(4200.0, epoch + Duration::from_millis(1500));
        assert_eq!(history.samples.len(), 2);
        assert_eq!(history.samples[0], (0, 4100.0));
        assert_eq!(history.samples[1], (1, 4200.0));
        // A late write from the second before is ignored.
        history.record(1.0, epoch + Duration::from_millis(950));
        assert_eq!(history.samples[0], (0, 4100.0));
    }

    #[test]
    fn a_gap_in_ticks_is_one_long_return_not_many_zeros() {
        let epoch = Instant::now();
        let mut history = PriceHistory::new(epoch);
        history.record(4000.0, epoch);
        history.record(4040.0, epoch + Duration::from_secs(100));
        let sigma = history
            .volatility(epoch + Duration::from_secs(100), Duration::from_secs(600))
            .unwrap();
        // One 1% return over 100 seconds: variance per second is ln(1.01)²/100.
        assert!((sigma - 1.01f64.ln() / 10.0).abs() < 1e-12);
    }

    #[test]
    fn history_outside_the_window_is_ignored_and_beyond_retention_dropped() {
        let epoch = Instant::now();
        let mut history = PriceHistory::new(epoch);
        history.record(1000.0, epoch);
        for s in 3000..3200u64 {
            history.record(4000.0, epoch + Duration::from_secs(s));
        }
        // The old 1000 print would be a huge return; it is outside a 600s window.
        let now = epoch + Duration::from_secs(3200);
        assert_eq!(history.volatility(now, Duration::from_secs(600)), Ok(0.0));
        // And past MAX_WINDOW it is gone entirely.
        history.record(4000.0, epoch + Duration::from_secs(3601));
        assert_eq!(history.samples.front().unwrap().0, 3000);
    }

    #[test]
    fn parse_bounds_every_knob() {
        let p = params();
        assert_eq!(p.gamma.get(), 0.1);
        assert_eq!(p.hold_secs.get(), 12.0);
        assert_eq!(p.fill_delay_secs.get(), 6.0);
        assert_eq!(p.target_share.get(), 0.5);
        assert_eq!(p.volatility_window, Duration::from_secs(600));

        let err = |gamma, k, kappa, share, window| {
            let mut raw = knobs(gamma, k, kappa);
            raw.target_share = share;
            raw.volatility_window_secs = window;
            VolatileParams::parse("p", raw).unwrap_err().to_string()
        };
        assert!(err("0", "700", "1", None, None).contains("gamma must be above zero"));
        assert!(err("0.1", "0", "1", None, None).contains("k must be above zero"));
        assert!(err("0.1", "700", "-1", None, None).contains("kappa \"-1\" is negative"));
        assert!(
            err("0.1", "700", "1", Some("0"), None).contains("target_share must be above zero")
        );
        assert!(err("0.1", "700", "1", Some("1"), None).contains("between 0 and 1"));
        assert!(err("0.1", "700", "1", Some("100"), None).contains("between 0 and 1"));
        assert!(err("0.1", "700", "1", None, Some("10")).contains("below the 60 seconds"));
        assert!(err("0.1", "700", "1", None, Some("7200")).contains("above the 3600 seconds"));
        assert!(err("abc", "700", "1", None, None).contains("invalid gamma"));
        assert!(err("inf", "700", "1", None, None).contains("not a finite number"));
    }

    #[test]
    fn the_base_share_values_the_base_at_the_market_mid() {
        let at = Instant::now();
        // 1 WETH at 4000 against 4000 USDC: half and half.
        let even = Inventory {
            vault: Address::zero(),
            base: 1.0,
            quote: 4000.0,
            at,
        };
        assert_eq!(even.base_share(4000.0), 0.5);
        // 3 WETH against 4000 USDC: 12000 of 16000.
        let heavy = Inventory {
            vault: Address::zero(),
            base: 3.0,
            quote: 4000.0,
            at,
        };
        assert_eq!(heavy.base_share(4000.0), 0.75);
        // Adding liquidity on both sides in the same ratio changes nothing.
        let bigger = Inventory {
            vault: Address::zero(),
            base: 30.0,
            quote: 40000.0,
            at,
        };
        assert_eq!(bigger.base_share(4000.0), 0.75);
        // An empty vault reads as balanced.
        let empty = Inventory {
            vault: Address::zero(),
            base: 0.0,
            quote: 0.0,
            at,
        };
        assert_eq!(empty.base_share(4000.0), 0.5);
    }

    #[test]
    fn histories_are_shared_per_symbol() {
        let histories = Histories::default();
        let a = histories.for_symbol("ETHUSDC");
        let b = histories.for_symbol("ethusdc");
        let c = histories.for_symbol("BTCUSDC");
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &c));
    }

    /// The vault is resolved on every read, not once: the owner can move a pair to another
    /// account with setPairVault while the pusher runs, and a balance read off the old vault
    /// would tilt the skew with nothing saying so.
    #[tokio::test]
    async fn inventory_follows_the_pair_vault_between_reads() {
        let rpc = crate::rpc_mock::MockRpc::spawn(100).await;
        let client = EthClient::new(url::Url::parse(&rpc.url).unwrap()).unwrap();
        let target = Address::from_low_u64_be(0x7a);
        let base = Side {
            token: Address::from_low_u64_be(0xc0),
            decimals: 18,
        };
        let quote = Side {
            token: Address::from_low_u64_be(0xa0),
            decimals: 6,
        };
        let vault_a = Address::from_low_u64_be(0xa);
        let vault_b = Address::from_low_u64_be(0xb);
        rpc.set_balance(vault_a, U256::from(5) * U256::exp10(18));
        rpc.set_balance(vault_b, U256::from(7) * U256::exp10(18));

        rpc.set_vault(vault_a);
        let first = read_inventory(&client, target, base, quote).await.unwrap();
        assert_eq!(first.vault, vault_a);
        assert_eq!(first.base, 5.0);

        rpc.set_vault(vault_b);
        let second = read_inventory(&client, target, base, quote).await.unwrap();
        assert_eq!(second.vault, vault_b);
        assert_eq!(second.base, 7.0);
    }
}

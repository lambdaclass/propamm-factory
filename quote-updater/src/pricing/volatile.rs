//! `volatile`: a spread computed every tick from the recent volatility and the vault's
//! inventory, and a mid tilted by the inventory. The formula is `crate::volatile::price`;
//! this is the lane's side of it: reading σ and the vault, and rendering the result.

use std::sync::{Arc, Mutex};

use ethrex_common::U256;

use super::{Diagnostics, Pricer, PricerOutput, Refusal, TickCtx};
use crate::{
    ensure_fits_216_bits,
    feed::scaled_to_f64,
    metrics::PairMetrics,
    update::{Pricing, UnusableKind},
    volatile::{self, PriceHistory, VolatileParams},
};

/// A volatile pair's pricer: the market gives the mid, the history gives σ, the inventory
/// gives q, and the knobs are the pair's. The three are read together on every tick so the
/// published pair is always one consistent reading.
pub(crate) struct VolatilePricer {
    /// The market's σ history, not this lane generation's: it outlives reloads (see
    /// `volatile::Histories`).
    pub(crate) history: Arc<Mutex<PriceHistory>>,
    pub(crate) inventory: crate::pricing::InventoryFeed,
    pub(crate) params: VolatileParams,
    pub(crate) invert: bool,
    pub(crate) price_decimals: u32,
    /// Where the terms are recorded, so an operator can see which one moved the spread.
    pub(crate) metrics: PairMetrics,
}

impl Pricer for VolatilePricer {
    fn price(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        let sigma = volatile::lock(&self.history)
            .volatility(tick.now(), self.params.volatility_window)
            .map_err(|covered| {
                Refusal::core(
                    UnusableKind::WarmingUp,
                    format!(
                        "{}s of price history, σ needs {}s; warming up",
                        covered.as_secs(),
                        volatile::MIN_HISTORY.as_secs()
                    ),
                )
            })?;
        // The channel is seeded before the pair starts, so the only way to have no usable
        // reading is for the one it holds to have aged out.
        let inventory = self.inventory.latest();
        if inventory.at.elapsed() > volatile::MAX_INVENTORY_AGE {
            return Err(Refusal::core(
                UnusableKind::NoInventory,
                format!(
                    "vault balance is {:.0?} old; refusing to tilt off a stale reading",
                    inventory.at.elapsed()
                ),
            ));
        }
        // The vault's base is valued at the market mid: the sample is in lane orientation,
        // so an inverted lane reads it back the other way up. Through f64, like the
        // history: q is an estimate, not a published number.
        let market_mid = scaled_to_f64(market.mid, self.price_decimals);
        let market_mid = if self.invert {
            1.0 / market_mid
        } else {
            market_mid
        };
        let base_share = inventory.base_share(market_mid);
        let terms = volatile::price(&self.params, sigma, base_share);
        let m = &self.metrics;
        m.pricing_sigma.set(terms.sigma);
        m.pricing_hold.set(terms.hold);
        m.pricing_edge.set(terms.edge);
        m.pricing_stale.set(terms.stale);
        m.pricing_inventory.set(terms.q);
        m.pricing_skew.set(terms.skew);
        m.inventory_base.set(inventory.base);
        m.inventory_quote.set(inventory.quote);
        m.inventory_base_share.set(base_share);

        let overflow =
            |err: eyre::Report| Refusal::core(UnusableKind::DeltaOverflow, format!("{err:#}"));
        let delta =
            volatile::fraction_scaled(terms.delta, self.price_decimals).map_err(overflow)?;
        let spread_scale = U256::exp10(self.price_decimals as usize);
        if delta >= spread_scale {
            return Err(Refusal::core(
                UnusableKind::DeltaOverflow,
                format!(
                    "computed half-spread {} is not below one whole unit; refusing to \
                     publish a spread that leaves the taker nothing",
                    terms.delta
                ),
            ));
        }
        ensure_fits_216_bits(delta).map_err(overflow)?;
        let mid = volatile::shifted_mid(market.mid, terms.skew, self.invert, self.price_decimals)
            .map_err(overflow)?;
        out.terms = Some(Pricing {
            sigma: terms.sigma,
            hold: terms.hold,
            edge: terms.edge,
            stale: terms.stale,
            skew: terms.skew,
        });
        Ok(PricerOutput::new(delta, mid))
    }

    /// `--check` does not wait the minute of history σ needs, so it shows the spread at
    /// σ = 0 (the competition term alone), on the unshifted mid, and says so in a note.
    /// It reads the vault the way the run will, so a target or token the run would refuse
    /// fails here first. Writes no gauges: `--check` serves no metrics.
    fn preview(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        let inventory = self.inventory.latest();
        let market_mid = scaled_to_f64(market.mid, self.price_decimals);
        let market_mid = if self.invert {
            1.0 / market_mid
        } else {
            market_mid
        };
        let share = inventory.base_share(market_mid);
        let terms = volatile::price(&self.params, 0.0, share);
        out.note(format!(
            "volatile: this delta is term 2 only, computed with σ = 0 \
             because --check does not wait the 60s of price history \
             σ needs; the running pusher adds term 1 and term 3 on \
             top. Vault {:#x}: {} base, {} quote, {:.1}% of its value in \
             the base against a target_share of {:.1}% (q = {:.3})",
            inventory.vault,
            inventory.base,
            inventory.quote,
            share * 100.0,
            self.params.target_share.get() * 100.0,
            terms.q
        ));
        let delta = volatile::fraction_scaled(terms.delta, self.price_decimals)
            .map_err(|err| Refusal::core(UnusableKind::DeltaOverflow, format!("{err:#}")))?;
        Ok(PricerOutput::new(delta, market.mid))
    }
}

//! `feed`: the market's mid, at the book's own half-spread or the pair's configured
//! `delta`.

use ethrex_common::U256;

use super::{Diagnostics, Pricer, PricerOutput, Refusal, TickCtx};
use crate::{config::SourceSpec, ensure_fits_216_bits, update::UnusableKind};

/// A pair with `symbol`/`sources` and no pricing model of its own.
pub(crate) struct FeedPricer {
    /// Kept whole rather than reduced to its `delta`, so the published spread comes from
    /// `SourceSpec::published_delta` here exactly as it does in `--check`.
    pub(crate) source: SourceSpec,
    pub(crate) spread_scale: U256,
}

impl Pricer for FeedPricer {
    fn price(&mut self, tick: &TickCtx, _out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        // `published_delta` and `ensure_fits_216_bits` both report with eyre. Their text is
        // carried through verbatim under a kind, so the withdrawn reason on the block summary
        // reads exactly as it did before pricing moved behind this trait.
        let delta = self
            .source
            .published_delta(market.delta, self.spread_scale)
            .map_err(|err| Refusal::core(UnusableKind::DeltaOverflow, format!("{err:#}")))?;
        ensure_fits_216_bits(delta)
            .map_err(|err| Refusal::core(UnusableKind::DeltaOverflow, format!("{err:#}")))?;
        Ok(PricerOutput::new(delta, market.mid))
    }
}

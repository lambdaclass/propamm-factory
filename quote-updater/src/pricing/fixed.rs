//! `fixed`: a pair whose config states `mid` and `delta` publishes them, whatever the
//! market does.

use ethrex_common::U256;

use super::{Diagnostics, Pricer, PricerOutput, Refusal, TickCtx};

/// The mid and delta a pair's config fixed, already in lane orientation: an inverted lane's
/// mid was inverted at parse time (config.rs), so nothing here knows about orientation.
pub(crate) struct FixedPricer {
    pub(crate) delta: U256,
    pub(crate) mid: U256,
}

impl Pricer for FixedPricer {
    fn price(&mut self, _tick: &TickCtx, _out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        Ok(PricerOutput::new(self.delta, self.mid))
    }
}

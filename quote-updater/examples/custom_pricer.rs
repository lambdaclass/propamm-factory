//! A quote updater with one custom pricing model, `skewed`: the market mid moved by a
//! fixed fraction, at a fixed half-spread, and never by more than that half-spread, so the
//! quote stays around the market's mid. A pair opts in with a stanza:
//!
//! ```toml
//! [[pairs]]
//! tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
//! symbol  = "ETHUSDC"
//! key_env = "UPDATER_KEY_WETH_USDC"
//!
//! [pairs.pricing]
//! kind        = "skewed"
//! half_spread = 0.0005
//! skew        = 0.0002
//! ```
//!
//! Everything else (config, reload, builders, metrics, the band and the core's backstop)
//! is the library's: `cargo run -p quote-updater --example custom_pricer -- --config c.toml`.

use quote_updater::prelude::*;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Skewed {
    half_spread: f64,
    skew: f64,
}

struct SkewedPricer {
    cfg: Skewed,
    book: DiagHandle,
}

impl Pricer for SkewedPricer {
    fn price(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        out.set(&self.book, market.half_spread());
        let half_spread = self.cfg.half_spread;
        let delta = market.scaled_fraction(half_spread)?;
        // Past the half-spread the quote is through the market: we would sell below its
        // mid or buy above it, and a taker unwinds that on the market at our cost.
        let skew = self.cfg.skew.clamp(-half_spread, half_spread);
        Ok(PricerOutput::new(delta, market.shift(skew)?))
    }
}

fn main() -> std::process::ExitCode {
    Updater::builder()
        .pricer_fn("skewed", |cfg: Skewed, ctx: &mut BuildCtx| {
            let book = ctx.diagnostic("book_half_spread")?;
            Ok(SkewedPricer { cfg, book })
        })
        .run_from_env()
}

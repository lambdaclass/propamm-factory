//! A quote updater with a pricing model that reads the vault: `tilted`, a fixed half-spread
//! with the mid tilted away from the side the vault is long, the way the volatile model
//! tilts, by an amount the operator chooses. What the library offers beyond the market
//! (`ctx.inventory()`, `ctx.history()`, `ctx.chain()`) is reached in the build, so the
//! tick stays a few lines of arithmetic; and reading the vault is async, which is why this
//! is a [`Factory`] rather than a `pricer_fn` closure. A pair opts in with:
//!
//! ```toml
//! [pairs.pricing]
//! kind        = "tilted"
//! half_spread = 0.0005   # published as the delta, a fraction of the mid
//! tilt        = 0.01     # the mid moves by tilt × (base share − 0.5), in market terms
//! ```
//!
//! `make e2e-custom` runs this binary against the mocks:
//! `cargo run -p quote-updater --example tilted -- --config c.toml`.

use std::time::Duration;

use quote_updater::{eyre, prelude::*};

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Cfg {
    half_spread: f64,
    tilt: f64,
}

struct Tilted {
    cfg: Cfg,
    inventory: InventoryFeed,
    share: DiagHandle,
    stale: RefusalHandle,
}

impl Pricer for Tilted {
    fn price(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        let reading = self.inventory.latest();
        if reading.age(tick.now()) > Duration::from_secs(60) {
            return Err(Refusal::new(
                &self.stale,
                "the vault reading is over a minute old",
            ));
        }
        let share = reading.base_share(market.mid_f64());
        out.set(&self.share, share);
        let skew = self.cfg.tilt * (share - 0.5);
        Ok(PricerOutput::new(
            market.scaled_fraction(self.cfg.half_spread)?,
            market.shift(skew)?,
        ))
    }
}

struct TiltedFactory;

impl Factory for TiltedFactory {
    type Config = Cfg;
    type Pricer = Tilted;

    fn validate(&self, cfg: &Cfg, _pair: &PairShape) -> eyre::Result<()> {
        // The run prefixes the pair's label and the stanza, so say only what is wrong.
        eyre::ensure!(
            (0.0..=0.5).contains(&cfg.tilt),
            "tilt {} is outside 0..=0.5, a full tilt at an empty vault",
            cfg.tilt
        );
        Ok(())
    }

    fn build<'a>(
        &'a self,
        cfg: &'a Cfg,
        ctx: &'a mut BuildCtx,
    ) -> BoxFuture<'a, eyre::Result<Tilted>> {
        Box::pin(async move {
            let share = ctx.diagnostic("base_share")?;
            let stale = ctx.refusal("stale_inventory")?;
            // Reads the vault now: a wrong target fails this build, and so the file.
            let inventory = ctx.inventory().await?;
            Ok(Tilted {
                cfg: cfg.clone(),
                inventory,
                share,
                stale,
            })
        })
    }
}

fn main() -> std::process::ExitCode {
    Updater::builder()
        .pricer("tilted", TiltedFactory)
        .run_from_env()
}

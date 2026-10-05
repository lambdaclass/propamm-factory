//! A pricer is unit-testable with no tokio runtime and no network: build it, hand it a
//! tick, read what it published. Plain `#[test]`s, and the first line of each proves no
//! runtime is around.

use quote_updater::{prelude::*, testing};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tilted {
    half_spread: f64,
    tilt: f64,
}

struct TiltedPricer {
    cfg: Tilted,
    wide: RefusalHandle,
    seen: DiagHandle,
}

impl Pricer for TiltedPricer {
    fn price(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        out.set(&self.seen, market.mid_f64());
        if self.cfg.half_spread > 0.05 {
            return Err(Refusal::new(&self.wide, "half_spread above 5%"));
        }
        Ok(PricerOutput::new(
            market.scaled_fraction(self.cfg.half_spread)?,
            market.shift(self.cfg.tilt)?,
        ))
    }
}

fn make(cfg: Tilted, ctx: &mut BuildCtx) -> quote_updater::eyre::Result<TiltedPricer> {
    Ok(TiltedPricer {
        cfg,
        wide: ctx.refusal("too_wide")?,
        seen: ctx.diagnostic("mid_seen")?,
    })
}

#[test]
fn a_pricer_prices_a_tick_with_no_runtime() {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "no runtime here"
    );
    let pair = testing::pair_with(true, 18); // an inverted lane: the pricer never notices
    let (mut pricer, ctx) =
        testing::build_fn(make, "half_spread = 0.0005\ntilt = 0.01", &pair).unwrap();
    let market = testing::market(&pair, 4000.0, 0.0001);
    let mut out = testing::diagnostics(&ctx);
    let priced = pricer
        .price(&testing::tick(&pair, Some(&market)), &mut out)
        .unwrap();
    assert_eq!(priced.delta, market.scaled_fraction(0.0005).unwrap());
    assert_eq!(priced.mid, market.shift(0.01).unwrap());
    assert!((out.get(&pricer.seen).unwrap() - 4000.0).abs() < 1e-6);
}

/// `price()` is not the last word: the run puts its answer through the core's backstop
/// before signing it, and a test that stops at `price()` passes where the run withdraws.
/// `testing::backstop` is that step, as the run takes it.
#[test]
fn the_cores_backstop_withdraws_what_the_pricer_would_publish() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let pair = testing::pair_with(true, 18);
    let market = testing::market(&pair, 4000.0, 0.0001);
    let tick = testing::tick(&pair, Some(&market));

    let (mut modest, ctx) =
        testing::build_fn(make, "half_spread = 0.0005\ntilt = 0.01", &pair).unwrap();
    let out = modest
        .price(&tick, &mut testing::diagnostics(&ctx))
        .unwrap();
    assert_eq!(
        testing::backstop(out, &tick).unwrap(),
        out,
        "a 1% tilt is published"
    );

    // A 75% tilt the pricer computes without complaint, and the core will not publish.
    let (mut wild, ctx) =
        testing::build_fn(make, "half_spread = 0.0005\ntilt = 0.75", &pair).unwrap();
    let out = wild
        .price(&tick, &mut testing::diagnostics(&ctx))
        .expect("the pricer itself prices it");
    let err = format!("{:#}", testing::backstop(out, &tick).unwrap_err());
    assert!(err.contains("the core allows"), "{err}");

    // Nor a half-spread of one whole unit, whatever the market.
    let whole = PricerOutput::new(U256::exp10(18), market.mid);
    let err = format!("{:#}", testing::backstop(whole, &tick).unwrap_err());
    assert!(err.contains("one whole unit"), "{err}");
}

#[test]
fn a_refusal_carries_its_declared_reason() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let pair = testing::pair();
    let (mut pricer, ctx) = testing::build_fn(make, "half_spread = 0.2\ntilt = 0", &pair).unwrap();
    let market = testing::market(&pair, 1.0, 0.0);
    let refusal = pricer
        .price(
            &testing::tick(&pair, Some(&market)),
            &mut testing::diagnostics(&ctx),
        )
        .unwrap_err();
    assert_eq!(
        (refusal.reason(), refusal.message()),
        ("too_wide", "half_spread above 5%")
    );
}

#[test]
fn no_market_is_the_cores_refusal() {
    let pair = testing::pair();
    let (mut pricer, ctx) =
        testing::build_fn(make, "half_spread = 0.001\ntilt = 0", &pair).unwrap();
    let refusal = pricer
        .price(&testing::tick(&pair, None), &mut testing::diagnostics(&ctx))
        .unwrap_err();
    assert_eq!(refusal.reason(), "no_sample");
}

/// A pricer that reads the market's age is tested on its aged branch by placing the sample
/// and the tick in time, with no sleeping.
#[test]
fn a_tick_and_a_market_can_be_placed_in_time() {
    use std::time::{Duration, Instant};
    struct Cautious {
        old: RefusalHandle,
    }
    impl Pricer for Cautious {
        fn price(&mut self, tick: &TickCtx, _: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
            let market = tick.market()?;
            if market.age(tick.now()) > Duration::from_secs(5) {
                return Err(Refusal::new(&self.old, "the market is older than 5s"));
            }
            Ok(PricerOutput::new(
                market.scaled_fraction(0.001)?,
                market.mid,
            ))
        }
    }
    let pair = testing::pair();
    let mut ctx = testing::build_ctx(&pair);
    let mut pricer = Cautious {
        old: ctx.refusal("old_market").unwrap(),
    };
    let sampled = Instant::now();
    let market = testing::market_at(&pair, 4000.0, 0.0001, sampled);
    let fresh = testing::tick_at(&pair, Some(&market), sampled + Duration::from_secs(1));
    assert!(
        pricer
            .price(&fresh, &mut testing::diagnostics(&ctx))
            .is_ok()
    );
    let late = testing::tick_at(&pair, Some(&market), sampled + Duration::from_secs(10));
    let refusal = pricer
        .price(&late, &mut testing::diagnostics(&ctx))
        .unwrap_err();
    assert_eq!(refusal.reason(), "old_market");
}

/// A pricer that reads the vault and σ is built with both seeded: no chain and no runtime,
/// through the trait path, since `ctx.inventory()` is async. Left unseeded, the build says
/// what to seed.
#[test]
fn seeded_inventory_and_history_reach_a_pricer_with_no_runtime() {
    use std::time::{Duration, Instant};
    #[derive(serde::Deserialize)]
    struct NoCfg {}
    struct Aware {
        inventory: InventoryFeed,
        history: History,
    }
    impl Pricer for Aware {
        fn price(
            &mut self,
            tick: &TickCtx,
            out: &mut Diagnostics,
        ) -> Result<PricerOutput, Refusal> {
            let market = tick.market()?;
            let share = self.inventory.latest().base_share(market.mid_f64());
            let sigma = self
                .history
                .volatility(tick.now(), Duration::from_secs(300))
                .unwrap_or(0.0);
            let _ = out;
            Ok(PricerOutput::new(
                market.scaled_fraction(sigma.max(0.0001))?,
                market.shift(0.01 * (share - 0.5))?,
            ))
        }
    }
    struct AwareFactory;
    impl Factory for AwareFactory {
        type Config = NoCfg;
        type Pricer = Aware;
        fn build<'a>(
            &'a self,
            _: &'a NoCfg,
            ctx: &'a mut BuildCtx,
        ) -> BoxFuture<'a, quote_updater::eyre::Result<Aware>> {
            Box::pin(async move {
                Ok(Aware {
                    inventory: ctx.inventory().await?,
                    history: ctx.history()?,
                })
            })
        }
    }
    assert!(tokio::runtime::Handle::try_current().is_err());
    let pair = testing::pair();
    let now = Instant::now();
    // Two minutes of mids alternating by 0.1% each second: a σ well above zero.
    let samples = (0..=120)
        .map(|s| {
            (
                now - Duration::from_secs(120 - s),
                4000.0 * (1.0 + 0.001 * (s % 2) as f64),
            )
        })
        .collect();
    let inputs = testing::Inputs {
        // Half the value on each side at 4000: base_share is 0.5 and the tilt is nil.
        inventory: Some(testing::inventory(1.0, 4000.0)),
        history: samples,
        // The rest as a run without them would answer: an input added later then
        // changes nothing here.
        ..testing::Inputs::default()
    };
    let (mut pricer, ctx) = testing::build_with(&AwareFactory, "", &pair, inputs).unwrap();
    let market = testing::market_at(&pair, 4000.0, 0.0001, now);
    let priced = pricer
        .price(
            &testing::tick_at(&pair, Some(&market), now),
            &mut testing::diagnostics(&ctx),
        )
        .unwrap();
    assert_eq!(priced.mid, market.mid, "a balanced vault tilts nothing");
    assert!(
        priced.delta > market.scaled_fraction(0.0001).unwrap(),
        "σ widened the spread"
    );

    let err = match testing::build(&AwareFactory, "", &pair) {
        Err(err) => err,
        Ok(_) => panic!("built with nothing seeded"),
    };
    assert!(
        format!("{err:#}").contains("testing::build_ctx_with"),
        "{err:#}"
    );
}

#[test]
fn the_config_rejects_unknown_fields() {
    testing::assert_rejects_unknown_fields::<Tilted>("half_spread = 0.001\ntilt = 0");
}

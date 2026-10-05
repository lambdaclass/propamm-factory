//! A quote guard tested the way a downstream binary tests one: no runtime, no network, no
//! lane. The build context is seeded with the pricer's declared diagnostics so the guard's
//! `read_diagnostic` binds, the candidate is built from a tick and a price, and the guard's
//! verdict is read back. What `README.md` promises for guards, kept honest here.

use quote_updater::{
    U256, eyre,
    guard::{Candidate, Gate, QuoteGuard, ReadHandle},
    pricing::{BuildCtx, Diagnostics, PairShape, PricerOutput, Refusal, RefusalHandle},
    testing::{self, Inputs},
};

/// Withdraws when the pricer's `base_share` is over `max`, and halts when it is over one
/// (a share that cannot be, so the pricer is broken).
struct Cap {
    share: ReadHandle,
    max: f64,
    over: RefusalHandle,
}

impl QuoteGuard for Cap {
    fn check(&mut self, candidate: &Candidate<'_>, _: &mut Diagnostics) -> Gate {
        match candidate.get(&self.share) {
            Some(share) if share > 1.0 => {
                Gate::Halt(quote_updater::guard::TripReason::new("base share over one"))
            }
            Some(share) if share > self.max => Gate::Withdraw(Refusal::new(
                &self.over,
                format!("base share {share} over cap"),
            )),
            _ => Gate::Allow,
        }
    }
}

fn build(ctx: &mut BuildCtx) -> eyre::Result<Cap> {
    Ok(Cap {
        share: ctx.read_diagnostic("base_share")?,
        max: 0.6,
        over: ctx.refusal("over_cap")?,
    })
}

fn pair() -> PairShape {
    testing::pair()
}

#[test]
fn a_quote_guard_reads_the_pricers_diagnostic_and_judges_the_tick() {
    let pair = pair();
    let mut ctx = testing::build_ctx_with(
        &pair,
        Inputs {
            pricer_diagnostics: vec!["base_share".to_owned()],
            ..Inputs::default()
        },
    );
    let mut guard = build(&mut ctx).unwrap();
    let market = testing::market(&pair, 4000.0, 0.0005);
    let tick = testing::tick(&pair, Some(&market));
    let priced = PricerOutput::new(U256::exp10(14), U256::exp10(18));
    let mut out = testing::diagnostics(&ctx);

    for (share, expect_allow) in [(0.5, true), (0.7, false)] {
        let seen = testing::pricer_diagnostics(&ctx, &[("base_share", share)]);
        let candidate = testing::candidate(&tick, Ok(&priced), &seen);
        let gate = guard.check(&candidate, &mut out);
        assert_eq!(
            matches!(gate, Gate::Allow),
            expect_allow,
            "share {share}: {gate:?}"
        );
    }
    let seen = testing::pricer_diagnostics(&ctx, &[("base_share", 1.5)]);
    let candidate = testing::candidate(&tick, Ok(&priced), &seen);
    assert!(matches!(guard.check(&candidate, &mut out), Gate::Halt(_)));
}

#[test]
fn a_guard_that_reads_a_diagnostic_the_pricer_did_not_declare_fails_its_build() {
    let pair = pair();
    let mut ctx = testing::build_ctx(&pair);
    let err = build(&mut ctx)
        .err()
        .expect("no pricer declared base_share");
    assert!(format!("{err:#}").contains("base_share"), "{err:#}");
}

/// A market guard that judges venue agreement is tested with named venues and no run:
/// two venues 1% apart trip a 0.5% dispersion cap, two in agreement pass. The composite's
/// half-spread is read as a fraction, like a market's.
#[test]
fn a_dispersion_guard_is_tested_with_named_sources() {
    use std::time::{Duration, Instant};

    use quote_updater::{prelude::*, testing};

    struct Dispersion {
        cap: f64,
    }
    impl MarketGuard for Dispersion {
        fn assess(&mut self, sample: &CompositeSample, _: &mut Diagnostics) -> Verdict {
            let mids: Vec<f64> = sample.sources().iter().map(|s| s.mid_f64()).collect();
            let (lo, hi) = mids
                .iter()
                .fold((f64::MAX, f64::MIN), |(lo, hi), m| (lo.min(*m), hi.max(*m)));
            if (hi - lo) / lo > self.cap {
                Verdict::Trip(TripReason::new(format!(
                    "venues {:.2}% apart",
                    (hi - lo) / lo * 100.0
                )))
            } else {
                Verdict::Pass
            }
        }
    }

    let pair = testing::pair();
    let now = Instant::now();
    let age = Duration::from_millis(100);
    let mut guard = Dispersion { cap: 0.005 };
    let ctx = testing::build_ctx(&pair);
    let apart = testing::composite_sample_with(
        &pair,
        4020.0,
        0.0001,
        now,
        vec![
            testing::source_sample(&pair, "binance", 0.5, 4000.0, 0.0001, age),
            testing::source_sample(&pair, "kraken", 0.5, 4040.0, 0.0001, age),
        ],
    );
    assert_eq!(apart.half_spread(), 0.0001, "read like Market::half_spread");
    assert_eq!(
        apart.sources()[0].mid_f64(),
        4000.0,
        "a venue's mid, in market terms"
    );
    assert_eq!(apart.sources()[0].half_spread(), 0.0001);
    assert!(matches!(
        guard.assess(&apart, &mut testing::diagnostics(&ctx)),
        Verdict::Trip(_)
    ));
    let agreed = testing::composite_sample_with(
        &pair,
        4000.0,
        0.0001,
        now,
        vec![
            testing::source_sample(&pair, "binance", 0.5, 4000.0, 0.0001, age),
            testing::source_sample(&pair, "kraken", 0.5, 4001.0, 0.0001, age),
        ],
    );
    assert_eq!(
        guard.assess(&agreed, &mut testing::diagnostics(&ctx)),
        Verdict::Pass
    );
}

/// A gate compares in a test, and a pair can be shaped from real addresses: the lane and
/// the orientation are derived as the config derives them, whichever way the tokens are
/// written.
#[test]
fn a_gate_compares_and_a_pair_is_shaped_from_its_tokens() {
    use quote_updater::{Address, testing};

    assert_eq!(Gate::Allow, Gate::Allow);
    let weth: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        .parse()
        .unwrap();
    let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse()
        .unwrap();
    let target: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        .parse()
        .unwrap();
    let as_written = testing::pair_for("WETH/USDC", (weth, usdc), target, 18);
    let other_way = testing::pair_for("USDC/WETH", (usdc, weth), target, 18);
    assert!(
        as_written.inverted,
        "WETH sorts after USDC, so the lane is inverted"
    );
    assert!(!other_way.inverted);
    assert_eq!(
        as_written.lane, other_way.lane,
        "one lane, whichever way the tokens are written"
    );
    assert_eq!(
        as_written.tokens,
        (weth, usdc),
        "tokens stay as written: market orientation"
    );
}

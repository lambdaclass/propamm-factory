//! `fixed`: a pair whose stanza states `mid` and `delta` publishes them while its market
//! agrees. The simplest kind, for a pair whose price should not move.
//!
//! A fixed price does not follow its market, so it is only safe while the market sits
//! inside its own quote, `mid · (1 − delta)` to `mid · (1 + delta)`. Outside it a taker
//! trades the vault at a stale price: a stablecoin depeg drains the sound side at par, one
//! small step at a time. So the pair needs a market (`symbol` or `sources`),
//! and the pricer refuses every tick on which the market is outside its quote, whatever
//! the pair's band. A smoke test with no market says so with `unguarded = true`.
//!
//! ```toml
//! [pairs.pricing]
//! kind  = "fixed"
//! mid   = "1.0001"   # quote per base, as a person says it; an inverted lane publishes 1/mid
//! delta = "0.0002"   # half-spread as a fraction of the mid (0.0002 = 2 bp)
//! ```

use ethrex_common::U256;

use super::{
    BoxFuture, BuildCtx, Diagnostics, Factory, FormField, PairShape, Pricer, PricerOutput, Refusal,
    RefusalHandle, TickCtx,
};
use crate::feed::{parse_decimal_scaled, reciprocal_scaled};

/// The `fixed` stanza: as written, parsed exactly against the pair's scale in
/// [`Factory::validate`], so a typo fails the file rather than every tick.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedConfig {
    pub mid: String,
    pub delta: String,
    /// Publish with no market to compare the price with: a smoke test's, never a real
    /// pair's. A TOML bool, or the text `"true"`/`"false"` a pair form sends.
    #[serde(default, deserialize_with = "flag")]
    pub unguarded: bool,
}

/// A bool written either way: `true`, or the form's `"true"`. Blank is false.
fn flag<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Written {
        Bool(bool),
        Text(String),
    }
    match <Written as serde::Deserialize>::deserialize(deserializer)? {
        Written::Bool(value) => Ok(value),
        Written::Text(text) => match text.trim() {
            "true" => Ok(true),
            "false" | "" => Ok(false),
            other => Err(serde::de::Error::custom(format!(
                "unguarded is true or false, not {other:?}"
            ))),
        },
    }
}

/// The reason a fixed price is withdrawn while its market is outside its own quote.
const OUTSIDE_QUOTE: &str = "market_outside_quote";

/// The `fixed` pricing kind. Register it with `Updater::builder().pricer("fixed", Fixed)`.
pub struct Fixed;

impl Fixed {
    /// The exact `(delta, mid)` the lane publishes for this stanza: the mid as declared in
    /// market orientation, inverted for an inverted lane (byte for byte the rule a feed
    /// follows), the delta as a fraction below one unit, both inside the pair's band.
    fn resolve(cfg: &FixedConfig, pair: &PairShape) -> eyre::Result<(U256, U256)> {
        // With no market nothing could stop a fixed price through a depeg.
        eyre::ensure!(
            pair.sources > 0 || cfg.unguarded,
            "pricing `fixed` publishes the same mid whatever the market does, and this pair \
             has no market to compare it with, so through a depeg the vault would fill at this \
             price until the pair is halted. Give the pair a `symbol` (for example \
             `USDCUSDT`) or `sources`: it then stops quoting whenever the market leaves its own \
             bid and ask. Or price it with `kind = \"feed\"`. For a smoke test with no market, \
             set `unguarded = true` in this stanza"
        );
        let decimals = pair.price_decimals;
        let declared_mid = parse_decimal_scaled(&cfg.mid, decimals)
            .map_err(|err| eyre::eyre!("invalid mid: {err:#}"))?;
        eyre::ensure!(
            !declared_mid.is_zero(),
            "mid must be nonzero; PropAMM rejects a zero mid"
        );
        let mid = if pair.inverted {
            // Truncation, not overflow: inverting a mid far above the scale floors to zero,
            // and PropAMM rejects a zero mid. Reported against the number the operator wrote.
            let inverted = reciprocal_scaled(declared_mid, decimals).ok_or_else(|| {
                eyre::eyre!("mid {} has no reciprocal at {decimals} decimals", cfg.mid)
            })?;
            eyre::ensure!(
                !inverted.is_zero(),
                "mid {} inverts to zero at {decimals} decimals; this lane publishes 1/{}, \
                 which is too small to represent at this scale",
                cfg.mid,
                cfg.mid
            );
            inverted
        } else {
            declared_mid
        };
        // Not inverted, and that is not an oversight: `delta` is a fraction of the mid, and
        // (ask-bid)/(ask+bid) is invariant under inversion.
        let delta = crate::config::parse_delta(&cfg.delta, decimals)?;
        // A fixed price is fixed, so a band it already violates can only be a mistake, and
        // one that would otherwise surface as every push refusing to publish.
        if let Some(min) = pair.min_mid {
            eyre::ensure!(
                mid >= min,
                "mid {mid} is below this pair's min_mid {min}, so it could never be published"
            );
        }
        if let Some(max) = pair.max_mid {
            eyre::ensure!(
                mid <= max,
                "mid {mid} is above this pair's max_mid {max}, so it could never be published"
            );
        }
        Ok((delta, mid))
    }
}

const FIELDS: &[FormField] = &[
    FormField::new(
        "mid",
        "1",
        "the price we publish, quote per base as a person says it (USDC per WETH). The same \
         every block.",
    ),
    FormField::new(
        "delta",
        "0.0005",
        "the spread, as a fraction of the mid. 0.0005 means we sell at mid + 0.05% and buy at \
         mid − 0.05%. We only quote while the market is inside that spread.",
    ),
    FormField::new(
        "unguarded",
        "",
        "true only for a smoke test with no venue ticked: publish with no market to compare \
         the price with. Leave blank for any real pair.",
    ),
];

impl Factory for Fixed {
    type Config = FixedConfig;
    type Pricer = FixedPricer;

    fn validate(&self, cfg: &FixedConfig, pair: &PairShape) -> eyre::Result<()> {
        Self::resolve(cfg, pair).map(drop)
    }

    fn fields(&self) -> &'static [FormField] {
        FIELDS
    }

    fn form_help(&self) -> &'static str {
        "<p class=explain>We send the same mid and the same spread every block, while the pair's \
         market sits inside that spread; when it leaves, we stop quoting until it is back. For \
         a pair whose price should not move. Tick its market below.</p>"
    }

    fn summary(&self, cfg: &FixedConfig) -> String {
        let unguarded = if cfg.unguarded { " unguarded" } else { "" };
        format!("mid {} delta {}{unguarded}", cfg.mid, cfg.delta)
    }

    fn build<'a>(
        &'a self,
        cfg: &'a FixedConfig,
        ctx: &'a mut BuildCtx,
    ) -> BoxFuture<'a, eyre::Result<FixedPricer>> {
        let built = Self::resolve(cfg, ctx.pair()).and_then(|(delta, mid)| {
            Ok(FixedPricer {
                delta,
                mid,
                outside_quote: ctx.refusal(OUTSIDE_QUOTE)?,
            })
        });
        Box::pin(std::future::ready(built))
    }
}

/// The mid and delta the stanza fixed, already in lane orientation, and the reason a tick
/// is withdrawn while the market is outside the quote they make.
pub struct FixedPricer {
    pub(crate) delta: U256,
    pub(crate) mid: U256,
    outside_quote: RefusalHandle,
}

impl FixedPricer {
    /// A pricer built outside a lane's build, for tests that drive one directly.
    #[cfg(test)]
    pub(crate) fn for_tests(delta: U256, mid: U256) -> Self {
        let mut ctx = crate::testing::build_ctx(&crate::testing::pair());
        FixedPricer {
            delta,
            mid,
            outside_quote: ctx
                .refusal(OUTSIDE_QUOTE)
                .expect("a fresh build declares it"),
        }
    }

    /// The quote this price makes, `mid · (1 − delta)` to `mid · (1 + delta)` in lane
    /// orientation, or `None` where the product does not fit.
    fn quote(&self, price_decimals: u32) -> Option<(U256, U256)> {
        let unit = crate::config::spread_scale(price_decimals);
        let reach = self.mid.checked_mul(self.delta)? / unit;
        Some((
            self.mid.saturating_sub(reach),
            self.mid.saturating_add(reach),
        ))
    }
}

impl Pricer for FixedPricer {
    fn price(&mut self, tick: &TickCtx, _out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        // A pair with a market quotes only while the market sits inside this price's own bid
        // and ask; outside them a taker trades the vault at a stale price. The
        // core has already refused a stale market, so a tick with none is an unguarded pair.
        if let Ok(market) = tick.market() {
            let quote = self.quote(tick.pair().price_decimals);
            let inside = quote.is_some_and(|(low, high)| low <= market.mid && market.mid <= high);
            if !inside {
                let range = quote.map_or_else(
                    || "beyond what the scale can hold".to_owned(),
                    |(low, high)| format!("{low} to {high}"),
                );
                return Err(Refusal::new(
                    &self.outside_quote,
                    format!(
                        "the market's mid {} is outside this fixed price's own quote, {range}: a \
                         taker would trade the vault at a stale price; refusing to publish",
                        market.mid
                    ),
                ));
            }
        }
        Ok(PricerOutput::new(self.delta, self.mid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    const STANZA: &str = "mid = \"1.0001\"\ndelta = \"0.0002\"";

    #[test]
    fn a_mid_on_a_direct_lane_is_published_as_written() {
        let pair = testing::pair();
        let (mut pricer, ctx) = testing::build(&Fixed, STANZA, &pair).unwrap();
        let out = pricer
            .price(&testing::tick(&pair, None), &mut testing::diagnostics(&ctx))
            .unwrap();
        assert_eq!(out.mid, U256::from_dec_str("1000100000000000000").unwrap());
        assert_eq!(out.delta, U256::from_dec_str("200000000000000").unwrap());
        assert!(ctx.diagnostic_names().is_empty(), "declares nothing");
    }

    /// The mid is declared in market orientation, exactly like a market's, so an inverted
    /// lane publishes its reciprocal. This is the one case where a wrong answer is silent
    /// and catastrophic: nothing downstream can tell a market-oriented mid from a
    /// lane-oriented one, and publishing 4001.98 where 0.000249… belongs is wrong by a
    /// factor of 1.6e7 on a lane a taker can trade.
    #[test]
    fn a_mid_on_an_inverted_lane_publishes_the_reciprocal() {
        let pair = testing::pair_with(true, 18);
        let (pricer, _) =
            testing::build(&Fixed, "mid = \"4001.98\"\ndelta = \"0.00025\"", &pair).unwrap();
        // Golden: 10^36 / 4001.98e18, the same floor division the feed path takes.
        assert_eq!(pricer.mid, U256::from_dec_str("249876311225943").unwrap());
        assert_ne!(
            pricer.mid,
            U256::from_dec_str("4001980000000000000000").unwrap(),
            "not the declared value"
        );
        // A fraction of the mid, and (ask-bid)/(ask+bid) is invariant under inversion, so
        // the delta passes through untouched.
        assert_eq!(pricer.delta, U256::from_dec_str("250000000000000").unwrap());
    }

    /// A fixed price is fixed, so a band it already violates can only be a mistake, and
    /// one that would otherwise surface as every push refusing to publish.
    #[test]
    fn a_mid_outside_the_pairs_band_fails_the_build() {
        let mut pair = testing::pair();
        pair.min_mid = Some(U256::exp10(18));
        let err = format!(
            "{:#}",
            testing::build(&Fixed, "mid = \"0.1\"\ndelta = \"0\"", &pair)
                .err()
                .unwrap()
        );
        assert!(err.contains("min_mid"), "{err}");
        pair.min_mid = None;
        pair.max_mid = Some(U256::exp10(18));
        let err = format!(
            "{:#}",
            testing::build(&Fixed, "mid = \"2\"\ndelta = \"0\"", &pair)
                .err()
                .unwrap()
        );
        assert!(err.contains("max_mid"), "{err}");
        // The band is read in lane orientation: an inverted lane's 4000 is 0.00025.
        let mut inverted = testing::pair_with(true, 18);
        inverted.min_mid = Some(U256::exp10(14));
        inverted.max_mid = Some(U256::exp10(15));
        testing::build(&Fixed, "mid = \"4000\"\ndelta = \"0\"", &inverted)
            .expect("inside the band");
    }

    #[test]
    fn a_malformed_or_impossible_stanza_fails_the_build() {
        let pair = testing::pair();
        let refused =
            |stanza: &str| format!("{:#}", testing::build(&Fixed, stanza, &pair).err().unwrap());
        assert!(refused("mid = \"abc\"\ndelta = \"0\"").contains("invalid mid"));
        assert!(refused("mid = \"0\"\ndelta = \"0\"").contains("nonzero"));
        assert!(refused("mid = \"1\"\ndelta = \"1\"").contains("not below 1"));
        assert!(refused("mid = \"1\"\ndelta = \"x\"").contains("invalid delta"));
        testing::assert_rejects_unknown_fields::<FixedConfig>(STANZA);
    }

    #[test]
    fn the_form_fields_and_the_summary_name_the_keys() {
        let names: Vec<&str> = Fixed.fields().iter().map(|f| f.name).collect();
        assert_eq!(names, ["mid", "delta", "unguarded"]);
        let cfg: FixedConfig = toml::from_str(STANZA).unwrap();
        assert_eq!(Fixed.summary(&cfg), "mid 1.0001 delta 0.0002");
        let unguarded: FixedConfig =
            toml::from_str(&format!("{STANZA}\nunguarded = true")).unwrap();
        assert_eq!(
            Fixed.summary(&unguarded),
            "mid 1.0001 delta 0.0002 unguarded"
        );
    }

    /// A fixed price does not follow its market, so it is only safe while the
    /// market sits inside its own quote. Outside it a taker trades the vault at a stale
    /// price: at the PoC's 0.9997 USDT per USDC the vault's bid, 1.0001 · (1 − 0.0002) ≈
    /// 0.99990, is already above the market, and a USDT depeg (1.0005) is past its ask. The
    /// pricer refuses there, whatever the pair's band says.
    #[test]
    fn a_fixed_price_refuses_while_its_market_is_outside_its_own_quote() {
        let pair = testing::pair();
        let (mut pricer, ctx) = testing::build(&Fixed, STANZA, &pair).unwrap();
        let mut out = testing::diagnostics(&ctx);
        for inside in [1.0001, 1.0, 1.0002] {
            let market = testing::market(&pair, inside, 0.0);
            let priced = pricer.price(&testing::tick(&pair, Some(&market)), &mut out);
            assert!(priced.is_ok(), "{inside} is inside the quote: {priced:?}");
        }
        for outside in [0.9997, 0.975, 0.915, 0.88, 1.0005] {
            let market = testing::market(&pair, outside, 0.0);
            let refusal = pricer
                .price(&testing::tick(&pair, Some(&market)), &mut out)
                .expect_err("outside the quote");
            assert_eq!(refusal.reason(), "market_outside_quote", "{outside}");
            assert!(refusal.message().contains("own quote"), "{refusal}");
        }
    }

    /// The quote is judged in lane orientation, where the market and the published mid both
    /// are: on an inverted lane a fixed 4000 USDC per WETH publishes 0.00025.
    #[test]
    fn the_quote_is_judged_in_lane_orientation_on_an_inverted_lane() {
        let pair = testing::pair_with(true, 18);
        let (mut pricer, ctx) =
            testing::build(&Fixed, "mid = \"4000\"\ndelta = \"0.0005\"", &pair).unwrap();
        let mut out = testing::diagnostics(&ctx);
        let inside = testing::market(&pair, 4001.0, 0.0); // 2.5 bp off, inside 5 bp
        assert!(
            pricer
                .price(&testing::tick(&pair, Some(&inside)), &mut out)
                .is_ok()
        );
        let outside = testing::market(&pair, 3990.0, 0.0); // 25 bp off
        let refusal = pricer
            .price(&testing::tick(&pair, Some(&outside)), &mut out)
            .expect_err("outside the quote");
        assert_eq!(refusal.reason(), "market_outside_quote");
    }

    /// With no market, nothing could stop a fixed price through a depeg, so the stanza
    /// needs a market (`symbol` or `sources`) or says it is a smoke test with `unguarded`.
    /// A pair form sends `"true"` as a string, so that reads as the flag too.
    #[test]
    fn a_fixed_price_needs_a_market_unless_it_says_it_is_unguarded() {
        let mut pair = testing::pair();
        pair.sources = 0;
        let err = format!(
            "{:#}",
            testing::build(&Fixed, STANZA, &pair)
                .err()
                .expect("no market")
        );
        for needle in ["symbol", "unguarded", "feed"] {
            assert!(err.contains(needle), "{needle}: {err}");
        }
        for flag in ["unguarded = true", "unguarded = \"true\""] {
            let (mut pricer, ctx) = testing::build(&Fixed, &format!("{STANZA}\n{flag}"), &pair)
                .unwrap_or_else(|err| panic!("{flag}: {err:#}"));
            let out = pricer.price(&testing::tick(&pair, None), &mut testing::diagnostics(&ctx));
            assert!(out.is_ok(), "{flag}");
        }
        let refused = testing::build(&Fixed, &format!("{STANZA}\nunguarded = \"yes\""), &pair);
        assert!(refused.is_err(), "only true or false");
    }
}

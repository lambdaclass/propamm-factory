//! `fixed`: a pair whose stanza states `mid` and `delta` publishes them, whatever the
//! market does. The simplest kind, and the one a stablecoin pair or a smoke test wants.
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
    TickCtx,
};
use crate::feed::{parse_decimal_scaled, reciprocal_scaled};

/// The `fixed` stanza: both as written, parsed exactly against the pair's scale in
/// [`Factory::validate`], so a typo fails the file rather than every tick.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedConfig {
    pub mid: String,
    pub delta: String,
}

/// The `fixed` pricing kind. Register it with `Updater::builder().pricer("fixed", Fixed)`.
pub struct Fixed;

impl Fixed {
    /// The exact `(delta, mid)` the lane publishes for this stanza: the mid as declared in
    /// market orientation, inverted for an inverted lane (byte for byte the rule a feed
    /// follows), the delta as a fraction below one unit, both inside the pair's band.
    fn resolve(cfg: &FixedConfig, pair: &PairShape) -> eyre::Result<(U256, U256)> {
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
         mid − 0.05%.",
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
        "<p class=explain>We send the same mid and the same spread every block. For a pair \
         whose price does not move, or to smoke-test the wiring.</p>"
    }

    fn summary(&self, cfg: &FixedConfig) -> String {
        format!("mid {} delta {}", cfg.mid, cfg.delta)
    }

    fn build<'a>(
        &'a self,
        cfg: &'a FixedConfig,
        ctx: &'a mut BuildCtx,
    ) -> BoxFuture<'a, eyre::Result<FixedPricer>> {
        Box::pin(std::future::ready(
            Self::resolve(cfg, ctx.pair()).map(|(delta, mid)| FixedPricer { delta, mid }),
        ))
    }
}

/// The mid and delta the stanza fixed, already in lane orientation.
pub struct FixedPricer {
    pub(crate) delta: U256,
    pub(crate) mid: U256,
}

impl Pricer for FixedPricer {
    fn price(&mut self, _tick: &TickCtx, _out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
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
    fn the_form_fields_and_the_summary_name_the_two_keys() {
        let names: Vec<&str> = Fixed.fields().iter().map(|f| f.name).collect();
        assert_eq!(names, ["mid", "delta"]);
        let cfg: FixedConfig = toml::from_str(STANZA).unwrap();
        assert_eq!(Fixed.summary(&cfg), "mid 1.0001 delta 0.0002");
    }
}

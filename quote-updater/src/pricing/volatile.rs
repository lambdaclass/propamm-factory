//! `volatile`: a spread computed every tick from the recent volatility and the vault's
//! inventory, and a mid tilted by the inventory. The formula is `crate::volatile::price`;
//! this is the kind around it: reading σ and the vault, reporting the terms, rendering the
//! result.
//!
//! ```toml
//! [pairs.pricing]
//! kind  = "volatile"
//! gamma = "0.1"      # γ, risk aversion
//! k     = "2000"     # k, competition
//! kappa = "1"        # κ, adverse-selection charge
//! # target_share, hold_secs, fill_delay_secs, volatility_window_secs and the inventory
//! # charge's knobs are optional; see the fields below and docs/manual.md.
//! ```

use super::{
    BoxFuture, BuildCtx, DiagHandle, Diagnostics, Factory, FormField, History, InventoryFeed,
    PairShape, Pricer, PricerOutput, Refusal, RefusalHandle, TickCtx,
};
use crate::volatile::{self, RawKnobs, VolatileParams};

/// The `volatile` stanza, every knob as written. γ, k and κ come as a set; the rest default
/// (see [`VolatileParams::parse`]). Strings, parsed and bounded in `validate`, so the
/// backoffice's form can write what it posts.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolatileConfig {
    pub gamma: Option<String>,
    pub k: Option<String>,
    pub kappa: Option<String>,
    pub target_share: Option<String>,
    pub hold_secs: Option<String>,
    pub fill_delay_secs: Option<String>,
    pub volatility_window_secs: Option<String>,
    pub inventory_aversion: Option<String>,
    pub inventory_band_lower: Option<String>,
    pub inventory_band_upper: Option<String>,
    pub inventory_aversion_hard: Option<String>,
    pub inventory_band_hard_lower: Option<String>,
    pub inventory_band_hard_upper: Option<String>,
}

impl VolatileConfig {
    /// The knobs, parsed and bounded. The three without a default come as a set: a stanza
    /// with some of them is one whose operator stopped half way, not one that wants the
    /// missing ones guessed.
    pub fn params(&self, at: &str) -> eyre::Result<VolatileParams> {
        let required = [
            ("gamma", &self.gamma),
            ("k", &self.k),
            ("kappa", &self.kappa),
        ];
        let missing: Vec<&str> = required
            .iter()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| *name)
            .collect();
        eyre::ensure!(
            missing.is_empty(),
            "volatile pricing needs gamma, k and kappa together; {} missing",
            missing.join(", ")
        );
        fn get(value: &Option<String>) -> &str {
            value.as_deref().expect("checked above")
        }
        VolatileParams::parse(
            at,
            RawKnobs {
                gamma: get(&self.gamma),
                k: get(&self.k),
                kappa: get(&self.kappa),
                target_share: self.target_share.as_deref(),
                hold_secs: self.hold_secs.as_deref(),
                fill_delay_secs: self.fill_delay_secs.as_deref(),
                volatility_window_secs: self.volatility_window_secs.as_deref(),
                inventory_aversion: self.inventory_aversion.as_deref(),
                inventory_band_lower: self.inventory_band_lower.as_deref(),
                inventory_band_upper: self.inventory_band_upper.as_deref(),
                inventory_aversion_hard: self.inventory_aversion_hard.as_deref(),
                inventory_band_hard_lower: self.inventory_band_hard_lower.as_deref(),
                inventory_band_hard_upper: self.inventory_band_hard_upper.as_deref(),
            },
        )
    }
}

/// The `volatile` pricing kind. Register it with
/// `Updater::builder().pricer("volatile", Volatile)`.
pub struct Volatile;

const FIELDS: &[FormField] = &[
    FormField::new(
        "gamma",
        "0.1",
        "γ. Bigger charges more for term 1 and tilts harder. Start at 0.1 and move it.",
    ),
    FormField::new(
        "k",
        "2000",
        "k. Bigger means people leave faster when we charge more, so we charge less. Pick it \
         from the spread you want: with gamma 0.1, k = 2000 makes term 2 a 0.05% spread per \
         side, k = 700 makes it 0.14%.",
    ),
    FormField::new(
        "kappa",
        "1",
        "κ. 1 charges the full typical move, 0 charges nothing for term 3.",
    ),
    FormField::new(
        "hold_secs",
        "12",
        "τ. Seconds until the next block, when we can change our price. 12 on mainnet. Blank \
         is 12.",
    ),
    FormField::new(
        "fill_delay_secs",
        "6",
        "Δ. Seconds between us posting a price and someone trading on it. 6 is half a block. \
         Blank is 6.",
    ),
    FormField::new(
        "volatility_window_secs",
        "600",
        "how many seconds of prices σ is computed from. 60 to 3600. Blank is 600.",
    ),
    FormField::new(
        "target_share",
        "0.5",
        "how much of the vault's value we want in the base token, 0 to 1. 0.5 is half and \
         half. Blank is 0.5.",
    ),
    FormField::new(
        "inventory_aversion",
        "0",
        "λ. Once the vault's base share leaves the band below, the trade that would push it \
         further off gets more expensive. The trade that brings it back does not. 0 is off. \
         Bigger charges more.",
    ),
    FormField::new(
        "inventory_band_lower",
        "0.25",
        "below this base share, the extra spread starts. Blank is half of target_share.",
    ),
    FormField::new(
        "inventory_band_upper",
        "0.75",
        "above this base share, the extra spread starts. Blank is twice target_share, which \
         at 0.5 or more is over 100% and never fires, so set it.",
    ),
    FormField::new(
        "inventory_aversion_hard",
        "",
        "λ_hard. A second, stronger charge once the base share leaves the wider band below. \
         Adds (λ_hard − λ_soft) on top of inventory_aversion past the hard edge. Must be ≥ \
         inventory_aversion. Blank means equal to it, so the hard tier is off. It only acts \
         on a side whose hard band edge below is set.",
    ),
    FormField::new(
        "inventory_band_hard_lower",
        "0.1",
        "below this base share, the stronger λ_hard charge starts. Must be ≤ \
         inventory_band_lower. Blank turns the hard tier off on this side.",
    ),
    FormField::new(
        "inventory_band_hard_upper",
        "0.9",
        "above this base share, the stronger λ_hard charge starts. Must be ≥ \
         inventory_band_upper. Blank turns the hard tier off on this side.",
    ),
];

const FORM_HELP: &str = r#"<p class=explain>Every block we compute two numbers and send them to the chain: the spread, and the
mid. The pool then sells at <code>mid + spread/2</code> and buys at <code>mid − spread/2</code>.</p>
<div class=equation>
  <div class=eqrow>
    <span class=eqlhs>spread =</span>
    <span class=term><span class=formula>γ&thinsp;σ²&thinsp;τ</span><span class=termname>term 1</span></span>
    <span class=op>+</span>
    <span class=term><span class=formula>(2/γ)&thinsp;ln(1 + γ/k)</span><span class=termname>term 2</span></span>
    <span class=op>+</span>
    <span class=term><span class=formula>κ&thinsp;σ&thinsp;√Δ</span><span class=termname>term 3</span></span>
    <span class=op>+</span>
    <span class=term><span class=formula>λ&thinsp;σ&thinsp;√τ&thinsp;·&thinsp;q_out</span><span class=termname>charge, one side</span></span>
  </div>
  <div class=eqrow>
    <span class=eqlhs>mid =</span>
    <span class=term><span class=formula>mid · (1 − skew)</span></span>
    <span class=op>,</span>
    <span class=term><span class=formula>skew = q&thinsp;γ&thinsp;σ&thinsp;√τ</span><span class=termname>skew</span></span>
  </div>
</div>
<p class=explain><b>Term 1</b>: we hold the base for τ seconds and it can drop. Someone sells us
the base at 2999; we cannot sell it until the next block, by which time it might be 2980. σ²τ is
how much the price typically moves in τ seconds; γ is how much of that to charge for.</p>
<p class=explain><b>Term 2</b>: our profit. Terms 1 and 3 cover what we expect to lose; this one is
what we earn. Charge more and fewer people trade with us; k is a guess for how fast they leave.</p>
<p class=explain><b>Term 3</b>: the price already moved and a bot trades on our old price. σ√Δ is how
much the price typically moves in the Δ seconds between us posting and someone trading; κ is how much
of that to charge for.</p>
<p class=explain><b>Skew</b>: do not sit on a big pile of the base while it is jumpy. Holding more than
target_share of the vault's value in the base, we lower both prices so people buy it from us; holding
less, we raise both. If the price is not moving we do not do this, even if the vault is lopsided.</p>
<p class=explain><b>The charge</b>: q_out is how far the vault's base share is outside the band
[inventory_band_lower, inventory_band_upper], divided by target_share; 0 inside it. It goes only on
the trade that pushes us further off target. Past the wider hard band it grows at λ_hard instead of
λ. A blank hard edge turns that side's hard tier off.</p>
<p class=explain>σ is how much the price has been moving: the last volatility_window_secs of the mid,
each second's percentage change, their standard deviation. For a stablecoin pair it is basically 0, so
term 1, term 3 and the skew are 0 and the spread is term 2, a constant.</p>"#;

impl Factory for Volatile {
    type Config = VolatileConfig;
    type Pricer = VolatilePricer;

    fn validate(&self, cfg: &VolatileConfig, pair: &PairShape) -> eyre::Result<()> {
        eyre::ensure!(
            pair.sources > 0,
            "volatile prices the pair's market, so the pair needs a symbol or sources"
        );
        cfg.params(&pair.label).map(drop)
    }

    fn fields(&self) -> &'static [FormField] {
        FIELDS
    }

    fn form_help(&self) -> &'static str {
        FORM_HELP
    }

    fn summary(&self, cfg: &VolatileConfig) -> String {
        let knob = |value: &Option<String>| value.as_deref().unwrap_or("?").to_owned();
        format!(
            "γ={} k={} κ={}",
            knob(&cfg.gamma),
            knob(&cfg.k),
            knob(&cfg.kappa)
        )
    }

    fn build<'a>(
        &'a self,
        cfg: &'a VolatileConfig,
        ctx: &'a mut BuildCtx,
    ) -> BoxFuture<'a, eyre::Result<VolatilePricer>> {
        Box::pin(async move {
            let params = cfg.params(&ctx.pair().label)?;
            // The market's history, not this lane generation's: it outlives reloads, so a
            // rebuilt pair needs no new warm-up.
            let history = ctx.history()?;
            let diagnostics = Diag {
                sigma: ctx.diagnostic("sigma")?,
                hold: ctx.diagnostic("hold")?,
                edge: ctx.diagnostic("edge")?,
                stale: ctx.diagnostic("stale")?,
                inventory_penalty: ctx.diagnostic("inventory_penalty")?,
                q: ctx.diagnostic("q")?,
                skew: ctx.diagnostic("skew")?,
                target_share: ctx.diagnostic("target_share")?,
                base: ctx.diagnostic("inventory_base")?,
                quote: ctx.diagnostic("inventory_quote")?,
                base_share: ctx.diagnostic("inventory_base_share")?,
            };
            let warming_up = ctx.refusal("warming_up")?;
            let no_inventory = ctx.refusal("no_inventory")?;
            // Read now, so a wrong target or token fails this build, then refreshed for the
            // life of the lane.
            let inventory = ctx.inventory().await?;
            Ok(VolatilePricer {
                history,
                inventory,
                params,
                diagnostics,
                warming_up,
                no_inventory,
            })
        })
    }
}

/// The terms, reported every tick as `quote_updater_diagnostic{kind="volatile",name}` and
/// recorded with each quote.
struct Diag {
    sigma: DiagHandle,
    hold: DiagHandle,
    edge: DiagHandle,
    stale: DiagHandle,
    inventory_penalty: DiagHandle,
    q: DiagHandle,
    skew: DiagHandle,
    target_share: DiagHandle,
    base: DiagHandle,
    quote: DiagHandle,
    base_share: DiagHandle,
}

/// A volatile pair's pricer: the market gives the mid, the history gives σ, the inventory
/// gives q, and the knobs are the pair's. The three are read together on every tick so the
/// published pair is always one consistent reading.
pub struct VolatilePricer {
    history: History,
    inventory: InventoryFeed,
    params: VolatileParams,
    diagnostics: Diag,
    warming_up: RefusalHandle,
    no_inventory: RefusalHandle,
}

impl VolatilePricer {
    fn report(
        &self,
        out: &mut Diagnostics,
        terms: &volatile::Terms,
        inventory: &super::Inventory,
        share: f64,
    ) {
        let d = &self.diagnostics;
        out.set(&d.sigma, terms.sigma);
        out.set(&d.hold, terms.hold);
        out.set(&d.edge, terms.edge);
        out.set(&d.stale, terms.stale);
        out.set(&d.inventory_penalty, terms.inventory_penalty);
        out.set(&d.q, terms.q);
        out.set(&d.skew, terms.skew);
        out.set(&d.target_share, self.params.target_share.get());
        out.set(&d.base, inventory.base);
        out.set(&d.quote, inventory.quote);
        out.set(&d.base_share, share);
    }
}

impl Pricer for VolatilePricer {
    fn price(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        let sigma = self
            .history
            .volatility(tick.now(), self.params.volatility_window)
            .map_err(|covered| {
                Refusal::new(
                    &self.warming_up,
                    format!(
                        "{}s of price history, σ needs {}s; warming up",
                        covered.as_secs(),
                        volatile::MIN_HISTORY.as_secs()
                    ),
                )
            })?;
        // The feed is seeded before the pair starts, so the only way to have no usable
        // reading is for the one it holds to have aged out.
        let inventory = self.inventory.latest();
        let age = inventory.age(tick.now());
        if age > volatile::MAX_INVENTORY_AGE {
            return Err(Refusal::new(
                &self.no_inventory,
                format!("vault balance is {age:.0?} old; refusing to tilt off a stale reading"),
            ));
        }
        // The vault's base is valued at the market mid in market orientation. Through f64,
        // like the history: q is an estimate, not a published number.
        let share = inventory.base_share(market.mid_f64());
        let terms = volatile::price(&self.params, sigma, share);
        self.report(out, &terms, &inventory, share);
        let delta = market.scaled_fraction(terms.delta)?;
        let mid = market.shift(terms.skew)?;
        Ok(PricerOutput::new(delta, mid))
    }

    /// `--check` does not wait the minute of history σ needs, so it shows the spread at
    /// σ = 0 (the competition term alone), on the unshifted mid, and says so in a note. It
    /// reads the vault the way the run will, so a target or token the run would refuse
    /// fails here first.
    fn preview(&mut self, tick: &TickCtx, out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        let inventory = self.inventory.latest();
        let share = inventory.base_share(market.mid_f64());
        let terms = volatile::price(&self.params, 0.0, share);
        self.report(out, &terms, &inventory, share);
        out.note(format!(
            "volatile: this delta is term 2 only, computed with σ = 0 because --check does \
             not wait the 60s of price history σ needs; the running updater adds term 1 and \
             term 3 on top. Vault {:#x}: {} base, {} quote, {:.1}% of its value in the base \
             against a target_share of {:.1}% (q = {:.3})",
            inventory.vault,
            inventory.base,
            inventory.quote,
            share * 100.0,
            self.params.target_share.get() * 100.0,
            terms.q
        ));
        Ok(PricerOutput::new(
            market.scaled_fraction(terms.delta)?,
            market.mid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testing::{self, Inputs};

    const STANZA: &str = "gamma = \"0.1\"\nk = \"2000\"\nkappa = \"1\"";

    /// A build with a vault reading and `secs` seconds of a flat price history ending now
    /// (one sample, so a history that exists but covers nothing, when `secs` is 0): what
    /// the run hands the kind, seeded.
    fn build(
        secs: u64,
        inventory: super::super::Inventory,
        now: Instant,
    ) -> (VolatilePricer, BuildCtx) {
        let history = (0..secs.max(1))
            .map(|back| (now - Duration::from_secs(back), 4000.0))
            .collect();
        testing::build_with(
            &Volatile,
            STANZA,
            &testing::pair(),
            Inputs {
                inventory: Some(inventory),
                history,
                ..Inputs::default()
            },
        )
        .unwrap()
    }

    /// The three knobs without a default come as a set: a stanza with some of them is one
    /// whose operator stopped half way, not one that wants the missing ones guessed.
    #[test]
    fn gamma_k_and_kappa_come_as_a_set() {
        let pair = testing::pair();
        let err = format!(
            "{:#}",
            testing::build(&Volatile, "gamma = \"0.1\"\nk = \"2000\"", &pair)
                .err()
                .unwrap()
        );
        assert!(err.contains("together") && err.contains("kappa"), "{err}");
        testing::assert_rejects_unknown_fields::<VolatileConfig>(STANZA);
        let mut unstreamed = testing::pair();
        unstreamed.sources = 0;
        let err = format!(
            "{:#}",
            testing::build(&Volatile, STANZA, &unstreamed)
                .err()
                .unwrap()
        );
        assert!(err.contains("symbol or sources"), "{err}");
    }

    /// The build declares every term it will report and both of its refusals, so the
    /// metrics, the recorder's `terms` map and the alert rules can bind to them by name.
    #[test]
    fn the_build_declares_its_terms_and_refusals() {
        let (_, ctx) = build(0, testing::inventory(1.0, 4000.0), Instant::now());
        assert_eq!(
            ctx.diagnostic_names(),
            [
                "sigma",
                "hold",
                "edge",
                "stale",
                "inventory_penalty",
                "q",
                "skew",
                "target_share",
                "inventory_base",
                "inventory_quote",
                "inventory_base_share",
            ]
        );
        let refusals: Vec<&str> = ctx.refusal_names().iter().map(|r| r.as_ref()).collect();
        assert_eq!(refusals, ["warming_up", "no_inventory"]);
        let err = format!(
            "{:#}",
            testing::build(&Volatile, STANZA, &testing::pair())
                .err()
                .unwrap()
        );
        assert!(err.contains("no market history"), "{err}");
    }

    /// Under a minute of history and σ is one tick's noise: the pair says it is warming up
    /// and publishes nothing. With a minute, a flat history gives σ = 0 and the spread is
    /// term 2 alone, on the unshifted mid.
    #[test]
    fn warming_up_until_a_minute_of_history_then_term_two_on_a_flat_market() {
        let now = Instant::now();
        let pair = testing::pair();
        let market = testing::market(&pair, 4000.0, 0.0001);
        let tick = testing::tick_at(&pair, Some(&market), now);

        let (mut young, ctx) = build(30, testing::inventory(1.0, 4000.0), now);
        let refusal = young
            .price(&tick, &mut testing::diagnostics(&ctx))
            .unwrap_err();
        assert_eq!(refusal.reason(), "warming_up");

        let (mut ready, ctx) = build(90, testing::inventory(1.0, 4000.0), now);
        let mut out = testing::diagnostics(&ctx);
        let priced = ready
            .price(&tick, &mut out)
            .expect("a minute of history prices");
        assert_eq!(
            priced.mid, market.mid,
            "σ = 0 and a balanced vault: no skew"
        );
        let expected = volatile::price(&ready.params, 0.0, 0.5);
        assert_eq!(
            priced.delta,
            market.scaled_fraction(expected.delta).unwrap()
        );
        assert_eq!(out.get(&ready.diagnostics.sigma), Some(0.0));
        assert_eq!(out.get(&ready.diagnostics.base), Some(1.0));
        assert_eq!(out.get(&ready.diagnostics.base_share), Some(0.5));
    }

    #[test]
    fn a_stale_vault_reading_is_refused() {
        let now = Instant::now();
        let pair = testing::pair();
        let market = testing::market(&pair, 4000.0, 0.0001);
        let stale = testing::inventory_at(1.0, 4000.0, now - Duration::from_secs(120));
        let (mut pricer, ctx) = build(90, stale, now);
        let refusal = pricer
            .price(
                &testing::tick_at(&pair, Some(&market), now),
                &mut testing::diagnostics(&ctx),
            )
            .unwrap_err();
        assert_eq!(refusal.reason(), "no_inventory");
    }

    /// `--check` does not wait the minute σ needs: the preview prices at σ = 0 and says so.
    #[test]
    fn the_preview_prices_at_sigma_zero_and_says_so() {
        let now = Instant::now();
        let pair = testing::pair();
        let market = testing::market(&pair, 4000.0, 0.0001);
        let (mut pricer, ctx) = build(0, testing::inventory(2.0, 4000.0), now);
        let mut out = testing::diagnostics(&ctx);
        let previewed = pricer
            .preview(&testing::tick_at(&pair, Some(&market), now), &mut out)
            .expect("previews without history");
        assert_eq!(previewed.mid, market.mid);
        let note = out.note.clone().expect("says what it did");
        assert!(note.contains("σ = 0") && note.contains("2 base"), "{note}");
        let summary = Volatile.summary(&toml::from_str(STANZA).unwrap());
        assert_eq!(summary, "γ=0.1 k=2000 κ=1");
    }
}

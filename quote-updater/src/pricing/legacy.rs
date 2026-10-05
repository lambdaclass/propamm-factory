//! The pricing code as it was before lanes priced through a `Pricer`: `ValueSource`'s
//! enum and its `sample`, frozen verbatim (renamed), so the pricers can be compared with it
//! in the same process.
//!
//! Same-process rather than a committed fixture: the volatile model calls `f64::ln`, which
//! is not correctly rounded and differs across libm implementations, so numbers recorded
//! on macOS could differ from Linux CI in the last digit of a `U256`. Both sides here run
//! on the same libm, over the same channels, and must agree exactly.
#![cfg(test)]
#![allow(clippy::large_enum_variant, dead_code)]

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use ethrex_common::U256;

use crate::{
    config::{MidBand, SourceSpec},
    ensure_fits_216_bits,
    feed::PriceSample,
    metrics::PairMetrics,
    update::{MAX_PRICE_AGE, Priced, Pricing, Unusable, UnusableKind},
    volatile::{self, Inventory, PriceHistory, VolatileParams},
};

#[derive(Clone)]
pub(crate) enum LegacyValueSource {
    Static {
        delta: U256,
        mid: U256,
    },
    Feed {
        rx: tokio::sync::watch::Receiver<Option<PriceSample>>,
        /// Kept whole rather than reduced to its `delta`, so the published spread comes
        /// from `SourceSpec::published_delta` here exactly as it does in `--check`.
        source: SourceSpec,
        spread_scale: U256,
    },
    /// A feed priced by `volatile::price`: the sample gives the mid, the history gives σ,
    /// the inventory gives q, and the knobs are the pair's. The three are read together on
    /// every tick so the published pair is always one consistent reading.
    Volatile {
        rx: tokio::sync::watch::Receiver<Option<PriceSample>>,
        history: Arc<Mutex<PriceHistory>>,
        inventory: tokio::sync::watch::Receiver<Inventory>,
        params: VolatileParams,
        invert: bool,
        price_decimals: u32,
        /// Where the terms are recorded, so an operator can see which one moved the spread.
        metrics: PairMetrics,
    },
}

/// The feed's latest sample, or why it cannot be published from.
fn fresh_sample(
    rx: &tokio::sync::watch::Receiver<Option<PriceSample>>,
) -> Result<PriceSample, Unusable> {
    let sample = (*rx.borrow()).ok_or_else(|| {
        Unusable::new(
            UnusableKind::NoSample,
            "no price received from the feed yet".to_owned(),
        )
    })?;
    let age = sample.age();
    if age > MAX_PRICE_AGE {
        return Err(Unusable::new(
            UnusableKind::Stale,
            format!("latest feed price is {age:.0?} old; refusing to push a stale value"),
        ));
    }
    Ok(sample)
}

impl LegacyValueSource {
    /// [`Self::current_detailed`] reduced to the `(delta, mid)` pair, for tests that only
    /// care what would go out.
    #[cfg(test)]
    pub(crate) fn current(&self, band: &MidBand) -> Result<(U256, U256), Unusable> {
        self.current_detailed(band).map(|p| (p.delta, p.mid))
    }

    /// The `(delta, mid)` to publish now, with the working behind it, or why there is none.
    /// `band` is checked here rather than at each call site so every send path is covered
    /// by construction: an out-of-band mid becomes the same unusable-price error a stale
    /// feed produces, which the RPC path skips the push on and the builder path withdraws
    /// its quote for.
    pub(crate) fn current_detailed(&self, band: &MidBand) -> Result<Priced, Unusable> {
        let priced = self.sample()?;
        band.check(priced.mid)?;
        Ok(priced)
    }

    fn sample(&self) -> Result<Priced, Unusable> {
        match self {
            LegacyValueSource::Static { delta, mid } => Ok(Priced {
                delta: *delta,
                mid: *mid,
                feed_mid: *mid,
                pricing: None,
            }),
            LegacyValueSource::Feed {
                rx,
                source,
                spread_scale,
            } => {
                let sample = fresh_sample(rx)?;
                // `published_delta` and `ensure_fits_216_bits` both report with eyre. Their
                // text is carried through verbatim under a kind, so the withdrawn reason on
                // the block summary reads exactly as it did before this change.
                let delta = source
                    .published_delta(sample.delta, *spread_scale)
                    .map_err(|err| {
                        Unusable::new(UnusableKind::DeltaOverflow, format!("{err:#}"))
                    })?;
                ensure_fits_216_bits(delta).map_err(|err| {
                    Unusable::new(UnusableKind::DeltaOverflow, format!("{err:#}"))
                })?;
                Ok(Priced {
                    delta,
                    mid: sample.mid,
                    feed_mid: sample.mid,
                    pricing: None,
                })
            }
            LegacyValueSource::Volatile {
                rx,
                history,
                inventory,
                params,
                invert,
                price_decimals,
                metrics,
            } => {
                let sample = fresh_sample(rx)?;
                let now = Instant::now();
                let sigma = volatile::lock(history)
                    .volatility(now, params.volatility_window)
                    .map_err(|covered| {
                        Unusable::new(
                            UnusableKind::WarmingUp,
                            format!(
                                "{}s of price history, σ needs {}s; warming up",
                                covered.as_secs(),
                                volatile::MIN_HISTORY.as_secs()
                            ),
                        )
                    })?;
                // The channel is seeded before the pair starts, so the only way to have no
                // usable reading is for the one it holds to have aged out.
                let inventory = *inventory.borrow();
                if inventory.at.elapsed() > volatile::MAX_INVENTORY_AGE {
                    return Err(Unusable::new(
                        UnusableKind::NoInventory,
                        format!(
                            "vault balance is {:.0?} old; refusing to tilt off a stale reading",
                            inventory.at.elapsed()
                        ),
                    ));
                }
                // The vault's base is valued at the market mid: the sample is in lane
                // orientation, so an inverted lane reads it back the other way up. Through
                // f64, like the history: q is an estimate, not a published number.
                let market_mid = crate::feed::scaled_to_f64(sample.mid, *price_decimals);
                let market_mid = if *invert {
                    1.0 / market_mid
                } else {
                    market_mid
                };
                let base_share = inventory.base_share(market_mid);
                let terms = volatile::price(params, sigma, base_share);
                metrics.pricing_sigma.set(terms.sigma);
                metrics.pricing_hold.set(terms.hold);
                metrics.pricing_edge.set(terms.edge);
                metrics.pricing_stale.set(terms.stale);
                metrics.pricing_inventory.set(terms.q);
                metrics.pricing_skew.set(terms.skew);
                metrics.inventory_base.set(inventory.base);
                metrics.inventory_quote.set(inventory.quote);
                metrics.inventory_base_share.set(base_share);

                let overflow = |err: eyre::Report| {
                    Unusable::new(UnusableKind::DeltaOverflow, format!("{err:#}"))
                };
                let delta =
                    volatile::fraction_scaled(terms.delta, *price_decimals).map_err(overflow)?;
                let spread_scale = U256::exp10(*price_decimals as usize);
                if delta >= spread_scale {
                    return Err(Unusable::new(
                        UnusableKind::DeltaOverflow,
                        format!(
                            "computed half-spread {} is not below one whole unit; refusing to \
                             publish a spread that leaves the taker nothing",
                            terms.delta
                        ),
                    ));
                }
                ensure_fits_216_bits(delta).map_err(overflow)?;
                let mid = volatile::shifted_mid(sample.mid, terms.skew, *invert, *price_decimals)
                    .map_err(overflow)?;
                Ok(Priced {
                    delta,
                    mid,
                    feed_mid: sample.mid,
                    pricing: Some(Pricing {
                        sigma: terms.sigma,
                        hold: terms.hold,
                        edge: terms.edge,
                        stale: terms.stale,
                        skew: terms.skew,
                    }),
                })
            }
        }
    }
}

/// `--check`'s per-source preview arithmetic as `pair::collect_prices` had it, frozen: the
/// row's `(delta, mid)` or its error text, and the volatile note.
pub(crate) fn legacy_preview(
    source: &SourceSpec,
    sample: Option<PriceSample>,
    inventory: Inventory,
    invert: bool,
    price_decimals: u32,
) -> (Result<(U256, U256), String>, Option<String>) {
    let mut note = None;
    let sample = match source {
        SourceSpec::Static { delta, mid } => Ok((*delta, *mid)),
        SourceSpec::Volatile { params: knobs, .. } => match sample {
            Some(sample) => {
                let market_mid = crate::feed::scaled_to_f64(sample.mid, price_decimals);
                let market_mid = if invert { 1.0 / market_mid } else { market_mid };
                let share = inventory.base_share(market_mid);
                let terms = volatile::price(knobs, 0.0, share);
                note = Some(format!(
                    "volatile: this delta is term 2 only, computed with σ = 0 \
                     because --check does not wait the 60s of price history \
                     σ needs; the running pusher adds term 1 and term 3 on \
                     top. Vault {:#x}: {} base, {} quote, {:.1}% of its value in \
                     the base against a target_share of {:.1}% (q = {:.3})",
                    inventory.vault,
                    inventory.base,
                    inventory.quote,
                    share * 100.0,
                    knobs.target_share.get() * 100.0,
                    terms.q
                ));
                volatile::fraction_scaled(terms.delta, price_decimals)
                    .map(|delta| (delta, sample.mid))
                    .map_err(|err| format!("{err:#}"))
            }
            None => Err("the feed reported a sample and then lost it".to_owned()),
        },
        SourceSpec::Feed { .. } => sample
            .ok_or_else(|| "the feed reported a sample and then lost it".to_owned())
            .and_then(|sample| {
                source
                    .published_delta(sample.delta, crate::config::spread_scale(price_decimals))
                    .map(|delta| (delta, sample.mid))
                    .map_err(|err| format!("{err:#}"))
            }),
        // The frozen code predates custom kinds; the comparison never builds one.
        SourceSpec::Custom { .. } => unreachable!("no custom kinds in the frozen preview"),
    };
    (sample, note)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ethrex_common::Address;

    use super::*;
    use crate::{
        config::Feeds,
        feed::parse_decimal_scaled,
        update::ValueSource,
        volatile::{MAX_INVENTORY_AGE, RawKnobs},
    };

    #[derive(Clone, Copy, Debug)]
    enum Src {
        Static,
        FeedBook,
        FeedDelta,
        Volatile,
    }

    #[derive(Clone, Copy, Debug)]
    enum Age {
        Missing,
        Fresh,
        Stale,
    }

    /// The σ the history measures: none yet, a calm book, and three that drive the averse
    /// knobs' half-spread to ≈ 0.48, ≈ 0.86 and past one whole unit.
    #[derive(Clone, Copy, Debug)]
    enum Hist {
        Empty,
        /// σ ≈ 0.001/√s.
        Calm,
        /// σ = 0.08/√s.
        Wild,
        /// σ = 0.11/√s: the averse tilt and charge both clamp, so the skew sits on an end of
        /// `skew_reach` for an inventory far enough off its band.
        Storm,
        /// σ = 0.13/√s.
        Crash,
    }

    /// The vault's base share: inside both knobs' bands, past either side of the averse
    /// one, and on the calm one's upper edge (1.0, which nothing can pass).
    #[derive(Clone, Copy, Debug)]
    enum Inv {
        /// 0.5.
        Balanced,
        /// 1.0.
        AllBase,
        /// 0.0.
        AllQuote,
        /// 0.2: below both bands' lower edge, 0.25.
        Short,
        /// 0.9: above the averse band's 0.75, inside the calm one's.
        Long,
        Stale,
    }

    /// The volatile knobs. `Calm` charges nothing for inventory; `Averse` is the reviewed
    /// case that moves the mid past ±SKEW_LIMIT: γ = 10, k = 2000, κ = 1, λ = 1, a band of
    /// [0.25, 0.75] around a 0.5 target.
    #[derive(Clone, Copy, Debug)]
    enum Knobs {
        Calm,
        Averse,
    }

    /// One point of the grid: its parameters (all `Debug`, so a failure names them) and the
    /// channels both implementations read.
    struct Case {
        params: (
            Src,
            Age,
            &'static str,
            &'static str,
            u32,
            bool,
            bool,
            Hist,
            Inv,
            Knobs,
        ),
        band: MidBand,
        rx: tokio::sync::watch::Receiver<Option<PriceSample>>,
        _tx: tokio::sync::watch::Sender<Option<PriceSample>>,
        history: Arc<Mutex<PriceHistory>>,
        inventory: tokio::sync::watch::Receiver<Inventory>,
        _inventory_tx: tokio::sync::watch::Sender<Inventory>,
        metrics: PairMetrics,
    }

    impl std::fmt::Debug for Case {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.params)
        }
    }

    fn knobs(knobs: Knobs) -> VolatileParams {
        let calm = RawKnobs {
            gamma: "0.1",
            k: "2000",
            kappa: "1",
            target_share: None,
            hold_secs: None,
            fill_delay_secs: None,
            volatility_window_secs: None,
            inventory_aversion: None,
            inventory_band_lower: None,
            inventory_band_upper: None,
            inventory_aversion_hard: None,
            inventory_band_hard_lower: None,
            inventory_band_hard_upper: None,
        };
        let raw = match knobs {
            Knobs::Calm => calm,
            Knobs::Averse => RawKnobs {
                gamma: "10",
                target_share: Some("0.5"),
                inventory_aversion: Some("1"),
                inventory_band_lower: Some("0.25"),
                inventory_band_upper: Some("0.75"),
                ..calm
            },
        };
        VolatileParams::parse("grid", raw).unwrap()
    }

    impl Case {
        fn scaled(&self, text: &str) -> U256 {
            parse_decimal_scaled(text, self.params.4).unwrap()
        }

        fn source_spec(&self) -> SourceSpec {
            let feeds = Feeds::single_binance("GRIDUSD");
            match self.params.0 {
                Src::FeedDelta => SourceSpec::Feed {
                    feeds,
                    delta: Some(self.scaled("0.0005")),
                },
                _ => SourceSpec::Feed { feeds, delta: None },
            }
        }

        fn legacy(&self) -> LegacyValueSource {
            let (src, _, mid, half, decimals, invert, ..) = self.params;
            match src {
                Src::Static => LegacyValueSource::Static {
                    delta: self.scaled(half),
                    mid: self.scaled(mid),
                },
                Src::FeedBook | Src::FeedDelta => LegacyValueSource::Feed {
                    rx: self.rx.clone(),
                    source: self.source_spec(),
                    spread_scale: crate::config::spread_scale(decimals),
                },
                Src::Volatile => LegacyValueSource::Volatile {
                    rx: self.rx.clone(),
                    history: Arc::clone(&self.history),
                    inventory: self.inventory.clone(),
                    params: knobs(self.params.9),
                    invert,
                    price_decimals: decimals,
                    metrics: self.metrics.clone(),
                },
            }
        }

        fn pricer(&self) -> ValueSource {
            let (src, _, mid, half, decimals, invert, ..) = self.params;
            match src {
                Src::Static => {
                    ValueSource::fixed_for_tests(self.scaled(half), self.scaled(mid), decimals)
                }
                Src::FeedBook | Src::FeedDelta => ValueSource::feed_for_tests(
                    self.rx.clone(),
                    self.source_spec(),
                    crate::config::spread_scale(decimals),
                    invert,
                    decimals,
                ),
                Src::Volatile => ValueSource::volatile_for_tests(
                    self.rx.clone(),
                    Arc::clone(&self.history),
                    self.inventory.clone(),
                    knobs(self.params.9),
                    invert,
                    decimals,
                    self.metrics.clone(),
                ),
            }
        }
    }

    /// Every combination the three built-ins meet. A static or configured delta is bounded
    /// below one whole unit at parse time (config.rs), so the grid builds none at or above
    /// it; a book's half-spread is not, so the feed cases include it. The volatile model
    /// ignores the book's half-spread, so its cases take one and spend the grid on what it
    /// does read: σ up to past one whole unit, inventory past both sides of the averse
    /// band, and a mid of one unit at 6 dp, where a tilt truncates the published mid to zero.
    fn grid() -> Vec<Case> {
        let mut cases = Vec::new();
        let metrics = crate::metrics::Metrics::new().unwrap();
        for src in [Src::Static, Src::FeedBook, Src::FeedDelta, Src::Volatile] {
            for age in [Age::Missing, Age::Fresh, Age::Stale] {
                for mid in ["0.000001", "0.00025", "1.0001", "4000", "65000"] {
                    let halves: &[&'static str] = match src {
                        Src::Static => &["0", "0.0001", "0.9999"],
                        Src::FeedBook | Src::FeedDelta => &["0", "0.0001", "0.9999", "1"],
                        Src::Volatile => &["0.0001"],
                    };
                    for &half in halves {
                        for decimals in [6u32, 18] {
                            for invert in [false, true] {
                                for excluding_band in [false, true] {
                                    let (hists, invs, knob_sets): (&[Hist], &[Inv], &[Knobs]) =
                                        match src {
                                            Src::Volatile => (
                                                &[
                                                    Hist::Empty,
                                                    Hist::Calm,
                                                    Hist::Wild,
                                                    Hist::Storm,
                                                    Hist::Crash,
                                                ],
                                                &[
                                                    Inv::Balanced,
                                                    Inv::AllBase,
                                                    Inv::AllQuote,
                                                    Inv::Short,
                                                    Inv::Long,
                                                    Inv::Stale,
                                                ],
                                                &[Knobs::Calm, Knobs::Averse],
                                            ),
                                            _ => (&[Hist::Empty], &[Inv::Balanced], &[Knobs::Calm]),
                                        };
                                    for &hist in hists {
                                        for &inv in invs {
                                            for &knob_set in knob_sets {
                                                cases.push(case(
                                                    &metrics,
                                                    (
                                                        src,
                                                        age,
                                                        mid,
                                                        half,
                                                        decimals,
                                                        invert,
                                                        excluding_band,
                                                        hist,
                                                        inv,
                                                        knob_set,
                                                    ),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        cases
    }

    fn case(
        metrics: &crate::metrics::Metrics,
        params: (
            Src,
            Age,
            &'static str,
            &'static str,
            u32,
            bool,
            bool,
            Hist,
            Inv,
            Knobs,
        ),
    ) -> Case {
        let (_, age, mid, half, decimals, invert, excluding_band, hist, inv, _) = params;
        let scaled = |text: &str| parse_decimal_scaled(text, decimals).unwrap();
        let now = Instant::now();
        let stale = MAX_PRICE_AGE + Duration::from_secs(1);
        let sample = match age {
            Age::Missing => None,
            Age::Fresh => Some(PriceSample {
                delta: scaled(half),
                mid: scaled(mid),
                at: now,
                wall: SystemTime::now(),
            }),
            Age::Stale => Some(PriceSample {
                delta: scaled(half),
                mid: scaled(mid),
                at: now - stale,
                wall: SystemTime::now() - stale,
            }),
        };
        let (tx, rx) = tokio::sync::watch::channel(sample);
        // The market mid in market orientation, which is what the history records and what
        // the inventory is valued at.
        let lane_mid: f64 = mid.parse().unwrap();
        let market_mid = if invert { 1.0 / lane_mid } else { lane_mid };
        let epoch = now - Duration::from_secs(200);
        let mut history = PriceHistory::new(epoch);
        // A log return of ±ln(step) every second: σ = ln(step)/√s.
        let step = match hist {
            Hist::Empty => None,
            Hist::Calm => Some(1.001),
            Hist::Wild => Some(0.08f64.exp()),
            Hist::Storm => Some(0.11f64.exp()),
            Hist::Crash => Some(0.13f64.exp()),
        };
        if let Some(step) = step {
            for s in 0..120u64 {
                let wiggle = if s % 2 == 0 { 1.0 } else { step };
                history.record(market_mid * wiggle, now - Duration::from_secs(120 - s));
            }
        }
        let (base, quote, at) = match inv {
            Inv::Balanced => (1.0, market_mid, now),
            Inv::AllBase => (1.0, 0.0, now),
            Inv::AllQuote => (0.0, market_mid, now),
            Inv::Short => (1.0, 4.0 * market_mid, now),
            Inv::Long => (9.0, market_mid, now),
            Inv::Stale => (
                1.0,
                market_mid,
                now - MAX_INVENTORY_AGE - Duration::from_secs(1),
            ),
        };
        let (inventory_tx, inventory) = tokio::sync::watch::channel(Inventory {
            vault: Address::zero(),
            base,
            quote,
            at,
        });
        let band = if excluding_band {
            MidBand {
                min: Some(scaled(mid) + U256::one()),
                max: None,
            }
        } else {
            MidBand::default()
        };
        Case {
            params,
            band,
            rx,
            _tx: tx,
            history: Arc::new(Mutex::new(history)),
            inventory,
            _inventory_tx: inventory_tx,
            metrics: metrics.for_pair("GRID/TEST"),
        }
    }

    /// Every combination the three built-ins meet, priced by the frozen code and by the
    /// pricers, must agree on `(delta, mid, feed_mid, pricing)` or on the refusal's kind
    /// and exact message, so the core's backstop never fires for a built-in.
    ///
    /// With one exception, asserted exactly rather than skipped: a volatile mid of one unit
    /// at 6 dp that a tilt truncates to zero. The frozen code published that zero (PropAMM
    /// rejects it), or refused it under the band's message; the backstop, which runs before
    /// the band, withdraws it as `out_of_band` under its own.
    #[test]
    fn the_pricers_agree_with_the_code_they_replaced() {
        let cases = grid();
        assert!(cases.len() > 8000, "the grid has {} cases", cases.len());
        let (lowest, highest) = crate::volatile::skew_reach();
        let (mut zero_mids, mut past_the_tilt, mut on_the_reach) = (0, 0, [false; 2]);
        let (mut wide, mut whole_unit) = (0, 0);
        for case in &cases {
            let old = case.legacy().current_detailed(&case.band);
            let new = case.pricer().current_detailed(&case.band);
            let unbanded = case.legacy().current_detailed(&MidBand::default());
            if matches!(&unbanded, Ok(priced) if priced.mid.is_zero()) {
                assert!(
                    matches!(case.params, (Src::Volatile, _, "0.000001", _, 6, ..)),
                    "{case:?}: a zero mid outside the one case that truncates to it"
                );
                let refused = new.expect_err("a zero mid must be withdrawn");
                assert_eq!(
                    (refused.kind(), refused.to_string()),
                    (
                        Some(UnusableKind::OutOfBand),
                        "the pricer's mid is zero; refusing to publish it".to_owned()
                    ),
                    "{case:?}"
                );
                zero_mids += 1;
                continue;
            }
            match (old, new) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a, b, "{case:?}");
                    if let Some(pricing) = a.pricing {
                        past_the_tilt += usize::from(pricing.skew.abs() > volatile::SKEW_LIMIT);
                        on_the_reach[0] |= pricing.skew == lowest;
                        on_the_reach[1] |= pricing.skew == highest;
                        let unit = crate::config::spread_scale(case.params.4);
                        wide += usize::from(a.delta > unit / U256::from(2));
                    }
                }
                (Err(a), Err(b)) => {
                    assert_eq!(
                        (a.kind(), a.to_string()),
                        (b.kind(), b.to_string()),
                        "{case:?}"
                    );
                    whole_unit += usize::from(a.to_string().contains("computed half-spread"));
                }
                (a, b) => panic!("{case:?}: legacy {a:?} vs pricer {b:?}"),
            }
        }
        // The regions the grid exists for, each reached: the zero-mid divergence, a mid past
        // ±SKEW_LIMIT (the old bound's refusal) and on both ends of the model's reach, a
        // published half-spread past half a unit, and one the model refuses as a whole unit.
        assert!(zero_mids > 0, "no zero mid");
        assert!(past_the_tilt > 0, "no mid past ±SKEW_LIMIT");
        assert_eq!(on_the_reach, [true, true], "an end of skew_reach unreached");
        assert!(
            wide > 0 && whole_unit > 0,
            "{wide} wide, {whole_unit} whole-unit"
        );
    }

    impl Case {
        fn spec(&self) -> SourceSpec {
            match self.params.0 {
                Src::Static => SourceSpec::Static {
                    delta: self.scaled(self.params.3),
                    mid: self.scaled(self.params.2),
                },
                Src::Volatile => SourceSpec::Volatile {
                    feeds: Feeds::single_binance("GRIDUSD"),
                    params: knobs(self.params.9),
                },
                _ => self.source_spec(),
            }
        }

        fn shape(&self) -> crate::pricing::PairShape {
            crate::pricing::PairShape {
                label: "GRID/TEST".into(),
                tokens: (Address::zero(), Address::zero()),
                lane: U256::zero(),
                inverted: self.params.5,
                price_decimals: self.params.4,
                target: Address::zero(),
            }
        }

        fn preview_pricer(&self) -> Box<dyn crate::pricing::Pricer> {
            let (src, _, mid, half, decimals, invert, ..) = self.params;
            match src {
                Src::Static => Box::new(crate::pricing::FixedPricer {
                    delta: self.scaled(half),
                    mid: self.scaled(mid),
                }),
                Src::FeedBook | Src::FeedDelta => Box::new(crate::pricing::FeedPricer {
                    source: self.source_spec(),
                    spread_scale: crate::config::spread_scale(decimals),
                }),
                Src::Volatile => Box::new(crate::pricing::VolatilePricer {
                    history: Arc::new(Mutex::new(PriceHistory::new(Instant::now()))),
                    inventory: crate::pricing::InventoryFeed::from_receiver(self.inventory.clone()),
                    params: knobs(self.params.9),
                    invert,
                    price_decimals: decimals,
                    metrics: self.metrics.clone(),
                }),
            }
        }
    }

    /// `--check`'s preview through each pricer's `preview` must print what the arithmetic
    /// it replaced printed: the same `(delta, mid)` or error text, and the same note. The
    /// preview prices at σ = 0 off an empty history, so cases that differ only in theirs are
    /// one case to it.
    #[test]
    fn the_preview_agrees_with_the_check_it_replaced() {
        let cases: Vec<Case> = grid()
            .into_iter()
            .filter(|c| {
                matches!(c.params.1, Age::Fresh) && !c.params.6 && matches!(c.params.7, Hist::Empty)
            })
            .collect();
        assert!(cases.len() > 400, "{} cases", cases.len());
        for case in &cases {
            let sample = *case.rx.borrow();
            let inventory = *case.inventory.borrow();
            let old = legacy_preview(
                &case.spec(),
                sample,
                inventory,
                case.params.5,
                case.params.4,
            );
            let new = crate::pair::preview_row(
                case.preview_pricer().as_mut(),
                sample.as_ref(),
                &case.shape(),
                0,
            );
            assert_eq!(old, new, "{case:?}");
        }
    }
}

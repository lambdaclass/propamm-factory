//! The deviation guard's settings, as the pair's `max_deviation*` keys resolve to, and the
//! percentage rendering its lines and `--check`'s columns share. The guard itself is
//! `guard::deviation`; the latch it trips is the lane's (`guard::Latch`).

use std::time::Duration;

use ethrex_common::{U256, U512};

/// One window's settings, resolved. `blocks` is kept beside `span` because it is what the
/// operator wrote and so what a trip line must show — a message reading "over 12000s"
/// against a config saying `1000` makes them do arithmetic while paging. `span` stays the
/// only input to the comparison; `blocks` is presentation and never re-derives the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowConfig {
    /// Trip threshold as a scaled decimal fraction, at `BreakerConfig::decimals`.
    pub threshold_scaled: U256,
    /// The block count as configured.
    pub blocks: u64,
    /// `blocks × BLOCK_TIME_SECS`, resolved at parse time.
    pub span: Duration,
}

/// Trip settings. Plain data (Copy) so it can live in a pair's config, which is borrowed
/// immutably; the stateful machine is built from it where the state lives.
///
/// Both thresholds are optional and at least one is set — a config with neither is refused
/// at parse time, because a pair carrying a breaker that cannot fire is a pair the operator
/// believes is guarded and is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Tick-to-tick threshold, a scaled decimal fraction, e.g. 0.02 × 10^decimals.
    pub threshold_scaled: Option<U256>,
    /// The trailing-window check, when configured.
    pub window: Option<WindowConfig>,
    /// The `--price-decimals` every threshold and mid is expressed at.
    pub decimals: u32,
}

impl BreakerConfig {
    /// 10^decimals, the scale every threshold and mid carries.
    pub fn scale(&self) -> U256 {
        U256::exp10(self.decimals as usize)
    }

    /// The tick-to-tick limit as a percentage, e.g. `"2.00%"`, or `None` when unset.
    pub fn tick_limit(&self) -> Option<String> {
        self.threshold_scaled
            .map(|threshold| percent(threshold, self.scale()))
    }

    /// The windowed limit as a percentage, or `None` when no window is configured.
    ///
    /// Called from `preflight`'s `window` column, which pairs it with `window.blocks` so
    /// an operator sees both halves of the setting rather than one.
    pub fn window_limit(&self) -> Option<String> {
        self.window
            .map(|window| percent(window.threshold_scaled, self.scale()))
    }
}

/// "3.40%" for the fraction numer/denom, truncated.
///
/// Two decimal places suit the moves this normally formats, but a threshold can
/// legitimately be far finer than a basis point — the smoke-test recipe in the README uses
/// 0.00001, which is 0.001% — and a guard that reports its own limit as "0.00%" tells the
/// operator nothing at exactly the moment they need to read it. So the precision extends,
/// but only as far as it must to show a nonzero figure.
///
/// A zero denominator (impossible for the mids and scales this formats, which are all
/// nonzero by construction) renders as "?%" rather than panicking in a log-line helper.
pub fn percent(numer: U256, denom: U256) -> String {
    percent_at_least(numer, denom, 2)
}

/// `percent`, but never coarser than `min_decimals`: the search for a nonzero rendering
/// starts there instead of at two.
pub(crate) fn percent_at_least(numer: U256, denom: U256, min_decimals: u32) -> String {
    if denom.is_zero() {
        return "?%".to_owned();
    }
    let render = |decimals: u32| {
        let scale = 10u64.pow(decimals);
        let scaled = numer.full_mul(U256::from(100u64) * U256::from(scale)) / U512::from(denom);
        let whole = scaled / U512::from(scale);
        let frac = (scaled % U512::from(scale)).as_u64();
        (
            scaled.is_zero(),
            format!("{whole}.{frac:0width$}%", width = decimals as usize),
        )
    };
    for decimals in [2u32, 4, 6] {
        if decimals < min_decimals {
            continue;
        }
        let (zero, rendered) = render(decimals);
        if !zero {
            return rendered;
        }
    }
    // The finest precision is the fallback whatever it renders, zero included: a genuinely
    // zero fraction reads as zero rather than spiralling into more digits.
    render(8).1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::parse_decimal_scaled;

    /// Both thresholds render independently, and an unset one renders as nothing rather
    /// than as a zero an operator would read as a configured limit.
    #[test]
    fn each_configured_threshold_renders_its_own_limit() {
        let both = BreakerConfig {
            threshold_scaled: Some(parse_decimal_scaled("0.02", 6).unwrap()),
            window: Some(WindowConfig {
                threshold_scaled: parse_decimal_scaled("0.20", 6).unwrap(),
                blocks: 1000,
                span: Duration::from_secs(12_000),
            }),
            decimals: 6,
        };
        assert_eq!(both.tick_limit().as_deref(), Some("2.00%"));
        assert_eq!(both.window_limit().as_deref(), Some("20.00%"));

        let window_only = BreakerConfig {
            threshold_scaled: None,
            ..both
        };
        assert_eq!(window_only.tick_limit(), None);
        assert_eq!(window_only.window_limit().as_deref(), Some("20.00%"));
    }

    /// `preflight`'s `breaker` column is a fixed width, so what this can return at its
    /// longest is load-bearing: an over-long value would push every later column on that
    /// row out of line. Precision only extends for values too small to show at two
    /// decimals, which forces the whole part to 0, so the longest legal rendering is
    /// `0.` + 8 digits + `%`.
    #[test]
    fn percent_never_exceeds_the_width_the_check_table_reserves() {
        // Thresholds are bounded to 0 < t < scale by `config::parse_breaker`.
        for (numer, denom) in [
            (U256::one(), U256::exp10(30)),              // absurdly fine
            (U256::one(), U256::exp10(9)),               // the 8-decimal case
            (U256::from(5), U256::from(100_000)),        // extends to 4
            (U256::exp10(13), U256::exp10(18)),          // the smoke-test threshold
            (U256::from(99), U256::from(100)),           // the loosest legal threshold
            (U256::from(12_345), U256::from(1_000_000)), // an ordinary one
        ] {
            let rendered = percent(numer, denom);
            assert!(
                rendered.len() <= crate::preflight::BREAKER_COLUMN_WIDTH,
                "{rendered} is {} chars, wider than the column reserves",
                rendered.len()
            );
        }
    }

    /// The operator lines print fractions as percentages, truncating: 1/3 is "33.33%", not
    /// a 78-digit scaled integer.
    #[test]
    fn percent_formats_to_basis_point_precision() {
        assert_eq!(percent(U256::from(34), U256::from(1000)), "3.40%");
        assert_eq!(percent(U256::from(1), U256::from(3)), "33.33%");
        assert_eq!(percent(U256::from(12_345), U256::from(10_000)), "123.45%");
        assert_eq!(percent(U256::from(1), U256::zero()), "?%");
    }

    /// Regression test for the finding that the README's own smoke-test threshold
    /// (0.00001, i.e. 0.001%) rendered as "0.00%", making the demo line meaningless: the
    /// precision has to follow the number down.
    #[test]
    fn percent_keeps_extending_until_a_sub_basis_point_value_shows() {
        // The smoke test's threshold at the default 18 decimals.
        assert_eq!(percent(U256::exp10(13), U256::exp10(18)), "0.0010%");
        assert_eq!(percent(U256::from(5), U256::from(100_000)), "0.0050%");
        assert_eq!(percent(U256::one(), U256::exp10(9)), "0.00000010%");
        // Genuinely zero still reads as zero rather than spiralling into more digits.
        assert_eq!(percent(U256::zero(), U256::from(1000)), "0.00000000%");
    }
}

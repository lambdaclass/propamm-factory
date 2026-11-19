//! A pair's size charges: the table a pair's `size_charges` states, and how it rides in the
//! update PropAMM reads.
//!
//! Each row says "up to this share of the vault, charge this much more": a fill pays the
//! average of the rows it spans, on top of `delta`, and a block's fills in one direction
//! continue the table from where the last one stopped (`contracts/src/SizeTable.sol`). A
//! share is what the fills are worth at mid over the vault's balance of the token it pays
//! out, so one table means the same on every pair.
//!
//! ```toml
//! # First 10% of the vault at no charge, 10% to 30% at 2 bp, everything past that at 5 bp.
//! size_charges = "10:0, 30:2, rest:5"
//! ```
//!
//! The rows are packed where the update has room: three above `delta` in slot 0, which the
//! update writes anyway, and six to a slot from slot 3 on. Slot 2 is left empty.

use ethrex_common::U256;
use eyre::{Result, WrapErr, bail, ensure};

use crate::feed::parse_decimal_scaled;

/// A row's end is published in millionths of the vault, so a percentage has four decimals.
const PERCENT_DECIMALS: u32 = 4;
/// A row's charge is published in hundredths of a basis point.
const BPS_DECIMALS: u32 = 2;
/// A row's end takes 24 bits: just under 1678%.
const MAX_END: u64 = (1 << 24) - 1;
/// A row's charge takes 16 bits: 655.35 bp.
const MAX_CHARGE: u64 = (1 << 16) - 1;
/// The bits of slot 0 `delta` keeps. PropAMM refuses a spread of one whole unit, 1e18, so a
/// `delta` it can price always fits.
const DELTA_BITS: usize = 64;
const ROW_BITS: usize = 40;
/// Rows that fit above `delta` in slot 0, which holds 216 bits.
const ROWS_IN_SLOT0: usize = 3;
const ROWS_PER_SLOT: usize = 6;
/// The slot the rows past slot 0 start at: slot 1 is `mid`, and slot 2 is left empty.
const FIRST_ROW_SLOT: usize = 3;
/// The registry takes at most 255 slots in an update.
const MAX_SLOTS: usize = 255;

/// One row: where it ends, in millionths of the vault (zero for the last row, which has no
/// end), and what it charges, in hundredths of a basis point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    end: u32,
    charge: u16,
}

/// A pair's size charges, parsed and in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SizeTable {
    rows: Vec<Row>,
}

impl SizeTable {
    /// Parses `size_charges`: rows `percent:bps` separated by commas, each ending further
    /// into the vault than the last and charging no less, the last optionally `rest:bps` for
    /// everything past the row before it. Without a `rest` row the last row's charge carries
    /// on past its end.
    pub fn parse(text: &str) -> Result<SizeTable> {
        let mut rows: Vec<Row> = Vec::new();
        let entries: Vec<&str> = text.split(',').map(str::trim).collect();
        for (i, entry) in entries.iter().enumerate() {
            let at = format!("row {} ({entry:?})", i + 1);
            let (end, charge) = entry.split_once(':').ok_or_else(|| {
                eyre::eyre!(
                    "{at} is not `percent:bps`; write rows like `10:0, 30:2, rest:5`: up to \
                     10% of the vault at no charge, up to 30% at 2 bp, the rest at 5 bp"
                )
            })?;
            let (end, charge) = (end.trim(), charge.trim());
            let end = if end.eq_ignore_ascii_case("rest") {
                ensure!(
                    i + 1 == entries.len(),
                    "{at}: `rest` is everything past the row before it, so it can only be the \
                     last row"
                );
                0
            } else {
                let end = scaled(end, PERCENT_DECIMALS)
                    .wrap_err_with(|| format!("{at}: invalid percentage {end:?}"))?;
                ensure!(end > 0, "{at}: a row that ends at 0% covers nothing");
                ensure!(
                    end <= MAX_END,
                    "{at}: {}% is past the {}% a row can end at",
                    end as f64 / 1e4,
                    MAX_END as f64 / 1e4
                );
                end
            };
            let charge = scaled(charge, BPS_DECIMALS)
                .wrap_err_with(|| format!("{at}: invalid charge {charge:?}"))?;
            ensure!(
                charge <= MAX_CHARGE,
                "{at}: {} bp is above the {} bp a row can charge; the charge is in basis \
                 points, so write 5 for 0.05%",
                charge as f64 / 1e2,
                MAX_CHARGE as f64 / 1e2
            );
            if let Some(last) = rows.last() {
                ensure!(
                    end == 0 || u64::from(last.end) < end,
                    "{at} ends at or before the row before it; each row ends further into the \
                     vault than the last"
                );
                ensure!(
                    u64::from(last.charge) <= charge,
                    "{at} charges less than the row before it; a charge may only rise with \
                     size, or a larger fill would get a better price than a smaller one"
                );
            }
            rows.push(Row {
                end: end as u32,
                charge: charge as u16,
            });
        }
        // The contract tells an update with a table from one without by whether anything
        // sits above `delta`, and a lone `rest:0` packs to nothing.
        ensure!(
            rows.iter().any(|row| row.end != 0 || row.charge != 0),
            "`rest:0` alone charges nothing at any size, and the update would read as having \
             no table; give it a row with an end (`100:0`) to publish a table of no charge"
        );
        let table = SizeTable { rows };
        ensure!(
            FIRST_ROW_SLOT + table.row_slots() <= MAX_SLOTS,
            "{} rows do not fit an update: the registry takes {MAX_SLOTS} slots, which is \
             {} rows",
            table.rows.len(),
            ROWS_IN_SLOT0 + ROWS_PER_SLOT * (MAX_SLOTS - FIRST_ROW_SLOT)
        );
        Ok(table)
    }

    /// The slots the rows past slot 0 take.
    fn row_slots(&self) -> usize {
        self.rows
            .len()
            .saturating_sub(ROWS_IN_SLOT0)
            .div_ceil(ROWS_PER_SLOT)
    }

    /// The slots the update writes for rows past slot 0: what the gas limit has to cover the
    /// first time they are written.
    pub(crate) fn extra_slots(&self) -> usize {
        self.row_slots()
    }

    /// The table as it is written: `10:0, 30:2, rest:5`.
    pub(crate) fn describe(&self) -> String {
        self.rows
            .iter()
            .map(|row| {
                let charge = trimmed(u64::from(row.charge), BPS_DECIMALS);
                match row.end {
                    0 => format!("rest:{charge}"),
                    end => format!("{}:{charge}", trimmed(u64::from(end), PERCENT_DECIMALS)),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A non-negative decimal as an integer at `decimals`, refusing digits it cannot hold: the
/// shared parser truncates them, and a row that ends at 12.34567% must not quietly end at
/// 12.3456%.
fn scaled(text: &str, decimals: u32) -> Result<u64> {
    let fraction_digits = text
        .split_once('.')
        .map_or(0, |(_, digits)| digits.trim_end_matches('0').len());
    ensure!(
        fraction_digits <= decimals as usize,
        "{text} has more than {decimals} decimal places"
    );
    let value = parse_decimal_scaled(text, decimals)?;
    ensure!(value <= U256::from(u64::MAX), "{text} is out of range");
    Ok(value.as_u64())
}

/// `value` at `decimals` as text, without trailing zeros.
fn trimmed(value: u64, decimals: u32) -> String {
    crate::feed::format_scaled(U256::from(value), decimals)
}

/// The slots of one update: `[delta, mid]`, and the pair's size charges when it has a table:
/// three rows above `delta` in slot 0 and the rest six to a slot from slot 3 on, past an empty
/// slot 2. Byte for byte what `contracts/src/SizeTable.sol` reads.
pub(crate) fn update_slots(delta: U256, mid: U256, table: Option<&SizeTable>) -> Result<Vec<U256>> {
    let Some(table) = table else {
        return Ok(vec![delta, mid]);
    };
    if delta >> DELTA_BITS != U256::zero() {
        bail!(
            "delta {delta} does not fit in {DELTA_BITS} bits, which is what slot 0 leaves it \
             beside a size table"
        );
    }
    let row_slots = table.row_slots();
    let mut slots = vec![delta, mid];
    if row_slots > 0 {
        slots.resize(FIRST_ROW_SLOT + row_slots, U256::zero());
    }
    for (i, row) in table.rows.iter().enumerate() {
        let packed = U256::from(u64::from(row.charge) | (u64::from(row.end) << 16));
        if i < ROWS_IN_SLOT0 {
            slots[0] |= packed << (DELTA_BITS + ROW_BITS * i);
        } else {
            let i = i - ROWS_IN_SLOT0;
            slots[FIRST_ROW_SLOT + i / ROWS_PER_SLOT] |= packed << (ROW_BITS * (i % ROWS_PER_SLOT));
        }
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> SizeTable {
        SizeTable::parse(text).unwrap()
    }

    fn refused(text: &str) -> String {
        format!("{:#}", SizeTable::parse(text).unwrap_err())
    }

    #[test]
    fn rows_parse_as_percent_and_basis_points() {
        let parsed = table("10:0, 30:2, rest:5");
        assert_eq!(
            parsed.rows,
            [
                Row {
                    end: 100_000,
                    charge: 0
                },
                Row {
                    end: 300_000,
                    charge: 200
                },
                Row {
                    end: 0,
                    charge: 500
                },
            ]
        );
        // Decimals as fine as the row holds, and no finer.
        assert_eq!(
            table("0.0001:0.01").rows,
            [Row { end: 1, charge: 1 }],
            "one millionth of the vault, one hundredth of a basis point"
        );
        assert_eq!(
            table(" 2.5 : 1.25 , REST : 3 ").describe(),
            "2.5:1.25, rest:3"
        );
        assert_eq!(parsed.describe(), "10:0, 30:2, rest:5");
    }

    #[test]
    fn a_table_out_of_order_or_out_of_range_is_refused_naming_the_row() {
        for (text, why) in [
            ("10", "is not `percent:bps`"),
            ("", "is not `percent:bps`"),
            ("10:0, 10:2", "ends at or before the row before it"),
            ("30:0, 10:2", "ends at or before the row before it"),
            ("10:3, 30:2", "charges less than the row before it"),
            ("rest:1, 30:2", "can only be the last row"),
            ("0:1", "covers nothing"),
            ("10:700", "is above the 655.35 bp"),
            ("1700:1", "is past the"),
            ("10.00001:1", "more than 4 decimal places"),
            ("10:1.001", "more than 2 decimal places"),
            ("ten:1", "invalid percentage"),
            ("10:-1", "invalid charge"),
            ("rest:0", "would read as having no table"),
        ] {
            let err = refused(text);
            assert!(err.contains(why), "{text:?}: {err}");
        }
        assert!(refused("10:0, 30:2, 20:5").contains("row 3"));
    }

    /// The layout `contracts/src/SizeTable.sol` reads: a row is `charge | end << 16` in 40
    /// bits, rows 0..2 start at bit 64 of slot 0, rows 3.. sit six to a slot from slot 3.
    #[test]
    fn rows_are_packed_where_the_contract_reads_them() {
        let delta = U256::from(500_000_000_000_000u64);
        let mid = U256::from(1600u64) * U256::exp10(18);
        let row = |end: u64, charge: u64| U256::from(charge | (end << 16));

        // Without a table the update is what it always was.
        assert_eq!(update_slots(delta, mid, None).unwrap(), [delta, mid]);

        // Three rows ride above delta: still two slots.
        let three = table("10:0, 30:2, rest:5");
        let slot0 =
            delta | (row(100_000, 0) << 64) | (row(300_000, 200) << 104) | (row(0, 500) << 144);
        assert_eq!(
            update_slots(delta, mid, Some(&three)).unwrap(),
            [slot0, mid]
        );
        // The same number `contracts/test/PropAMMSizeTable.t.sol` publishes for this table.
        assert_eq!(
            slot0,
            U256::from_str_radix("1f40493e000c80186a000000001c6bf52634000", 16).unwrap()
        );
        assert_eq!(slot0 >> 216, U256::zero(), "slot 0 keeps to its 27 bytes");
        assert_eq!(three.extra_slots(), 0);

        // A fourth row starts slot 3, past an empty slot 2.
        let ten = table("1:1, 2:2, 3:3, 4:4, 5:5, 6:6, 7:7, 8:8, 9:9, 10:10");
        let slots = update_slots(delta, mid, Some(&ten)).unwrap();
        assert_eq!(slots.len(), 5);
        assert_eq!(slots[2], U256::zero());
        assert_eq!(
            slots[3],
            (0..6).fold(U256::zero(), |slot, i| {
                slot | (row((i + 4) * 10_000, (i + 4) * 100) << (40 * i as usize))
            })
        );
        assert_eq!(slots[4], row(100_000, 1000));
        assert_eq!(ten.extra_slots(), 2);
    }

    #[test]
    fn a_delta_too_wide_for_its_share_of_slot_0_is_refused() {
        let three = table("10:0, rest:5");
        let wide = U256::one() << 64;
        let err = update_slots(wide, U256::one(), Some(&three)).unwrap_err();
        assert!(format!("{err:#}").contains("does not fit in 64 bits"));
        // Without a table slot 0 is delta's alone.
        assert_eq!(
            update_slots(wide, U256::one(), None).unwrap(),
            [wide, U256::one()]
        );
    }
}

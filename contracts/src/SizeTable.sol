// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import "@openzeppelin/contracts/utils/math/Math.sol";

/// A row's end does not rise past the previous row's, or its charge falls below it.
error InvalidSizeTable(uint256 row);

/// @title SizeTable
/// @notice The size charges a price update carries: rows of (end, charge). The part of a block's
/// trading between the previous row's end and this row's end pays this row's charge.
/// @dev Ends are shares of the vault: what the block's fills in one direction are worth at mid,
/// over the vault's tokenOut balance when the first of them arrived. A row is 40 bits:
///     bits  0..15  charge, in 1e-6 (0.01 bp); at most 6.5535%
///     bits 16..39  end, in 1e-6 of the vault. 0: the row has no end and is the last one.
/// Rows 0..2 sit in slot 0 above delta (bits 64..183); rows 3.. sit six to a slot from slot 3 on
/// (slot 1 is mid, slot 2 is left to the updater). The table ends at the first row with no end. A
/// row of all zeros is one, at the previous row's charge, and so is the last row an update can
/// hold whatever its end. Above the rows, slot 0 holds the retail delta (bits 184..215, see
/// `PropAMM._pricing`), which is no part of the table.
library SizeTable {
    uint256 internal constant SCALE = 1e18;
    uint256 internal constant DELTA_MASK = (1 << 64) - 1;
    /// Charges and ends are published at 1e-6.
    uint256 internal constant UNIT = 1e12;
    uint256 private constant ROW_MASK = (1 << 40) - 1;
    /// The three rows slot 0 holds, once shifted down past delta.
    uint256 private constant SLOT0_ROWS_MASK = (1 << 120) - 1;
    uint256 private constant FIRST_SLOT = 3;

    function present(uint256[] memory slots) internal pure returns (bool) {
        // Only the rows: a retail delta above them does not make a table.
        return (slots[0] >> 64) & SLOT0_ROWS_MASK != 0;
    }

    function _count(uint256[] memory slots) private pure returns (uint256) {
        return slots.length > FIRST_SLOT ? 3 + 6 * (slots.length - FIRST_SLOT) : 3;
    }

    /// A row's end as a share at SCALE, and its charge in 1e-6.
    function _row(uint256[] memory slots, uint256 i) private pure returns (uint256 end, uint256 charge) {
        uint256 r = i < 3
            ? (slots[0] >> (64 + 40 * i)) & ROW_MASK
            : (slots[FIRST_SLOT + (i - 3) / 6] >> (40 * ((i - 3) % 6))) & ROW_MASK;
        charge = r & 0xffff;
        end = (r >> 16) * UNIT;
    }

    /// @notice The average charge, at SCALE and rounded up, over the shares [from, to) of the vault.
    function average(uint256[] memory slots, uint256 from, uint256 to) internal pure returns (uint256) {
        uint256 n = _count(slots);
        uint256 total;
        uint256 start;
        uint256 last;
        for (uint256 i = 0; i < n; i++) {
            (uint256 end, uint256 charge) = _row(slots, i);
            // A row of all zeros is padding: the row before it is the last, and has no end.
            if (end == 0 && charge == 0) charge = last;
            require(charge >= last && (end == 0 || end > start), InvalidSizeTable(i));
            bool open = end == 0 || i == n - 1;
            if (open || end > from) {
                // A fill too small to span any share pays the charge of the row it starts in.
                if (to <= from) return charge * UNIT;
                uint256 lo = from > start ? from : start;
                uint256 hi = open || to < end ? to : end;
                total += charge * (hi - lo);
                if (open || end >= to) break;
            }
            start = end;
            last = charge;
        }
        return Math.mulDiv(total, UNIT, to - from, Math.Rounding.Ceil);
    }

    /// @notice The most a fill may be worth at mid, starting after `filled`, for its output to
    /// stay within `capacity`, stopping at `want`. `ref` is the balance the shares are of. Along
    /// the way the output only rises, so every smaller fill fits too.
    function fillable(
        uint256[] memory slots,
        uint256 delta,
        uint256 filled,
        uint256 ref,
        uint256 capacity,
        uint256 want
    ) internal pure returns (uint256 worth) {
        uint256 n = _count(slots);
        uint256 start;
        uint256 last;
        uint256 pos = filled;
        for (uint256 i = 0; i < n; i++) {
            (uint256 end, uint256 charge) = _row(slots, i);
            if (end == 0 && charge == 0) charge = last;
            require(charge >= last && (end == 0 || end > start), InvalidSizeTable(i));
            bool open = end == 0 || i == n - 1;
            // Where the row ends, as worth at mid. Rounded down: a fill is charged the next
            // row's rate no later than `average` starts charging it.
            uint256 endAt = open ? type(uint256).max : Math.mulDiv(end, ref, SCALE);
            if (endAt > pos) {
                uint256 spread = delta + charge * UNIT;
                // Past here a larger fill would pay out less: stop at the row's start.
                if (spread >= SCALE) return worth;
                uint256 rate = SCALE - spread;
                uint256 reach = Math.mulDiv(capacity, SCALE, rate);
                uint256 room = endAt - pos;
                uint256 step = reach < room ? reach : room;
                if (want - worth <= step) return want;
                worth += step;
                if (reach <= room) return worth;
                capacity -= Math.mulDiv(step, rate, SCALE, Math.Rounding.Ceil);
                pos = endAt;
            }
            start = end;
            last = charge;
        }
    }

    /// @notice Packs one row, for tests and for off-chain encoders that mirror this one.
    function row(uint256 end1e6, uint256 charge) internal pure returns (uint256) {
        return charge | (end1e6 << 16);
    }
}

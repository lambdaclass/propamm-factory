// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PropAMM, FilledOverflow} from "../src/PropAMM.sol";
import {SizeTable, InvalidSizeTable} from "../src/SizeTable.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";

/// An update that carries a size table: how its rows price a fill, how a block's fills add up,
/// and what `quoteFillable` makes of it. One WETH/USDT pair, a vault holding both.
contract PropAMMSizeTableTest is Test {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // token0
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7; // token1
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;
    uint256 constant MID = 1600e18;
    uint256 constant DELTA = 5e14;

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address recipient = makeAddr("recipient");

    PropAMM amm;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.etch(ORACLE, address(new MockPUR()).code);
        vm.etch(WETH, address(new MockToken()).code);
        MockToken(WETH).setDecimals(18);
        vm.etch(USDT, address(new MockToken()).code);
        MockToken(USDT).setDecimals(6);

        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: WETH, token1: USDT, vault: vault});
        amm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, pairs))
                )
            )
        );
        // 64,000,000 USDT and 40,000 WETH: the same worth at MID.
        MockToken(USDT).mint(vault, 64_000_000e6);
        MockToken(WETH).mint(vault, 40_000e18);
        vm.startPrank(vault);
        MockToken(USDT).approve(address(amm), type(uint256).max);
        MockToken(WETH).approve(address(amm), type(uint256).max);
        vm.stopPrank();
    }

    /// Packs rows into an update the way the updater does: three above delta in slot 0, six to
    /// a slot from slot 3, slot 2 left empty.
    function _update(uint256 delta, uint256[] memory rows) internal pure returns (uint256[] memory s) {
        uint256 extra = rows.length > 3 ? (rows.length - 3 + 5) / 6 : 0;
        s = new uint256[](extra == 0 ? 2 : 3 + extra);
        s[0] = delta;
        s[1] = MID;
        for (uint256 i = 0; i < rows.length; i++) {
            if (i < 3) s[0] |= rows[i] << (64 + 40 * i);
            else s[3 + (i - 3) / 6] |= rows[i] << (40 * ((i - 3) % 6));
        }
    }

    function _publish(uint256 delta, uint256[] memory rows) internal {
        MockPUR(ORACLE).setSlots(_update(delta, rows));
    }

    /// First 10% of the vault free, 10% to 30% at 2 bp, above that 5 bp.
    function _steps() internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        r[0] = SizeTable.row(100_000, 0);
        r[1] = SizeTable.row(300_000, 200);
        r[2] = SizeTable.row(0, 500);
    }

    /// A random valid table: 1 to 15 rows, each ending up to 8% of the vault past the last,
    /// charges never falling.
    function _random(uint256 seed) internal pure returns (uint256[] memory r) {
        uint256 rows = 1 + seed % 15;
        r = new uint256[](rows);
        uint256 end;
        uint256 charge = (seed >> 8) % 50;
        for (uint256 i = 0; i < rows; i++) {
            seed = uint256(keccak256(abi.encode(seed)));
            end += 1 + seed % 80_000;
            charge += (seed >> 32) % 400;
            r[i] = SizeTable.row(i == rows - 1 && seed & (1 << 200) != 0 ? 0 : end, charge);
        }
    }

    function _nextBlock() internal {
        vm.warp(block.timestamp + 12);
        vm.roll(block.number + 1);
    }

    function _swap(address tokenIn, address tokenOut, uint256 amountIn) internal returns (uint256) {
        MockToken(tokenIn).mint(address(amm), amountIn);
        return amm.swap(tokenIn, tokenOut, amountIn, 0, recipient, block.timestamp);
    }

    function _tokens(bool sell0) internal pure returns (address tokenIn, address tokenOut) {
        return sell0 ? (WETH, USDT) : (USDT, WETH);
    }

    /// Up to 30% of the vault either way, and never so little that it is worth less than a unit
    /// of tokenOut, which `swap` refuses.
    function _amount(bool sell0, uint256 x) internal pure returns (uint256) {
        return sell0 ? bound(x, 1e12, 12_000e18) : bound(x, 1, 19_200_000e6);
    }

    /// The expected output of `weth` whole WETH at `spread`.
    function _usdt(uint256 weth, uint256 spread) internal pure returns (uint256) {
        return weth * 1600e6 * (1e18 - spread) / 1e18;
    }

    /// The update the quote updater publishes for `size_charges = "10:0, 30:2, rest:5"` at a
    /// delta of 5 bp: its first slot, as `quote-updater/src/size_table.rs` packs it.
    function test_theUpdaterPacksRowsWhereTheContractReadsThem() public pure {
        // 0x1f40493e000c80186a000000001c6bf52634000, in decimal so it is not taken for an address.
        assertEq(_update(DELTA, _steps())[0], 11150771367668103648343042573990471777237811200);
    }

    function test_aFillPaysTheAverageOfTheRowsItSpans() public {
        _publish(DELTA, _steps());
        // 4,000 WETH is worth 6.4M USDT, 10% of the vault: all in the free row.
        assertEq(amm.quote(WETH, USDT, 4_000e18), _usdt(4_000, DELTA));
        // 8,000 WETH is 20%: half free, half at 2 bp, so 1 bp over delta.
        assertEq(amm.quote(WETH, USDT, 8_000e18), _usdt(8_000, DELTA + 1e14));
        // 16,000 WETH is 40%: 10% free, 20% at 2 bp, 10% at 5 bp, so 2.25 bp.
        assertEq(amm.quote(WETH, USDT, 16_000e18), _usdt(16_000, DELTA + 2.25e14));
    }

    /// `isActive` reads `delta` from the low bits of its slot, as pricing does: rows above it
    /// do not make the pair read as one whose spread is out of range.
    function test_aPairWithATableIsActive() public {
        _publish(DELTA, _steps());
        assertTrue(amm.isActive(WETH, USDT));
        assertTrue(amm.isActive(USDT, WETH));
    }

    function test_aBlocksFillsContinueWhereTheLastStopped() public {
        _publish(DELTA, _steps());
        uint256 whole = amm.quote(WETH, USDT, 8_000e18);
        // The first 10% is free. The second starts at 10% and pays 2 bp on all of it, though the
        // vault it draws on is smaller by then: both are shares of what the block started with.
        uint256 first = _swap(WETH, USDT, 4_000e18);
        assertEq(first, _usdt(4_000, DELTA));
        uint256 second = _swap(WETH, USDT, 4_000e18);
        assertEq(second, _usdt(4_000, DELTA + 2e14));
        assertApproxEqAbs(first + second, whole, 2);
        // The other direction has fills of its own to count: none yet.
        assertEq(amm.quote(USDT, WETH, 6_400_000e6), uint256(4_000e18) * (1e18 - DELTA) / 1e18);
    }

    function test_theNextBlockStartsOverAgainstWhatTheVaultHoldsThen() public {
        _publish(DELTA, _steps());
        uint256 first = _swap(WETH, USDT, 4_000e18);
        _nextBlock();
        _publish(DELTA, _steps());
        // The vault paid out 10% of its USDT, so the same 4,000 WETH is now more than 10% of
        // it and its last part pays 2 bp.
        uint256 next = amm.quote(WETH, USDT, 4_000e18);
        assertLt(next, first);
        assertGt(next, _usdt(4_000, DELTA + 2e14));
    }

    function test_anUpdateWithoutRowsPricesAsBefore() public {
        MockPUR(ORACLE).setState(DELTA, MID);
        MockPUR(ORACLE).setSlotCount(2);
        // The fixed impact: 1 bp for the whole vault, so 0.1 bp for 10% of it.
        assertEq(amm.quote(WETH, USDT, 4_000e18), _usdt(4_000, DELTA + 1e13));
        _swap(WETH, USDT, 4_000e18);
        assertEq(amm.fills(uint256(keccak256(abi.encodePacked(WETH, USDT))), 0), 0, "nothing is counted");
    }

    function test_aRowOfZerosEndsTheTableAtTheChargeBeforeIt() public {
        uint256[] memory r = new uint256[](1);
        r[0] = SizeTable.row(100_000, 300);
        _publish(DELTA, r);
        // One row with an end: past it the charge stays 3 bp.
        assertEq(amm.quote(WETH, USDT, 16_000e18), _usdt(16_000, DELTA + 3e14));
    }

    function test_aTableOutOfOrderRevertsFromTheRowThatBreaksIt() public {
        uint256[] memory r = _steps();
        r[1] = SizeTable.row(300_000, 0);
        r[0] = SizeTable.row(100_000, 300); // the second row charges less than the first
        _publish(DELTA, r);
        vm.expectRevert(abi.encodeWithSelector(InvalidSizeTable.selector, 1));
        amm.quote(WETH, USDT, 8_000e18);
        // A fill that stays in the first row never reads the second.
        assertEq(amm.quote(WETH, USDT, 2_000e18), _usdt(2_000, DELTA + 3e14));

        r[1] = SizeTable.row(50_000, 400); // ends before the first row does
        _publish(DELTA, r);
        vm.expectRevert(abi.encodeWithSelector(InvalidSizeTable.selector, 1));
        amm.quote(WETH, USDT, 8_000e18);
    }

    function test_aVaultTooLargeToCountIsRefused() public {
        _publish(DELTA, _steps());
        MockToken(USDT).mint(vault, 1 << 112);
        vm.expectRevert(abi.encodeWithSelector(FilledOverflow.selector, (1 << 112) + 64_000_000e6));
        amm.quote(WETH, USDT, 1e18);
    }

    function test_quoteFillableStopsWhereTheVaultRunsOut() public {
        _publish(DELTA, _steps());
        // An order worth twice the vault: the fill is what the vault can pay, to the unit.
        (uint256 fillable, uint256 out) = amm.quoteFillable(WETH, USDT, 80_000e18);
        assertLt(fillable, 80_000e18);
        assertApproxEqAbs(out, 64_000_000e6, 1);
        assertEq(amm.quote(WETH, USDT, fillable), out);
        assertEq(_swap(WETH, USDT, fillable), out);
    }

    function testFuzz_aSplitPaysWhatTheWholePays(uint256 seed, uint256 x, uint256 y, bool sell0) public {
        _publish(DELTA, _random(seed));
        (address tokenIn, address tokenOut) = _tokens(sell0);
        x = _amount(sell0, x);
        y = _amount(sell0, y);
        uint256 whole = amm.quote(tokenIn, tokenOut, x + y);
        uint256 parts = _swap(tokenIn, tokenOut, x) + _swap(tokenIn, tokenOut, y);
        // The charge is a fraction at 1e-18 rounded up once per swap, and each output rounds
        // down: the two ways differ by a few units plus about 1e-18 of the fill.
        assertApproxEqAbs(parts, whole, 3 + whole / 1e17);
    }

    /// What `PropAMMRouter` holds a venue to when it trims a leg: the floored pro-rata share
    /// of the quote it ranked the venue by.
    function testFuzz_aSmallerLegGetsAtLeastItsShare(
        uint256 seed,
        uint256 fill,
        uint256 leg,
        bool sell0,
        uint256 before
    ) public {
        _publish(DELTA, _random(seed));
        (address tokenIn, address tokenOut) = _tokens(sell0);
        if (before % 2 == 1) _swap(tokenIn, tokenOut, _amount(sell0, before));
        fill = _amount(sell0, fill);
        leg = bound(leg, 1, fill);
        uint256 out = amm.quote(tokenIn, tokenOut, fill);
        assertGe(amm.quote(tokenIn, tokenOut, leg), out * leg / fill);
    }

    function testFuzz_quoteFillableNeverOverdraws(
        uint256 seed,
        uint256 want,
        uint256 cap,
        uint256 leg,
        bool sell0,
        uint256 delta
    ) public {
        delta = bound(delta, 0, 9e17);
        _publish(delta, _random(seed));
        (address tokenIn, address tokenOut) = _tokens(sell0);
        want = _amount(sell0, want);
        // The vault lets the instance move only `cap` of tokenOut.
        cap = sell0 ? bound(cap, 1, 30_000_000e6) : bound(cap, 1, 18_000e18);
        vm.prank(vault);
        MockToken(tokenOut).approve(address(amm), cap);

        (uint256 fillable, uint256 out) = amm.quoteFillable(tokenIn, tokenOut, want);
        assertLe(fillable, want);
        assertLe(out, cap);
        if (fillable == 0) return;
        assertEq(amm.quote(tokenIn, tokenOut, fillable), out);
        // Not overly cautious: a fill one part in a million larger would overdraw.
        if (fillable < want) {
            uint256 more = fillable + fillable / 1e6 + (sell0 ? 1e12 : 1e4);
            if (more <= want) assertGt(amm.quote(tokenIn, tokenOut, more), cap);
        }
        // Every smaller leg gets at least its share, floored as the router floors it, and swaps.
        leg = bound(leg, 1, fillable);
        uint256 legOut = amm.quote(tokenIn, tokenOut, leg);
        assertGe(legOut, out * leg / fillable);
        // A leg worth less than a unit of tokenOut is one `swap` refuses.
        if (legOut != 0) assertEq(_swap(tokenIn, tokenOut, leg), legOut);
    }

    function testFuzz_outputRisesWithSize(uint256 seed, uint256 x, uint256 y, bool sell0) public {
        _publish(DELTA, _random(seed));
        (address tokenIn, address tokenOut) = _tokens(sell0);
        x = _amount(sell0, x);
        y = _amount(sell0, y);
        if (x > y) (x, y) = (y, x);
        // Up to rounding: the charge is rounded up at 1e-18 and the output down, so a fill a
        // hair larger can come out one unit lower.
        uint256 larger = amm.quote(tokenIn, tokenOut, y);
        assertLe(amm.quote(tokenIn, tokenOut, x), larger + 1 + larger / 1e17);
    }
}

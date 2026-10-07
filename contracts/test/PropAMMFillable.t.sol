// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    PropAMM,
    EmptyVault,
    InsufficientOracleData,
    InsufficientVaultBalance,
    InvalidMid,
    SpreadTooWide,
    UnsupportedPair
} from "../src/PropAMM.sol";
import {IPrioUpdateRegistry} from "../src/interfaces/IPrioUpdateRegistry.sol";
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {IPropAMMFillable} from "../src/interfaces/IPropAMMFillable.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";

/// What the real registry reverts with outside the block a price was stamped for.
error StaleUpdate();

/// Exercises `IPropAMMFillable`, the extension `PropAMMRouter.swapSplitV1` prices a venue through
/// in one call instead of its blind two-point probe. What the router relies on is narrower than
/// "the quote is right": every leg it may carve out of the reported fill has to swap, at no less
/// than its pro-rata share of the reported output. Tokens sit at their mainnet addresses with
/// their mainnet decimals, so the fuzzing below covers every decimals pairing from 2 to 24 and
/// both orientations of `mid`:
///     GUSD (0x05, 2) < WBTC (0x22, 8) < NEAR (0x85, 24) < USDC (0xA0, 6) < WETH (0xC0, 18)
///     < USDT (0xdA, 6)
contract PropAMMFillableTest is Test {
    address constant GUSD = 0x056Fd409E1d7A124BD7017459dFEa2F387b6d5Cd;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address constant NEAR = 0x85F17Cf997934a597031b2E18a9aB6ebD4B9f6a4;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;

    uint256 constant SPREAD_SCALE = 1e18;

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address trader = makeAddr("trader");

    PropAMM propAmm;
    /// The listed pairs, one fuzz seed each. Every pair fills from `vault`.
    address[2][] pairs;

    function setUp() public {
        vm.etch(ORACLE, address(new MockPUR()).code);

        _deployToken(GUSD, 2);
        _deployToken(WBTC, 8);
        _deployToken(NEAR, 24);
        _deployToken(USDC, 6);
        _deployToken(WETH, 18);
        _deployToken(USDT, 6);

        pairs.push([WETH, USDT]); // 18 -> 6, the first-listed pair in setUp below
        pairs.push([WBTC, USDC]); // 8 -> 6
        pairs.push([USDC, USDT]); // 6 -> 6
        pairs.push([WETH, USDC]); // WETH is token1 here, so `mid` divides when selling it
        pairs.push([GUSD, USDC]); // 2 -> 6
        pairs.push([NEAR, WETH]); // 24 -> 18

        PropAMM.PairConfig[] memory configs = new PropAMM.PairConfig[](pairs.length);
        for (uint256 i = 0; i < pairs.length; i++) {
            configs[i] = PropAMM.PairConfig({token0: pairs[i][0], token1: pairs[i][1], vault: vault});
        }
        propAmm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()),
                    abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, configs))
                )
            )
        );
    }

    //------------------------------
    // Discovery
    //------------------------------

    /// The router only takes the one-call path for a venue `ERC165Checker` says supports it, and
    /// `ERC165Checker` also insists on a correct "no" for 0xffffffff before believing any "yes".
    function test_supportsInterface_advertisesTheFillableExtension() public view {
        assertTrue(ERC165Checker.supportsInterface(address(propAmm), type(IPropAMMFillable).interfaceId));
        assertTrue(ERC165Checker.supportsInterface(address(propAmm), type(IPropAMM).interfaceId));
        assertTrue(propAmm.supportsInterface(type(IERC165).interfaceId));
        assertFalse(propAmm.supportsInterface(0xffffffff));
        assertFalse(propAmm.supportsInterface(0xdeadbeef));
    }

    /// Advertising is static: a pause shows up as `quoteFillable` reverting, which the router
    /// reads as no candidate, not as the instance dropping off the one-call path.
    function test_supportsInterface_survivesAPause() public {
        vm.prank(owner);
        propAmm.pause();

        assertTrue(ERC165Checker.supportsInterface(address(propAmm), type(IPropAMMFillable).interfaceId));
    }

    //------------------------------
    // Sizing
    //------------------------------

    function test_quoteFillable_takesAnOrderTheVaultCoversWhole() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e18);

        assertEq(fill, 1e18);
        assertEq(out, propAmm.quote(WETH, USDT, 1e18));
    }

    function test_quoteFillable_offersNothingForNothing() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 0);

        assertEq(fill, 0);
        assertEq(out, 0);
    }

    /// The case the extension exists for. The vault holds 1000 WETH worth of USDT and the order is
    /// ten times that, so both points of the router's blind probe (the order and half of it)
    /// revert and the router would see no venue at all. Through the extension it still gets the
    /// whole vault, short only of the rounding `quoteFillable` gives up to stay safe.
    function test_quoteFillable_capsAnOrderLargerThanTheVault() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        vm.expectPartialRevert(InsufficientVaultBalance.selector);
        propAmm.quote(WETH, USDT, 10_000e18);
        vm.expectPartialRevert(InsufficientVaultBalance.selector);
        propAmm.quote(WETH, USDT, 5_000e18);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 10_000e18);

        assertLt(fill, 10_000e18);
        assertEq(out, propAmm.quote(WETH, USDT, fill), "out is not the quote for exactly the fill");
        assertLe(out, 1_600_000e6, "reported more than the vault holds");
        assertApproxEqRel(out, 1_600_000e6, 1e9, "left more of the vault unsold than rounding explains");
    }

    /// Same in the other direction, where `mid` divides instead of multiplying and a wei of
    /// tokenIn is worth far more than a wei of tokenOut.
    function test_quoteFillable_capsTheOtherDirectionToo() public {
        _setPrice(1600e18, 5e14);
        _fundVault(WETH, 1000e18, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(USDT, WETH, 16_000_000e6);

        assertLt(fill, 16_000_000e6);
        assertEq(out, propAmm.quote(USDT, WETH, fill), "out is not the quote for exactly the fill");
        assertLe(out, 1000e18, "reported more than the vault holds");
        assertApproxEqRel(out, 1000e18, 1e9, "left more of the vault unsold than rounding explains");
    }

    /// Once the vault binds, how far past it the order goes changes nothing: the router asks with
    /// its whole order, which can be any size.
    function test_quoteFillable_answersTheSameHoweverFarTheOrderOvershoots() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fillA, uint256 outA) = propAmm.quoteFillable(WETH, USDT, 2_000e18);
        (uint256 fillB, uint256 outB) = propAmm.quoteFillable(WETH, USDT, type(uint128).max);

        assertEq(fillA, fillB);
        assertEq(outA, outB);
    }

    /// `swap` pulls tokenOut with `transferFrom`, so the vault's allowance caps a fill exactly as
    /// its balance does. Reporting past it would hand the router a leg that reverts.
    function test_quoteFillable_capsAtTheVaultsAllowance() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, 800_000e6);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1000e18);

        assertLt(fill, 1000e18);
        assertEq(out, propAmm.quote(WETH, USDT, fill));
        assertLe(out, 800_000e6, "reported more than the vault allows");
        assertApproxEqRel(out, 800_000e6, 1e9);
    }

    /// An allowance above the balance is no capacity: the balance still binds.
    function test_quoteFillable_capsAtTheBalanceWhenTheAllowanceIsLarger() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 800_000e6, 1_600_000e6);

        (, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1000e18);

        assertLe(out, 800_000e6, "reported more than the vault holds");
        assertApproxEqRel(out, 800_000e6, 1e9);
    }

    function test_quoteFillable_offersNothingWithoutAnAllowance() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, 0);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e18);

        assertEq(fill, 0);
        assertEq(out, 0);
    }

    //------------------------------
    // What the router does with it
    //------------------------------

    /// A leg the size of the fill is floored at exactly the reported output, and pays it.
    function test_quoteFillable_aLegOfTheWholeFillPaysExactlyTheReportedOutput() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 10_000e18);
        uint256 delivered = _pushAndSwap(WETH, USDT, fill, out);

        assertEq(delivered, out);
        assertEq(MockToken(USDT).balanceOf(vault), 1_600_000e6 - out);
        assertEq(MockToken(WETH).balanceOf(vault), fill);
    }

    /// A partial leg is floored at its pro-rata share of the reported output, so the quote's own
    /// rounding loss must not exceed that share's. Here a better-ranked venue took 0.000000699
    /// WETH, leaving a leg just under the 1 WETH fill, on a vault deep enough that impact gives
    /// no slack: rounding mid and spread off separately delivers 1 wei under the floor.
    function test_quoteFillable_aPartialLegClearsItsProRataFloor() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 100_000_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e18);
        assertEq(fill, 1e18);

        uint256 leg = 999_999_301e9;
        uint256 minOut = out * leg / fill; // SplitPlanner.proRataMin
        uint256 delivered = _pushAndSwap(WETH, USDT, leg, minOut);

        assertGe(delivered, minOut);
    }

    /// The router places `leg = min(fill, remaining)` with a floor of `out * leg / fill`, where
    /// `remaining` is whatever better-ranked venues left over, so any leg up to the fill can come
    /// back. Each of them has to fit the vault's balance and allowance and clear that floor:
    /// a leg that reverts is not lost, but its input goes to Uniswap with no floor of its own.
    function testFuzz_quoteFillable_everyLegUpToTheFillSwaps(
        uint256 pairSeed,
        bool flip,
        uint256 amountIn,
        uint256 leg,
        uint256 mid,
        uint256 delta,
        uint256 balance,
        uint256 allowance
    ) public {
        (address tokenIn, address tokenOut, uint256 unitIn, uint256 unitOut) = _pickPair(pairSeed, flip);
        mid = bound(mid, 1e12, 1e24); // a whole token0 at 1e-6 to 1e6 whole token1
        delta = bound(delta, 0, 1e17); // up to a 10% half-spread
        _setPrice(mid, delta);

        balance = bound(balance, 1, 1e12 * unitOut);
        allowance = bound(allowance, 0, 2 * balance);
        amountIn = bound(amountIn, 1, 1e12 * unitIn);
        _fundVault(tokenOut, balance, allowance);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(tokenIn, tokenOut, amountIn);
        assertLe(fill, amountIn, "the router discards a venue that fills more than it was offered");
        // The router drops a candidate with nothing on either side and never places a leg on it.
        if (fill == 0 || out == 0) return;
        assertEq(out, propAmm.quote(tokenIn, tokenOut, fill), "out is not the quote for exactly the fill");

        leg = bound(leg, 1, fill);
        uint256 minOut = leg == fill ? out : out * leg / fill; // SplitPlanner.proRataMin
        uint256 delivered = _pushAndSwap(tokenIn, tokenOut, leg, minOut);

        assertGe(delivered, minOut);
        assertEq(MockToken(tokenOut).balanceOf(trader), delivered);
    }

    /// The other half of the contract with the router: safety alone would pass for a venue that
    /// always answers (0, 0). When the vault binds, a fill larger by one part in 1e8 (and two wei,
    /// for tokens whose wei is coarse) has to overdraw it, so the reported fill is that close to
    /// the most the vault can cover. Capacity starts at 1e10 wei, below which a wei of rounding
    /// is more than one part in 1e8 of it, and a wei of tokenIn must be worth no more than the
    /// whole capacity: past that, even one wei overdraws the vault, `(0, 0)` is the answer, and
    /// the next whole wei can land beyond the output curve's peak, where it pays almost nothing
    /// and "fits" only because a smaller leg would not.
    function testFuzz_quoteFillable_leavesNoRoomForALargerFill(
        uint256 pairSeed,
        bool flip,
        uint256 mid,
        uint256 delta,
        uint256 balance,
        uint256 allowance
    ) public {
        (address tokenIn, address tokenOut, uint256 unitIn, uint256 unitOut) = _pickPair(pairSeed, flip);
        mid = bound(mid, 1e12, 1e24);
        delta = bound(delta, 0, 1e17);
        _setPrice(mid, delta);

        balance = bound(balance, 1e10, 1e12 * unitOut + 1e10);
        allowance = bound(allowance, 1e10, 2 * balance);
        _fundVault(tokenOut, balance, allowance);
        uint256 capacity = balance < allowance ? balance : allowance;
        uint256 weiWorth = tokenIn < tokenOut ? mid * unitOut / (1e18 * unitIn) : 1e18 * unitOut / (mid * unitIn);
        vm.assume(weiWorth <= capacity);

        // An order no vault in range can fill, so the cap always binds.
        uint256 amountIn = 1e30 * unitIn;
        (uint256 fill, uint256 out) = propAmm.quoteFillable(tokenIn, tokenOut, amountIn);
        assertLt(fill, amountIn);
        assertLe(out, capacity);

        uint256 larger = fill + fill / 1e8 + 2;
        try propAmm.quote(tokenIn, tokenOut, larger) returns (uint256 largerOut) {
            assertGt(largerOut, capacity, "a fill one part in 1e8 larger still fits");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), InsufficientVaultBalance.selector, "a larger fill failed for another reason");
        }
    }

    //------------------------------
    // Edges of the price and spread domain
    //------------------------------

    /// At the top of the price domain a fill sized against the vault must still leave every
    /// smaller leg priceable. The pricing's intermediate products are largest for the smallest
    /// spread, so a smaller leg (less impact) is the one that would overflow first.
    function test_quoteFillable_everyLegSwapsAtTheTopOfThePriceDomain() public {
        _setPrice(1e60, 0); // a whole WETH at 1e42 USDT
        _fundVault(USDT, 1e50, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e21);
        assertLt(fill, 1e21, "the vault should bind");
        assertApproxEqRel(out, 1e50, 1e9);

        uint256 leg = fill * 2 / 5;
        uint256 minOut = out * leg / fill;
        assertGe(_pushAndSwap(WETH, USDT, leg, minOut), minOut);
    }

    /// With delta within a couple of percent of one, impact makes the output curve peak below
    /// the vault: no fill can overdraw it, and past the peak a larger fill pays less. The answer
    /// is the peak, the most this pair can pay. Here (98.6%) a fill sized past the peak would
    /// take the spread over one, and the router would drop a venue that can fill.
    function test_quoteFillable_sizesAtThePeakWhenTheSpreadIsExtreme() public {
        _setPrice(1600e18, SPREAD_SCALE - 1.4e16);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e30);

        assertLt(fill, 1e30);
        assertEq(out, propAmm.quote(WETH, USDT, fill));
        assertLe(out, 1_600_000e6);
        assertGe(out, propAmm.quote(WETH, USDT, fill / 2), "a smaller fill pays more");
        assertGe(out, propAmm.quote(WETH, USDT, fill + fill / 10), "a larger fill pays more");
    }

    /// At 98.5% a fill past the peak still prices, so nothing reverts, but it pays less than half
    /// of itself would: the router would rank the venue on a worse rate than it offers.
    function test_quoteFillable_neverSizesPastThePeak() public {
        _setPrice(1600e18, SPREAD_SCALE - 1.5e16);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 1e30);

        assertGe(out, propAmm.quote(WETH, USDT, fill / 2), "a smaller fill pays more");
    }

    /// Spreads from 90% to as close to one as the vault's impact rounding allows. Same contract
    /// with the router as everywhere else, and the fill is never on the falling side of the curve.
    function testFuzz_quoteFillable_extremeSpreadsStillSizeSafely(
        uint256 pairSeed,
        bool flip,
        uint256 amountIn,
        uint256 leg,
        uint256 mid,
        uint256 delta,
        uint256 balance,
        uint256 allowance
    ) public {
        (address tokenIn, address tokenOut, uint256 unitIn, uint256 unitOut) = _pickPair(pairSeed, flip);
        mid = bound(mid, 1e12, 1e24);
        // Up to 1 - 2*IMPACT_FACTOR: closer than that, a vault of a few wei leaves no fill whose
        // impact rounding keeps the spread under one.
        delta = bound(delta, 9e17, SPREAD_SCALE - 2e14);
        _setPrice(mid, delta);

        balance = bound(balance, 1, 1e12 * unitOut);
        allowance = bound(allowance, 0, 2 * balance);
        amountIn = bound(amountIn, 1, 1e12 * unitIn);
        _fundVault(tokenOut, balance, allowance);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(tokenIn, tokenOut, amountIn);
        assertLe(fill, amountIn);
        if (fill == 0 || out == 0) return;
        assertEq(out, propAmm.quote(tokenIn, tokenOut, fill));
        if (fill < amountIn) assertGe(out, propAmm.quote(tokenIn, tokenOut, fill / 2), "sized past the peak");

        leg = bound(leg, 1, fill);
        uint256 minOut = leg == fill ? out : out * leg / fill;
        assertGe(_pushAndSwap(tokenIn, tokenOut, leg, minOut), minOut);
    }

    /// Converting the cap back to tokenIn can overflow when the whole vault is worth more than
    /// 2^256 wei of tokenIn, but an order that fits inside the cap never needs that conversion.
    /// A whole GUSD at 1e44 USDC is absurd on purpose.
    function test_quoteFillable_anOrderInsideAHugeCapNeverConvertsIt() public {
        _setPrice(1e62, 0);
        _fundVault(GUSD, 1e30, type(uint256).max);

        (uint256 fill, uint256 out) = propAmm.quoteFillable(USDC, GUSD, 1e50);

        assertEq(fill, 1e50);
        assertEq(out, 100);
    }

    //------------------------------
    // Guards: the router reads a revert as "no candidate"
    //------------------------------

    function test_quoteFillable_revertsWhilePaused() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        vm.prank(owner);
        propAmm.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    function test_quoteFillable_revertsForUnregisteredPair() public {
        _setPrice(1600e18, 5e14);

        vm.expectRevert(abi.encodeWithSelector(UnsupportedPair.selector, WBTC, USDT));
        propAmm.quoteFillable(WBTC, USDT, 1e8);
    }

    /// Outside the block its price was stamped for, the registry reverts and so does the quote.
    function test_quoteFillable_revertsWithoutAFreshPrice() public {
        _fundVault(USDT, 1_600_000e6, type(uint256).max);
        vm.mockCallRevert(
            ORACLE,
            abi.encodeWithSelector(IPrioUpdateRegistry.getState.selector),
            abi.encodeWithSelector(StaleUpdate.selector)
        );

        vm.expectRevert(StaleUpdate.selector);
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    function test_quoteFillable_revertsWhenTheOracleIsShortOfSlots() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);
        MockPUR(ORACLE).setSlotCount(1);

        vm.expectRevert(
            abi.encodeWithSelector(
                InsufficientOracleData.selector, uint256(keccak256(abi.encodePacked(WETH, USDT))), uint256(1)
            )
        );
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    function test_quoteFillable_revertsOnZeroMid() public {
        _setPrice(0, 5e14);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        vm.expectRevert(abi.encodeWithSelector(InvalidMid.selector, uint256(keccak256(abi.encodePacked(WETH, USDT)))));
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    function test_quoteFillable_revertsWhenTheVaultIsEmpty() public {
        _setPrice(1600e18, 5e14);

        vm.expectRevert(abi.encodeWithSelector(EmptyVault.selector, USDT));
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    /// A delta of one would take the whole fill as spread; there is no price to size a fill at.
    function test_quoteFillable_revertsWhenDeltaReachesOne() public {
        _setPrice(1600e18, SPREAD_SCALE);
        _fundVault(USDT, 1_600_000e6, type(uint256).max);

        vm.expectRevert(abi.encodeWithSelector(SpreadTooWide.selector, SPREAD_SCALE));
        propAmm.quoteFillable(WETH, USDT, 1e18);
    }

    //------------------------------
    // Helpers
    //------------------------------

    function _deployToken(address where, uint8 decimals) internal {
        vm.etch(where, address(new MockToken()).code);
        MockToken(where).setDecimals(decimals);
    }

    function _setPrice(uint256 mid, uint256 delta) internal {
        MockPUR(ORACLE).setState(delta, mid);
    }

    function _fundVault(address token, uint256 balance, uint256 allowance) internal {
        MockToken(token).mint(vault, balance);
        vm.prank(vault);
        MockToken(token).approve(address(propAmm), allowance);
    }

    /// One listed pair, in either direction, and one whole unit of each side in wei.
    function _pickPair(uint256 seed, bool flip)
        internal
        view
        returns (address tokenIn, address tokenOut, uint256 unitIn, uint256 unitOut)
    {
        address[2] memory pair = pairs[seed % pairs.length];
        (tokenIn, tokenOut) = flip ? (pair[1], pair[0]) : (pair[0], pair[1]);
        unitIn = 10 ** MockToken(tokenIn).decimals();
        unitOut = 10 ** MockToken(tokenOut).decimals();
    }

    /// Pays `amountIn` in the way the router does (push, then `swap`), to `trader`.
    function _pushAndSwap(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut)
        internal
        returns (uint256)
    {
        MockToken(tokenIn).mint(address(propAmm), amountIn);
        return propAmm.swap(tokenIn, tokenOut, amountIn, minOut, trader, block.timestamp);
    }
}

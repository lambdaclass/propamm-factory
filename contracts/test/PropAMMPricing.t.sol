// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import "forge-std/console.sol";
import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
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
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";

/// Exercises `quote`/`swap` across pairs that differ in decimals, price and which token sorts
/// first. Tokens sit at their mainnet addresses so the token0/token1 ordering the lane key and
/// the quote direction depend on is the real one:
///     WBTC (0x22) < USDC (0xA0) < WETH (0xC0) < USDT (0xdA)
contract PropAMMPricingTest is Test {
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;

    /// Mirrors the contract's own constants, so a change to either shows up as a failure here.
    uint256 constant PRICE_SCALE = 1e18;
    uint256 constant SPREAD_SCALE = 1e18;
    uint256 constant IMPACT_FACTOR = 1e14;

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address trader = makeAddr("trader");

    PropAMM propAmm;

    function setUp() public {
        vm.etch(ORACLE, address(new MockPUR()).code);

        _deployToken(WBTC, 8);
        _deployToken(USDC, 6);
        _deployToken(WETH, 18);
        _deployToken(USDT, 6);

        propAmm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()),
                    abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, new PropAMM.PairConfig[](0)))
                )
            )
        );

        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);
        propAmm.addPair(WETH, USDT, vault);
        propAmm.addPair(WETH, USDC, vault);
        propAmm.addPair(WBTC, USDC, vault);
        vm.stopPrank();
    }

    //------------------------------
    // Prices, across pairs
    //------------------------------

    /// `mid` prices one whole token0 in whole token1 at PRICE_SCALE, whatever decimals the two
    /// tokens use. Quotes are checked against the human price to a tolerance, because the impact
    /// term is deliberately non-zero even on a deep vault; `test_quote_impact*` pins it exactly.
    function test_quote_pricesEveryPairInBothDirections() public {
        // USDC/USDT at parity: token0 = USDC, both 6 decimals.
        // Deep vaults throughout, so the impact term stays well inside the tolerance below.
        _setPrice(1e18, 0);
        _fundVault(USDT, 100_000_000e6);
        _fundVault(USDC, 10_000_000_000e6);
        assertApproxEqRel(propAmm.quote(USDC, USDT, 100e6), 100e6, 1e12);
        assertApproxEqRel(propAmm.quote(USDT, USDC, 100e6), 100e6, 1e12);

        // WETH/USDT at 1600: token0 = WETH, 18 decimals in, 6 out.
        _setPrice(1600e18, 0);
        _fundVault(WETH, 1_000_000e18);
        assertApproxEqRel(propAmm.quote(WETH, USDT, 1e18), 1600e6, 1e12);
        assertApproxEqRel(propAmm.quote(USDT, WETH, 1600e6), 1e18, 1e12);

        // WETH/USDC at the same 1600, but now WETH is token1, so mid is its inverse.
        _setPrice(625e12, 0);
        assertApproxEqRel(propAmm.quote(USDC, WETH, 1600e6), 1e18, 1e12);
        assertApproxEqRel(propAmm.quote(WETH, USDC, 1e18), 1600e6, 1e12);

        // WBTC/USDC at 60,000: token0 = WBTC, 8 decimals in, 6 out.
        _setPrice(60_000e18, 0);
        _fundVault(WBTC, 100_000e8);
        assertApproxEqRel(propAmm.quote(WBTC, USDC, 1e8), 60_000e6, 1e12);
        assertApproxEqRel(propAmm.quote(USDC, WBTC, 60_000e6), 1e8, 1e12);
    }

    /// The point of a fractional delta: one number is the same spread on every pair, whatever
    /// the pair's price or decimals.
    function test_quote_oneDeltaIsTheSameSpreadOnEveryPair() public {
        uint256 fiveBps = 5e14;

        _setPrice(1e18, fiveBps);
        _fundVault(USDT, 100_000_000e6);
        _assertRelativeSpread(propAmm.quote(USDC, USDT, 100e6), 100e6, fiveBps);
        console.log("USDC/USDT", propAmm.quote(USDC, USDT, 99_000_000e6));

        _setPrice(1600e18, fiveBps);
        _assertRelativeSpread(propAmm.quote(WETH, USDT, 1e18), 1600e6, fiveBps);

        _setPrice(60_000e18, fiveBps);
        _fundVault(USDC, 100_000_000e6);
        _assertRelativeSpread(propAmm.quote(WBTC, USDC, 1e8), 60_000e6, fiveBps);
    }

    //------------------------------
    // Impact
    //------------------------------

    /// Impact is IMPACT_FACTOR scaled by the share of the vault's tokenOut balance the fill
    /// takes, so these come out exact: the vault holds 1000 WETH worth of USDT.
    function test_quote_impactIsLinearInTheVaultShare() public {
        _setPrice(1600e18, 0);
        _fundVault(USDT, 1_600_000e6);

        // 1/1000 of the vault -> 1/1000 of IMPACT_FACTOR -> 0.001bp off 1600 USDT.
        assertEq(propAmm.quote(WETH, USDT, 1e18), 1_599_999_840);
        // half the vault -> half of IMPACT_FACTOR -> 0.5bp off.
        assertEq(propAmm.quote(WETH, USDT, 500e18) / 500, 1_599_920_000);
        // the whole vault -> the full 1bp.
        assertEq(propAmm.quote(WETH, USDT, 1000e18) / 1000, 1_599_840_000);
    }

    function test_quote_impactAddsToTheOracleSpread() public {
        _setPrice(1600e18, 5e14); // 5bps, and the fill below takes 1/1000 of the vault
        _fundVault(USDT, 1_600_000e6);

        // 1600 USDT less 5bps less 0.001bp impact.
        assertEq(propAmm.quote(WETH, USDT, 1e18), 1_599_199_840);
    }

    /// The output is rounded once, from amountIn, not once for the mid value and again for the
    /// spread. A wei of WETH under 1 WETH is worth a fraction of a USDT wei, so it pays what 1 WETH
    /// pays; rounding twice paid a wei less (1_599_199_839). That second loss did not shrink with
    /// the fill, which left `PropAMMRouter`'s partial legs a wei under their pro-rata floor.
    function test_quote_roundsTheOutputOnce() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);

        assertEq(propAmm.quote(WETH, USDT, 1e18), 1_599_199_840);
        assertEq(propAmm.quote(WETH, USDT, 1e18 - 1), 1_599_199_840);
    }

    /// The rounding's boundary case: an output that is exactly whole, reached through a remainder.
    /// A wei of USDT at 3 USDT per WETH is worth 1e12/3 WETH wei at mid, and a 25% spread leaves
    /// exactly 2.5e11 of it. Taking the floor in two steps has to carry the remainder's share into
    /// the result even when it lands exactly on a whole wei; floored without it, this is 1 short.
    function test_quote_isExactWhenTheOutputIsWhole() public {
        _setPrice(3e18, 2.5e17);
        _fundVault(WETH, 1e26); // deep enough that impact rounds to zero

        assertEq(propAmm.quote(USDT, WETH, 1), 250_000_000_000);
    }

    /// Rounding once must not cost range: any price whose mid and decimals fit a word still
    /// quotes. A whole WETH at 1e42 USDT is absurd on purpose; multiplying the conversion by the
    /// spread's scale before dividing would overflow here (and for prices 1e18 times smaller).
    function test_quote_pricesAtTheTopOfThePriceDomain() public {
        _setPrice(1e60, 0);
        _fundVault(USDT, 1e50);

        // 1e48 USDT wei at mid, less an impact of 1e48/1e50 of IMPACT_FACTOR.
        assertEq(propAmm.quote(WETH, USDT, 1e18), 999_999e42);
    }

    //------------------------------
    // Symmetry
    //------------------------------

    /// Both directions take the same fractional haircut, so a round trip costs (1 - spread)^2 and
    /// never more. Checked on a deep vault so impact stays negligible against the 5bps delta.
    function test_quote_roundTripCostsTheSpreadTwice() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 100_000_000e6);
        _fundVault(WETH, 1_000_000e18);

        uint256 usdt = propAmm.quote(WETH, USDT, 1e18);
        uint256 back = propAmm.quote(USDT, WETH, usdt);

        assertLt(back, 1e18);
        assertApproxEqRel(back, 1e18 - 2 * 5e14, 1e13); // ~10bps round trip
    }

    function testFuzz_quote_roundTripNeverProfits(uint256 amountIn) public {
        amountIn = bound(amountIn, 1e12, 100e18);
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 100_000_000e6);
        _fundVault(WETH, 1_000_000e18);

        uint256 out = propAmm.quote(WETH, USDT, amountIn);
        assertLe(propAmm.quote(USDT, WETH, out), amountIn);
    }

    function testFuzz_quote_growsWithAmountInAndFitsTheVault(uint256 amountIn) public {
        amountIn = bound(amountIn, 1e12, 500e18);
        _setPrice(1600e18, 0);
        _fundVault(USDT, 1_600_000e6);

        uint256 out = propAmm.quote(WETH, USDT, amountIn);
        assertLe(out, 1_600_000e6, "quoted more than the vault holds");
        assertGe(propAmm.quote(WETH, USDT, amountIn + 1e12), out, "not monotonic in amountIn");
    }

    //------------------------------
    // Guards
    //------------------------------

    function test_quote_revertsForUnregisteredPair() public {
        _setPrice(1600e18, 0);
        _fundVault(USDC, 1_000e6);

        vm.prank(owner);
        propAmm.removePair(WETH, USDC);

        vm.expectRevert(abi.encodeWithSelector(UnsupportedPair.selector, WETH, USDC));
        propAmm.quote(WETH, USDC, 1e18);
    }

    function test_quote_revertsWhenTheOracleIsShortOfSlots() public {
        _setPrice(1600e18, 0);
        _fundVault(USDT, 1_000_000e6);
        MockPUR(ORACLE).setSlotCount(1);

        vm.expectRevert(
            abi.encodeWithSelector(
                InsufficientOracleData.selector, uint256(keccak256(abi.encodePacked(WETH, USDT))), uint256(1)
            )
        );
        propAmm.quote(WETH, USDT, 1e18);
    }

    function test_quote_revertsOnZeroMid() public {
        _setPrice(0, 0);
        _fundVault(USDT, 1_000_000e6);

        vm.expectRevert(abi.encodeWithSelector(InvalidMid.selector, uint256(keccak256(abi.encodePacked(WETH, USDT)))));
        propAmm.quote(WETH, USDT, 1e18);
    }

    function test_quote_revertsWhenTheVaultIsEmpty() public {
        _setPrice(1600e18, 0);

        vm.expectRevert(abi.encodeWithSelector(EmptyVault.selector, USDT));
        propAmm.quote(WETH, USDT, 1e18);
    }

    /// A fill above the vault at mid can still fit once impact is charged, so this has to be
    /// large enough that the haircut cannot bring it back under.
    function test_quote_revertsWhenTheFillExceedsTheVault() public {
        _setPrice(1600e18, 0);
        _fundVault(USDT, 1_600_000e6);

        vm.expectRevert(
            abi.encodeWithSelector(InsufficientVaultBalance.selector, USDT, uint256(3_199_360e6), uint256(1_600_000e6))
        );
        propAmm.quote(WETH, USDT, 2000e18);
    }

    function test_quote_revertsWhenTheSpreadWouldReachOne() public {
        _setPrice(1600e18, SPREAD_SCALE - IMPACT_FACTOR); // delta plus a full-vault impact hits 1
        _fundVault(USDT, 1_600_000e6);

        vm.expectRevert(abi.encodeWithSelector(SpreadTooWide.selector, SPREAD_SCALE));
        propAmm.quote(WETH, USDT, 1000e18);
    }

    //------------------------------
    // swap
    //------------------------------

    function test_swap_deliversTheQuotedAmount() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        MockToken(WETH).mint(trader, 1e18);

        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);

        uint256 expected = propAmm.quote(WETH, USDT, 1e18);

        vm.startPrank(trader);
        MockToken(WETH).transfer(address(propAmm), 1e18); // push-payment, as IPropAMM specifies
        vm.expectEmit(true, true, true, true);
        emit IPropAMM.Swapped(trader, WETH, USDT, 1e18, expected, trader);
        uint256 amountOut = propAmm.swap(WETH, USDT, 1e18, expected, trader, block.timestamp);
        vm.stopPrank();

        assertEq(amountOut, expected);
        assertEq(MockToken(USDT).balanceOf(trader), expected);
        assertEq(MockToken(WETH).balanceOf(vault), 1e18);
        assertEq(MockToken(WETH).balanceOf(address(propAmm)), 0);
    }

    function test_swap_pricesTheOtherDirectionToo() public {
        _setPrice(1600e18, 5e14);
        _fundVault(WETH, 1_000_000e18); // deep, so the 5bps delta dominates the impact term
        MockToken(USDT).mint(trader, 1600e6);

        vm.prank(vault);
        MockToken(WETH).approve(address(propAmm), type(uint256).max);

        uint256 expected = propAmm.quote(USDT, WETH, 1600e6);

        vm.startPrank(trader);
        MockToken(USDT).transfer(address(propAmm), 1600e6);
        uint256 amountOut = propAmm.swap(USDT, WETH, 1600e6, expected, trader, block.timestamp);
        vm.stopPrank();

        assertEq(amountOut, expected);
        assertApproxEqRel(amountOut, 1e18 - 5e14, 1e13); // ~1 WETH less the 5bps spread
        assertEq(MockToken(WETH).balanceOf(trader), expected);
    }

    /// Two pairs, two vaults: a swap on one moves both of its legs through that pair's vault and
    /// leaves the other account's balances exactly where they were.
    function test_swap_eachPairFillsFromItsOwnVault() public {
        address otherVault = makeAddr("other-vault");
        vm.prank(owner);
        propAmm.setPairVault(WETH, USDT, otherVault); // USDC/USDT stays on `vault`

        _setPrice(1600e18, 0);
        MockToken(USDT).mint(otherVault, 1_600_000e6);
        _fundVault(USDT, 1_600_000e6);
        vm.prank(otherVault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);
        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);

        MockToken(WETH).mint(trader, 1e18);
        uint256 expected = propAmm.quote(WETH, USDT, 1e18);
        vm.startPrank(trader);
        MockToken(WETH).transfer(address(propAmm), 1e18);
        uint256 amountOut = propAmm.swap(WETH, USDT, 1e18, expected, trader, block.timestamp);
        vm.stopPrank();

        assertEq(amountOut, expected);
        assertEq(MockToken(USDT).balanceOf(trader), expected);
        // Both legs went through otherVault.
        assertEq(MockToken(WETH).balanceOf(otherVault), 1e18);
        assertEq(MockToken(USDT).balanceOf(otherVault), 1_600_000e6 - expected);
        // `vault` is untouched on both tokens.
        assertEq(MockToken(WETH).balanceOf(vault), 0);
        assertEq(MockToken(USDT).balanceOf(vault), 1_600_000e6);
    }

    /// Impact is measured against the pair's own vault, not any other account holding the same
    /// token: the deep `vault` here would make the impact negligible, and it does not count.
    function test_quote_impactUsesThePairsOwnVault() public {
        address otherVault = makeAddr("other-vault");
        vm.prank(owner);
        propAmm.setPairVault(WETH, USDT, otherVault);

        _setPrice(1600e18, 0);
        MockToken(USDT).mint(otherVault, 1_600_000e6);
        _fundVault(USDT, 100 * 1_600_000e6);

        // Same figures as test_quote_impactIsLinearInTheVaultShare: the whole of otherVault's
        // balance is the full 1bp.
        assertEq(propAmm.quote(WETH, USDT, 1000e18) / 1000, 1_599_840_000);
    }

    //------------------------------
    // Oracle
    //------------------------------

    /// The registry is per-instance state, not a constant, so `setOracle` moves the whole price
    /// feed: same pair, same vault, priced by a different registry from that call on.
    function test_setOracle_repointsWhereQuotesRead() public {
        _setPrice(1600e18, 0);
        _fundVault(USDT, 100_000_000e6);
        assertApproxEqRel(propAmm.quote(WETH, USDT, 1e18), 1600e6, 1e12);

        // A second registry carrying its own price, so the switch is observable in the quote.
        address otherOracle = address(0xE2);
        vm.etch(otherOracle, address(new MockPUR()).code);
        MockPUR(otherOracle).setState(0, 3200e18);

        vm.prank(owner);
        propAmm.setOracle(otherOracle);

        assertEq(address(propAmm.oracle()), otherOracle);
        assertApproxEqRel(propAmm.quote(WETH, USDT, 1e18), 3200e6, 1e12);
    }

    //------------------------------
    // Pause
    //------------------------------

    /// The owner's kill switch on the taker-facing path: while it is on, quotes revert instead
    /// of pricing, and the same quote comes back unchanged once it is off.
    function test_pause_stopsQuotesUntilUnpaused() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        uint256 quoted = propAmm.quote(WETH, USDT, 1e18);

        vm.prank(owner);
        propAmm.pause();
        assertTrue(propAmm.paused());

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        propAmm.quote(WETH, USDT, 1e18);

        vm.prank(owner);
        propAmm.unpause();
        assertFalse(propAmm.paused());
        assertEq(propAmm.quote(WETH, USDT, 1e18), quoted);
    }

    /// Swaps are gated separately from quotes, so a pause has to stop them on their own. The
    /// push-payment happens before the call, so the check also has to leave the taker's tokens
    /// where they are rather than half-filling: nothing reaches the vault or the recipient.
    function test_pause_stopsSwapsUntilUnpaused() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        MockToken(WETH).mint(trader, 1e18);

        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);

        uint256 expected = propAmm.quote(WETH, USDT, 1e18);

        vm.prank(owner);
        propAmm.pause();

        vm.startPrank(trader);
        MockToken(WETH).transfer(address(propAmm), 1e18); // push-payment, as IPropAMM specifies
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        propAmm.swap(WETH, USDT, 1e18, expected, trader, block.timestamp);
        vm.stopPrank();

        assertEq(MockToken(USDT).balanceOf(trader), 0, "recipient was paid while paused");
        assertEq(MockToken(WETH).balanceOf(vault), 0, "vault took the input while paused");
        assertEq(MockToken(WETH).balanceOf(address(propAmm)), 1e18, "the push did not survive");

        // Unpausing settles the swap the taker already funded, at the price quoted before.
        vm.prank(owner);
        propAmm.unpause();

        vm.prank(trader);
        uint256 amountOut = propAmm.swap(WETH, USDT, 1e18, expected, trader, block.timestamp);

        assertEq(amountOut, expected);
        assertEq(MockToken(USDT).balanceOf(trader), expected);
        assertEq(MockToken(WETH).balanceOf(vault), 1e18);
    }

    /// The router probes `isActive` to skip propAMMs before paying for a quote, so a pause has
    /// to surface there as `false`. Reverting instead would take the router's probe down with it.
    function test_pause_isActiveTurnsFalseWithoutReverting() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        assertTrue(propAmm.isActive(WETH, USDT));

        vm.prank(owner);
        propAmm.pause();
        assertFalse(propAmm.isActive(WETH, USDT));

        vm.prank(owner);
        propAmm.unpause();
        assertTrue(propAmm.isActive(WETH, USDT));
    }

    function test_pause_onlyOwnerCanFlipIt() public {
        vm.prank(trader);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, trader));
        propAmm.pause();
        assertFalse(propAmm.paused());

        vm.prank(owner);
        propAmm.pause();

        vm.prank(trader);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, trader));
        propAmm.unpause();
        assertTrue(propAmm.paused(), "a non-owner lifted the pause");
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

    function _fundVault(address token, uint256 amount) internal {
        MockToken(token).mint(vault, amount);
    }

    /// Asserts `amountOut` is `midAmountOut` less `delta`, allowing for the impact term on top.
    function _assertRelativeSpread(uint256 amountOut, uint256 midAmountOut, uint256 delta) internal pure {
        uint256 atDelta = midAmountOut - (midAmountOut * delta / SPREAD_SCALE);
        assertLe(amountOut, atDelta, "taker got more than mid less delta");
        assertApproxEqRel(amountOut, atDelta, 1e13, "spread is not delta on this pair");
    }
}

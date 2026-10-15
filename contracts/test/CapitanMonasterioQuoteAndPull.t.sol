// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PropAMM, InsufficientOutput, EmptyVault} from "../src/PropAMM.sol";
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockPUR} from "./mocks/MockPUR.sol";

/// @title Capitán Monasterio — a malicious maker modeled on ElZorro's real architecture, not a
/// third-party venue
/// @notice POL/Lambda security test of the router's anti-spoofing surface
/// (internal_outputs/POL/Aligned/elzorro-unlocks/seguridad/). Supersedes the earlier
/// Kipseli-based attempt in propamm-router-contracts/test/SpoofRegistryQuoteAndPullFork.t.sol,
/// which required reverse-engineering an undocumented third-party proxy chain and got the
/// registry address wrong. This file uses ElZorro's own contract (`PropAMM.sol`, the one the
/// factory deploys) and its own oracle wiring, confirmed line-for-line from
/// `PropAMM.sol`/`PropAMMFactory.sol`/`PropAMM.t.sol` in this repo. Fully local: no RPC, no
/// mainnet fork, same `vm.etch` trick the repo's own tests use for the oracle
/// (`0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81`).
///
/// CORRECTION vs the router-level "Spoofer A" model (propamm-router-contracts/test/
/// SpoofQuoteMismatch.t.sol): that model assumed a venue's `quote()` and `swap()` could return
/// independently different amounts. They cannot, here: `swap()` (PropAMM.sol:168) calls `_quote`
/// AGAIN at execution time and prices off whatever the oracle says *right then*, not off
/// whatever `quote()` returned earlier. A factory-deployed instance cannot lie between its own
/// quote and its own fill. The real attack surface against this architecture is entirely in the
/// oracle it reads from (`IPrioUpdateRegistry`/PUR): whoever controls an authorized updater key
/// can rewrite the lane's `(delta, mid)` between the moment a taker read a price off-chain and
/// the moment its swap transaction executes. That is quote-and-pull, and it is what this file
/// tests — the same mechanism ElZorro's own `quote-updater` service uses to push honest prices
/// (`quote-updater/src/node.rs`: `updateState(target, lane, ts, [delta, mid])`), here driven by a
/// compromised/malicious key instead.
contract CapitanMonasterioQuoteAndPullTest is Test {
    // The PUR oracle address PropAMM.sol hardcodes its reads against (via the oracle it's
    // initialized with) — confirmed real/live address, not the stale one in
    // propamm-router-contracts/test/interfaces/IPrioUpdateRegistry.sol.
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;
    uint256 constant PRICE_SCALE = 1e18; // PropAMM.PRICE_SCALE
    uint256 constant AMOUNT_IN = 1 ether;

    MockERC20 internal tokenIn;
    MockERC20 internal tokenOut;
    PropAMM internal propAmm;

    address internal owner = makeAddr("owner");
    address internal vault = makeAddr("vault");
    // The authorized price-updater key. In production this is ElZorro's quote-updater service;
    // here it is the attacker — modeling a compromised or malicious key with legitimate write
    // access to the lane, not a flaw in PropAMM.sol itself.
    address internal updater = makeAddr("updater");
    address internal taker = makeAddr("taker");

    uint256 internal pairKey;

    function setUp() public {
        vm.etch(ORACLE, address(new MockPUR()).code);

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
        pairKey = uint256(
            keccak256(
                address(tokenIn) < address(tokenOut)
                    ? abi.encodePacked(address(tokenIn), address(tokenOut))
                    : abi.encodePacked(address(tokenOut), address(tokenIn))
            )
        );

        // Fund the vault with tokenOut and have it approve the instance, the precondition
        // `setPairVault`'s own NatSpec calls out: "fund the new vault and have it approve this
        // instance ... before calling this, or every swap reverts on the output leg."
        tokenOut.mint(vault, 10_000 ether);
        vm.prank(vault);
        tokenOut.approve(address(propAmm), type(uint256).max);
    }

    /// @dev Pushes `(delta, mid)` to the oracle lane as the authorized updater — exactly the call
    /// ElZorro's own quote-updater makes (`quote-updater/src/node.rs`), just invoked here as
    /// whoever holds that key, honest or not.
    function _updatePrice(uint256 delta, uint256 mid) internal {
        vm.prank(updater);
        MockPUR(ORACLE).setState(delta, mid);
    }

    /// @dev Mirrors the router's push-payment model (`PropAMMRouter._dispatchVenue`): the taker's
    /// `tokenIn` lands on the venue contract BEFORE `swap()` is called, so calling `swap()`
    /// directly here (bypassing the router) needs the same pre-transfer to stay faithful to how
    /// a real fill reaches this contract.
    function _fundTakerAndPush(uint256 amountIn) internal {
        tokenIn.mint(taker, amountIn);
        vm.prank(taker);
        tokenIn.transfer(address(propAmm), amountIn);
    }

    /// @notice Baseline: no pull. The lane is set once, the taker quotes and swaps against the
    /// same state. What an honest fill looks like, to measure the pulled scenarios against.
    function test_noPull_honestFillBaseline() public {
        _updatePrice(0, 2_500 * PRICE_SCALE); // delta=0 (no spread), mid=2500 tokenOut per tokenIn
        uint256 expected = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _fundTakerAndPush(AMOUNT_IN);
        vm.prank(taker);
        uint256 amountOut = propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, expected, taker, block.timestamp);

        assertEq(amountOut, expected, "honest fill should settle at the quoted price");
        assertEq(tokenOut.balanceOf(taker), expected, "taker should receive exactly what it quoted");
    }

    /// @notice The pull, tight `minAmountOut`: the taker reads an attractive price (delta=0,
    /// mid=2500), builds its swap with `minAmountOut` from THAT price, but before the swap lands
    /// the updater rewrites the lane to a worse one (delta=50 bps, same mid). `swap()` re-quotes
    /// fresh against the pulled lane, undershoots the taker's floor, and reverts outright —
    /// `InsufficientOutput`, thrown by PropAMM.sol itself (PropAMM.sol:169), with no fallback at
    /// this layer: calling the venue directly (as this test does, and as the router's
    /// `_dispatchVenue` does before its own try/catch) has nowhere else to go. The taker is out
    /// only gas, not funds, but gets no fill at all.
    function test_pulledBeforeSwap_tightMinOut_revertsNoFallback() public {
        _updatePrice(0, 2_500 * PRICE_SCALE);
        uint256 amountOutMinFromAttractivePrice = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        // The pull: same block, no event the taker can react to, by the same key that pushes
        // ElZorro's honest prices in production.
        _updatePrice(50 * PRICE_SCALE / 10_000, 2_500 * PRICE_SCALE); // 50 bps spread now

        _fundTakerAndPush(AMOUNT_IN);
        vm.prank(taker);
        // Selector-only: the exact second argument (realAmountOut) also bakes in
        // `_priceImpact`'s charge for the size of this fill against the vault, which is incidental
        // to this scenario — asserting the revert type and the taker's own floor is enough to
        // prove the pull causes an outright revert, without pinning to that unrelated detail.
        vm.expectPartialRevert(InsufficientOutput.selector);
        propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, amountOutMinFromAttractivePrice, taker, block.timestamp);
    }

    /// @notice The pull, loose `minAmountOut`: same pull, but the taker's floor was set loosely
    /// (e.g. a wide default slippage tolerance) rather than pinned to the attractive price. The
    /// swap now succeeds — re-quoted fresh at the pulled (worse) price, same as the honest case
    /// would at that price — and the taker is shortchanged by the full gap between the price it
    /// saw and the price it got, with the contract treating it as an entirely ordinary fill.
    function test_pulledBeforeSwap_looseMinOut_takerShortchangedSilently() public {
        _updatePrice(0, 2_500 * PRICE_SCALE);
        uint256 attractiveQuote = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _updatePrice(50 * PRICE_SCALE / 10_000, 2_500 * PRICE_SCALE);

        uint256 looseMinOut = attractiveQuote * 95 / 100; // a generic 5% slippage tolerance

        _fundTakerAndPush(AMOUNT_IN);
        vm.prank(taker);
        uint256 amountOut =
            propAmm.swap(address(tokenIn), address(tokenOut), AMOUNT_IN, looseMinOut, taker, block.timestamp);

        assertLt(amountOut, attractiveQuote, "taker received less than the price it saw before the pull");
        assertEq(attractiveQuote - amountOut, 12_500000000000000000, "quantified pull cost: 50bps of the attractive quote");
    }

    /// @notice Contrast case, not an exploit: phantom depth. An attractive price is live, but the
    /// vault backing the pair has no `tokenOut` at all. Unlike the pull, this is caught BEFORE any
    /// fill is attempted — `quote()` itself reverts `EmptyVault` (PropAMM.sol:304), so a taker (or
    /// the router's own selection loop, which try/catches `quote()`) never selects this venue in
    /// the first place. Included to show the contract's existing defenses are not uniformly
    /// absent: insolvency is caught at quote time, a pulled price is not.
    function test_phantomDepth_emptyVaultCaughtAtQuoteNotAtFill() public {
        address starvedVault = makeAddr("starved-vault");
        vm.prank(owner);
        propAmm.setPairVault(address(tokenIn), address(tokenOut), starvedVault);
        // starvedVault holds no tokenOut and has approved nothing.

        _updatePrice(0, 2_500 * PRICE_SCALE);

        vm.expectRevert(abi.encodeWithSelector(EmptyVault.selector, address(tokenOut)));
        propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);
    }
}

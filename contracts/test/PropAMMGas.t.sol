// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {PropAMM} from "../src/PropAMM.sol";
import {IPropAMMFillable} from "../src/interfaces/IPropAMMFillable.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";

/// Gas of the calls `PropAMMRouter` makes on an instance, each measured from cold accounts and
/// storage as the router's own transaction would meet them, and recorded to
/// snapshots/PropAMMGasTest.json so a change shows up in the diff.
///
/// Cold means reverting to a state snapshot taken before the test touched anything: the snapshot
/// carries the access lists, so a revert to it makes everything cold again. Two shortcuts measure
/// warm instead. `vm.cool` re-cools storage slots but leaves accounts warm, which understates a
/// call by 2,500 gas per account it reaches, and a snapshot taken after a call keeps that call's
/// warmth. `vm.load` warms the slot it reads.
///
/// The assertions are limits that matter rather than exact figures: the snapshots move with the
/// compiler and with `MockPUR`, whose `getState` does not cost what the real registry's does. The
/// overhead of `quoteFillable` over `quote` is measured as a difference, since both pay for the
/// same registry read.
contract PropAMMGasTest is Test {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;

    /// The gas `ERC165Checker` gives each `supportsInterface` call. Past it the call fails, the
    /// router concludes the instance does not implement `IPropAMMFillable`, and falls back to its
    /// blind probe without any error to notice.
    uint256 constant ERC165_CHECKER_GAS = 30_000;
    /// What `quoteFillable` may cost over a cold `quote` of the same order. Measured at 5,326
    /// (5,520 when the vault binds): one cold `allowance` read plus the closed-form sizing. The
    /// headroom absorbs compiler drift; a second registry read or a search loop would not fit in it.
    uint256 constant FILLABLE_OVERHEAD_BUDGET = 7_000;

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address trader = makeAddr("trader");

    PropAMM propAmm;

    function setUp() public {
        vm.etch(ORACLE, address(new MockPUR()).code);
        _deployToken(WETH, 18);
        _deployToken(USDT, 6);

        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: WETH, token1: USDT, vault: vault});
        propAmm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, pairs))
                )
            )
        );

        MockPUR(ORACLE).setState(5e14, 1600e18);
        MockToken(USDT).mint(vault, 1_600_000e6); // 1000 WETH worth
        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);
    }

    /// ERC165Checker makes three such calls (IERC165, 0xffffffff, then the interface), the first
    /// against a cold proxy and implementation. All have to fit its budget.
    function test_gas_supportsInterfaceFitsTheERC165CheckerBudget() public {
        uint256 cold = vm.snapshotState();
        propAmm.supportsInterface(type(IPropAMMFillable).interfaceId);
        uint256 used = vm.snapshotGasLastCall("supportsInterface");
        assertLt(used, ERC165_CHECKER_GAS, "cold supportsInterface exceeds ERC165Checker's budget");

        vm.revertToState(cold);
        assertTrue(ERC165Checker.supportsInterface(address(propAmm), type(IPropAMMFillable).interfaceId));
    }

    /// The router's blind probe quotes the order and half of it in one transaction. It searches
    /// further down only when both quotes return the same output, the mark of a venue that keeps
    /// what it cannot fill. Past its vault this one reverts instead, which the router reads as a
    /// dead point, so the probe here is always those two quotes. The one call it takes instead
    /// must cost less than both.
    function test_gas_quoteFillableIsCheaperThanTheBlindProbe() public {
        uint256 cold = vm.snapshotState();
        propAmm.quoteFillable(WETH, USDT, 500e18);
        uint256 fillable = vm.snapshotGasLastCall("quoteFillable");

        vm.revertToState(cold);
        propAmm.quote(WETH, USDT, 500e18);
        uint256 probeFull = vm.snapshotGasLastCall("quote");
        propAmm.quote(WETH, USDT, 250e18);
        uint256 probeHalf = vm.snapshotGasLastCall("quote_warm");

        assertLt(fillable, probeFull + probeHalf);
    }

    function test_gas_quoteFillableCostsLittleMoreThanAQuote() public {
        uint256 cold = vm.snapshotState();
        propAmm.quote(WETH, USDT, 500e18);
        uint256 quoted = vm.lastCallGas().gasTotalUsed;

        vm.revertToState(cold);
        propAmm.quoteFillable(WETH, USDT, 500e18);
        uint256 uncapped = vm.lastCallGas().gasTotalUsed;

        // Capped by the vault: the same work, priced at the smaller fill.
        vm.revertToState(cold);
        propAmm.quoteFillable(WETH, USDT, 10_000e18);
        uint256 capped = vm.snapshotGasLastCall("quoteFillable_capped");

        assertLt(uncapped - quoted, FILLABLE_OVERHEAD_BUDGET, "uncapped overhead over quote");
        assertLt(capped - quoted, FILLABLE_OVERHEAD_BUDGET, "capped overhead over quote");
    }

    /// A leg the router places at the reported fill, for the record. Measured warm, as the router
    /// runs it: `quoteFillable` and the push come earlier in the same transaction.
    function test_gas_swapAtTheReportedFill() public {
        (uint256 fill, uint256 out) = propAmm.quoteFillable(WETH, USDT, 10_000e18);
        MockToken(WETH).mint(address(propAmm), fill); // the router's push

        propAmm.swap(WETH, USDT, fill, out, trader, block.timestamp);
        vm.snapshotGasLastCall("swap");

        assertEq(MockToken(USDT).balanceOf(trader), out);
    }

    function _deployToken(address where, uint8 decimals) internal {
        vm.etch(where, address(new MockToken()).code);
        MockToken(where).setDecimals(decimals);
    }
}

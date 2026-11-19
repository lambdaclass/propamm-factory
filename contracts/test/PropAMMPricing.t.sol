// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import "forge-std/console.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    PropAMM,
    EmptyVault,
    Expired,
    InsufficientOracleData,
    InsufficientOutput,
    InsufficientVaultBalance,
    InvalidMid,
    InvalidRecipient,
    SpreadTooWide,
    StaleOracleData,
    UnsupportedPair,
    ZeroAmountIn,
    ZeroAmountOut
} from "../src/PropAMM.sol";
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";
import {FeeOnTransferToken} from "./mocks/FeeOnTransferToken.sol";
import {ReentrantToken} from "./mocks/ReentrantToken.sol";

// Oracle shapes etched over `ORACLE` by the `isActive` tests (audit F-14).

/// Every call returns no data.
contract EmptyReturnOracle {
    fallback() external payable {}
}

/// Every call returns one word: this block's timestamp, a fresh stamp with no slots behind it.
contract OneWordOracle {
    fallback() external payable {
        assembly {
            mstore(0, timestamp())
            return(0, 32)
        }
    }
}

/// Every call reverts.
contract RevertingOracle {
    fallback() external payable {
        revert("nope");
    }
}

/// First word does not fit a uint32, so `abi.decode` reverts on it.
contract HighBitsOracle {
    fallback() external payable {
        assembly {
            mstore(0, not(0))
            mstore(0x20, 0x40)
            mstore(0x40, 0)
            return(0, 0x60)
        }
    }
}

/// Claims two slots under this block's timestamp, but returns only the head.
contract TruncatedArrayOracle {
    fallback() external payable {
        assembly {
            mstore(0, timestamp())
            mstore(0x20, 0x40)
            mstore(0x40, 2)
            return(0, 0x60)
        }
    }
}

/// Every call reverts, and the revert data is a whole answer: this block's timestamp, then two
/// slots holding a usable `delta` and `mid`, laid out as a registry would return them.
contract RevertsWithAnAnswerOracle {
    fallback() external payable {
        assembly {
            mstore(0, timestamp())
            mstore(0x20, 0x40)
            mstore(0x40, 2)
            mstore(0x60, 500000000000000)
            mstore(0x80, 1600000000000000000000)
            revert(0, 0xa0)
        }
    }
}

/// Answers every call it has no function for with the bytes it was last given: answers no
/// registry built with Solidity would encode.
contract RawAnswerOracle {
    bytes public answer;

    function setAnswer(bytes calldata answer_) external {
        answer = answer_;
    }

    fallback() external payable {
        bytes memory a = answer;
        assembly {
            return(add(a, 0x20), mload(a))
        }
    }
}

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

    /// A `delta` of one or more is refused as it is read, with the `delta` itself: before, the
    /// largest word overflowed the sum with the impact and `quote` panicked where `quoteFillable`
    /// named the reason. `swap` prices through the same read.
    function test_quote_andSwapRefuseADeltaOfOneOrMore() public {
        _fundVault(USDT, 1_600_000e6);
        MockToken(WETH).mint(address(propAmm), 1e18);

        uint256[3] memory deltas = [SPREAD_SCALE, SPREAD_SCALE + 1, type(uint256).max];
        for (uint256 i = 0; i < deltas.length; i++) {
            _setPrice(1600e18, deltas[i]);

            vm.expectRevert(abi.encodeWithSelector(SpreadTooWide.selector, deltas[i]));
            propAmm.quote(WETH, USDT, 1e18);
            vm.expectRevert(abi.encodeWithSelector(SpreadTooWide.selector, deltas[i]));
            propAmm.swap(WETH, USDT, 1e18, 0, trader, block.timestamp);
        }
    }

    //------------------------------
    // Freshness
    //------------------------------

    /// A price is good for the block it was stamped for. A block later the registry has no
    /// update for the window it is asked about, so quotes revert and `isActive` says so.
    function test_quote_revertsOnceThePriceIsABlockOld() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        assertGt(propAmm.quote(WETH, USDT, 1e18), 0);
        assertTrue(propAmm.isActive(WETH, USDT));

        skip(12);

        vm.expectRevert(MockPUR.StaleUpdate.selector);
        propAmm.quote(WETH, USDT, 1e18);
        vm.expectRevert(MockPUR.StaleUpdate.selector);
        propAmm.quoteFillable(WETH, USDT, 1e18);
        assertFalse(propAmm.isActive(WETH, USDT));

        // A new update for the new block, and the pair quotes again.
        _setPrice(1600e18, 5e14);
        assertGt(propAmm.quote(WETH, USDT, 1e18), 0);
        assertTrue(propAmm.isActive(WETH, USDT));
    }

    /// Freshness is not only the registry's promise. One that keeps no window hands back its
    /// last update however old; the instance reads the stamp on the answer and refuses any that
    /// is not this block's, on every path that prices.
    function test_quote_refusesAnOldUpdateFromARegistryThatKeepsNoWindow() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);
        MockPUR(ORACLE).setLenient(true);
        uint32 stamped = uint32(vm.getBlockTimestamp());
        uint256 fresh = propAmm.quote(WETH, USDT, 1e18);

        skip(12);

        bytes memory stale =
            abi.encodeWithSelector(StaleOracleData.selector, uint256(keccak256(abi.encodePacked(WETH, USDT))), stamped);
        vm.expectRevert(stale);
        propAmm.quote(WETH, USDT, 1e18);
        vm.expectRevert(stale);
        propAmm.quoteFillable(WETH, USDT, 1e18);
        MockToken(WETH).mint(address(propAmm), 1e18);
        vm.expectRevert(stale);
        propAmm.swap(WETH, USDT, 1e18, 0, trader, vm.getBlockTimestamp());
        assertFalse(propAmm.isActive(WETH, USDT));

        // The same registry with an update for this block is priced from as before.
        _setPrice(1600e18, 5e14);
        assertEq(propAmm.quote(WETH, USDT, 1e18), fresh);
        assertTrue(propAmm.isActive(WETH, USDT));
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

    /// The deadline is the last timestamp the swap may execute at: this block's is still in time,
    /// one second earlier is not.
    function test_swap_revertsPastItsDeadline() public {
        skip(1 hours);
        uint256 expected = _readyToSwapOneWeth();

        vm.startPrank(trader);
        vm.expectRevert(Expired.selector);
        propAmm.swap(WETH, USDT, 1e18, 0, trader, vm.getBlockTimestamp() - 1);

        assertEq(propAmm.swap(WETH, USDT, 1e18, 0, trader, vm.getBlockTimestamp()), expected);
        vm.stopPrank();
    }

    /// `minAmountOut` is a floor on what the swap pays: a wei above the quote reverts, naming
    /// both figures. The quote itself clears it.
    function test_swap_revertsBelowMinAmountOut() public {
        uint256 expected = _readyToSwapOneWeth();

        vm.startPrank(trader);
        vm.expectRevert(abi.encodeWithSelector(InsufficientOutput.selector, expected + 1, expected));
        propAmm.swap(WETH, USDT, 1e18, expected + 1, trader, block.timestamp);

        assertEq(propAmm.swap(WETH, USDT, 1e18, expected, trader, block.timestamp), expected);
        vm.stopPrank();
    }

    /// A swap of nothing moved nothing and still logged a `Swapped`, which anyone could pad the
    /// event stream with. It reverts instead.
    function test_swap_refusesAZeroAmountIn() public {
        _readyToSwapOneWeth();

        vm.prank(trader);
        vm.expectRevert(ZeroAmountIn.selector);
        propAmm.swap(WETH, USDT, 0, 0, trader, block.timestamp);
    }

    /// A wei of WETH at 1600 is worth a billionth of a USDT wei, so the swap would take it and
    /// pay nothing. It reverts instead.
    function test_swap_refusesAFillThatPaysNothing() public {
        _readyToSwapOneWeth();
        assertEq(propAmm.quote(WETH, USDT, 1), 0);

        vm.prank(trader);
        vm.expectRevert(ZeroAmountOut.selector);
        propAmm.swap(WETH, USDT, 1, 0, trader, block.timestamp);
    }

    /// The output has to go to someone. A token that accepts transfers to the zero address
    /// (USDT does) would burn it there, and paid to the vault it comes out of it would not move
    /// at all: the taker's input gone, nothing received. Both are refused.
    function test_swap_refusesTheZeroAddressAndThePairsVaultAsRecipient() public {
        _readyToSwapOneWeth();

        vm.startPrank(trader);
        vm.expectRevert(abi.encodeWithSelector(InvalidRecipient.selector, address(0)));
        propAmm.swap(WETH, USDT, 1e18, 0, address(0), block.timestamp);
        vm.expectRevert(abi.encodeWithSelector(InvalidRecipient.selector, vault));
        propAmm.swap(WETH, USDT, 1e18, 0, vault, block.timestamp);
        vm.stopPrank();
    }

    /// Two hops on one instance, the way a push-payment router chains them: the first swap names
    /// the instance as recipient, so its output is already where the second swap takes its input
    /// from. Nothing is left on the instance, and the taker ends with what the second hop quoted
    /// for the first hop's output.
    function test_swap_twoHopsOnOneInstance() public {
        // WETH -> USDT -> USDC. The mock serves one price for every lane, so a USDC is priced at
        // 1600 USDT here; what matters is that each hop pays what it quotes.
        uint256 firstOut = _readyToSwapOneWeth();
        _fundVault(USDC, 1_000_000e6);
        uint256 secondOut = propAmm.quote(USDT, USDC, firstOut);
        assertGt(secondOut, 0);

        assertEq(this.swapWethToUsdcThroughUsdt(firstOut, secondOut), secondOut);
        assertEq(MockToken(USDC).balanceOf(trader), secondOut);
        assertEq(MockToken(USDT).balanceOf(address(propAmm)), 0, "the first hop's output was left behind");
        assertEq(MockToken(WETH).balanceOf(address(propAmm)), 0);
    }

    /// Both hops inside one external call, as a router makes them: one transaction.
    function swapWethToUsdcThroughUsdt(uint256 minUsdt, uint256 minUsdc) external returns (uint256) {
        uint256 usdt = propAmm.swap(WETH, USDT, 1e18, minUsdt, address(propAmm), block.timestamp);
        return propAmm.swap(USDT, USDC, usdt, minUsdc, trader, block.timestamp);
    }

    /// `Swapped` is the last thing a swap logs, after both transfers, as `IPropAMM` documents:
    /// the output is delivered by the time it is reported.
    function test_swap_logsSwappedAfterBothTransfers() public {
        _readyToSwapOneWeth();

        vm.recordLogs();
        vm.prank(trader);
        propAmm.swap(WETH, USDT, 1e18, 0, trader, block.timestamp);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 3);
        assertEq(logs[0].emitter, WETH);
        assertEq(logs[1].emitter, USDT);
        assertEq(logs[2].emitter, address(propAmm));
        assertEq(logs[2].topics[0], IPropAMM.Swapped.selector);
    }

    /// A token that calls out while it moves cannot nest a second swap inside the first. Left
    /// open, the inner swap would settle and log before the outer one that contains it, and
    /// indexers would read two swaps in the wrong order. The guard is per call, not per
    /// transaction: the swaps the router makes one after another on an instance still go through.
    function test_swap_cannotBeReenteredFromATokenTransfer() public {
        // WETH becomes a token with a transfer hook. Its balances and decimals stay: the etch
        // replaces code, not storage.
        vm.etch(WETH, address(new ReentrantToken()).code);
        _readyToSwapOneWeth();
        MockToken(WETH).mint(address(propAmm), 1e18); // a second WETH for the nested swap to spend

        ReentrantToken(WETH)
            .arm(address(propAmm), abi.encodeCall(IPropAMM.swap, (WETH, USDT, 1e18, 0, trader, block.timestamp)));
        vm.prank(trader);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        propAmm.swap(WETH, USDT, 1e18, 0, trader, block.timestamp);

        // The revert undid the hook's own reset along with everything else, so it is still armed.
        // Disarmed, two swaps in one call both settle.
        ReentrantToken(WETH).arm(address(0), "");
        this.swapOneWethTwice();
        assertEq(MockToken(WETH).balanceOf(vault), 2e18);
        assertGt(MockToken(USDT).balanceOf(trader), 0);
    }

    /// Two swaps inside one external call, so they share a transaction however the tests are run.
    function swapOneWethTwice() external {
        propAmm.swap(WETH, USDT, 1e18, 0, trader, block.timestamp);
        propAmm.swap(WETH, USDT, 1e18, 0, trader, block.timestamp);
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

    /// `isActive` is the probe a caller can make to skip a propAMM before paying for a quote, so
    /// a pause has to surface there as `false`. Reverting instead would take the probe down
    /// with it.
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

    /// Replaces the code at `ORACLE`: whatever sits there, `isActive` answers instead of
    /// reverting (audit F-14).
    function _etchOracle(address shape) internal {
        vm.etch(ORACLE, shape.code);
    }

    function test_isActive_falseForAnOracleWithoutCode() public {
        vm.etch(ORACLE, "");
        assertFalse(propAmm.isActive(WETH, USDT));
    }

    function test_isActive_falseForAnEmptyReturnOracle() public {
        _etchOracle(address(new EmptyReturnOracle()));
        assertFalse(propAmm.isActive(WETH, USDT));
    }

    function test_isActive_falseForARevertingOracle() public {
        _etchOracle(address(new RevertingOracle()));
        assertFalse(propAmm.isActive(WETH, USDT));
    }

    /// A malformed answer used to revert `isActive` in its decoder. It reads as inactive, like
    /// anything else `quote` cannot price from: a fresh stamp with nothing behind it, a stamp
    /// that does not fit a uint32, a slot array cut short.
    function test_isActive_falseForAMalformedAnswer() public {
        _fundVault(USDT, 1_600_000e6);
        address[3] memory shapes =
            [address(new OneWordOracle()), address(new HighBitsOracle()), address(new TruncatedArrayOracle())];
        string[3] memory names = ["one word", "timestamp above uint32", "truncated array"];
        for (uint256 i = 0; i < shapes.length; i++) {
            _etchOracle(shapes[i]);
            assertFalse(propAmm.isActive(WETH, USDT), names[i]);
            vm.expectRevert();
            propAmm.quote(WETH, USDT, 1e18);
        }
    }

    /// `isActive` reads five words of the registry's answer by hand where `quote` uses the ABI
    /// decoder. Each answer here carries a fresh stamp and a usable `delta` and `mid` in the
    /// places `isActive` looks, and is one the decoder refuses or `quote` cannot price from.
    function test_isActive_falseForAnAnswerQuoteWouldRefuse() public {
        _fundVault(USDT, 1_600_000e6);
        _etchOracle(address(new RawAnswerOracle()));
        RawAnswerOracle raw = RawAnswerOracle(payable(ORACLE));

        // Stamp, the array's offset, its length, then the two slots: what a registry encodes.
        raw.setAnswer(_answer(64, 2));
        assertTrue(propAmm.isActive(WETH, USDT), "the well-formed answer");
        propAmm.quote(WETH, USDT, 1e18);

        uint256[2][3] memory malformed = [[uint256(64), 3], [uint256(64), 1], [uint256(96), 2]];
        string[3] memory names = ["three slots announced, two there", "one slot announced", "array at another offset"];
        for (uint256 i = 0; i < malformed.length; i++) {
            raw.setAnswer(_answer(malformed[i][0], malformed[i][1]));
            assertFalse(propAmm.isActive(WETH, USDT), names[i]);
            vm.expectRevert();
            propAmm.quote(WETH, USDT, 1e18);
        }
    }

    /// A registry that reverts has not answered, whatever its revert data holds. Here the data is
    /// the well-formed answer of the test above, byte for byte, which `isActive` would price
    /// from had the call succeeded; `quote` reverts on the call itself.
    function test_isActive_falseForARegistryThatRevertsWithAnAnswer() public {
        _fundVault(USDT, 1_600_000e6);
        _etchOracle(address(new RevertsWithAnAnswerOracle()));

        assertFalse(propAmm.isActive(WETH, USDT));
        vm.expectRevert();
        propAmm.quote(WETH, USDT, 1e18);
    }

    /// The stamp is compared whole, not by its low 32 bits. This one is this block's timestamp
    /// with a bit set above them, in an answer that is otherwise well formed: the decoder
    /// refuses it as no uint32, so `quote` reverts, and `isActive` must not read it as fresh.
    /// (`HighBitsOracle` is turned away for its length, before its stamp is looked at.)
    function test_isActive_falseForAStampThatMatchesOnlyInItsLow32Bits() public {
        _fundVault(USDT, 1_600_000e6);
        _etchOracle(address(new RawAnswerOracle()));
        uint256 stamp = vm.getBlockTimestamp() | (1 << 32);
        RawAnswerOracle(payable(ORACLE))
            .setAnswer(abi.encode(stamp, uint256(64), uint256(2), uint256(5e14), uint256(1600e18)));

        assertFalse(propAmm.isActive(WETH, USDT));
        vm.expectRevert();
        propAmm.quote(WETH, USDT, 1e18);
    }

    /// The one place the two readings differ, and it errs toward skipping the pair: an answer
    /// with its array somewhere other than straight after the head is valid ABI, so `quote`
    /// prices from it, while `isActive` expects the layout every Solidity registry produces.
    function test_isActive_expectsTheCanonicalLayout() public {
        _fundVault(USDT, 1_600_000e6);
        _etchOracle(address(new RawAnswerOracle()));
        // The array's offset is 96, and a spare word sits between the head and the array.
        RawAnswerOracle(payable(ORACLE))
            .setAnswer(abi.encode(vm.getBlockTimestamp(), uint256(96), uint256(0), uint256(2), 5e14, 1600e18));

        assertGt(propAmm.quote(WETH, USDT, 1e18), 0);
        assertFalse(propAmm.isActive(WETH, USDT));
    }

    /// The vault's balance is asked for with a low-level call, like the registry: a token that
    /// reverts, answers with nothing or has no code reads as an empty vault, not as a revert.
    /// (The shapes are the registry ones; all a shape does is answer every call the same way.)
    function test_isActive_falseForATokenThatDoesNotAnswer() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        assertTrue(propAmm.isActive(WETH, USDT));

        vm.etch(USDT, address(new RevertingOracle()).code);
        assertFalse(propAmm.isActive(WETH, USDT), "a token that reverts");
        vm.etch(USDT, address(new EmptyReturnOracle()).code);
        assertFalse(propAmm.isActive(WETH, USDT), "a token that answers with nothing");
        vm.etch(USDT, "");
        assertFalse(propAmm.isActive(WETH, USDT), "a token without code");
    }

    /// `isActive` makes `_pricing`'s checks by hand, so the two could drift apart. Whatever the
    /// lane holds, however old, and whatever the instance and its vault are doing, it answers
    /// true exactly when `quote` answers for the pair. `fault` picks what, if anything, is wrong.
    function testFuzz_isActive_agreesWithQuote(uint256 fault, uint256 mid, uint256 delta, uint256 slots) public {
        fault = bound(fault, 0, 8);
        // Up to 1e36: past about 1e41, scaling `mid` by a token's decimals overflows, which
        // `isActive` leaves to `quote`.
        mid = fault == 1 ? 0 : bound(mid, 1, 1e36);
        // `delta` keeps the low 64 bits of its slot, so that is the range it can be out of: what
        // sits above them is a size table's rows, which `PropAMMSizeTable.t.sol` covers.
        delta = fault == 2 ? bound(delta, SPREAD_SCALE, type(uint64).max) : bound(delta, 0, SPREAD_SCALE - 1);
        MockPUR(ORACLE).setState(delta, mid);
        // Two slots, or more: the mock pads with zeros, and extra slots are not `_pricing`'s concern.
        MockPUR(ORACLE).setSlotCount(fault == 3 ? 1 : uint64(bound(slots, 2, 4)));
        if (fault == 4 || fault == 5) skip(12); // an old update, which the registry refuses...
        if (fault == 5) MockPUR(ORACLE).setLenient(true); // ...or hands back under its true stamp
        if (fault != 6) _fundVault(USDT, 1_600_000e6);
        vm.startPrank(owner);
        if (fault == 7) propAmm.pause();
        if (fault == 8) propAmm.removePair(WETH, USDT);
        vm.stopPrank();

        bool quotes;
        try propAmm.quote(WETH, USDT, 0) {
            quotes = true;
        } catch {}
        assertEq(quotes, fault == 0, "the fault did not decide whether quote answers");
        assertEq(propAmm.isActive(WETH, USDT), quotes);
    }

    /// A fresh lane is not enough: `isActive` answers what `quote` would, so slots `quote`
    /// rejects read as inactive, each for the reason `quote` names.
    function test_isActive_falseWhenTheSlotsCannotBePricedFrom() public {
        uint256 pairKey = uint256(keccak256(abi.encodePacked(WETH, USDT)));
        _fundVault(USDT, 1_600_000e6);
        _setPrice(1600e18, 5e14);
        assertTrue(propAmm.isActive(WETH, USDT), "a price quote accepts");

        _setPrice(0, 5e14);
        assertFalse(propAmm.isActive(WETH, USDT), "mid == 0");
        vm.expectRevert(abi.encodeWithSelector(InvalidMid.selector, pairKey));
        propAmm.quote(WETH, USDT, 1e18);

        _setPrice(1600e18, SPREAD_SCALE);
        assertFalse(propAmm.isActive(WETH, USDT), "delta of one");
        vm.expectRevert(abi.encodeWithSelector(SpreadTooWide.selector, SPREAD_SCALE));
        propAmm.quote(WETH, USDT, 1e18);

        _setPrice(1600e18, 5e14);
        MockPUR(ORACLE).setSlotCount(1);
        assertFalse(propAmm.isActive(WETH, USDT), "one slot");
        vm.expectRevert(abi.encodeWithSelector(InsufficientOracleData.selector, pairKey, uint256(1)));
        propAmm.quote(WETH, USDT, 1e18);
    }

    /// Removing a pair leaves its lane in the registry, still holding a fresh update: only the
    /// listing turns `isActive` false. The balance check would not: an unlisted pair's vault
    /// reads as the zero address, where most real tokens have a balance, burnt. Audit F-09.
    function test_isActive_falseForARemovedPair() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        deal(USDT, address(0), 1e6);
        assertTrue(propAmm.isActive(WETH, USDT));
        vm.prank(owner);
        propAmm.removePair(WETH, USDT);
        assertFalse(propAmm.isActive(WETH, USDT), "the lane still has a fresh price");
    }

    /// A vault holding none of `tokenOut` cannot fill anything, and `quote` says so. `isActive`
    /// is per direction for that reason: the same pair is active the other way round as long as
    /// the vault holds that side. It is still not told a size, so a wei in the vault is enough.
    function test_isActive_falseForAnEmptyVault() public {
        _setPrice(1600e18, 5e14);
        assertFalse(propAmm.isActive(WETH, USDT), "no USDT to pay out");
        vm.expectRevert(abi.encodeWithSelector(EmptyVault.selector, USDT));
        propAmm.quote(WETH, USDT, 1e18);

        MockToken(USDT).mint(vault, 1);
        assertTrue(propAmm.isActive(WETH, USDT), "a wei of USDT");
        assertFalse(propAmm.isActive(USDT, WETH), "still no WETH");
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

    /// A `getState` answer stamped now, with `delta` and `mid` as its fourth and fifth words, and
    /// the array's offset and length as given.
    function _answer(uint256 offset, uint256 count) internal view returns (bytes memory) {
        return abi.encode(vm.getBlockTimestamp(), offset, count, uint256(5e14), uint256(1600e18));
    }

    function _setPrice(uint256 mid, uint256 delta) internal {
        MockPUR(ORACLE).setState(delta, mid);
    }

    /// A fee-on-transfer tokenOut (USDT with its fee switch on): the recipient gets less than
    /// computed, so `minAmountOut` must be checked against what it received. Audit F-09.
    function test_swap_revertsWhenTheRecipientWouldReceiveLessThanMinAmountOut() public {
        (PropAMM amm, FeeOnTransferToken fot) = _feeOnTransferOutputPair();
        uint256 quoted = amm.quote(WETH, address(fot), 1_000e18);
        _pushIn(amm, 1_000e18);
        uint256 delivered = quoted - quoted / 100;
        vm.expectRevert(abi.encodeWithSelector(InsufficientOutput.selector, quoted, delivered));
        amm.swap(WETH, address(fot), 1_000e18, quoted, trader, block.timestamp);
    }

    /// `Swapped.amountOut` is documented as a balance delta, and the router-facing return value
    /// should agree with it. Audit F-09.
    function test_swap_returnsAndEmitsWhatTheRecipientReceived() public {
        (PropAMM amm, FeeOnTransferToken fot) = _feeOnTransferOutputPair();
        uint256 quoted = amm.quote(WETH, address(fot), 1_000e18);
        _pushIn(amm, 1_000e18);
        uint256 delivered = quoted - quoted / 100;
        vm.expectEmit(true, true, true, true, address(amm));
        emit IPropAMM.Swapped(address(this), WETH, address(fot), 1_000e18, delivered, trader);
        uint256 out = amm.swap(WETH, address(fot), 1_000e18, 0, trader, block.timestamp);
        assertEq(out, delivered);
        assertEq(fot.balanceOf(trader), delivered);
    }

    /// Push payment cannot tell a payment from a stray transfer: tokens left on the instance can be
    /// swapped by anyone. The vault is still paid in full; the loss is the sender's. Audit F-09.
    function test_swap_aStrayBalanceIsSwappableByAnyone() public {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        MockToken(WETH).mint(address(propAmm), 1e18); // left behind, not paid for this swap
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        uint256 out = propAmm.swap(WETH, USDT, 1e18, 0, stranger, block.timestamp);
        assertGt(out, 0);
        assertEq(MockToken(USDT).balanceOf(stranger), out, "the stranger was paid");
        assertEq(MockToken(WETH).balanceOf(vault), 1e18, "the vault received the stray");
    }

    /// A fee-on-transfer tokenIn (USDT with its fee switch on) is not supported: with nothing else on
    /// the instance, it holds less than amountIn and the swap reverts. Audit F-09.
    function test_swap_feeOnTransferTokenInReverts() public {
        (PropAMM amm, FeeOnTransferToken fot) = _feeOnTransferInputPair();
        fot.mint(address(this), 100e18);
        fot.transfer(address(amm), 100e18); // arrives as 99e18
        // Paying the vault 100e18 burns the 1e18 fee first, leaving 98e18 for the 99e18 transfer.
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, address(amm), 98e18, 99e18)
        );
        amm.swap(address(fot), WETH, 100e18, 0, trader, block.timestamp);
    }

    /// ...but it does not fail closed: when the instance already holds the shortfall (a caller that
    /// sends more than amountIn, or a stray), the swap fills, and the vault receives amountIn less
    /// the token's fee, selling below its price. Documented, not prevented. Audit F-09 (review).
    function test_swap_feeOnTransferTokenInFillsWhenTheShortfallIsHeld() public {
        (PropAMM amm, FeeOnTransferToken fot) = _feeOnTransferInputPair();
        fot.mint(address(this), 102e18);
        fot.transfer(address(amm), 102e18); // arrives as 100.98e18, more than amountIn
        uint256 out = amm.swap(address(fot), WETH, 100e18, 0, trader, block.timestamp);
        assertGt(out, 99e18, "the vault sold about 100 WETH at par");
        assertEq(fot.balanceOf(vault), 99e18, "and received amountIn less the 1% fee");
    }

    /// An instance of its own listing a token that charges 1% per transfer against WETH, its vault
    /// funded and approved in WETH, priced at par with no spread.
    function _feeOnTransferInputPair() internal returns (PropAMM amm, FeeOnTransferToken fot) {
        fot = new FeeOnTransferToken(18);
        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: address(fot), token1: WETH, vault: vault});
        amm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, pairs))
                )
            )
        );
        MockToken(WETH).mint(vault, 1_000e18);
        vm.prank(vault);
        MockToken(WETH).approve(address(amm), type(uint256).max);
        MockPUR(ORACLE).setState(0, 1e18);
    }

    /// An instance of its own listing WETH against a token that charges 1% per transfer, its vault
    /// funded and approved in that token, priced at par with no spread.
    function _feeOnTransferOutputPair() internal returns (PropAMM amm, FeeOnTransferToken fot) {
        fot = new FeeOnTransferToken(18);
        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: WETH, token1: address(fot), vault: vault});
        amm = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, pairs))
                )
            )
        );
        fot.mint(vault, 1_000_000e18);
        vm.prank(vault);
        fot.approve(address(amm), type(uint256).max);
        MockPUR(ORACLE).setState(0, 1e18);
    }

    /// Pays `amount` of WETH to the instance, as the router's push does before calling `swap`.
    function _pushIn(PropAMM amm, uint256 amount) internal {
        MockToken(WETH).mint(address(amm), amount);
    }

    /// Funds the vault and approves this instance from it, as a live vault would, so a test can
    /// `swap` against it.
    function _fundVault(address token, uint256 amount) internal {
        MockToken(token).mint(vault, amount);
        vm.prank(vault);
        MockToken(token).approve(address(propAmm), type(uint256).max);
    }

    /// WETH/USDT at 1600 and 5bps on a vault of 1000 WETH worth of USDT that has approved the
    /// instance, with the trader's 1 WETH already pushed. Returns what that WETH quotes for.
    function _readyToSwapOneWeth() internal returns (uint256 expected) {
        _setPrice(1600e18, 5e14);
        _fundVault(USDT, 1_600_000e6);
        vm.prank(vault);
        MockToken(USDT).approve(address(propAmm), type(uint256).max);
        MockToken(WETH).mint(address(propAmm), 1e18);
        return propAmm.quote(WETH, USDT, 1e18);
    }

    /// Asserts `amountOut` is `midAmountOut` less `delta`, allowing for the impact term on top.
    function _assertRelativeSpread(uint256 amountOut, uint256 midAmountOut, uint256 delta) internal pure {
        uint256 atDelta = midAmountOut - (midAmountOut * delta / SPREAD_SCALE);
        assertLe(amountOut, atDelta, "taker got more than mid less delta");
        assertApproxEqRel(amountOut, atDelta, 1e13, "spread is not delta on this pair");
    }
}

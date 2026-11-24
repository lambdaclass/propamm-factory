// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {
    PropAMM,
    InvalidRetailSigner,
    RetailSignerAlreadyAdded,
    NotRetailSigner,
    AttestationExpired,
    AttestationForAnotherPair,
    AttestationAmountExceeded,
    AttestationAccountAbsent,
    AttestationUsed,
    RetailDeltaAboveDelta,
    InsufficientOutput
} from "../src/PropAMM.sol";
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {IPropAMMRetail} from "../src/interfaces/IPropAMMRetail.sol";
import {SizeTable} from "../src/SizeTable.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockToken} from "./mocks/MockToken.sol";
import {ReentrantToken} from "./mocks/ReentrantToken.sol";

/// Retail flow: an update that carries a retail delta, the quotes that price with it, and the
/// attestation `swapRetail` asks for before it does. One WETH/USDT pair, a vault holding both.
contract PropAMMRetailTest is Test {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // token0
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7; // token1
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;
    uint256 constant MID = 1600e18;
    /// 5 bp for everyone, 2 bp for retail.
    uint256 constant DELTA = 5e14;
    uint256 constant RETAIL = 2e14;
    uint256 constant VAULT_USDT = 64_000_000e6;

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address recipient = makeAddr("recipient");
    /// The user's wallet, a contract that swaps for them, and a relayer that sends for them.
    address user = makeAddr("user");
    address router = makeAddr("router");
    address stranger = makeAddr("stranger");

    uint256 signerKey;
    address signer;

    PropAMM amm;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.etch(ORACLE, address(new MockPUR()).code);
        vm.etch(WETH, address(new MockToken()).code);
        MockToken(WETH).setDecimals(18);
        vm.etch(USDT, address(new MockToken()).code);
        MockToken(USDT).setDecimals(6);

        amm = _deploy();
        MockToken(USDT).mint(vault, VAULT_USDT);
        MockToken(WETH).mint(vault, 40_000e18);

        (signer, signerKey) = makeAddrAndKey("okx");
        vm.prank(owner);
        amm.addRetailSigner(signer);

        _publish(_slot0(DELTA, RETAIL));
    }

    function _deploy() internal returns (PropAMM instance) {
        PropAMM.PairConfig[] memory pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: WETH, token1: USDT, vault: vault});
        instance = PropAMM(
            address(
                new ERC1967Proxy(
                    address(new PropAMM()), abi.encodeCall(PropAMM.initialize, (owner, new address[](0), ORACLE, pairs))
                )
            )
        );
        vm.startPrank(vault);
        MockToken(USDT).approve(address(instance), type(uint256).max);
        MockToken(WETH).approve(address(instance), type(uint256).max);
        vm.stopPrank();
    }

    /// Slot 0 of an update with a retail delta, as the updater packs it: `delta` at the bottom,
    /// the retail delta in 1e-6 under its "set" bit from bit 184.
    function _slot0(uint256 delta, uint256 retail) internal pure returns (uint256) {
        return delta | (((1 << 31) | (retail / 1e12)) << 184);
    }

    function _publish(uint256 slot0) internal {
        MockPUR(ORACLE).setState(slot0, MID);
    }

    /// First 10% of the vault free, 10% to 30% at 2 bp, above that 5 bp.
    function _steps() internal pure returns (uint256 rows) {
        return (SizeTable.row(100_000, 0) << 64) | (SizeTable.row(300_000, 200) << 104) | (SizeTable.row(0, 500) << 144);
    }

    /// The expected output of `weth` whole WETH at `spread`.
    function _usdt(uint256 weth, uint256 spread) internal pure returns (uint256) {
        return weth * 1600e6 * (1e18 - spread) / 1e18;
    }

    /// The fixed impact an update without a table charges `weth` whole WETH: 1 bp of its share
    /// of the vault.
    function _impact(uint256 weth) internal pure returns (uint256) {
        return 1e14 * weth * 1600e6 / VAULT_USDT;
    }

    function _attestation(address account, uint256 nonce)
        internal
        view
        returns (IPropAMMRetail.RetailAttestation memory)
    {
        return IPropAMMRetail.RetailAttestation({
            account: account,
            tokenIn: WETH,
            tokenOut: USDT,
            maxAmountIn: 10e18,
            expiry: block.timestamp + 30,
            nonce: nonce
        });
    }

    function _sign(uint256 key, PropAMM instance, IPropAMMRetail.RetailAttestation memory a)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "RetailAttestation(address account,address tokenIn,address tokenOut,uint256 maxAmountIn,uint256 expiry,uint256 nonce)"
                ),
                a.account,
                a.tokenIn,
                a.tokenOut,
                a.maxAmountIn,
                a.expiry,
                a.nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked("\x19\x01", instance.domainSeparator(), structHash)));
        return abi.encodePacked(r, s, v);
    }

    function _sign(IPropAMMRetail.RetailAttestation memory a) internal view returns (bytes memory) {
        return _sign(signerKey, amm, a);
    }

    /// A retail swap of `amountIn` WETH, sent by `origin` through `caller`.
    function _swapRetail(
        address origin,
        address caller,
        uint256 amountIn,
        IPropAMMRetail.RetailAttestation memory a,
        bytes memory signature
    ) internal returns (uint256) {
        MockToken(WETH).mint(address(amm), amountIn);
        vm.prank(caller, origin);
        return amm.swapRetail(WETH, USDT, amountIn, 0, recipient, block.timestamp, a, signature);
    }

    /// The user's own swap through a router: the plain case.
    function _swapRetail(uint256 amountIn, IPropAMMRetail.RetailAttestation memory a) internal returns (uint256) {
        return _swapRetail(user, router, amountIn, a, _sign(a));
    }

    // ------------------------------------------------------------------
    // The price
    // ------------------------------------------------------------------

    function test_retailQuotesAtTheRetailDeltaAndTheRestAtDelta() public view {
        assertEq(amm.quoteRetail(WETH, USDT, 4e18), _usdt(4, RETAIL + _impact(4)));
        assertEq(amm.quote(WETH, USDT, 4e18), _usdt(4, DELTA + _impact(4)));
        // The other direction too: 6,400 USDT buys 4 WETH at mid.
        assertEq(amm.quoteRetail(USDT, WETH, 6_400e6), 4e18 * (1e18 - RETAIL - 1e10) / 1e18);
        assertEq(amm.quote(USDT, WETH, 6_400e6), 4e18 * (1e18 - DELTA - 1e10) / 1e18);
    }

    /// The update the quote updater publishes for `delta = 5 bp`, `retail_delta = 2 bp` and
    /// `size_charges = "10:0, 30:2, rest:5"`: its first slot, as `quote-updater/src/size_table.rs`
    /// packs it.
    function test_theUpdaterPacksTheRetailDeltaWhereTheContractReadsIt() public pure {
        assertEq(_slot0(DELTA, RETAIL) | _steps(), 52656150738264324130954131956213806688779977854230218391920263168);
    }

    function test_anUpdateWithoutARetailDeltaPricesRetailAtDelta() public {
        _publish(DELTA);
        assertEq(amm.quoteRetail(WETH, USDT, 4e18), amm.quote(WETH, USDT, 4e18));
        (uint256 fillable, uint256 out) = amm.quoteFillableRetail(WETH, USDT, 4e18);
        (uint256 plainFillable, uint256 plainOut) = amm.quoteFillable(WETH, USDT, 4e18);
        assertEq(fillable, plainFillable);
        assertEq(out, plainOut);
    }

    /// The "set" bit tells a retail delta of zero from none at all.
    function test_aRetailDeltaOfZeroIsOne() public {
        _publish(_slot0(DELTA, 0));
        assertEq(amm.quoteRetail(WETH, USDT, 4e18), _usdt(4, _impact(4)));
    }

    /// The bits below the "set" bit are not read without it.
    function test_aRetailDeltaThatIsNotSetIsNotRead() public {
        _publish(DELTA | (uint256(200) << 184));
        assertEq(amm.quoteRetail(WETH, USDT, 4e18), _usdt(4, DELTA + _impact(4)));
    }

    /// A retail delta sits above where a size table's rows do, and is not one: the update still
    /// charges the fixed impact, and counts no fills.
    function test_aRetailDeltaIsNotASizeTable() public {
        uint256 withRetail = amm.quote(WETH, USDT, 4_000e18);
        _publish(DELTA);
        assertEq(withRetail, amm.quote(WETH, USDT, 4_000e18));
        assertEq(withRetail, _usdt(4_000, DELTA + _impact(4_000)));

        _publish(_slot0(DELTA, RETAIL));
        _swapRetail(4e18, _attestation(user, 0));
        assertEq(amm.fills(uint256(keccak256(abi.encodePacked(WETH, USDT))), 0), 0);
    }

    function test_aPairWithARetailDeltaIsActive() public view {
        assertTrue(amm.isActive(WETH, USDT));
        assertTrue(amm.isActive(USDT, WETH));
    }

    /// Retail never pays more than the rest. An update that says otherwise is refused where it
    /// would be priced from, and nowhere else.
    function test_aRetailDeltaAboveDeltaIsRefusedForRetailOnly() public {
        _publish(_slot0(DELTA, 6e14));
        vm.expectRevert(abi.encodeWithSelector(RetailDeltaAboveDelta.selector, 6e14, DELTA));
        amm.quoteRetail(WETH, USDT, 4e18);
        vm.expectRevert(abi.encodeWithSelector(RetailDeltaAboveDelta.selector, 6e14, DELTA));
        amm.quoteFillableRetail(WETH, USDT, 4e18);

        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(amm), 4e18);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(RetailDeltaAboveDelta.selector, 6e14, DELTA));
        amm.swapRetail(WETH, USDT, 4e18, 0, recipient, block.timestamp, a, signature);

        assertEq(amm.quote(WETH, USDT, 4e18), _usdt(4, DELTA + _impact(4)));
        // Equal to delta is not above it.
        _publish(_slot0(DELTA, DELTA));
        assertEq(amm.quoteRetail(WETH, USDT, 4e18), amm.quote(WETH, USDT, 4e18));
    }

    function testFuzz_retailNeverGetsLessThanTheRest(uint256 amountIn, uint256 retail, uint256 rows, bool sell0)
        public
    {
        retail = bound(retail, 0, DELTA / 1e12) * 1e12;
        _publish(_slot0(DELTA, retail) | (rows % 2 == 0 ? 0 : _steps()));
        (address tokenIn, address tokenOut) = sell0 ? (WETH, USDT) : (USDT, WETH);
        amountIn = sell0 ? bound(amountIn, 1e12, 12_000e18) : bound(amountIn, 1, 19_200_000e6);

        assertGe(amm.quoteRetail(tokenIn, tokenOut, amountIn), amm.quote(tokenIn, tokenOut, amountIn));
        (uint256 fillable, uint256 out) = amm.quoteFillableRetail(tokenIn, tokenOut, amountIn);
        assertEq(fillable, amountIn);
        assertEq(out, amm.quoteRetail(tokenIn, tokenOut, amountIn));
    }

    /// Size charges are about the vault, not about who trades: retail pays them on top of its
    /// own delta, and its fills and everyone else's continue one count.
    function test_retailPaysTheSizeTableOnTopOfItsDelta() public {
        _publish(_slot0(DELTA, RETAIL) | _steps());
        // 8,000 WETH is 20% of the vault: half free, half at 2 bp, so 1 bp over the delta.
        assertEq(amm.quote(WETH, USDT, 8_000e18), _usdt(8_000, DELTA + 1e14));
        assertEq(amm.quoteRetail(WETH, USDT, 8_000e18), _usdt(8_000, RETAIL + 1e14));

        // A plain fill of the free 10%, then a retail one of the next 10%, all of it at 2 bp.
        MockToken(WETH).mint(address(amm), 4_000e18);
        assertEq(amm.swap(WETH, USDT, 4_000e18, 0, recipient, block.timestamp), _usdt(4_000, DELTA));
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        a.maxAmountIn = 4_000e18;
        assertEq(_swapRetail(4_000e18, a), _usdt(4_000, RETAIL + 2e14));
        // And the plain fill after that starts where the retail one stopped: 10% more at 2 bp.
        assertEq(amm.quote(WETH, USDT, 4_000e18), _usdt(4_000, DELTA + 2e14));
    }

    /// With the vault's allowance as the limit, the better price fills less input for the same
    /// output, and still pays what `quoteRetail` says for it.
    function test_quoteFillableRetailSizesAtTheRetailPrice() public {
        vm.prank(vault);
        MockToken(USDT).approve(address(amm), 1_600_000e6);
        (uint256 fillable, uint256 out) = amm.quoteFillableRetail(WETH, USDT, 4_000e18);
        (uint256 plainFillable,) = amm.quoteFillable(WETH, USDT, 4_000e18);
        assertLt(fillable, plainFillable);
        assertLe(out, 1_600_000e6);
        assertEq(out, amm.quoteRetail(WETH, USDT, fillable));
    }

    function test_theRetailQuotesRevertWhilePaused() public {
        vm.prank(owner);
        amm.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        amm.quoteRetail(WETH, USDT, 4e18);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        amm.quoteFillableRetail(WETH, USDT, 4e18);
    }

    function test_supportsInterface_advertisesTheRetailExtension() public view {
        assertTrue(ERC165Checker.supportsInterface(address(amm), type(IPropAMMRetail).interfaceId));
    }

    // ------------------------------------------------------------------
    // The swap
    // ------------------------------------------------------------------

    function test_swapRetailFillsAtTheRetailPrice() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 7);
        bytes memory signature = _sign(a);
        uint256 quoted = amm.quoteRetail(WETH, USDT, 4e18);
        assertGt(quoted, amm.quote(WETH, USDT, 4e18));

        MockToken(WETH).mint(address(amm), 4e18);
        vm.expectEmit(address(amm));
        emit IPropAMMRetail.RetailFill(signer, user, 7);
        vm.expectEmit(address(amm));
        emit IPropAMM.Swapped(router, WETH, USDT, 4e18, quoted, recipient);
        vm.prank(router, user);
        uint256 out = amm.swapRetail(WETH, USDT, 4e18, 0, recipient, block.timestamp, a, signature);

        assertEq(out, quoted);
        assertEq(MockToken(USDT).balanceOf(recipient), quoted);
        assertEq(MockToken(WETH).balanceOf(vault), 40_004e18);
        assertTrue(amm.retailNonceUsed(signer, 7));
        assertFalse(amm.retailNonceUsed(signer, 6));
    }

    /// `swap` itself is not moved by any of this: it fills at `delta`, attestation or no.
    function test_swapStillFillsAtDelta() public {
        MockToken(WETH).mint(address(amm), 4e18);
        vm.prank(router, user);
        assertEq(amm.swap(WETH, USDT, 4e18, 0, recipient, block.timestamp), _usdt(4, DELTA + _impact(4)));
    }

    /// The account the venue named has to take part: as the transaction's sender, the caller or
    /// the recipient. Each is enough.
    function test_theAccountMaySendTheTransactionCallOrReceive() public {
        // Sends: the user's wallet through a router, or the venue's relayer for a gasless swap.
        _swapRetail(user, router, 1e18, _attestation(user, 0), _sign(_attestation(user, 0)));
        // Calls: a direct swap, sent by someone else (a smart wallet through a bundler).
        _swapRetail(stranger, user, 1e18, _attestation(user, 1), _sign(_attestation(user, 1)));
        // Receives: nobody the attestation names sends or calls, and the output goes to it.
        IPropAMMRetail.RetailAttestation memory a = _attestation(recipient, 2);
        _swapRetail(stranger, router, 1e18, a, _sign(a));
    }

    /// Lifted out of the mempool, an attestation is of no use to another sender: the account it
    /// names is not in their swap.
    function test_anAttestationForSomeoneElseIsRefused() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, stranger);
        vm.expectRevert(abi.encodeWithSelector(AttestationAccountAbsent.selector, user));
        amm.swapRetail(WETH, USDT, 1e18, 0, stranger, block.timestamp, a, signature);
    }

    /// One attestation, one swap: the nonce is spent by the first, and by a swap of only part of
    /// what it allowed.
    function test_anAttestationIsGoodOnce() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 3);
        bytes memory signature = _sign(a);
        _swapRetail(user, router, 1e18, a, signature);

        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationUsed.selector, signer, 3));
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);

        // Its neighbours in the same word are untouched, and so is the same nonce one word up.
        _swapRetail(1e18, _attestation(user, 2));
        _swapRetail(1e18, _attestation(user, 4));
        _swapRetail(1e18, _attestation(user, 3 + 256));
    }

    /// A swap that reverts takes the spending back with it: the attestation is still good.
    function test_aRevertedSwapDoesNotSpendTheAttestation() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(amm), 1e18);
        uint256 quoted = amm.quoteRetail(WETH, USDT, 1e18);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(InsufficientOutput.selector, quoted + 1, quoted));
        amm.swapRetail(WETH, USDT, 1e18, quoted + 1, recipient, block.timestamp, a, signature);

        assertFalse(amm.retailNonceUsed(signer, 0));
        vm.prank(router, user);
        assertEq(amm.swapRetail(WETH, USDT, 1e18, quoted, recipient, block.timestamp, a, signature), quoted);
    }

    /// Nonces are each signer's own: one venue cannot spend another's.
    function test_noncesArePerSigner() public {
        (address other, uint256 otherKey) = makeAddrAndKey("another venue");
        vm.prank(owner);
        amm.addRetailSigner(other);

        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        _swapRetail(user, router, 1e18, a, _sign(otherKey, amm, a));
        assertTrue(amm.retailNonceUsed(other, 0));
        assertFalse(amm.retailNonceUsed(signer, 0));
        _swapRetail(user, router, 1e18, a, _sign(a));
    }

    function test_anAttestationCoversUpToItsAmount() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(amm), 10e18 + 1);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationAmountExceeded.selector, 10e18, 10e18 + 1));
        amm.swapRetail(WETH, USDT, 10e18 + 1, 0, recipient, block.timestamp, a, signature);

        vm.prank(router, user);
        amm.swapRetail(WETH, USDT, 10e18, 0, recipient, block.timestamp, a, signature);
    }

    function test_anAttestationIsForOnePairAndDirection() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        // The other direction of the same pair.
        MockToken(USDT).mint(address(amm), 1_600e6);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationForAnotherPair.selector, WETH, USDT));
        amm.swapRetail(USDT, WETH, 1_600e6, 0, recipient, block.timestamp, a, signature);
        // Another token out.
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationForAnotherPair.selector, WETH, USDT));
        amm.swapRetail(WETH, address(0xdead), 1e18, 0, recipient, block.timestamp, a, signature);
        // Another token in.
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationForAnotherPair.selector, WETH, USDT));
        amm.swapRetail(address(0xdead), USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }

    function test_anAttestationExpires() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        uint256 expiry = a.expiry;

        // Good through its last second.
        vm.warp(expiry);
        _publish(_slot0(DELTA, RETAIL));
        uint256 last = vm.snapshotState();
        _swapRetail(user, router, 1e18, a, signature);

        vm.revertToState(last);
        vm.warp(expiry + 1);
        _publish(_slot0(DELTA, RETAIL));
        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationExpired.selector, expiry));
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }

    /// Only a retail signer's word counts, and only over the attestation the swap carries: one
    /// changed after signing recovers to some other address.
    function test_onlyARetailSignersAttestationCounts() public {
        (address other, uint256 otherKey) = makeAddrAndKey("not a venue");
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        MockToken(WETH).mint(address(amm), 20e18);

        bytes memory signature = _sign(otherKey, amm, a);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(NotRetailSigner.selector, other));
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);

        // Each field in turn, changed under a signature that does not cover the change.
        signature = _sign(a);
        IPropAMMRetail.RetailAttestation memory changed = _attestation(stranger, 0);
        _expectNotASigner(stranger, 1e18, changed, signature);
        changed = _attestation(user, 0);
        changed.maxAmountIn = 20e18;
        _expectNotASigner(user, 20e18, changed, signature);
        changed = _attestation(user, 0);
        changed.expiry += 1;
        _expectNotASigner(user, 1e18, changed, signature);
        changed = _attestation(user, 1);
        _expectNotASigner(user, 1e18, changed, signature);

        // Unchanged, it is good.
        vm.prank(router, user);
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }

    function _expectNotASigner(
        address origin,
        uint256 amountIn,
        IPropAMMRetail.RetailAttestation memory a,
        bytes memory signature
    ) internal {
        vm.prank(router, origin);
        vm.expectPartialRevert(NotRetailSigner.selector);
        amm.swapRetail(WETH, USDT, amountIn, 0, recipient, block.timestamp, a, signature);
    }

    /// An attestation is signed for one instance on one chain, and is good nowhere else, even
    /// where the same signer is trusted.
    function test_anAttestationIsForOneInstanceAndChain() public {
        PropAMM second = _deploy();
        vm.prank(owner);
        second.addRetailSigner(signer);
        assertNotEq(second.domainSeparator(), amm.domainSeparator());

        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(second), 1e18);
        vm.prank(router, user);
        vm.expectPartialRevert(NotRetailSigner.selector);
        second.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);

        bytes32 here = amm.domainSeparator();
        vm.chainId(block.chainid + 1);
        assertNotEq(amm.domainSeparator(), here);
        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, user);
        vm.expectPartialRevert(NotRetailSigner.selector);
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }

    /// The domain is the standard EIP-712 one, so a wallet or a library signs for it as it is.
    function test_theDomainIsTheStandardOne() public view {
        assertEq(
            amm.domainSeparator(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("PropAMM"),
                    keccak256("1"),
                    block.chainid,
                    address(amm)
                )
            )
        );
    }

    function test_swapRetailRevertsWhilePaused() public {
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        bytes memory signature = _sign(a);
        vm.prank(owner);
        amm.pause();
        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, user);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }

    /// Like `swap`, and sharing its guard: neither can be nested inside the other.
    function test_swapRetailCannotBeReentered() public {
        vm.etch(WETH, address(new ReentrantToken()).code);
        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 0);
        IPropAMMRetail.RetailAttestation memory inner = _attestation(user, 1);
        bytes memory signature = _sign(a);
        MockToken(WETH).mint(address(amm), 2e18);

        ReentrantToken(WETH)
            .arm(
                address(amm),
                abi.encodeCall(
                    IPropAMMRetail.swapRetail, (WETH, USDT, 1e18, 0, recipient, block.timestamp, inner, _sign(inner))
                )
            );
        vm.prank(router, user);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);

        ReentrantToken(WETH)
            .arm(address(amm), abi.encodeCall(IPropAMMRetail.swapRetail, (WETH, USDT, 1e18, 0, recipient, 0, a, "")));
        vm.prank(router, user);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        amm.swap(WETH, USDT, 1e18, 0, recipient, block.timestamp);
    }

    // ------------------------------------------------------------------
    // The signers
    // ------------------------------------------------------------------

    function test_onlyTheOwnerManagesRetailSigners() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger));
        amm.addRetailSigner(stranger);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, stranger));
        amm.removeRetailSigner(signer);
        assertTrue(amm.retailSigners(signer));
        assertFalse(amm.retailSigners(stranger));
    }

    function test_addingAndRemovingASignerLogsOnlyRealChanges() public {
        vm.startPrank(owner);
        vm.expectRevert(InvalidRetailSigner.selector);
        amm.addRetailSigner(address(0));
        vm.expectRevert(abi.encodeWithSelector(RetailSignerAlreadyAdded.selector, signer));
        amm.addRetailSigner(signer);
        vm.expectRevert(abi.encodeWithSelector(NotRetailSigner.selector, stranger));
        amm.removeRetailSigner(stranger);

        vm.expectEmit(address(amm));
        emit PropAMM.RetailSignerAdded(stranger);
        amm.addRetailSigner(stranger);
        assertTrue(amm.retailSigners(stranger));
        vm.expectEmit(address(amm));
        emit PropAMM.RetailSignerRemoved(stranger);
        amm.removeRetailSigner(stranger);
        assertFalse(amm.retailSigners(stranger));
        vm.stopPrank();
    }

    /// Removing a signer stops every attestation it signed, and adding it back does not bring
    /// back one that was already used.
    function test_aRemovedSignersAttestationsStopWorking() public {
        IPropAMMRetail.RetailAttestation memory used = _attestation(user, 0);
        bytes memory usedSignature = _sign(used);
        _swapRetail(user, router, 1e18, used, usedSignature);

        IPropAMMRetail.RetailAttestation memory a = _attestation(user, 1);
        bytes memory signature = _sign(a);
        vm.prank(owner);
        amm.removeRetailSigner(signer);
        MockToken(WETH).mint(address(amm), 1e18);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(NotRetailSigner.selector, signer));
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);

        vm.prank(owner);
        amm.addRetailSigner(signer);
        vm.prank(router, user);
        vm.expectRevert(abi.encodeWithSelector(AttestationUsed.selector, signer, 0));
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, used, usedSignature);
        vm.prank(router, user);
        amm.swapRetail(WETH, USDT, 1e18, 0, recipient, block.timestamp, a, signature);
    }
}

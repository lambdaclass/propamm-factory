// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
    PropAMM,
    InvalidOracle,
    NoVault,
    NotAToken,
    PairAlreadyExists,
    UnsupportedDecimals,
    UnsupportedPair,
    UpdaterAlreadyAuthorized,
    UpdaterNotAuthorized
} from "../src/PropAMM.sol";
import {IPropAMM} from "../src/interfaces/IPropAMM.sol";
import {MockPUR} from "./mocks/MockPUR.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// A contract with code whose every call reverts, `decimals()` included: listed, it could never
/// be quoted, since `_pricing` reads its decimals on every quote.
contract NoDecimalsToken {
    fallback() external {
        revert();
    }
}

/// A registry from before `isUpdater(address,address)`: it records keys per caller under another
/// name, so a call to `isUpdater` reverts on the unknown selector.
contract LegacyRegistry {
    mapping(address target => mapping(address updater => bool)) public authorized;

    function addUpdater(address updater) external {
        authorized[msg.sender][updater] = true;
    }

    function removeUpdater(address updater) external {
        authorized[msg.sender][updater] = false;
    }
}

contract PropAMMTest is Test {
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    // The PUR oracle address these tests initialize against. `initialize` calls it straight
    // away, so tests need code there.
    address constant ORACLE = 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81;
    /// keccak256(token0 ++ token1) over the sorted pair: the registry lane, and the key of
    /// `pairVaults`.
    uint256 constant USDC_USDT_KEY = uint256(keccak256(abi.encodePacked(USDC, USDT)));

    address owner = makeAddr("owner");
    address vault = makeAddr("vault");
    address otherVault = makeAddr("other-vault");
    address updater = makeAddr("updater");
    PropAMM propAmm;

    function setUp() public {
        // Same trick as `make local`'s anvil_setCode: a bare test chain has no code at the
        // PUR address under test, so initialize's addUpdater calls would go nowhere.
        vm.etch(ORACLE, address(new MockPUR()).code);
        // Likewise for the two tokens the pair tests list: `_addPair` refuses a token address
        // without code.
        vm.etch(USDC, address(new MockERC20()).code);
        vm.etch(USDT, address(new MockERC20()).code);

        address[] memory updaters = new address[](1);
        updaters[0] = updater;
        propAmm = _deploy(updaters, new PropAMM.PairConfig[](0));
    }

    //------------------------------
    // initialize
    //------------------------------

    function test_initialize_registersUpdatersWithTheOracle() public view {
        assertTrue(MockPUR(ORACLE).isUpdater(address(propAmm), updater));
        // Only the addresses passed in, nothing else.
        assertFalse(MockPUR(ORACLE).isUpdater(address(propAmm), owner));
    }

    /// The keys an instance starts with are on its own log, like the ones added later. That holds
    /// for instances created on this implementation; one upgraded from an earlier implementation
    /// logged its creation keys nowhere of its own, so for it the registry's log is the record.
    /// Audit F-16 (and F-15).
    function test_initialize_emitsUpdaterAuthorizedForEachUpdater() public {
        // The implementation's CREATE must not be the call the expectation guards.
        address implementation = address(new PropAMM());
        address[] memory ups = new address[](2);
        ups[0] = makeAddr("first-updater");
        ups[1] = makeAddr("second-updater");
        // `_proxy` deploys the proxy with this contract's next CREATE, so the emitter is known.
        address proxy = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectEmit(true, true, false, true, proxy);
        emit PropAMM.UpdaterAuthorized(ups[0], ORACLE);
        vm.expectEmit(true, true, false, true, proxy);
        emit PropAMM.UpdaterAuthorized(ups[1], ORACLE);
        PropAMM instance = _proxy(implementation, ups, new PropAMM.PairConfig[](0));
        assertEq(address(instance), proxy, "predicted emitter");
    }

    function test_initialize_listsThePairsItIsGivenWithTheirVaults() public {
        // The implementation is deployed before the expectation is set: a CREATE between
        // expectEmit and the call it guards would consume the expectation itself.
        address implementation = address(new PropAMM());
        // Reversed on purpose: initialize canonicalizes exactly like addPair does, and the event
        // carries the canonical order. The emitter is the proxy, whose address is not known until
        // it exists, so the expectation is not pinned to an address.
        vm.expectEmit(true, true, true, true);
        emit PropAMM.PairAdded(USDC, USDT, vault);
        PropAMM instance = _proxy(implementation, new address[](0), _one(USDT, USDC, vault));

        IPropAMM.TokenPair[] memory pairs = instance.getPairs();
        assertEq(pairs.length, 1);
        assertEq(pairs[0].token0, USDC);
        assertEq(pairs[0].token1, USDT);
        assertEq(instance.vaultFor(USDT, USDC), vault);
        assertEq(instance.vaultFor(USDC, USDT), vault);
        assertEq(instance.pairVaults(USDC_USDT_KEY), vault);
    }

    function test_initialize_refusesAPairWithNoVault() public {
        // Same as above: the implementation's CREATE must not be the call expectRevert guards.
        address implementation = address(new PropAMM());
        vm.expectRevert(abi.encodeWithSelector(NoVault.selector, USDC, USDT));
        _proxy(implementation, new address[](0), _one(USDC, USDT, address(0)));
    }

    /// The registry is no longer baked into the implementation, so `initialize` has to record
    /// the one it was handed: everything else on the contract reads prices through it.
    function test_initialize_storesTheOracleItIsGiven() public view {
        assertEq(address(propAmm.oracle()), ORACLE);
    }

    /// `initialize` runs `__Pausable_init`, and an instance upgraded onto this implementation
    /// without re-running it lands on the same default: open for business.
    function test_initialize_startsUnpaused() public view {
        assertFalse(propAmm.paused());
    }

    /// With no updaters nothing else would ever call the oracle at creation, so an address
    /// without code would only surface later, as an instance that never quotes. Audit F-12.
    function test_initialize_refusesAnOracleWithoutCode() public {
        // The implementation's CREATE must not be the call expectRevert guards.
        address implementation = address(new PropAMM());
        address eoa = makeAddr("eoa-oracle");
        vm.expectRevert(abi.encodeWithSelector(InvalidOracle.selector, eoa));
        new ERC1967Proxy(
            implementation,
            abi.encodeCall(PropAMM.initialize, (owner, new address[](0), eoa, new PropAMM.PairConfig[](0)))
        );
    }

    //------------------------------
    // pairs
    //------------------------------

    function test_getPairs_isEmptyUntilAPairIsAdded() public view {
        assertEq(propAmm.getPairs().length, 0);
    }

    function test_addPair_storesTheCanonicalPairAndItsVault() public {
        vm.expectEmit(true, true, true, true, address(propAmm));
        emit PropAMM.PairAdded(USDC, USDT, vault);
        vm.prank(owner);
        propAmm.addPair(USDT, USDC, vault);

        IPropAMM.TokenPair[] memory pairs = propAmm.getPairs();
        assertEq(pairs.length, 1);
        // Stored canonically ordered, whatever order they were passed in.
        assertEq(pairs[0].token0, USDC);
        assertEq(pairs[0].token1, USDT);
        assertEq(propAmm.pairVaults(USDC_USDT_KEY), vault);
        assertEq(propAmm.vaultFor(USDC, USDT), vault);
    }

    function test_addPair_refusesAZeroVault() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(NoVault.selector, USDC, USDT));
        propAmm.addPair(USDC, USDT, address(0));
    }

    function test_addPair_refusesADuplicateInEitherOrder() public {
        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);
        vm.expectRevert(abi.encodeWithSelector(PairAlreadyExists.selector, USDC, USDT));
        propAmm.addPair(USDT, USDC, otherVault);
        vm.stopPrank();
    }

    /// A token address with no code (a typo, another chain's token, zero) would be listed and
    /// reported active while every quote reverts on `decimals()`, and would trade at the lane's
    /// price for whatever is deployed there later. Audit F-13.
    function test_addPair_refusesATokenWithoutCode() public {
        address ghost = makeAddr("ghost");
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(NotAToken.selector, ghost));
        propAmm.addPair(ghost, USDT, vault);
        vm.expectRevert(abi.encodeWithSelector(NotAToken.selector, address(0)));
        propAmm.addPair(address(0), USDT, vault);
        vm.stopPrank();
        assertEq(propAmm.getPairs().length, 0);
    }

    /// The vault is an account, not a token: an EOA that holds inventory is a valid vault.
    function test_addPair_acceptsAVaultWithoutCode() public {
        vm.prank(owner);
        propAmm.addPair(USDC, USDT, makeAddr("eoa-vault"));
        assertEq(propAmm.getPairs().length, 1);
    }

    /// `_pricing` multiplies by `10**decimals`; past 36 a pair can overflow on every quote, so it
    /// is refused when listed rather than discovered at the first quote. Audit F-13.
    function test_addPair_refusesMoreThan36Decimals() public {
        MockERC20 wide = new MockERC20();
        wide.setMeta("W", "W", 37);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UnsupportedDecimals.selector, address(wide), uint8(37)));
        propAmm.addPair(address(wide), USDT, vault);
    }

    function test_addPair_accepts36Decimals() public {
        MockERC20 wide = new MockERC20();
        wide.setMeta("W", "W", 36);
        vm.prank(owner);
        propAmm.addPair(address(wide), USDT, vault);
        assertEq(propAmm.getPairs().length, 1);
    }

    function test_addPair_refusesATokenWithoutDecimals() public {
        address bad = address(new NoDecimalsToken());
        vm.prank(owner);
        vm.expectRevert();
        propAmm.addPair(bad, USDT, vault);
    }

    //------------------------------
    // setPairVault
    //------------------------------

    function test_setPairVault_movesThePairToAnotherVault() public {
        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);

        vm.expectEmit(true, true, true, true, address(propAmm));
        emit PropAMM.PairVaultChanged(USDC, USDT, otherVault);
        propAmm.setPairVault(USDT, USDC, otherVault);
        vm.stopPrank();

        assertEq(propAmm.vaultFor(USDC, USDT), otherVault);
        assertEq(propAmm.pairVaults(USDC_USDT_KEY), otherVault);
        // The listing itself is untouched: same pair, new account behind it.
        assertEq(propAmm.getPairs().length, 1);
    }

    function test_setPairVault_refusesAnUnregisteredPair() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UnsupportedPair.selector, USDC, USDT));
        propAmm.setPairVault(USDC, USDT, vault);
    }

    function test_setPairVault_refusesAZeroVault() public {
        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);
        vm.expectRevert(abi.encodeWithSelector(NoVault.selector, USDC, USDT));
        propAmm.setPairVault(USDC, USDT, address(0));
        vm.stopPrank();
    }

    //------------------------------
    // removePair
    //------------------------------

    function test_removePair_clearsTheVaultAndEmits() public {
        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);

        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.PairRemoved(USDC, USDT);
        propAmm.removePair(USDT, USDC);
        vm.stopPrank();

        assertEq(propAmm.getPairs().length, 0);
        // Cleared, not left behind: the zero vault is what unregisters the pair, and one re-added
        // later must name its vault again rather than silently inherit this one.
        assertEq(propAmm.pairVaults(USDC_USDT_KEY), address(0));
        vm.expectRevert(abi.encodeWithSelector(UnsupportedPair.selector, USDC, USDT));
        propAmm.vaultFor(USDC, USDT);
    }

    function test_removePair_refusesAnUnregisteredPair() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UnsupportedPair.selector, USDC, USDT));
        propAmm.removePair(USDC, USDT);
    }

    //------------------------------
    // access
    //------------------------------

    function test_nonOwnerCannotManageVaults() public {
        vm.prank(owner);
        propAmm.addPair(USDC, USDT, vault);
        // Real tokens, so the only reason `addPair` can revert below is the caller. Deployed up
        // front: a CREATE between expectRevert and the call it guards would consume the expectation.
        address tokenA = address(new MockERC20());
        address tokenB = address(new MockERC20());

        address rando = makeAddr("rando");
        // The exact error, not any revert, so a revert for any other reason cannot pass for
        // access control.
        bytes memory notOwner = abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, rando);
        vm.startPrank(rando);
        vm.expectRevert(notOwner);
        propAmm.addPair(tokenA, tokenB, vault);
        vm.expectRevert(notOwner);
        propAmm.setPairVault(USDC, USDT, rando);
        vm.expectRevert(notOwner);
        propAmm.removePair(USDC, USDT);
        vm.stopPrank();
    }

    //------------------------------
    // setOracle, addUpdater, removeUpdater, withdrawERC20
    //------------------------------

    function test_setOracle_storesTheNewOracleAndEmits() public {
        address newOracle = makeAddr("new-oracle");
        // `setOracle` refuses an address without code. Etched before the expectation: a CREATE
        // between expectEmit and the call it guards would consume the expectation itself.
        vm.etch(newOracle, address(new MockPUR()).code);
        vm.expectEmit(true, false, false, true, address(propAmm));
        emit PropAMM.OracleChanged(newOracle);
        vm.prank(owner);
        propAmm.setOracle(newOracle);
        assertEq(address(propAmm.oracle()), newOracle);
    }

    /// An oracle without code leaves an instance that can never quote, and `isActive` reverting
    /// on it. Audit F-12.
    function test_setOracle_refusesAnAddressWithoutCode() public {
        address eoa = makeAddr("eoa-oracle");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(InvalidOracle.selector, eoa));
        propAmm.setOracle(eoa);
        assertEq(address(propAmm.oracle()), ORACLE);
    }

    function test_setOracle_refusesTheZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(InvalidOracle.selector, address(0)));
        propAmm.setOracle(address(0));
        assertEq(address(propAmm.oracle()), ORACLE);
    }

    /// The registry logs its own `UpdaterAdded(target, updater)` / `UpdaterRemoved(target,
    /// updater)` in the same transaction as the instance's event. Sharing their topic0 with fields
    /// in other positions would let a consumer filtering by topic alone read one as the other.
    function test_updaterEvents_doNotShareATopicWithTheRegistrysEvents() public pure {
        assertTrue(PropAMM.UpdaterAuthorized.selector != keccak256("UpdaterAdded(address,address)"), "added");
        assertTrue(PropAMM.UpdaterRevoked.selector != keccak256("UpdaterRemoved(address,address)"), "removed");
    }

    function test_addUpdater_registersWithTheOracleAndEmits() public {
        address another = makeAddr("another-updater");
        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.UpdaterAuthorized(another, ORACLE);
        vm.prank(owner);
        propAmm.addUpdater(another);
        assertTrue(MockPUR(ORACLE).isUpdater(address(propAmm), another));
    }

    function test_removeUpdater_unregistersFromTheOracleAndEmits() public {
        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.UpdaterRevoked(updater, ORACLE);
        vm.prank(owner);
        propAmm.removeUpdater(updater);
        assertFalse(MockPUR(ORACLE).isUpdater(address(propAmm), updater));
    }

    /// The registry ignores a duplicate add, so the instance must not log one. Audit F-16.
    function test_addUpdater_refusesAKeyTheRegistryAlreadyHas() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UpdaterAlreadyAuthorized.selector, ORACLE, updater));
        propAmm.addUpdater(updater);
    }

    /// The registry ignores a remove for a key it does not have, so the instance must not log
    /// a revocation. Audit F-16.
    function test_removeUpdater_refusesAKeyTheRegistryDoesNotHave() public {
        address stranger = makeAddr("stranger");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UpdaterNotAuthorized.selector, ORACLE, stranger));
        propAmm.removeUpdater(stranger);
    }

    /// The audit's PoC: after a move, removeUpdater reaches only the new registry, so it must not
    /// log a revocation there while the key stays live on the old one. Audit F-16.
    function test_removeUpdater_afterSetOracle_refusesToLogARevocationThatDidNotHappen() public {
        address other = makeAddr("other-registry");
        vm.etch(other, address(new MockPUR()).code);
        vm.startPrank(owner);
        propAmm.setOracle(other);
        vm.expectRevert(abi.encodeWithSelector(UpdaterNotAuthorized.selector, other, updater));
        propAmm.removeUpdater(updater);
        vm.stopPrank();
        assertTrue(MockPUR(ORACLE).isUpdater(address(propAmm), updater), "still live on the old registry");
    }

    /// The registry scopes keys to this instance's address, so a key stays live on a registry the
    /// instance has left; the owner revokes it there without pointing the instance back. Audit F-16.
    function test_removeUpdaterFrom_revokesOnARegistryTheInstanceLeft() public {
        address other = makeAddr("other-registry");
        vm.etch(other, address(new MockPUR()).code);
        vm.startPrank(owner);
        propAmm.setOracle(other);
        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.UpdaterRevoked(updater, ORACLE);
        propAmm.removeUpdaterFrom(ORACLE, updater);
        vm.stopPrank();
        assertFalse(MockPUR(ORACLE).isUpdater(address(propAmm), updater));
        assertEq(address(propAmm.oracle()), other, "the current oracle is untouched");
    }

    /// Revoking must never depend on the registry answering `isUpdater`: on one that cannot (an
    /// older build), the removal is forwarded unchecked, so a compromised key can still be
    /// revoked. Review of audit F-16.
    function test_removeUpdaterFrom_revokesOnARegistryWithoutIsUpdater() public {
        LegacyRegistry legacy = new LegacyRegistry();
        // A key the instance authorized there before `isUpdater` was part of the interface.
        vm.prank(address(propAmm));
        legacy.addUpdater(updater);

        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.UpdaterRevoked(updater, address(legacy));
        vm.prank(owner);
        propAmm.removeUpdaterFrom(address(legacy), updater);
        assertFalse(legacy.authorized(address(propAmm), updater));
    }

    /// A mistyped or zero registry gets the same named error `setOracle` gives it, not a bare
    /// revert from decoding nothing. Review of audit F-16.
    function test_removeUpdaterFrom_refusesARegistryWithoutCode() public {
        address eoa = makeAddr("eoa-registry");
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(InvalidOracle.selector, eoa));
        propAmm.removeUpdaterFrom(eoa, updater);
        vm.expectRevert(abi.encodeWithSelector(InvalidOracle.selector, address(0)));
        propAmm.removeUpdaterFrom(address(0), updater);
        vm.stopPrank();
    }

    function test_removeUpdaterFrom_refusesAKeyThatRegistryDoesNotHave() public {
        address stranger = makeAddr("stranger");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UpdaterNotAuthorized.selector, ORACLE, stranger));
        propAmm.removeUpdaterFrom(ORACLE, stranger);
    }

    function test_withdrawERC20_movesTheTokensAndEmits() public {
        MockERC20 token = new MockERC20();
        token.mint(address(propAmm), 1_000);
        address to = makeAddr("recipient");

        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.ERC20Withdrawn(address(token), to, 400);
        vm.prank(owner);
        propAmm.withdrawERC20(address(token), to, 400);
        assertEq(token.balanceOf(to), 400);
        assertEq(token.balanceOf(address(propAmm)), 600);
    }

    function test_nonOwnerCannotManageOracleUpdatersOrFunds() public {
        address rando = makeAddr("rando");
        // A real oracle, so the only reason `setOracle` can revert below is the caller. Deployed
        // up front: a CREATE between expectRevert and the call it guards would consume the expectation.
        address newOracle = address(new MockPUR());
        // The exact error, not any revert, so a revert for any other reason cannot pass for
        // access control.
        bytes memory notOwner = abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, rando);
        vm.startPrank(rando);
        vm.expectRevert(notOwner);
        propAmm.setOracle(newOracle);
        vm.expectRevert(notOwner);
        propAmm.addUpdater(rando);
        vm.expectRevert(notOwner);
        propAmm.removeUpdater(updater);
        vm.expectRevert(notOwner);
        propAmm.removeUpdaterFrom(ORACLE, updater);
        vm.expectRevert(notOwner);
        propAmm.withdrawERC20(USDC, rando, 1);
        vm.stopPrank();
    }

    //------------------------------
    // Helpers
    //------------------------------

    function _deploy(address[] memory updaters, PropAMM.PairConfig[] memory pairs) internal returns (PropAMM) {
        return _proxy(address(new PropAMM()), updaters, pairs);
    }

    /// PropAMM is UUPS: the implementation holds no state, all calls go through the proxy. Split
    /// from `_deploy` so a test can put the implementation's CREATE before a cheatcode expectation
    /// and leave the proxy's CREATE, which runs initialize, as the call the expectation guards.
    function _proxy(address implementation, address[] memory updaters, PropAMM.PairConfig[] memory pairs)
        internal
        returns (PropAMM)
    {
        return PropAMM(
            address(
                new ERC1967Proxy(implementation, abi.encodeCall(PropAMM.initialize, (owner, updaters, ORACLE, pairs)))
            )
        );
    }

    function _one(address tokenX, address tokenY, address vault_)
        internal
        pure
        returns (PropAMM.PairConfig[] memory pairs)
    {
        pairs = new PropAMM.PairConfig[](1);
        pairs[0] = PropAMM.PairConfig({token0: tokenX, token1: tokenY, vault: vault_});
    }
}

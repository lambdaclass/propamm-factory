// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
    PropAMM,
    IdenticalTokens,
    InvalidOracle,
    NoVault,
    NotAToken,
    OracleUnchanged,
    PairAlreadyExists,
    UnsupportedDecimals,
    UnsupportedPair,
    UpdaterAlreadyAuthorized,
    UpdaterNotAuthorized,
    VaultUnchanged
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

/// A registry that logs each change, as the real one does, so a test can see where its log
/// falls relative to the instance's own. It answers `isUpdater`, which the instance asks before
/// either change.
contract LoggingRegistry {
    event UpdaterAdded(address indexed target, address indexed updater);
    event UpdaterRemoved(address indexed target, address indexed updater);

    mapping(address target => mapping(address updater => bool)) public isUpdater;

    function addUpdater(address updater) external {
        isUpdater[msg.sender][updater] = true;
        emit UpdaterAdded(msg.sender, updater);
    }

    function removeUpdater(address updater) external {
        isUpdater[msg.sender][updater] = false;
        emit UpdaterRemoved(msg.sender, updater);
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

    function test_initialize_refusesAPairOfOneToken() public {
        address implementation = address(new PropAMM());
        vm.expectRevert(abi.encodeWithSelector(IdenticalTokens.selector, USDC));
        _proxy(implementation, new address[](0), _one(USDC, USDC, vault));
    }

    /// The registry is no longer baked into the implementation, so `initialize` has to record
    /// the one it was handed: everything else on the contract reads prices through it.
    function test_initialize_storesTheOracleItIsGiven() public view {
        assertEq(address(propAmm.oracle()), ORACLE);
    }

    /// What `setOracle` and `addUpdater` log later, `initialize` logs for the oracle and updaters
    /// an instance starts with, in the order it works: the oracle, then each updater as it is
    /// registered.
    function test_initialize_logsItsOracleThenEachUpdater() public {
        address implementation = address(new PropAMM());
        address[] memory updaters = new address[](2);
        updaters[0] = updater;
        updaters[1] = makeAddr("second-updater");

        vm.expectEmit(true, true, true, true);
        emit PropAMM.OracleChanged(ORACLE);
        vm.expectEmit(true, true, true, true);
        emit PropAMM.UpdaterAuthorized(updaters[0], ORACLE);
        vm.expectEmit(true, true, true, true);
        emit PropAMM.UpdaterAuthorized(updaters[1], ORACLE);
        _proxy(implementation, updaters, new PropAMM.PairConfig[](0));
    }

    /// `initialize` runs `__Pausable_init`, and an instance upgraded onto this implementation
    /// without re-running it lands on the same default: open for business.
    function test_initialize_startsUnpaused() public view {
        assertFalse(propAmm.paused());
    }

    /// No pauser until the owner names one: until then only the owner can pause, as before the
    /// role existed.
    function test_initialize_startsWithNoPauser() public view {
        assertEq(propAmm.pauser(), address(0));
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

    /// `getPairs` promises `token0 < token1`; a pair of one token would be listed as
    /// `token0 == token1` (audit F-11).
    function test_addPair_refusesTheSameTokenTwice() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdenticalTokens.selector, USDC));
        propAmm.addPair(USDC, USDC, vault);
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

    /// Each side of the pair is checked, whichever the bad token sorts as: paired with a token at
    /// a lower address it is token1, and with one at a higher address, token0.
    function test_addPair_refusesATokenWithoutCodeOnEitherSide() public {
        address ghost = makeAddr("ghost");
        (address below, address above) = _tokensAroundAnyAddress();
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(NotAToken.selector, ghost));
        propAmm.addPair(ghost, below, vault);
        vm.expectRevert(abi.encodeWithSelector(NotAToken.selector, ghost));
        propAmm.addPair(ghost, above, vault);
        vm.stopPrank();
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

    /// On either side of the pair, like the check for code.
    function test_addPair_refusesMoreThan36DecimalsOnEitherSide() public {
        MockERC20 wide = new MockERC20();
        wide.setMeta("W", "W", 37);
        (address below, address above) = _tokensAroundAnyAddress();
        bytes memory tooWide = abi.encodeWithSelector(UnsupportedDecimals.selector, address(wide), uint8(37));
        vm.startPrank(owner);
        vm.expectRevert(tooWide);
        propAmm.addPair(address(wide), below, vault);
        vm.expectRevert(tooWide);
        propAmm.addPair(address(wide), above, vault);
        vm.stopPrank();
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

    /// Naming the vault the pair already has changes nothing, so it is refused: `PairVaultChanged`
    /// is what indexers move a pair's inventory on. In either token order, as everywhere.
    function test_setPairVault_refusesTheVaultThePairAlreadyHas() public {
        vm.startPrank(owner);
        propAmm.addPair(USDC, USDT, vault);

        vm.expectRevert(abi.encodeWithSelector(VaultUnchanged.selector, USDC, USDT, vault));
        propAmm.setPairVault(USDC, USDT, vault);
        vm.expectRevert(abi.encodeWithSelector(VaultUnchanged.selector, USDC, USDT, vault));
        propAmm.setPairVault(USDT, USDC, vault);
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

    /// Naming the registry the instance already reads changes nothing, so it is refused, like
    /// `setPairVault` to the vault a pair already has: `OracleChanged` reports a move.
    function test_setOracle_refusesTheOracleItAlreadyHas() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(OracleUnchanged.selector, ORACLE));
        propAmm.setOracle(ORACLE);
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

    /// Each call is refused for not being the owner's, by name. The withdrawal is of a token the
    /// instance holds, so with the owner check gone it would go through, not revert for want of
    /// a balance.
    function test_nonOwnerCannotManageOracleUpdatersOrFunds() public {
        MockERC20 token = new MockERC20();
        token.mint(address(propAmm), 1_000);
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
        propAmm.withdrawERC20(address(token), rando, 1);
        vm.stopPrank();
    }

    /// The instance logs a change before it calls out to make it, so whatever the callee logs
    /// (or anything it calls back into) comes after, in the order things happened: the registry's
    /// own record of an updater follows the instance's, and a token's Transfer follows the
    /// withdrawal that caused it.
    function test_eventsComeBeforeTheCallsTheyAnnounce() public {
        address registry = address(new LoggingRegistry());
        MockERC20 token = new MockERC20();
        token.mint(address(propAmm), 1_000);
        vm.startPrank(owner);
        propAmm.setOracle(registry);

        vm.recordLogs();
        propAmm.addUpdater(updater);
        _assertInstanceLoggedFirst(PropAMM.UpdaterAuthorized.selector, registry);

        propAmm.removeUpdater(updater);
        _assertInstanceLoggedFirst(PropAMM.UpdaterRevoked.selector, registry);

        propAmm.withdrawERC20(address(token), owner, 400);
        _assertInstanceLoggedFirst(PropAMM.ERC20Withdrawn.selector, address(token));
        vm.stopPrank();
    }

    /// The same at creation: each updater is logged by the instance, then by the registry.
    function test_initialize_logsEachUpdaterBeforeRegisteringIt() public {
        address registry = address(new LoggingRegistry());
        address implementation = address(new PropAMM());
        address[] memory updaters = new address[](1);
        updaters[0] = updater;

        vm.recordLogs();
        address instance = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeCall(PropAMM.initialize, (owner, updaters, registry, new PropAMM.PairConfig[](0)))
            )
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 mine = _indexOf(logs, instance, PropAMM.UpdaterAuthorized.selector);
        uint256 theirs = _indexOf(logs, registry, LoggingRegistry.UpdaterAdded.selector);
        assertLt(mine, theirs, "the registry logged the updater before the instance did");
    }

    //------------------------------
    // setPauser
    //------------------------------

    function test_setPauser_storesThePauserAndEmits() public {
        address pauser = makeAddr("pauser");
        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.PauserChanged(address(0), pauser);
        vm.prank(owner);
        propAmm.setPauser(pauser);
        assertEq(propAmm.pauser(), pauser);

        // Replacing and clearing announce the account they retire, so an indexer following the
        // log alone always knows who holds the role.
        address next = makeAddr("next-pauser");
        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.PauserChanged(pauser, next);
        vm.prank(owner);
        propAmm.setPauser(next);

        vm.expectEmit(true, true, false, true, address(propAmm));
        emit PropAMM.PauserChanged(next, address(0));
        vm.prank(owner);
        propAmm.setPauser(address(0));
        assertEq(propAmm.pauser(), address(0));
    }

    /// `pauser` is appended after `oracle`, at slot 5, so instances upgrading onto this
    /// implementation keep every earlier variable where it was. Pinned here because a variable
    /// declared above it would compile and pass every other test while shifting the layout.
    function test_setPauser_writesSlotFiveAndLeavesTheOracleAlone() public {
        address pauser = makeAddr("pauser");
        vm.prank(owner);
        propAmm.setPauser(pauser);

        assertEq(address(uint160(uint256(vm.load(address(propAmm), bytes32(uint256(5)))))), pauser);
        assertEq(address(uint160(uint256(vm.load(address(propAmm), bytes32(uint256(4)))))), ORACLE);
        assertEq(address(propAmm.oracle()), ORACLE);
    }

    /// While paused is when the owner most needs to swap a pauser out, so the setter must not
    /// be gated on the pause.
    function test_setPauser_worksWhilePaused() public {
        vm.prank(owner);
        propAmm.pause();

        address pauser = makeAddr("pauser");
        vm.prank(owner);
        propAmm.setPauser(pauser);
        assertEq(propAmm.pauser(), pauser);
    }

    /// The pauser can pause and nothing more: naming its own successor would let a leaked key
    /// keep the role after the owner moves to retire it.
    function test_setPauser_onlyTheOwnerCanSetIt() public {
        address pauser = makeAddr("pauser");
        vm.prank(owner);
        propAmm.setPauser(pauser);

        address rando = makeAddr("rando");
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, rando));
        propAmm.setPauser(rando);

        vm.prank(pauser);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, pauser));
        propAmm.setPauser(rando);

        assertEq(propAmm.pauser(), pauser);
    }

    /// An owner that is a multisig upgrades an existing instance and names its pauser in one
    /// transaction: `upgradeToAndCall` delegatecalls `setPauser` with the owner still the
    /// sender, so the owner check passes. No reinitializer is involved, so there is nothing for
    /// anyone else to call first.
    function test_setPauser_inTheUpgradeTransaction() public {
        address pauser = makeAddr("pauser");
        address newImplementation = address(new PropAMM());

        vm.prank(owner);
        propAmm.upgradeToAndCall(newImplementation, abi.encodeCall(PropAMM.setPauser, (pauser)));

        assertEq(
            address(uint160(uint256(vm.load(address(propAmm), ERC1967Utils.IMPLEMENTATION_SLOT)))), newImplementation
        );
        assertEq(propAmm.pauser(), pauser);

        vm.prank(pauser);
        propAmm.pause();
        assertTrue(propAmm.paused());
    }

    //------------------------------
    // Helpers
    //------------------------------

    /// Reads the logs recorded since the last read, which must be exactly two: the instance's
    /// `topic0`, then one from `callee`.
    function _assertInstanceLoggedFirst(bytes32 topic0, address callee) internal view {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2, "expected the instance's event and the callee's");
        assertEq(logs[0].emitter, address(propAmm), "the callee logged first");
        assertEq(logs[0].topics[0], topic0);
        assertEq(logs[1].emitter, callee);
    }

    function _indexOf(Vm.Log[] memory logs, address emitter, bytes32 topic0) internal pure returns (uint256) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == emitter && logs[i].topics[0] == topic0) return i;
        }
        revert("log not found");
    }

    /// Two tokens that any ordinary address sorts between: one just past the precompiles' range,
    /// one at the highest address there is. Call it before setting an expectation, since it
    /// deploys.
    function _tokensAroundAnyAddress() internal returns (address below, address above) {
        below = address(0x1000);
        above = address(type(uint160).max);
        bytes memory code = address(new MockERC20()).code;
        vm.etch(below, code);
        vm.etch(above, code);
    }

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

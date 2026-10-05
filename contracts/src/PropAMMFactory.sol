// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {PropAMM} from "./PropAMM.sol";

/// Deploys PropAMM instances with CREATE2, so anyone gets their own PropAMM by sending one
/// transaction, at an address computable before it exists (see computeAddress). The salt
/// commits to the creator and every parameter: the same creator calling twice with the same
/// parameters reverts (CREATE2 collision), and no one can front-run someone else's address.
///
/// PropAMM is UUPS, so what CREATE2 deploys is an ERC1967 proxy, not PropAMM itself. Every
/// instance delegates to the one implementation this factory deploys in its constructor, and
/// carries its own state and its own upgrade path: the owner the creator names can upgrade the
/// instance away from the shared implementation whenever they like.
contract PropAMMFactory {
    event PropAMMCreated(address indexed propAmm, address indexed creator, address oracle, address[] updaters);

    /// The implementation every instance created here starts out delegating to.
    PropAMM public immutable implementation;

    /// Every PropAMM ever created through this factory, in creation order.
    address[] public allPropAMMs;

    mapping(address creator => address[] propAmms) private _byCreator;

    constructor() {
        implementation = new PropAMM();
    }

    /// Creates a PropAMM owned by `owner`, who need not be the caller: `owner` can manage the
    /// instance's pairs, their vaults and updaters afterwards, and upgrade it (see PropAMM's
    /// onlyOwner functions), while the caller keeps no rights over it beyond appearing in
    /// `propAMMsOf`. Each pair names the vault it fills from; there is no instance-wide vault.
    /// `oracle` is the registry the instance reads prices from and registers its updaters with.
    /// The pairs and their vaults are not in the event: the instance emits one `PairAdded` per
    /// pair from `initialize`, in this same transaction, and that is the one source of pair state.
    function createPropAMM(
        address owner,
        address oracle,
        address[] calldata updaters,
        PropAMM.PairConfig[] calldata pairs
    ) external returns (address propAmm) {
        propAmm = address(
            new ERC1967Proxy{salt: _salt(msg.sender, owner, oracle, updaters, pairs)}(
                address(implementation), _initData(owner, oracle, updaters, pairs)
            )
        );
        allPropAMMs.push(propAmm);
        _byCreator[msg.sender].push(propAmm);
        emit PropAMMCreated(propAmm, msg.sender, oracle, updaters);
    }

    /// The address createPropAMM would deploy to for these inputs, without deploying. `creator` is
    /// the account that will send the createPropAMM transaction and `owner` the account it will
    /// name as the instance's owner; the salt commits to both, so passing them the wrong way round
    /// predicts a different instance rather than failing.
    function computeAddress(
        address creator,
        address owner,
        address oracle,
        address[] calldata updaters,
        PropAMM.PairConfig[] calldata pairs
    ) external view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(address(implementation), _initData(owner, oracle, updaters, pairs))
            )
        );
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), address(this), _salt(creator, owner, oracle, updaters, pairs), initCodeHash
                        )
                    )
                )
            )
        );
    }

    /// The CREATE2 salt for an instance, committing to the creator and every parameter, the
    /// oracle and the pairs' vaults included: two creations that differ only in a vault land at
    /// different addresses. Shared by createPropAMM and computeAddress so the two can never drift
    /// apart, which would make computeAddress silently predict wrong addresses.
    function _salt(
        address creator,
        address owner,
        address oracle,
        address[] calldata updaters,
        PropAMM.PairConfig[] calldata pairs
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(creator, owner, oracle, updaters, pairs));
    }

    /// The initialize call the proxy runs on construction. Part of the proxy's init code, so
    /// computeAddress has to build it exactly as createPropAMM does; hence one helper.
    function _initData(address owner, address oracle, address[] calldata updaters, PropAMM.PairConfig[] calldata pairs)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(PropAMM.initialize, (owner, updaters, oracle, pairs));
    }

    function propAMMsOf(address creator) external view returns (address[] memory) {
        return _byCreator[creator];
    }

    function allPropAMMsLength() external view returns (uint256) {
        return allPropAMMs.length;
    }
}

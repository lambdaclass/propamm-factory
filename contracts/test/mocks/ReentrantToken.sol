// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {MockToken} from "./MockToken.sol";

/// A token with a transfer hook, like an ERC-777 or any token that calls out while it moves:
/// once armed, its next transfer makes one call of the test's choosing before it returns, and a
/// failure of that call fails the transfer with the same revert data. Storage only, like
/// MockToken, so it works written over an address with vm.etch.
contract ReentrantToken is MockToken {
    address private _target;
    bytes private _callData;

    /// Arms the hook for one transfer. Call it after minting: a mint is a transfer too.
    function arm(address target, bytes calldata callData) external {
        _target = target;
        _callData = callData;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);

        address target = _target;
        if (target == address(0)) return;
        delete _target;
        (bool ok, bytes memory returned) = target.call(_callData);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(returned, 0x20), mload(returned))
            }
        }
    }
}

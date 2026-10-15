// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// Stand-in for the PUR registry that, unlike the shared `MockPUR` (used by this repo's other
/// suites, which deliberately leaves `setState` open to any caller so a test can drive it
/// directly), enforces the one invariant a security test about a compromised updater key needs
/// to be faithful to: only an address the instance registered via `addUpdater` may write state.
/// Without this, "the attacker holds the updater key" cannot be distinguished from "anyone can
/// write," and a test pranking as the updater proves nothing about authorization.
contract MockPURAuthenticated {
    error NotAnUpdater(address caller);

    mapping(address => bool) public isUpdater;

    uint256 public delta;
    uint256 public mid;

    function setState(uint256 delta_, uint256 mid_) external {
        require(isUpdater[msg.sender], NotAnUpdater(msg.sender));
        delta = delta_;
        mid = mid_;
    }

    function getState(uint256, uint32, uint32) external view returns (uint32 updateTimestamp, uint256[] memory slots) {
        slots = new uint256[](2);
        slots[0] = delta;
        slots[1] = mid;
        return (uint32(block.timestamp), slots);
    }

    function addUpdater(address updater) external {
        isUpdater[updater] = true;
    }

    function removeUpdater(address updater) external {
        isUpdater[updater] = false;
    }
}

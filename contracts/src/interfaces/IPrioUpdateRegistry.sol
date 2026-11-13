// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

interface IPrioUpdateRegistry {
    function getState(uint256 laneIndex, uint32 minTimestamp, uint32 maxTimestamp)
        external
        view
        returns (uint32 updateTimestamp, uint256[] memory slots);

    function addUpdater(address updater) external;

    function removeUpdater(address updater) external;

    /// Whether `updater` may write `target`'s lanes. Authorization is scoped per target: a
    /// PropAMM's keys are recorded under the PropAMM's own address.
    function isUpdater(address target, address updater) external view returns (bool);
}

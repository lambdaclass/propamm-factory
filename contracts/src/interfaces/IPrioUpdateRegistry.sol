// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

interface IPrioUpdateRegistry {
    function getState(uint256 laneIndex, uint32 minTimestamp, uint32 maxTimestamp)
        external
        view
        returns (uint32 updateTimestamp, uint256[] memory slots);

    function addUpdater(address updater) external;

    function removeUpdater(address updater) external;
}

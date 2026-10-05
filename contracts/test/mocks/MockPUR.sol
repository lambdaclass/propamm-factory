// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// Stand-in for the PUR registry in unit tests, written into the PUR address under test with
/// vm.etch; without it a bare test chain has no code there, so initialize's addUpdater calls go
/// nowhere and quote/swap revert. Serves one lane's worth of state, set with `setState`, and
/// enforces no freshness window. `make local` runs the real registry instead.
contract MockPUR {
    /// Records what `initialize` registered. The real registry gates who may push updates on
    /// this; the mock only remembers, so the calls have somewhere to land and can be asserted on.
    mapping(address => bool) public isUpdater;

    /// The two slots PropAMM reads: the fractional spread and the mid price. Storage rather than
    /// immutables, so a mock installed with vm.etch can still be configured.
    uint256 public delta;
    uint256 public mid;
    /// How many slots `getState` returns, to exercise the InsufficientOracleData path. Zero
    /// means the two PropAMM expects: a constructor default would not survive the vm.etch.
    uint256 public slotCount;

    function setState(uint256 delta_, uint256 mid_) external {
        delta = delta_;
        mid = mid_;
    }

    function setSlotCount(uint256 slotCount_) external {
        slotCount = slotCount_;
    }

    function getState(uint256, uint32, uint32) external view returns (uint32 updateTimestamp, uint256[] memory slots) {
        uint256 count = slotCount == 0 ? 2 : slotCount;
        slots = new uint256[](count);
        if (count > 0) slots[0] = delta;
        if (count > 1) slots[1] = mid;
        return (uint32(block.timestamp), slots);
    }

    function addUpdater(address updater) external {
        isUpdater[updater] = true;
    }

    function removeUpdater(address updater) external {
        isUpdater[updater] = false;
    }
}

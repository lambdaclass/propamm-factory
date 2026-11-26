// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// Stand-in for the PUR registry in unit tests, written into the PUR address under test with
/// vm.etch; without it a bare test chain has no code there, so initialize's addUpdater calls go
/// nowhere and quote/swap revert. Serves one lane's worth of state, set with `setState`, and
/// enforces the freshness window the way the real registry does: an update answers only for a
/// window its own timestamp falls in, so a price set in one block is gone once time moves on.
/// `make local` runs the real registry instead.
contract MockPUR {
    /// `getState` asked for a window the stored update's timestamp is outside of. Named after
    /// what the real registry reverts with there.
    error StaleUpdate();

    /// Records what each instance registered, per target (the calling instance), like the real
    /// registry: PropAMM reads it back to refuse no-op `addUpdater`/`removeUpdater` calls. The
    /// real registry also gates who may push updates on this; the mock only remembers.
    mapping(address target => mapping(address updater => bool)) public isUpdater;

    /// The two slots PropAMM reads: the fractional spread and the mid price. Storage rather than
    /// immutables, so a mock installed with vm.etch can still be configured.
    uint256 public delta;
    uint256 public mid;
    /// How many slots `getState` returns, to exercise the InsufficientOracleData path. Zero
    /// means the two PropAMM expects: a constructor default would not survive the vm.etch.
    /// Sized to share a storage slot with the two fields after it, so `getState` reads as many
    /// slots as it did before it kept a timestamp, and the gas snapshots taken through this
    /// mock move with the contract, not with the mock.
    uint64 public slotCount;
    /// The timestamp of the block `setState` was last called in, which is the update's stamp.
    uint32 public updatedAt;
    /// A registry that keeps no window: it answers with its last update however old, stamped
    /// truthfully. PropAMM has to refuse that answer on its own.
    bool public lenient;

    function setState(uint256 delta_, uint256 mid_) external {
        delta = delta_;
        mid = mid_;
        updatedAt = uint32(block.timestamp);
    }

    function setSlotCount(uint64 slotCount_) external {
        slotCount = slotCount_;
    }

    function setLenient(bool lenient_) external {
        lenient = lenient_;
    }

    function getState(uint256, uint32 minTimestamp, uint32 maxTimestamp)
        external
        view
        returns (uint32 updateTimestamp, uint256[] memory slots)
    {
        require(lenient || (updatedAt >= minTimestamp && updatedAt <= maxTimestamp), StaleUpdate());
        uint256 count = slotCount == 0 ? 2 : slotCount;
        slots = new uint256[](count);
        if (count > 0) slots[0] = delta;
        if (count > 1) slots[1] = mid;
        return (updatedAt, slots);
    }

    function addUpdater(address updater) external {
        isUpdater[msg.sender][updater] = true;
    }

    function removeUpdater(address updater) external {
        isUpdater[msg.sender][updater] = false;
    }
}

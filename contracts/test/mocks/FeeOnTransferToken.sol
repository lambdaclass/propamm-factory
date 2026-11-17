// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// An ERC-20 that burns 1% of every transfer between two accounts: what a fee-on-transfer token,
/// or USDT with Tether's fee switched on, does to a transfer. Minting is fee-free. Deployed rather
/// than etched, so the constructor's decimals hold.
contract FeeOnTransferToken is ERC20 {
    uint8 private immutable _decimals;

    constructor(uint8 decimals_) ERC20("Fee on transfer", "FOT") {
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from == address(0) || to == address(0)) return super._update(from, to, value);
        uint256 fee = value / 100;
        super._update(from, address(0), fee);
        super._update(from, to, value - fee);
    }
}

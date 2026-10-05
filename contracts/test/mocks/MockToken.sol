// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Mintable ERC20 whose decimals are settable, so tests can put a 6-decimal token at USDC's
/// address and an 18-decimal one at WETH's. Decimals live in storage rather than an immutable
/// because vm.etch copies code, not the state a constructor would have written; `setDecimals`
/// is called after the etch. Name and symbol read as empty for the same reason.
contract MockToken is ERC20 {
    uint8 private _decimals;

    constructor() ERC20("Mock", "MOCK") {}

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function setDecimals(uint8 decimals_) external {
        _decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

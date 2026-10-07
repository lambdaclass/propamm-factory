// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// A mintable ERC-20 for tests and the local chain. `make local` writes this contract's code
/// onto the mainnet USDC and USDT addresses with `anvil_setCode`, which copies code but no
/// storage, so the name, symbol and decimals the constructor set are not there; `setMeta`
/// writes them afterwards, and the updater's startup table then names the pair `USDC/USDT`
/// instead of falling back to its lane.
contract MockERC20 is ERC20 {
    string private _metaName;
    string private _metaSymbol;
    uint8 private _metaDecimals;

    constructor() ERC20("Mock", "MOCK") {
        _metaName = "Mock";
        _metaSymbol = "MOCK";
        _metaDecimals = 18;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setMeta(string calldata name_, string calldata symbol_, uint8 decimals_) external {
        _metaName = name_;
        _metaSymbol = symbol_;
        _metaDecimals = decimals_;
    }

    function name() public view override returns (string memory) {
        return _metaName;
    }

    function symbol() public view override returns (string memory) {
        return _metaSymbol;
    }

    function decimals() public view override returns (uint8) {
        return _metaDecimals;
    }
}

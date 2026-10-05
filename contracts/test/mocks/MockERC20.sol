// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Mintable ERC20 for the local setup. `make local` writes this contract's runtime code onto
/// the mainnet USDC/USDT addresses PropAMM registers as its pair, so swaps can actually move
/// tokens. Anyone can mint.
///
/// The name and symbol read as empty on-chain: anvil_setCode copies code but not the storage
/// a constructor would have written. Nothing depends on them for correctness, but the quote
/// updater's preflight does read `symbol()` — to label each pair and to cross-check a
/// configured Binance stream against its tokens. Against `make local` both reads come back
/// empty, so pairs are labelled by lane (`lane 0x4aafb6…`) instead of `USDC/USDT` and the
/// stream cross-check reports that it could not run. Both are warnings, not failures, so the
/// local flow works — but it does mean `make local` cannot exercise either feature. Use
/// `make fork-test-multi`, which forks mainnet and reads the real tokens, for that.
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

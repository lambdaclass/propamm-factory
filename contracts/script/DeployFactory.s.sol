// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {Script, console} from "forge-std/Script.sol";
import {PropAMMFactory} from "../src/PropAMMFactory.sol";

/// Factory-only deployment for real networks, once per chain. Deploy.s.sol is the local
/// flavor (it also creates a first PropAMM from env vars); on a real network instances are
/// created by their owners through the factory afterwards. See DEPLOYMENT.md.
contract DeployFactory is Script {
    function run() external {
        vm.startBroadcast();
        PropAMMFactory factory = new PropAMMFactory();
        vm.stopBroadcast();
        console.log("PropAMMFactory deployed at:", address(factory));
    }
}

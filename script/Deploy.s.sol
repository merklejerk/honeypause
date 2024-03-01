// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Script, console2 } from 'forge-std/Script.sol';
import { HoneyPause } from '../src/HoneyPause.sol';

contract Deploy is Script {
    function run() public {
        vm.broadcast(uint256(vm.envBytes32('DEPLOYER_KEY')));
        new HoneyPause();
    }
}

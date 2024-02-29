// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console2 } from 'forge-std/Script.sol';
import { HoneyPause } from '../src/HoneyPause.sol';

contract DeployScript is Script {
    function run() public {
        vm.broadcast(uint256(vm.envBytes32('DEPLOYER_KEY')));
        new HoneyPause();
    }
}

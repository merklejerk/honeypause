// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, IExploiter, ETH_TOKEN } from '../../src/HoneyPause.sol';

contract TestToken is ERC20 {
    constructor(string memory name, string memory symbol, uint8 decimals)
        ERC20(name, symbol, decimals)
    {} 

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 } from 'solmate/tokens/ERC20.sol';

contract TestERC20 is ERC20('TEST', 'TST', 18) {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
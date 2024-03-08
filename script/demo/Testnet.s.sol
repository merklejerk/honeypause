// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Script, console2 } from 'forge-std/Script.sol';
import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, ETH_TOKEN } from '../../src/HoneyPause.sol';
import {
    SecretProtocol,
    SecretExploiter,
    SecretProtocolBountyDeployer,
    SecretProtocolVerifier
} from './SecretProtocol.sol';
import { TestToken } from './Dummies.sol';

contract Testnet is Script {
    uint256 deployerKey;
    address deployer; 
    HoneyPause honey;
    TestToken usdc;
    address operator;

    function setUp() external {
        deployerKey = uint256(vm.envBytes32('DEPLOYER_KEY'));
        deployer = vm.addr(deployerKey);
        honey = HoneyPause(vm.envAddress('HONEY'));
        usdc = TestToken(vm.envAddress('USDC'));
        operator = vm.envAddress('OPERATOR');
    }

    function registerJson(string memory jsonConfig) external {
        string memory name = vm.parseJsonString(jsonConfig, 'name') ;
        ERC20 payoutToken = ERC20(vm.parseJsonAddress(jsonConfig, 'payoutToken'));
        uint256 payoutAmount = vm.parseJsonUint(jsonConfig, 'payoutAmount');
        IVerifier verifier = IVerifier(vm.parseJsonAddress(jsonConfig, 'verifier'));
        IPauser pauser = IPauser(vm.parseJsonAddress(jsonConfig, 'pauser'));
        IPayer payer = IPayer(vm.parseJsonAddress(jsonConfig, 'payer'));
        _broadcast();
        honey.add({
            name: name,
            payoutToken: payoutToken,
            payoutAmount: payoutAmount,
            verifier: verifier,
            pauser: pauser,
            payer: payer, 
            operator: operator
        });
    }
   
    function deployFakeUsdc() external {
        _broadcast();
        new TestToken('USDC', 'USDC', 6);
    }

    function exploitProtocol(uint256 bountyId, string memory preimage) external {
        (,,, IVerifier verifier,,) = honey.getBounty(bountyId);
        SecretProtocol proto = SecretProtocolVerifier(address(verifier)).proto();
        require(bytes3(keccak256(bytes(preimage))) == proto.hash(), 'invalid preimage');
        _broadcast();
        SecretExploiter exploiter = new SecretExploiter();
        _broadcast();
        honey.claim(bountyId, payable(tx.origin), exploiter, abi.encode(proto, preimage), "");
    }

    function registerUsdcProtocol(string memory name, uint256 amount, string memory preimage) external {
        bytes3 hash = bytes3(keccak256(bytes(preimage)));
        _broadcast();
        SecretProtocolBountyDeployer d = new SecretProtocolBountyDeployer(
            honey,
            name,
            usdc,
            amount,
            hash,
            operator
        );
        require(honey.verifyBountyCanPay(d.bountyId(), payable(tx.origin)), 'cannot pay');
    }

    function _broadcast() private {
        vm.broadcast(deployerKey);
    }
}
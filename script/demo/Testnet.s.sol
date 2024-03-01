// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Script, console2 } from 'forge-std/Script.sol';
import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, ETH_TOKEN } from '../../src/HoneyPause.sol';
import { SecretProtocol, SecretProtocolVerifier, SecretExploiter } from './SecretProtocol.sol';
import { TestPayer, TestToken, SucceedingContract, FailingContract } from './Dummies.sol';

contract Testnet is Script {
    uint256 deployerKey;
    HoneyPause honey;
    TestToken usdc;
    address operator;

    function setUp() external {
        deployerKey = uint256(vm.envBytes32('DEPLOYER_KEY'));
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

    function exploitProtocol(uint256 bountyId, SecretProtocol proto, bytes32 preimage) external {
        require(bytes3(keccak256(abi.encode(preimage))) == proto.hash(), 'invalid preimage');
        _broadcast();
        SecretExploiter exploiter = new SecretExploiter();
        _broadcast();
        honey.claim(bountyId, payable(tx.origin), exploiter, abi.encode(proto, preimage), "");
    }

    function registerUsdcProtocol(string memory name, uint256 amount, bytes3 hash) external {
        _broadcast();
        SecretProtocol proto = new SecretProtocol(hash);
        _broadcast();
        IVerifier verifier = new SecretProtocolVerifier(proto);
        IPauser pauser = IPauser(_deploySucceedingContract()) ;
        IPayer payer = _deployPayerContract(usdc, amount);
        _broadcast();
        honey.add({
            name: name,
            payoutToken: usdc,
            payoutAmount: amount,
            verifier: verifier,
            pauser: pauser,
            payer: payer, 
            operator: operator
        });
    }

    function registerEthProtocol(string memory name, uint256 amount, bytes3 hash) external {
        _broadcast();
        SecretProtocol proto = new SecretProtocol(hash);
        _broadcast();
        IVerifier verifier = new SecretProtocolVerifier(proto);
        IPauser pauser = IPauser(_deploySucceedingContract()) ;
        IPayer payer = _deployPayerContract(ETH_TOKEN, amount);
        _broadcast();
        honey.add({
            name: name,
            payoutToken: usdc,
            payoutAmount: amount,
            verifier: verifier,
            pauser: pauser,
            payer: payer, 
            operator: operator
        });
    }

    function _broadcast() private {
        vm.broadcast(deployerKey);
    }

    function _deployPayerContract(ERC20 token, uint256 amount) private returns (IPayer) {
        _broadcast();
        if (token == ETH_TOKEN) {
            return new TestPayer{value: amount}();
        }
        IPayer payer = new TestPayer();
        _broadcast();
        TestToken(address(token)).mint(address(payer), amount);
        return payer;
    }
   
    function _deploySucceedingContract() private returns (address) {
        _broadcast();
        return address(new SucceedingContract());
    }

    function _deployFailingContract() private returns (address) {
        _broadcast();
        return address(new FailingContract());
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from 'forge-std/Test.sol';
import { ERC20 } from 'solmate/tokens/ERC20.sol';
import {
    HoneyPause,
    IPauser,
    IPayer,
    IExploiter,
    IVerifier,
    ETH_TOKEN,
    InsufficientPayoutError,
    SandboxFailedError,
    SandboxSucceededError,
    Claimed,
    Created,
    Cancelled,
    OnlyBountyOperatorError
} from '../src/HoneyPause.sol';
import { TestERC20 } from './TestERC20.sol';

error TestError(string);

contract HoneyPauseTest is Test {
    TestHoneyPause honey = new TestHoneyPause();

    function test_payout_canPayERC20() external {
        TestERC20Payer payer = new TestERC20Payer(0);
        ERC20 token = payer.token();
        address payable receiver = payable(makeAddr('receiver'));
        honey.__payout(payer, token, receiver, 100);
        assertEq(payer.token().balanceOf(receiver), 100);
    }

    function test_payout_canPayZeroERC20() external {
        TestERC20Payer payer = new TestERC20Payer(0);
        ERC20 token = payer.token();
        address payable receiver = payable(makeAddr('receiver'));
        honey.__payout(payer, token, receiver, 0);
        assertEq(payer.token().balanceOf(receiver), 0);
    }

    function test_payout_failsIfUnderpaysERC20() external {
        TestERC20Payer payer = new TestERC20Payer(1);
        ERC20 token = payer.token();
        address payable receiver = payable(makeAddr('receiver'));
        vm.expectRevert(InsufficientPayoutError.selector);
        honey.__payout(payer, token, receiver, 100);
    }

    function test_payout_canPayEth() external {
        TestEthPayer payer = new TestEthPayer{value: 100}(0);
        address payable receiver = payable(makeAddr('receiver'));
        honey.__payout(payer, ETH_TOKEN, receiver, 100);
        assertEq(receiver.balance, 100);
    }

    function test_payout_canPayZeroEth() external {
        TestEthPayer payer = new TestEthPayer(0);
        address payable receiver = payable(makeAddr('receiver'));
        honey.__payout(payer, ETH_TOKEN, receiver, 0);
        assertEq(receiver.balance, 0);
    }

    function test_payout_failsIfUnderpaysEth() external {
        TestEthPayer payer = new TestEthPayer{value: 100}(1);
        address payable receiver = payable(makeAddr('receiver'));
        vm.expectRevert(InsufficientPayoutError.selector);
        honey.__payout(payer, ETH_TOKEN, receiver, 100);
    }

    function test_sandboxExploit_revertsOnSuccess() external {
        TestVerifier verifier = new TestVerifier(true, true);
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectRevert(SandboxSucceededError.selector);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnExploitFailure() external {
        TestVerifier verifier = new TestVerifier(true, true);
        TestExploiter exploiter = new TestExploiter(false);
        vm.expectRevert(abi.encodeWithSelector(
            SandboxFailedError.selector,
            abi.encodeWithSelector(TestError.selector, 'exploit FAILED')
        ));
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnVerifierBeforeExploitFailure() external {
        TestVerifier verifier = new TestVerifier(false, true);
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectRevert(abi.encodeWithSelector(
            SandboxFailedError.selector,
            abi.encodeWithSelector(TestError.selector, 'beforeExploit FAILED')
        ));
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnVerifierAssertExploitFailure() external {
        TestVerifier verifier = new TestVerifier(true, false);
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectRevert(abi.encodeWithSelector(
            SandboxFailedError.selector,
            abi.encodeWithSelector(TestError.selector, 'assertExploit FAILED')
        ));
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_propagatesData() external {
        bytes memory exploiterData = hex"1234";
        bytes memory verifierData = hex"5678";
        bytes memory verifierStateData = hex"9ABC";
        TestVerifier verifier = new TestVerifier(true, true);
        verifier.setStateData(verifierStateData) ;
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.BeforeExploitCalled(verifierData);
        vm.expectEmit(true, true, true, true);
        emit TestExploiter.ExploitCalled(exploiterData);
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.AssertExploitCalled(verifierData, verifierStateData);
        vm.expectRevert(SandboxSucceededError.selector);
        honey.sandboxExploit(exploiter, verifier, exploiterData, verifierData);
    }

    function test_add_canCreateABounty() external {
        ERC20 token = ERC20(makeAddr('TOKEN'));
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('OPERATOR');
        uint256 bountyId = honey.bountyCount() + 1;
        vm.expectEmit(true, true, true, true);
        emit Created(bountyId, "TestBounty", token, 100, verifier);
        uint256 bountyId_ = honey.add({
            name: "TestBounty",
            payoutToken: token,
            payoutAmount: 100,
            verifier: verifier,
            pauser: pauser,
            payer: payer,
            operator: operator
        });
        assertEq(bountyId_, bountyId);
        assertEq(honey.isBountyClaimed(bountyId), false);
    }

    function test_cancel_operatorCan() external {
        ERC20 token = ERC20(makeAddr('TOKEN'));
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('OPERATOR');
        uint256 bountyId = honey.add({
            name: "TestBounty",
            payoutToken: token,
            payoutAmount: 100,
            verifier: verifier,
            pauser: pauser,
            payer: payer,
            operator: operator
        });
        vm.prank(operator);
        vm.expectEmit(true, true, true, true);
        emit Cancelled(bountyId);
        honey.cancel(bountyId);
    }

    function test_cancel_onlyOperator() external {
        ERC20 token = ERC20(makeAddr('TOKEN'));
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('OPERATOR');
        uint256 bountyId = honey.add({
            name: "TestBounty",
            payoutToken: token,
            payoutAmount: 100,
            verifier: verifier,
            pauser: pauser,
            payer: payer,
            operator: operator
        });
        vm.prank(makeAddr('NOT OPERATOR'));
        vm.expectRevert(OnlyBountyOperatorError.selector);
        honey.cancel(bountyId);
    }

    function test_claim_canClaim() external {
        uint256 bountyId = _addTestBounty(true);
        address payable payReceiver = payable(makeAddr('RECEIVER'));
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectEmit(true, true, true, true);
        emit Claimed(bountyId, ETH_TOKEN, 100);
        honey.claim(bountyId, payReceiver, exploiter, "", "");
    }

    function test_claim_PassesData() external {
        uint256 bountyId = _addTestBounty(true);
        address payable payReceiver = payable(makeAddr('RECEIVER'));
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.BeforeExploitCalled(hex"1337");
        vm.expectEmit(true, true, true, true);
        emit TestExploiter.ExploitCalled(hex"7331");
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.AssertExploitCalled(hex"1337", "");
        honey.claim(bountyId, payReceiver, exploiter, hex"7331", hex"1337");
    }

    function test_claim_CallsPauser() external {
        uint256 bountyId = _addTestBounty(true);
        address payable payReceiver = payable(makeAddr('RECEIVER'));
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectEmit(true, true, true, true);
        emit TestPauser.PauseCalled();
        honey.claim(bountyId, payReceiver, exploiter, "", "");
    }

    function test_claim_paysReceiver() external {
        uint256 bountyId = _addTestBounty(true);
        address payable payReceiver = payable(makeAddr('RECEIVER'));
        TestExploiter exploiter = new TestExploiter(true);
        honey.claim(bountyId, payReceiver, exploiter, "", "");
        assertEq(payReceiver.balance, 100);
    }

    function test_claim_revertsIfExploitFails() external {
        uint256 bountyId = _addTestBounty(false);
        address payable payReceiver = payable(makeAddr('RECEIVER'));
        TestExploiter exploiter = new TestExploiter(true);
        vm.expectRevert();
        honey.claim(bountyId, payReceiver, exploiter, "", "");
    }

    function _addTestBounty(bool willVerify)
        private returns (uint256 bountyId)
    {
        return honey.add(
            'TestProtocol',
            ETH_TOKEN,
            100,
            new TestVerifier(true, willVerify),
            new TestPauser(true),
            new TestEthPayer{value: 100}(0),
            address(this)
        );
    }
}

contract TestExploiter is IExploiter {
    event ExploitCalled(bytes exploiterData);

    bool _succeeds;

    constructor(bool succeeds) {
        _succeeds = succeeds;
    }
    
    function exploit(bytes memory exploiterData) external {
        if (!_succeeds) {
            revert TestError('exploit FAILED');
        }
        emit ExploitCalled(exploiterData);
    }
}

contract TestPauser is IPauser {
    event PauseCalled();

    bool _succeeds;

    constructor(bool succeeds) {
        _succeeds = succeeds;
    }

    function pause() external {
        if (!_succeeds) {
            revert TestError('pause FAILED');
        }
        emit PauseCalled();
    }
}

contract TestVerifier is IVerifier {
    event BeforeExploitCalled(bytes verifierData);
    event AssertExploitCalled(bytes verifierData, bytes verifierStateData);
    
    bool _succeedsBeforeExploit;
    bool _succeedsAssertExploit;
    bytes _stateData;
    
    constructor(bool succeedsBeforeExploit, bool succeedsAssertExploit) {
        _succeedsBeforeExploit = succeedsBeforeExploit;
        _succeedsAssertExploit = succeedsAssertExploit;
    }

    function setStateData(bytes memory verifierStateData) external {
        _stateData = verifierStateData;
    }

    function beforeExploit(bytes memory verifierData) external returns (bytes memory verifierStateData) {
        emit BeforeExploitCalled(verifierData);
        if (!_succeedsBeforeExploit) {
                revert TestError('beforeExploit FAILED');
        }
        return _stateData;
    }

    function assertExploit(bytes memory verifierData, bytes memory verifierStateData) external {
        emit AssertExploitCalled(verifierData, verifierStateData);
        if (!_succeedsAssertExploit) {
                revert TestError('assertExploit FAILED');
        }
    }
}

contract TestERC20Payer is IPayer {
    TestERC20 public token = new TestERC20();
    uint256 _lessPay;

    constructor(uint256 lessPay) {
        _lessPay = lessPay;
    }

    function payExploiter(ERC20 token_, address payable to, uint256 amount) external {
        assert(token_ == token);
        return token.mint(to, amount - _lessPay);
    }
}

contract TestEthPayer is IPayer {
    uint256 _lessPay;

    constructor(uint256 lessPay) payable {
        _lessPay = lessPay;
    }

    function payExploiter(ERC20 token, address payable to, uint256 amount) external {
        assert(token == ETH_TOKEN);
        return to.transfer(amount - _lessPay);
    }
}


contract TestHoneyPause is HoneyPause {
    function __payout(IPayer payer, ERC20 token, address payable to, uint256 amount)
        external
    {
        _payout(payer, token, to, amount);
    }
}
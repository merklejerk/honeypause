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
    Claimed,
    Created,
    Cancelled,
    OnlyBountyOperatorError,
    InvalidExploitError,
    InvalidClaimError,
    InvalidBountyConfigError,
    OperatorChanged,
    Updated,
    InvalidExploitError
} from '../src/HoneyPause.sol';
import { SandboxFailedError, SandboxSucceededError } from '../src/LibSandbox.sol';
import { LibBytes } from '../src/LibBytes.sol';
import { TestERC20 } from './TestERC20.sol';

error TestError(string);

contract HoneyPauseTest is Test {
    using LibBytes for bytes;

    uint256 constant TEST_BOUNTY_AMOUNT = 100;
    address payable constant RECEIVER = payable(0x94201143cC0a32610F14f8F185Ebb23e4CA60f17);
    address payable constant OPERATOR = payable(0x523a704056Dcd17bcF83Bed8b68c59416dac1119);

    TestHoneyPause honey = new TestHoneyPause();
    TestERC20 testToken = new TestERC20();
    bytes TEST_ERROR = abi.encodeWithSelector(TestError.selector, 'FAILED');
    bytes SANDBOX_SUCCEEDED_ERROR = abi.encodeWithSelector(SandboxSucceededError.selector);
    bytes WRAPPED_SANDBOX_SUCCEEDED_ERROR = abi.encodeWithSelector(SandboxFailedError.selector,
        abi.encodeWithSelector(SandboxSucceededError.selector)
    );

    function test_errorSelectorsCanBeSandboxed() external {
        assertTrue(InsufficientPayoutError.selector != SandboxSucceededError.selector, 'InsufficientPayoutError');
        assertTrue(InvalidExploitError.selector != SandboxSucceededError.selector, 'InvalidExploitError');
        assertTrue(InvalidClaimError.selector != SandboxSucceededError.selector, 'InvalidClaimError');
        assertTrue(InsufficientPayoutError.selector != SandboxSucceededError.selector, 'InsufficientPayoutError');
        assertTrue(bytes4(keccak256('Error(string)')) != SandboxSucceededError.selector, 'Error');
        assertTrue(bytes4(keccak256('Panic(uint256)')) != SandboxSucceededError.selector, 'Panic');
    }

    function test_payout_canPayERC20() external {
        IPayer payer = new TestERC20Payer(testToken, TEST_BOUNTY_AMOUNT);
        vm.expectEmit(true, true, true, true);
        emit TestERC20Payer.PayExploiterCalled(1337, testToken, RECEIVER, TEST_BOUNTY_AMOUNT);
        honey.__payout(1337, payer, testToken, RECEIVER, TEST_BOUNTY_AMOUNT);
        assertEq(testToken.balanceOf(RECEIVER), TEST_BOUNTY_AMOUNT);
    }

    function test_payout_canPayZeroERC20() external {
        IPayer payer = new TestERC20Payer(testToken, 0);
        vm.expectEmit(true, true, true, true);
        emit TestERC20Payer.PayExploiterCalled(1337, testToken, RECEIVER, 0);
        honey.__payout(1337, payer, testToken, RECEIVER, 0);
        assertEq(testToken.balanceOf(RECEIVER), 0);
    }

    function test_payout_failsIfUnderpaysERC20() external {
        IPayer payer = new TestERC20Payer(testToken, TEST_BOUNTY_AMOUNT - 1);
        vm.expectRevert(InsufficientPayoutError.selector);
        honey.__payout(1337, payer, testToken, RECEIVER, TEST_BOUNTY_AMOUNT);
    }

    function test_payout_canPayEth() external {
        IPayer payer = new TestEthPayer{value: TEST_BOUNTY_AMOUNT}();
        vm.expectEmit(true, true, true, true);
        emit TestERC20Payer.PayExploiterCalled(1337, ETH_TOKEN, RECEIVER, TEST_BOUNTY_AMOUNT);
        honey.__payout(1337, payer, ETH_TOKEN, RECEIVER, TEST_BOUNTY_AMOUNT);
        assertEq(RECEIVER.balance, TEST_BOUNTY_AMOUNT);
    }

    function test_payout_canPayZeroEth() external {
        IPayer payer = new TestEthPayer();
        vm.expectEmit(true, true, true, true);
        emit TestERC20Payer.PayExploiterCalled(1337, ETH_TOKEN, RECEIVER, 0);
        honey.__payout(1337, payer, ETH_TOKEN, RECEIVER, 0);
        assertEq(RECEIVER.balance, 0);
    }

    function test_payout_failsIfUnderpaysEth() external {
        IPayer payer = new TestEthPayer{value: TEST_BOUNTY_AMOUNT - 1}();
        vm.expectRevert(InsufficientPayoutError.selector);
        honey.__payout(1337, payer, ETH_TOKEN, RECEIVER, TEST_BOUNTY_AMOUNT);
    }

    function test_sandboxExploit_revertsOnSuccess() external {
        IVerifier verifier = new TestVerifier();
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(SandboxSucceededError.selector);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnExploitFailure() external {
        IVerifier verifier = new TestVerifier();
        IExploiter exploiter = IExploiter(_createFailingFnContract(
            IExploiter.exploit.selector,
            TEST_ERROR
        ));
        vm.expectRevert(TEST_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnVerifierBeforeExploitFailure() external {
        IVerifier verifier = IVerifier(_createFailingFnContract(
            IVerifier.beforeExploit.selector,
            TEST_ERROR
        ));
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(TEST_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_revertsOnVerifierAssertExploitFailure() external {
        IVerifier verifier = IVerifier(_createFailingFnContract(
            IVerifier.assertExploit.selector,
            TEST_ERROR
        ));
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(TEST_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_wrapsSandboxSuccessFromVerifierBeforeExploitCall() external {
        IVerifier verifier = IVerifier(_createFailingFnContract(
            IVerifier.beforeExploit.selector,
            SANDBOX_SUCCEEDED_ERROR
        ));
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(WRAPPED_SANDBOX_SUCCEEDED_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_wrapsSandboxSuccessFromVerifierAssertExploitCall() external {
        IVerifier verifier = IVerifier(_createFailingFnContract(
            IVerifier.assertExploit.selector,
            SANDBOX_SUCCEEDED_ERROR
        ));
        TestExploiter exploiter = new TestExploiter();
        vm.expectRevert(WRAPPED_SANDBOX_SUCCEEDED_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_wrapsSandboxSuccessFromExploitCall() external {
        IVerifier verifier = new TestVerifier();
        IExploiter exploiter = IExploiter(_createFailingFnContract(
            IExploiter.exploit.selector,
            SANDBOX_SUCCEEDED_ERROR
        ));
        vm.expectRevert(WRAPPED_SANDBOX_SUCCEEDED_ERROR);
        honey.sandboxExploit(exploiter, verifier, "", "");
    }

    function test_sandboxExploit_propagatesData() external {
        bytes memory exploiterData = hex"1234";
        bytes memory verifierData = hex"5678";
        bytes memory verifierStateData = hex"9ABC";
        TestVerifier verifier = new TestVerifier();
        verifier.setStateData(verifierStateData) ;
        IExploiter exploiter = new TestExploiter();
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
        (
            address operator_,
            ERC20 payoutToken_,
            uint256 payoutAmount_,
            IVerifier verifier_,
            IPauser pauser_,
            IPayer payer_
        ) = honey.getBounty(bountyId);
        assertEq(operator_, operator);
        assertEq(address(payoutToken_), address(token));
        assertEq(payoutAmount_, 100);
        assertEq(address(verifier_), address(verifier));
        assertEq(address(pauser_), address(pauser));
        assertEq(address(payer_), address(payer));
        assertEq(honey.bountyCount(), bountyId);
    }

    function test_validateBountyConfig_failsWithInvalidOperator() external {
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        vm.expectRevert(InvalidBountyConfigError.selector);
        honey.__publicValidateBountyConfig({
            operator: address(0),
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
    }

    function test_validateBountyConfig_cannotCreateABountyWithInvalidPauser() external {
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(address(0));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('OPERATOR');
        vm.expectRevert(InvalidBountyConfigError.selector);
        honey.__publicValidateBountyConfig({
            operator: operator,
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
    }

    function test_validateBountyConfig_cannotCreateABountyWithInvalidPayer() external {
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(address(0));
        address operator = makeAddr('OPERATOR');
        vm.expectRevert(InvalidBountyConfigError.selector);
        honey.__publicValidateBountyConfig({
            operator: operator,
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
    }

    function test_validateBountyConfig_cannotCreateABountyWithInvalidVerifier() external {
        IVerifier verifier = IVerifier(address(0));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('OPERATOR');
        vm.expectRevert(InvalidBountyConfigError.selector);
        honey.__publicValidateBountyConfig({
            operator: operator,
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
    }

    function test_cancel_operatorCanCancel() external {
        uint256 bountyId = _addTestBounty(); 
        vm.prank(OPERATOR);
        vm.expectEmit(true, true, true, true);
        emit Cancelled(bountyId);
        honey.cancel(bountyId);
    }

    function test_cancel_onlyOperator() external {
        uint256 bountyId = _addTestBounty(); 
        vm.prank(address(~uint160(address(OPERATOR))));
        vm.expectRevert(OnlyBountyOperatorError.selector);
        honey.cancel(bountyId);
    }

    function test_update_canUpdate() external {
        uint256 bountyId = _addTestBounty(); 
        ERC20 token = ERC20(makeAddr('TOKEN'));
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('NEW_OPERATOR');
        vm.prank(OPERATOR);
        vm.expectEmit(true, true, true, true);
        emit Updated(bountyId, token, 555, verifier);
        honey.update({
            bountyId: bountyId,
            payoutToken: token,
            payoutAmount: 555,
            verifier: verifier,
            pauser: pauser,
            payer: payer,
            operator: operator
        });
        (
            address operator_,
            ERC20 payoutToken_,
            uint256 payoutAmount_,
            IVerifier verifier_,
            IPauser pauser_,
            IPayer payer_
        ) = honey.getBounty(bountyId);
        assertEq(operator_, operator);
        assertEq(address(payoutToken_), address(token));
        assertEq(payoutAmount_, 555);
        assertEq(address(verifier_), address(verifier));
        assertEq(address(pauser_), address(pauser));
        assertEq(address(payer_), address(payer));
        assertEq(honey.bountyCount(), bountyId);
        assertEq(honey.isBountyClaimed(bountyId), false);
    }

    function test_update_onlyOperator() external {
        uint256 bountyId = _addTestBounty(); 
        vm.prank(makeAddr("NOT_OPERATOR"));
        ERC20 token = ERC20(makeAddr('TOKEN'));
        IVerifier verifier = IVerifier(makeAddr('VERIFIER'));
        IPauser pauser = IPauser(makeAddr('PAUSER'));
        IPayer payer = IPayer(makeAddr('PAYER'));
        address operator = makeAddr('NEW_OPERATOR');
        vm.expectRevert(OnlyBountyOperatorError.selector);
        honey.update({
            bountyId: bountyId,
            payoutToken: token,
            payoutAmount: 555,
            verifier: verifier,
            pauser: pauser,
            payer: payer,
            operator: operator
        });
    }

    function test_claim_canClaim() external {
        uint256 bountyId = _addTestBounty();
        IExploiter exploiter = new TestExploiter();
        vm.expectEmit(true, true, true, true);
        emit Claimed(bountyId, ETH_TOKEN, 100);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
        assertEq(honey.isBountyClaimed(bountyId), true);
    }

    function test_claim_passesData() external {
        uint256 bountyId = _addTestBounty();
        IExploiter exploiter = new TestExploiter();
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.BeforeExploitCalled(hex"1337");
        vm.expectEmit(true, true, true, true);
        emit TestExploiter.ExploitCalled(hex"7331");
        vm.expectEmit(true, true, true, true);
        emit TestVerifier.AssertExploitCalled(hex"1337", "");
        honey.claim(bountyId, RECEIVER, exploiter, hex"7331", hex"1337");
    }

    function test_claim_callsPauser() external {
        uint256 bountyId = _addTestBounty();
        IExploiter exploiter = new TestExploiter();
        vm.expectEmit(true, true, true, true);
        emit TestPauser.PauseCalled(bountyId);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_paysReceiver() external {
        uint256 bountyId = _addTestBounty();
        IExploiter exploiter = new TestExploiter();
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
        assertEq(RECEIVER.balance, 100);
    }

    function test_claim_revertsIfExploitIsPauser() external {
        uint256 bountyId = _addTestBounty();
        (,,,, IPauser pauser,) = honey.getBounty(bountyId);
        IExploiter exploiter = IExploiter(address(pauser));
        vm.expectRevert(InvalidExploitError.selector);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_revertsIfExploitIsPayer() external {
        uint256 bountyId = _addTestBounty();
        (,,,,, IPayer payer) = honey.getBounty(bountyId);
        IExploiter exploiter = IExploiter(address(payer));
        vm.expectRevert(InvalidExploitError.selector);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_revertsIfExploitFails() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyVerifier(bountyId, new TestVerifier());
        IExploiter exploiter = IExploiter(_createFailingFnContract(
            IExploiter.exploit.selector,
            TEST_ERROR
        ));
        vm.expectRevert(TEST_ERROR);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_failsIfPayerReverts() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPayer(bountyId, IPayer(
            _createFailingFnContract(IPayer.payExploiter.selector, TEST_ERROR)
        ));
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(TEST_ERROR);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_failsIfPauserReverts() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPauser(bountyId, IPauser(
            _createFailingFnContract(IPauser.pause.selector, TEST_ERROR)
        ));
        IExploiter exploiter = new TestExploiter();
        vm.expectRevert(TEST_ERROR);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_claim_failsIfExploiterThrowsSandboxSucceededError() external {
        uint256 bountyId = _addTestBounty();
        IExploiter exploiter = IExploiter(_createFailingFnContract(
            IExploiter.exploit.selector,
            SANDBOX_SUCCEEDED_ERROR
        ));
        vm.expectRevert(SANDBOX_SUCCEEDED_ERROR);
        honey.claim(bountyId, RECEIVER, exploiter, "", "");
    }

    function test_verifyBountyCanPay_returnsTrueIfBountyPays() external {
        uint256 bountyId = _addTestBounty();
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), true);
    }

    function test_verifyBountyCanPay_doesNotModifyState() external {
        uint256 bountyId = _addTestBounty();
        honey.verifyBountyCanPay(bountyId, RECEIVER);
        assertEq(honey.isBountyClaimed(bountyId), false);
        (,,,,, IPayer payer) = honey.getBounty(bountyId);
        assertEq(address(payer).balance, TEST_BOUNTY_AMOUNT);
        assertEq(RECEIVER.balance, 0);
    }

    function test_verifyBountyCanPay_returnsFalseIfPayerReverts() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPayer(bountyId, IPayer(_createFailingFnContract(
            IPayer.payExploiter.selector,
            TEST_ERROR 
        )));
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function test_verifyBountyCanPay_returnsFalseIfPauserReverts() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPauser(bountyId, IPauser(_createFailingFnContract(
            IPauser.pause.selector,
            TEST_ERROR 
        )));
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function test_verifyBountyCanPay_returnsFalseIfPayerDoesNotPayEnoughEth() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPayer(bountyId, new TestEthPayer{value: TEST_BOUNTY_AMOUNT - 1}());
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function test_verifyBountyCanPay_returnsFalseIfPayerDoesNotPayEnoughErc20() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPayer(bountyId, new TestERC20Payer(testToken, TEST_BOUNTY_AMOUNT - 1));
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function test_verifyBountyCanPay_returnsFalseIfPayerRevertsWithSandoxSucceeded() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPayer(bountyId, IPayer(_createFailingFnContract(
            IPayer.payExploiter.selector,
            SANDBOX_SUCCEEDED_ERROR
        )));
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function test_verifyBountyCanPay_returnsFalseIfPauserRevertsWithSandoxSucceeded() external {
        uint256 bountyId = _addTestBounty();
        honey.__testSetBountyPauser(bountyId, IPauser(_createFailingFnContract(
            IPauser.pause.selector,
            SANDBOX_SUCCEEDED_ERROR
        )));
        assertEq(honey.verifyBountyCanPay(bountyId, RECEIVER), false);
    }

    function _addTestBounty()
        private returns (uint256 bountyId)
    {
        return honey.add(
            'TestProtocol',
            ETH_TOKEN,
            TEST_BOUNTY_AMOUNT,
            new TestVerifier(),
            new TestPauser(),
            new TestEthPayer{value: TEST_BOUNTY_AMOUNT}(),
            OPERATOR
        );
    }

    function _addTestErc20Bounty()
        private returns (uint256 bountyId)
    {
        return honey.add(
            'TestProtocol',
            testToken,
            TEST_BOUNTY_AMOUNT,
            new TestVerifier(),
            new TestPauser(),
            new TestERC20Payer(testToken, TEST_BOUNTY_AMOUNT),
            OPERATOR
        );
    }

    function _createAlwaysFailingContract(bytes memory alwaysRevertData)
        private returns (address payable)
    {
        FailingContract fc = new FailingContract();
        fc.setFnRevertData(bytes4(0), alwaysRevertData);
        return payable(fc);
    }

    function _createFailingFnContract(bytes4 fnSelector, bytes memory alwaysRevertData)
        private returns (address payable)
    {
        FailingContract fc = new FailingContract();
        fc.setFnRevertData(fnSelector, alwaysRevertData);
        return payable(fc);
    }

    function test_BountyCannotUseAnotherBountyPauserPayer() external {
        MockPauser mockPauser = new MockPauser();
        MockPayer mockPayer = new MockPayer();

        testToken.mint(address(mockPayer), 100 ether);

        // Create a legitimate bounty with the mock contracts
        uint256 bountyAmount = 1 ether;
        uint256 legitimateBountyId = honey.add("LegitimateExploitTest", testToken, bountyAmount, new TestVerifier(), mockPauser, mockPayer, address(this));

        // Set the bountyId in mock contracts to the valid bountyId
        mockPauser.setValidBountyId(legitimateBountyId);
        mockPayer.setValidBountyId(legitimateBountyId);

        // claim the legitimate bounty
        IExploiter exploiter = new TestExploiter();
        honey.claim(legitimateBountyId, payable(address(this)), exploiter, "", "");

        // Create a fake bounty attempting to use the first bounty's pauser/payer with an always successful Verifyer
        uint256 fakeBountyId = honey.add("BogusExploitTest", testToken, bountyAmount, new TestVerifier(), mockPauser, mockPayer, address(this));

        // Expecting failure due to bountyId checks in the impl of IPauser IPayer
        vm.expectRevert("Unauthorized bountyId");
        honey.claim(fakeBountyId, payable(address(this)), exploiter, "", "");
    }

}

contract MockPauser is IPauser {
    event PauseCalled(uint256 bountyId);
    uint256 private validBountyId;

    function setValidBountyId(uint256 _validBountyId) external {
        validBountyId = _validBountyId;
    }

    function pause(uint256 bountyId) external {
        emit PauseCalled(bountyId);
        require(bountyId == validBountyId, "Unauthorized bountyId");
    }
}

contract MockPayer is IPayer {
    uint256 private validBountyId;

    function setValidBountyId(uint256 _validBountyId) external {
        validBountyId = _validBountyId;
    }

    function payExploiter(uint256 bountyId, ERC20 token, address payable to, uint256 amount) external override {
        require(bountyId == validBountyId, "Unauthorized bountyId");
        require(token.transfer(to, amount), "Transfer failed");
    }
}

contract TestExploiter is IExploiter {
    event ExploitCalled(bytes exploiterData);
    
    function exploit(bytes memory exploiterData) external {
        emit ExploitCalled(exploiterData);
    }
}

contract TestPauser is IPauser {
    event PauseCalled(uint256 bountyId);

    function pause(uint256 bountyId) external {
        emit PauseCalled(bountyId);
    }
}

contract TestVerifier is IVerifier {
    event BeforeExploitCalled(bytes verifierData);
    event AssertExploitCalled(bytes verifierData, bytes verifierStateData);
    
    bytes _stateData;
    
    constructor() {}

    function setStateData(bytes memory verifierStateData) external {
        _stateData = verifierStateData;
    }

    function beforeExploit(bytes memory verifierData) external returns (bytes memory verifierStateData) {
        emit BeforeExploitCalled(verifierData);
        return _stateData;
    }

    function assertExploit(bytes memory verifierData, bytes memory verifierStateData) external {
        emit AssertExploitCalled(verifierData, verifierStateData);
    }
}

contract TestERC20Payer is IPayer {
    event PayExploiterCalled(uint256 bountyId, ERC20 token, address payable to, uint256 amount);

    constructor(TestERC20 token, uint256 reserve) {
        token.mint(address(this), reserve) ;
    }

    function payExploiter(uint256 bountyId, ERC20 token, address payable to, uint256 amount) external {
        emit PayExploiterCalled(bountyId, token, to, amount);
        token.transfer(to, token.balanceOf(address(this)));
    }
}

contract FailingContract {
    struct RevertData {
        bool exists;
        bytes revertData;
    }

    RevertData _alwaysRevertData;
    mapping (bytes4 selector => RevertData revertData) _fnRevertData;

    function setFnRevertData(bytes4 selector, bytes calldata revertData)
        external
    {
        if (selector == bytes4(0)) {
            _alwaysRevertData = RevertData(true, revertData); 
        } else {
            _fnRevertData[selector] = RevertData(true, revertData);
        }
    }

    fallback() external payable {
        RevertData storage rd = _fnRevertData[msg.sig];
        if (rd.exists) {
            LibBytes.rawRevert(rd.revertData);
        }
        assembly ("memory-safe") { return(0x60, 0x20) }
    }
}

contract TestEthPayer is IPayer {
    event PayExploiterCalled(uint256 bountyId, ERC20 token, address payable to, uint256 amount);
    constructor() payable {}

    function payExploiter(uint256 bountyId, ERC20 token, address payable to, uint256 amount) external {
        emit PayExploiterCalled(bountyId, token, to, amount);
        assert(token == ETH_TOKEN);
        return to.transfer(address(this).balance);
    }
}

contract TestHoneyPause is HoneyPause {
    function __payout(
        uint256 bountyId,
        IPayer payer,
        ERC20 token,
        address payable to,
        uint256 amount
    )
        external
    {
        _payout(bountyId, payer, token, to, amount);
    }

    function __testSetBountyVerifier(uint256 bountyId, IVerifier verifier)
        external
    {
        getBounty[bountyId].verifier = verifier;
    }
    
    function __testSetBountyPayer(uint256 bountyId, IPayer payer)
        external
    {
        getBounty[bountyId].payer = payer;
    }

    function __testSetBountyPauser(uint256 bountyId, IPauser pauser)
        external
    {
        getBounty[bountyId].pauser = pauser;
    }
   
    function __publicValidateBountyConfig(
        address operator,
        IPauser pauser,
        IVerifier verifier,
        IPayer payer
    ) external pure {
        _validateBountyConfig({ operator: operator, pauser: pauser, verifier: verifier, payer: payer });
    }
}

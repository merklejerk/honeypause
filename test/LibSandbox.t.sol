// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from 'forge-std/Test.sol';
import { LibSandbox, SandboxSucceededError, SandboxFailedError } from '../src/LibSandbox.sol';

contract LibSandboxTest is Test {

    function test_handleSafeCallResult_returnsDataIfSuccesful() external {
        bytes memory data = bytes("foo");
        assertEq(LibSandbox._handleSafeCallResult(true, data), data);
    }

    function test_handleSafeCallResult_revertsIfNotSuccessful() external {
        bytes memory data = bytes("foo");
        vm.expectRevert(data);
        LibSandbox._handleSafeCallResult(false, data);
    }

    function test_handleSafeCallResult_canRevertEmptyIfNotSuccessful() external {
        bytes memory data = "";
        vm.expectRevert(data);
        LibSandbox._handleSafeCallResult(false, data);
    }

    function test_handleSafeCallResult_wrapsSandboxSucceededErrorRevert() external {
        bytes memory data = abi.encodeWithSelector(SandboxSucceededError.selector);
        vm.expectRevert(abi.encodeWithSelector(SandboxFailedError.selector, data));
        LibSandbox._handleSafeCallResult(false, data);
    }

    function test_handleSandboxCallRevert_swallow_returnsFalseIfErrDataIsShort() external {
        bytes memory data = "abc";
        assertEq(LibSandbox.handleSandboxCallRevert(data, true), false);
    }

    function test_handleSandboxCallRevert_swallow_returnsFalseOnSandboxFailed() external {
        bytes memory data = abi.encodeWithSelector(SandboxFailedError.selector, "foo");
        assertEq(LibSandbox.handleSandboxCallRevert(data, true), false);
    }

    function test_handleSandboxCallRevert_swallow_returnsFalseOnMalformedSandboxFailed() external {
        bytes memory data = abi.encodeWithSelector(SandboxFailedError.selector);
        assertEq(LibSandbox.handleSandboxCallRevert(data, true), false);
    }

    function test_handleSandboxCallRevert_swallow_returnsFalseOnNotSandboxSucceeded() external {
        bytes memory data = "abcd";
        assertEq(LibSandbox.handleSandboxCallRevert(data, true), false);
    }

    function test_handleSandboxCallRevert_swallow_returnsTrueOnSandboxSucceeded() external {
        bytes memory data = abi.encodeWithSelector(SandboxSucceededError.selector);
        assertEq(LibSandbox.handleSandboxCallRevert(data, true), true);
    }

    function test_handleSandboxCallRevert_revertsIfErrDataIsShort() external {
        bytes memory data = "abc";
        vm.expectRevert(data) ;
        LibSandbox.handleSandboxCallRevert(data, false);
    }

    function test_handleSandboxCallRevert_revertsOnSandboxFailed() external {
        bytes memory data = abi.encodeWithSelector(SandboxFailedError.selector, "foo");
        vm.expectRevert(bytes("foo")) ;
        LibSandbox.handleSandboxCallRevert(data, false);
    }

    function test_handleSandboxCallRevert_revertsOnMalformedSandboxFailed() external {
        bytes memory data = abi.encodeWithSelector(SandboxFailedError.selector);
        vm.expectRevert(bytes("")) ;
        LibSandbox.handleSandboxCallRevert(data, false);
    }

    function test_handleSandboxCallRevert_revertsOnNotSandboxSucceeded() external {
        bytes memory data = "abcd";
        vm.expectRevert(data) ;
        LibSandbox.handleSandboxCallRevert(data, false);
    }

    function test_handleSandboxCallRevert_returnsTrueOnSandboxSucceeded() external {
        bytes memory data = abi.encodeWithSelector(SandboxSucceededError.selector);
        assertEq(LibSandbox.handleSandboxCallRevert(data, false), true);
    }
}
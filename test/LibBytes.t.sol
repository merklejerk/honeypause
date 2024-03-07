// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from 'forge-std/Test.sol';
import { LibBytes } from '../src/LibBytes.sol';

contract LibBytesTest is Test {
    function test_rawRevert_canRevertNothing() external {
        bytes memory data = "";
        vm.expectRevert(data);
        LibBytes.rawRevert(data);
    }

    function test_rawRevert_canRevertSomething() external {
        bytes memory data = "foobar";
        vm.expectRevert(data);
        LibBytes.rawRevert(data);
    }

    function test_skip_canSkipLeadingBytes() external {
        bytes memory data = "foobar";
        bytes memory ptr = LibBytes.skip(data, 2);
        assertEq(ptr, "obar");
        uint256 dataOffset;
        uint256 ptrOffset;
        assembly ("memory-safe")  {
            dataOffset := data
            ptrOffset := ptr
        }
        assertGt(ptrOffset, dataOffset);
    }

    function test_skip_canSkipAllBytes() external {
        bytes memory data = "foobar";
        bytes memory ptr = LibBytes.skip(data, data.length);
        assertEq(ptr, "");
    }

    function test_skip_revertsIfSkippingMoreThanLength() external {
        bytes memory data = "foobar";
        vm.expectRevert();
        LibBytes.skip(data, data.length + 1);
    }

    function test_readSelector_canReadFirst4Bytes() external {
        bytes memory data = "foobar";
        bytes4 sel = LibBytes.readSelector(data);
        assertEq(sel, bytes4(0x666f6f62));
    }

    function test_readSelector_reversIfReadingBeyondEnd() external {
        bytes memory data = "foo";
        vm.expectRevert(); 
        LibBytes.readSelector(data);
    }
}
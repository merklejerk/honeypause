// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library LibBytes {
    function rawRevert(bytes memory data) internal pure {
        assembly ('memory-safe') {
            revert(add(data, 0x20), mload(data))
        }
    }

    function destroySelector(bytes memory data)
        internal pure returns (bytes4 selector, bytes memory ptr)
    {
        uint256 dataLen = data.length;
        assert(dataLen >= 4);
        assembly ('memory-safe') {
            selector := shl(224, shr(224, mload(add(data, 0x20))))
            ptr := add(data, 0x4) 
            mstore(ptr, sub(dataLen, 0x4))
        }
    }
}

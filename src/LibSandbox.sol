// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { LibBytes } from './LibBytes.sol';

error SandboxFailedError(bytes innerError);
error SandboxSucceededError(bytes data);

library LibSandbox {
    using LibBytes for bytes;

    function safeCall(address target, bytes memory callData)
        internal returns (bytes memory resultData)
    {
        bool success;
        (success, resultData) = target.call(callData);
        return _handleSafeCallResult(success, resultData);
    }

    function safeStaticCall(address target, bytes memory callData)
        internal view returns (bytes memory resultData)
    {
        bool success;
        (success, resultData) = target.staticcall(callData);
        return _handleSafeCallResult(success, resultData);
    }

    // Look for successful sandbox revert data and either revert or return false otherwise,
    // depending on the value of `swallow`. Warning: Modifies `errData` in place.
    function handleSandboxCallRevert(bytes memory errData, bool swallow)
        internal pure returns (bool succeeded)
    {
        if (errData.length >= 4) {
            bytes4 selector = errData.readSelector();
            if (selector == SandboxFailedError.selector) {
                if (!swallow) {
                    abi.decode(errData.skip(4), (bytes)).rawRevert();
                }
                return false;
            }
            if (selector != SandboxSucceededError.selector) {
                if (!swallow) {
                    errData.rawRevert();
                }
                return false;
            }
        } else {
           if (!swallow) {
                errData.rawRevert();
           }
           return false;
        }
        return true;
    }
   
    function _handleSafeCallResult(bool success, bytes memory resultData)
        internal pure returns (bytes memory resultData_)
    {
        if (!success) {
            // Bubble up a revert unless it leads with the
            // SandboxSucceededError selector.
            if (resultData.length >= 4 && resultData.readSelector()
                    == SandboxSucceededError.selector)
            {
                // Wrap the revert and throw it.
                revert SandboxFailedError(resultData);
            }
            // Re-throw the revert.
            resultData.rawRevert();
        }
        return resultData;
    }
}
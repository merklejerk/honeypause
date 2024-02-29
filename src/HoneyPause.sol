// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 } from 'solmate/tokens/ERC20.sol';

interface IVerifier {
    function beforeExploit(bytes memory exploitData) external returns (bytes memory stateData);
    function assertExploit(bytes memory exploitData, bytes memory stateData) external;
}

interface IPauser {
    function pause() external;
}

interface IExploiter {
    function exploit() external;
}

interface IPayer {
    function payExploiter(ERC20 token, address payable to, uint256 amount) external;
}

library LibBytes {
    function rawRevert(bytes memory data) internal pure {
        assembly ('memory-safe') {
            revert(add(data, 0x20), mload(data))
        }
    }

    function rawRevert(bytes memory data, uint256 startOffset) internal pure {
    }

    function destroySelector(bytes memory data)
        internal pure returns (bytes4 selector, bytes memory ptr)
    {
        uint256 dataLen = data.length;
        assert(dataLen >= 4);
        assembly ('memory-safe') {
            selector := shl(252, shr(252, mload(add(data, 0x20))))
            ptr := add(data, 0x4) 
            mstore(ptr, sub(dataLen, 0x4))
        }
    }
}

using LibBytes for bytes;

ERC20 constant ETH_TOKEN = ERC20(address(0));

struct Pot {
    address operator;
    ERC20 payoutToken;
    uint256 payoutAmount;
    IVerifier verifier;
    IPauser pauser;
    IPayer payer; 
}

error OnlyPotOperatorError();
error InvalidOperatorError();
error InvalidClaimError();
error InvalidExploitError();
error InvalidPotConfigError();
error InsufficientPayoutError();
error ExploitFailedError(bytes innerError);
error ExploitSucceededError();

event OperatorChanged(uint256 indexed potId, address oldOperator, address newOperator);
event Created(uint256 potId, string name, ERC20 payoutToken, uint256 payoutAmount, IVerifier verifier);
event Cancelled(uint256 potId);
event Claimed(uint256 indexed potId, ERC20 payoutToken, uint256 payoutAmount);

contract HoneyPause {

    uint256 public potCount;
    mapping (uint256 potId => Pot pot) public pots;
    
    modifier onlyPotOperator(uint256 potId) {
        if (msg.sender != pots[potId].operator) {
            revert OnlyPotOperatorError();
        }
        _; 
    }

    function isPotClaimed(uint256 potId) external view returns (bool claimed) {
        return pots[potId].operator == address(0);
    }

    function add(
        string memory name,
        ERC20 payoutToken,
        uint256 payoutAmount,
        IVerifier verifier,
        IPauser pauser,
        IPayer payer,
        address operator
    )
        external returns (uint256 potId)
    {
        potId = ++potCount;
        if (operator == address(0) ||
            address(pauser) == address(0) ||
            address(verifier) == address(0) ||
            address(payer)  == address(0)
        ) {
            revert InvalidPotConfigError();
        }
        pots[potId]  = Pot({
            operator: operator,
            payoutToken: payoutToken,
            payoutAmount: payoutAmount,
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
        emit Created(potId, name, payoutToken, payoutAmount, verifier);
    }

    function replaceOperator(uint256 potId, address newOperator)
        external onlyPotOperator(potId)
    {
        if (newOperator == address(0)) {
            revert InvalidOperatorError();
        }
        pots[potId].operator = newOperator;
        emit OperatorChanged(potId, msg.sender, newOperator);
    }

    function cancel(uint256 potId)
        external onlyPotOperator(potId)
    {
        Pot storage pot = pots[potId];
        pot.operator = address(0);
        emit Cancelled(potId);
    }

    // Warning: DO NOT call via public mempool/RPC.
    function claim(
        uint256 potId,
        address payable payReceiver,
        IExploiter exploiter,
        bytes memory exploitData
    )
        external
    {
        Pot memory pot = pots[potId];
        if (pot.operator == address(0)) {
            // Invalid pot or already claimed.
            revert InvalidClaimError();
        }
        if (address(exploiter) == address(pot.pauser) ||
            address(exploiter) == address(pot.payer))
        {
            revert InvalidExploitError();
        }
        // Preemptively mark pot as claimed.
        pots[potId].operator = address(0);
        // Perform exploit in a sandbox.
        try this.sandboxExploit(exploiter, pot.verifier, exploitData) {
            // Should always fail.
            assert(false);
        } catch (bytes memory errData) {
            if (errData.length >= 4) {
                bytes4 selector;
                (selector, errData) = errData.destroySelector();
                if (selector == ExploitFailedError.selector) {
                    abi.decode(errData, (bytes)).rawRevert();
                }
                if (selector != ExploitSucceededError.selector) {
                    errData.rawRevert();
                }
            } else {
                errData.rawRevert();
            }
        }
        // Pause the protocol.
        pot.pauser.pause();
        // Pay the whitehat.
        _payout(pot.payer, pot.payoutToken, payReceiver, pot.payoutAmount);
        emit Claimed(potId, pot.payoutToken, pot.payoutAmount);
    }

    // Intended to be called through claim. Always reverts. 
    function sandboxExploit(
        IExploiter exploiter,
        IVerifier verifier,
        bytes memory exploitData
    )
        external
    {
        bytes memory stateData;
        try verifier.beforeExploit(exploitData) returns (bytes memory stateData_) {
            stateData = stateData_;
        } catch (bytes memory errData) {
            revert ExploitFailedError(errData);
        }
        try exploiter.exploit() {}
        catch (bytes memory errData) {
            revert ExploitFailedError(errData);
        }
        // TODO: guidance to check that protocol is not already paused or else
        //       WH can both exploit and claim bounty.
        try verifier.assertExploit(exploitData, stateData) {}
        catch (bytes memory errData) {
            revert ExploitFailedError(errData);
        }
        revert ExploitSucceededError();
    }

    function _payout(IPayer payer, ERC20 token, address payable to, uint256 amount)
        internal
    {
        uint256 balBefore = _balanceOf(token, to);
        payer.payExploiter(token, to, amount);
        uint256 balAfter = _balanceOf(token, to);
        if (balBefore > balAfter || balAfter - balBefore < amount) {
            revert InsufficientPayoutError();
        }
    }

    function _balanceOf(ERC20 token, address owner)
        internal view returns (uint256 bal)
    {
        if (token == ETH_TOKEN) {
            return owner.balance;
        }
        return token.balanceOf(owner);
    }
}

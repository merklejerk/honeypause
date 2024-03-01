// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { LibBytes } from './LibBytes.sol';

/// @dev Interface for a protocol's verifier contract.
interface IVerifier {
    /// @dev Called before the exploit is carried out to prepare any necessary observations
    ///      required for assertExploit().
    /// @param verifierData Data supplied by the whitehat that can help identify where
    ///                     the exploit takes place. For example, a specific pool in the protocol.
    /// @return verifierStateData Arbitrary data the verifier may return to be passed into
    ///                           assertExploit().
    function beforeExploit(bytes memory verifierData) external returns (bytes memory verifierStateData);
    /// @dev Called after the exploit is carried out to assert that the protocol is in an exploited
    ///      state. This is typically done by checking that comprehensive invariants have been violated.
    ///      The protocol should 
    ///      If the function succeeds, the protocol is exploited.
    ///      If the function reverts, the protocol is NOT exploited.
    /// @param verifierData The same data passed into `beforeExploit()`.
    /// @param verifierStateData The same data returned by `beforeExploit()`.
    function assertExploit(bytes memory verifierData, bytes memory verifierStateData) external;
}

/// @dev Interface for a protocol's pauser contract.
interface IPauser {
    /// @dev Pause a protocol.
    ///      The implementer MUST check that the caller of this function is the HoneyPause contract.
    function pause() external;
}

/// @dev Interface for an exploit contract provided by a whitehat making a claim.
interface IExploiter {
    /// @dev Perform the exploit.
    /// @param exploiterData Arbitrary data that the caller of `claim()` can pass in.
    function exploit(bytes memory exploiterData) external;
}

/// @dev Interface for a protocol's payer contract.
interface IPayer {
    /// @dev Pay the whitehat the bounty after proving an exploit was possible.
    ///      The implementer MUST check that the caller of this function is the HoneyPause contract.
    ///      This payment mechanism should be distinct from typical protocol
    ///      interactions because this function will be called AFTER the pauser has been invoked.
    /// @param token The bounty token.
    /// @param to The receving account for payment.
    /// @param amount The bounty amount.
    function payExploiter(ERC20 token, address payable to, uint256 amount) external;
}

/// @dev ERC20 type alias for ETH.
ERC20 constant ETH_TOKEN = ERC20(address(0));

error OnlyBountyOperatorError();
error InvalidOperatorError();
error InvalidClaimError();
error InvalidExploitError();
error InvalidBountyConfigError();
error InsufficientPayoutError();
error SandboxFailedError(bytes innerError);
error SandboxSucceededError();

event OperatorChanged(uint256 indexed bountyId, address oldOperator, address newOperator);
event Created(uint256 bountyId, string name, ERC20 payoutToken, uint256 payoutAmount, IVerifier verifier);
event Cancelled(uint256 bountyId);
event Claimed(uint256 indexed bountyId, ERC20 payoutToken, uint256 payoutAmount);

/// @notice An on-chain mechanism for atomically verifying an exploit,
///         pausing a protocol, and paying out a reward. Made possible
///         thanks to private mempools. Made for the EthDenver 2024 hackathon. 
/// @author Lawrence Forman <@merklejerk>
contract HoneyPause {
    using LibBytes for bytes;

    /// @dev A bounty record.
    struct Bounty {
        address operator;
        ERC20 payoutToken;
        uint256 payoutAmount;
        IVerifier verifier;
        IPauser pauser;
        IPayer payer; 
    }

    /// @notice Number of bounties that have been registered, in total.
    ///         The next bounty is simply the ID of this.
    uint256 public bountyCount;
    /// @notice Bounty ID -> bounty information.
    mapping (uint256 bountyId => Bounty bounty) public bounties;
    
    modifier onlyBountyOperator(uint256 bountyId) {
        if (msg.sender != bounties[bountyId].operator) {
            revert OnlyBountyOperatorError();
        }
        _; 
    }

    /// @notice Check whether a bounty has been claimed or is valid.
    /// @param bountyId The bounty.
    function isBountyClaimed(uint256 bountyId) external view returns (bool claimed) {
        return bounties[bountyId].operator == address(0);
    }

    /// @notice Add a new bounty for a protocol.
    /// @param name Name of the protocol to emit as part of the listing.
    /// @param payoutToken The token the bounty will be paid out in. 0 for ETH.
    /// @param payoutToken The bounty amount (in wei).
    /// @param verifier The protocol's verifier contract, which asserts that critical invariants have been broken.
    /// @param pauser A privileged contract that can pause the protocol when called.
    /// @param operator Who can cancel this bounty.
    /// @return bountyId The ID of the created bounty.
    function add(
        string memory name,
        ERC20 payoutToken,
        uint256 payoutAmount,
        IVerifier verifier,
        IPauser pauser,
        IPayer payer,
        address operator
    )
        external returns (uint256 bountyId)
    {
        bountyId = ++bountyCount;
        if (operator == address(0) ||
            address(pauser) == address(0) ||
            address(verifier) == address(0) ||
            address(payer)  == address(0)
        ) {
            revert InvalidBountyConfigError();
        }
        bounties[bountyId]  = Bounty({
            operator: operator,
            payoutToken: payoutToken,
            payoutAmount: payoutAmount,
            verifier: verifier,
            pauser: pauser,
            payer: payer
        });
        emit Created(bountyId, name, payoutToken, payoutAmount, verifier);
    }

    /// @notice Replace the operator for a valid (unclaimed) bounty.
    /// @dev    Must be called by the current operator of a bounty.
    /// @param bountyId The bounty.
    /// @param newOperator The new operator address.
    function replaceOperator(uint256 bountyId, address newOperator)
        external onlyBountyOperator(bountyId)
    {
        if (newOperator == address(0)) {
            revert InvalidOperatorError();
        }
        bounties[bountyId].operator = newOperator;
        emit OperatorChanged(bountyId, msg.sender, newOperator);
    }

    /// @notice Cancel a bounty that has not been claimed.
    /// @dev    Must be called by the current operator of a bounty.
    /// @param bountyId The bounty.
    function cancel(uint256 bountyId)
        external onlyBountyOperator(bountyId)
    {
        Bounty storage bounty = bounties[bountyId];
        bounty.operator = address(0);
        emit Cancelled(bountyId);
    }

    /// @notice The mechanism for whitehats to claim a bounty by proving an exploit.
    ///         The exploit will be carried out but then reverted. If considered valid by
    ///         the bounty protocol's verifier then the protocol will be paused and a payment
    ///         for the bounty will be made to the whtiehat.
    ///         WARNING: The transaction that calls this MUST be submitted to a private
    ///         mempool to prevent bots from frontrunning the transaction and
    ///         actually carrying out the exploit. Even a reverting transaction may
    ///         leak details of the exploit to be dangerous. Only sophisticated whitehats,
    ///         or someone under the guidance of one should attempt to perform this action.
    /// @param bountyId The bounty to claim.
    /// @param payReceiver Where the bounty should go to.
    /// @param exploiter The contract that will carry out the exploit.
    /// @param exploiterData Arbitrary data supplied by the caller to pass to the exploiter contract.
    /// @param verifierData Data the bounty protocol's verifier contract may require to help identify
    ///                     the exploit. For example, a specific pool in a multi-pool protocol.  
    ///                     Whitehats should examine the verifier contract for details.
    function claim(
        uint256 bountyId,
        address payable payReceiver,
        IExploiter exploiter,
        bytes memory exploiterData,
        bytes memory verifierData
    )
        external
    {
        Bounty memory bounty = bounties[bountyId];
        if (bounty.operator == address(0)) {
            // Invalid bounty or already claimed.
            revert InvalidClaimError();
        }
        if (address(exploiter) == address(bounty.pauser) ||
            address(exploiter) == address(bounty.payer))
        {
            revert InvalidExploitError();
        }
        // Preemptively mark bounty as claimed.
        bounties[bountyId].operator = address(0);
        // Perform then exploit in a sandbox.
        try this.sandboxExploit(exploiter, bounty.verifier, exploiterData, verifierData) {
            // Should always fail.
            assert(false);
        } catch (bytes memory errData) {
            _handleSandboxCallRevert(errData);
        }
        // Pause the protocol.
        bounty.pauser.pause();
        // Pay the whitehat.
        _payout(bounty.payer, bounty.payoutToken, payReceiver, bounty.payoutAmount);
        emit Claimed(bountyId, bounty.payoutToken, bounty.payoutAmount);
    }

    /// @notice Carries out an exploit, verifies it, then reverts the call frame.
    /// @dev Not intended to be called directly, but through `claim()`. Unprotected because
    ///      it always reverts anyway.
    function sandboxExploit(
        IExploiter exploiter,
        IVerifier verifier,
        bytes memory exploiterData,
        bytes memory verifierData
    )
        external
    {
        bytes memory verifierStateData;
        try verifier.beforeExploit(verifierData) returns (bytes memory stateData_) {
            verifierStateData = stateData_;
        } catch (bytes memory errData) {
            revert SandboxFailedError(errData);
        }
        try exploiter.exploit(exploiterData) {}
        catch (bytes memory errData) {
            revert SandboxFailedError(errData);
        }
        try verifier.assertExploit(verifierData, verifierStateData) {}
        catch (bytes memory errData) {
            revert SandboxFailedError(errData);
        }
        revert SandboxSucceededError();
    }

    // Look for successful sandbox revert data. Revert otherwise.
    function _handleSandboxCallRevert(bytes memory errData) private pure {
        if (errData.length >= 4) {
            bytes4 selector;
            (selector, errData) = errData.destroySelector();
            if (selector == SandboxFailedError.selector) {
                abi.decode(errData, (bytes)).rawRevert();
            }
            if (selector != SandboxSucceededError.selector) {
                errData.rawRevert();
            }
        } else {
            errData.rawRevert();
        }
    }

    // Call a bounty's payer contract and verify that it transferred the payment.
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

    // Get the balance of a token (or ETH) of an account.
    function _balanceOf(ERC20 token, address owner)
        internal view returns (uint256 bal)
    {
        if (token == ETH_TOKEN) {
            return owner.balance;
        }
        return token.balanceOf(owner);
    }
}

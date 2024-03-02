// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, IExploiter, ETH_TOKEN } from '../../src/HoneyPause.sol';

contract SecretProtocol {
    address public immutable pauser;
    bytes3 public hash;
    bool public paused;

    event PreimageFound(bytes32 preimage);
    event Paused();

    constructor(bytes3 hash_, address pauser_) {
        hash = hash_;
        pauser = pauser_;
    }

    function solve(bytes32 preimage) external {
        require(!paused, 'paused');
        if (hash != 0 && bytes3(keccak256(abi.encode(preimage))) == hash) {
            emit PreimageFound(preimage);
            hash = 0;
        }
    }

    function pause() external {
        require(msg.sender == pauser, 'not pauser');
        paused = true;
        emit Paused();
    }
}

contract SecretProtocolVerifier is IVerifier {
    SecretProtocol immutable public proto;

    constructor(SecretProtocol proto_) { proto = proto_; }

    function beforeExploit(bytes memory)
        external returns (bytes memory stateData)
    {
        require(proto.hash() != 0, 'already exploited');
    }

    function assertExploit(bytes memory, bytes memory) external view {
        require(proto.hash() == 0, 'not exploited');
    }
}

contract SecretExploiter is IExploiter {
    function exploit(bytes memory exploiterData) external {
        (SecretProtocol proto, bytes32 preimage) =
            abi.decode(exploiterData, (SecretProtocol, bytes32));
        proto.solve(preimage);
    }
}

contract SecretProtocolPauser is IPauser {
    HoneyPause immutable honey;
    SecretProtocol public immutable proto;

    constructor(HoneyPause honey_, SecretProtocol proto_) {
        honey = honey_;
        proto = proto_;
    }

    function pause() external {
        require(msg.sender == address(honey), 'not honey');
        proto.pause();
    }
}

contract SecretProtocolPayer is IPayer {
    HoneyPause immutable honey;

    constructor(HoneyPause honey_) {
        honey = honey_;
    }

    function payExploiter(ERC20 token, address payable to, uint256 amount) external {
        require(msg.sender == address(honey), 'not honey');
        token.transfer(to, amount);
    }
}
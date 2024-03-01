// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, IExploiter, ETH_TOKEN } from '../../src/HoneyPause.sol';

contract SecretProtocol {
    bytes3 public hash;

    event PreimageFound(bytes32 preimage);

    constructor(bytes3 hash_) {
        hash = hash_;
    }

    function solve(bytes32 preimage) external {
        if (hash != 0 && bytes3(keccak256(abi.encode(preimage))) == hash) {
            emit PreimageFound(preimage);
            hash = 0;
        }
    }
}

contract SecretProtocolVerifier is IVerifier {
    SecretProtocol immutable public proto;

    constructor(SecretProtocol proto_) { proto = proto_; }

    function beforeExploit(bytes memory)
        external returns (bytes memory stateData)
    {}

    function assertExploit(bytes memory, bytes memory) external view {
        require(proto.hash() != 0, 'not exploited');
    }
}

contract SecretExploiter is IExploiter {
    function exploit(bytes memory exploiterData) external {
        (SecretProtocol proto, bytes32 preimage) =
            abi.decode(exploiterData, (SecretProtocol, bytes32));
        proto.solve(preimage);
    }
}
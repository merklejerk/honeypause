// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC20 } from 'solmate/tokens/ERC20.sol';
import { TestToken } from './Dummies.sol';
import { HoneyPause, IVerifier, IPauser, IPayer, IExploiter, ETH_TOKEN } from '../../src/HoneyPause.sol';

contract SecretProtocol {
    address public immutable pauser;
    bytes3 public hash;
    bool public paused;

    event PreimageFound(string preimage);
    event Paused();

    constructor(bytes3 hash_, address pauser_) {
        hash = hash_;
        pauser = pauser_;
    }

    function solve(string memory preimage) external {
        require(!paused, 'paused');
        if (hash != 0 && bytes3(keccak256(bytes(preimage))) == hash) {
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
        external view returns (bytes memory)
    {
        require(proto.hash() != 0, 'already exploited');
        return "";
    }

    function assertExploit(bytes memory, bytes memory) external view {
        require(proto.hash() == 0, 'not exploited');
    }
}

contract SecretExploiter is IExploiter {
    function exploit(bytes memory exploiterData) external {
        (SecretProtocol proto, string memory preimage) =
            abi.decode(exploiterData, (SecretProtocol, string));
        proto.solve(preimage);
    }
}

contract SecretProtocolPauser is IPauser {
    HoneyPause immutable honey;
    SecretProtocol public immutable proto;
    uint256 immutable public bountyId;

    constructor(
        SecretProtocol proto_,
        HoneyPause honey_,
        uint256 bountyId_
    ) {
        honey = honey_;
        proto = proto_;
        bountyId = bountyId_;
    }

    function pause(uint256 bountyId_) external {
        require(msg.sender == address(honey), 'not honey');
        require(bountyId_ == bountyId, 'wrong bounty');
        proto.pause();
    }
}

contract SecretProtocolPayer is IPayer {
    HoneyPause immutable honey;
    uint256 immutable bountyId;

    constructor(HoneyPause honey_, uint256 bountyId_) {
        honey = honey_;
        bountyId = bountyId_;
    }

    function payExploiter(
        uint256 bountyId_,
        ERC20 token,
        address payable to,
        uint256 amount
    )
        external
    {
        require(msg.sender == address(honey), 'not honey');
        require(bountyId_ == bountyId, 'wrong bounty');
        token.transfer(to, amount);
    }
}

contract SecretProtocolBountyDeployer {
    event Deployed(
        uint256 bountyId,
        SecretProtocol proto,
        SecretProtocolPauser pauser,
        SecretProtocolVerifier verifier,
        SecretProtocolPayer payer
    );

    SecretProtocol immutable public proto;
    SecretProtocolPauser immutable public pauser;
    SecretProtocolVerifier immutable public verifier;
    SecretProtocolPayer immutable public payer;
    uint256 immutable public bountyId;

    constructor(
        HoneyPause honey,
        string memory name,
        TestToken token,
        uint256 amount,
        bytes3 hash,
        address operator
    ) {
        bountyId = honey.bountyCount() + 1;
        address pauserAddress = _getDeployedAddress(address(this), 2);
        proto = new SecretProtocol(hash, pauserAddress);
        pauser = new SecretProtocolPauser(proto, honey, bountyId);
        assert(address(pauser) == pauserAddress);
        verifier = new SecretProtocolVerifier(proto);
        payer = new SecretProtocolPayer(honey, bountyId);
        token.mint(address(payer), amount);
        uint256 bountyId_ = honey.add({
            name: name,
            payoutToken: token,
            payoutAmount: amount,
            verifier: verifier,
            pauser: pauser,
            payer: payer, 
            operator: operator
        });
        assert(bountyId_ == bountyId);
        emit Deployed(bountyId, proto, pauser, verifier, payer);
    }

    function _getDeployedAddress(address deployer, uint32 deployNonce)
        private
        pure
        returns (address deployed)
    {
        assembly {
            mstore(0x02, shl(96, deployer))
            let rlpNonceLength
            switch gt(deployNonce, 0xFFFFFF)
                case 1 { // 4 byte nonce
                    rlpNonceLength := 5
                    mstore8(0x00, 0xD8)
                    mstore8(0x16, 0x84)
                    mstore(0x17, shl(224, deployNonce))
                }
                default {
                    switch gt(deployNonce, 0xFFFF)
                        case 1 {
                            // 3 byte nonce
                            rlpNonceLength := 4
                            mstore8(0x16, 0x83)
                            mstore(0x17, shl(232, deployNonce))
                        }
                        default {
                            switch gt(deployNonce, 0xFF)
                                case 1 {
                                    // 2 byte nonce
                                    rlpNonceLength := 3
                                    mstore8(0x16, 0x82)
                                    mstore(0x17, shl(240, deployNonce))
                                }
                                default {
                                    switch gt(deployNonce, 0x7F)
                                        case 1 {
                                            // 1 byte nonce >= 0x80
                                            rlpNonceLength := 2
                                            mstore8(0x16, 0x81)
                                            mstore8(0x17, deployNonce)
                                        }
                                        default {
                                            rlpNonceLength := 1
                                            switch iszero(deployNonce)
                                                case 1 {
                                                    // zero nonce
                                                    mstore8(0x16, 0x80)
                                                }
                                                default {
                                                    // 1 byte nonce < 0x80
                                                    mstore8(0x16, deployNonce)
                                                }
                                        }
                                }
                        }
                }
            mstore8(0x00, add(0xD5, rlpNonceLength))
            mstore8(0x01, 0x94)
            deployed := and(
                keccak256(0x00, add(0x16, rlpNonceLength)),
                0xffffffffffffffffffffffffffffffffffffffff
            )
        }
    }
}
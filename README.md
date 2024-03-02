# HoneyPause

HoneyPause is a permissionless, on-chain, non-custodial mechanism that allows whitehat hackers to atmoically, objectively, and transparently prove an exploit on a live protocol, pause that protocol, and then collect a bounty. For Ethereum applications that can be exploited in a single transaction, this enables a novel form of proactive protection that can supplement traditional (off-chain) bug bounties, which usually involve potentially lengthy arbitrations.

## Flow

### Protocol Registration
First a protocol must register itself to the HoneyPause contract via the `add()` function, providing:

1. A bounty token and amount.
2. The address of a custom **Verifier** contract which asserts on-chain state invariants that would be violated in the case of an exploit. Examples could be an AMM's reserve violating the constant product formula or a lending protocol incurring bad debt.
3. The address of a custom **Pauser** contract which is authorized to pause/freeze the protocol when called by the HoneyPause contract.
4. The address of a custom **Payer** contract which must pay the bounty to the whitehat when called by the HoneyPause contract. 

Note that the HoneyPause contract never custodies bounties. It is up to the protocol's **Payer** contract to surface funds to cover the bounty when called. This means a protocol may employ an indirect way of paying the bounty when it is demanded, such is liquidating assets, activating a safety module, etc.

### Claiming a Bounty
A whitehat that has discovered an exploit on a registered protocol will post a `claim()` transaction **TO A PRIVATE MEMPOOL**, providing an **Exploiter** contract that will perform the exploit when called by the HoneyPause contract. The HoneyPause contract will:

1. Call into itself to enter a new call frame.
    1. Call into the **Exploiter**, applying the exploit.
    2. Run the protocol's **Verifier** to assert that the protocol has reached an exploited state.
    3. Revert the call frame, undoing the exploit and bubbling up the result of 2.
2. If the exploit was successful, we will then:
    1. Call into the protocol's **Pauser** to freeze the protocol!
    2. Call into the protocol's **Payer** to pay the bounty to the whitehat.
    3. Ensure the whitehat received the stipulated bounty amount.

> ⚠️ It is critical that the whitehat uses a private mempool to submit the transaction to in order to prevent an MEV bot from extracting the exploit from the unmined transaction and frontrunning the claim!

As a further safeguard against extra clever MEV bots, it is recommended that the deployment of the **Exploiter** contract be performed in the same transaction as (prior to) the `claim()` call.

## Writing Verifiers

TODO

## Deployed Addresses

| Chain | Address |
|-------|---------|
| Ethereum Mainnet | `TBD` |
| Ethereum Sepolia | `0x00a4748f0D0072f65aFe9bb52A723733c5878821` |


## Credits

HoneyPause is an EthDenver hackathon project by the following sleep deprived folks:
[@JordanCason](https://github.com/JordanCason)
[@justinschuldt](https://github.com/justinschuldt)
[@merklejer](https://github.com/merklejer)
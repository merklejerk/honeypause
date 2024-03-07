# HoneyPause

HoneyPause is an onchain exploit bounty linked to a circuit breaker. HoneyPause lets whitehats safely and atomically prove a smart contract exploit on chain, `pause` the affected protocol, then collect the bounty-- all in a single transaction. Projects opt into the system by registering a bounty on the smart contract. The entire system is permissionless, non-custodial, and free!

For Ethereum protocols that can be exploited in a single transaction (which are often the case), this offers a novel form of proactive defense that can complement traditional (off-chain) bug bounties, threat monitoring, and in-protocol circuit breakers.

## How it Works

### Protocol Registration
Projects register bounties with the HoneyPause contract via the `add()` function, providing:

1. A bounty token and amount, but no deposit*.
2. The address of a custom [`Verifier`](ause/blob/main/src/HoneyPause.sol#L8) contract which asserts onchain state invariants that would be violated in the case of an exploit. Examples could be an AMM's reserve violating the constant product formula or a lending protocol incurring bad debt.
3. The address of a custom [`Pauser`](./src/HoneyPause.sol#L28) contract which is authorized to pause/freeze the protocol when called by the HoneyPause contract.
4. The address of a custom [`Payer`](./src/HoneyPause.sol#L42) contract which must pay the bounty to the whitehat when called by the HoneyPause contract. 
5. An operator account for the bounty, who will be able to modify the bounty.

> \* Note that the HoneyPause contract never custodies bounties. It is up to the project's **Payer** contract to surface funds to cover the bounty when called.

### Claiming a Bounty
A whitehat that has discovered an exploit on a registered project will submit a successful `claim()` transaction **TO A PRIVATE MEMPOOL**, providing an [`Exploiter`](./src/HoneyPause.sol#L35) contract that will perform the exploit when called by HoneyPause. In the same transaction, the HoneyPause contract will:

1. Call into itself to enter a new call frame.
    1. Run the project's **Verifier** to assert that the protocol has not been exploited yet and to track any necessary state.
    2. Call into the **Exploiter**, applying the exploit.
    3. Run the project's **Verifier** again to assert that the protocol has reached an exploited state (success means exploited).
    4. Revert the call frame, undoing the exploit and bubbling up the result of 3.
2. If the exploit was successful, we will then:
    1. Call into the project's **Pauser** to freeze the protocol.
    2. Call into the project's **Payer** to pay the bounty to the whitehat.
    3. Ensure the whitehat received the agreed bounty amount.

> ⚠️ On Ethereum mainnet, it is critical that the whitehat uses a private mempool mechanism (e.g., Flashbots Protect with max privacy) to submit the transaction in order to prevent discovery of the exploit mechanism before the transaction is mined and the protocol can be paused! On other chains where sequencing cannot be practically frontrun, it may be sufficient to submit directly to the tx sequencer.

You can check out an example trace of a claim tx [here](https://phalcon.blocksec.com/explorer/tx/sepolia/0xd3ce2ef3a80a6461142020909acc8499e8b6e893073c77d534734d7d129abdc7).

## Writing Verifiers
**Verifier**s must confirm that some critical invariants or health checks have been violated in the post-exploit state. Projects need to do the legwork of identifying a robust set of checks that would be considered critical enough to warrant pausing the entire protocol. These would typically be invariants that do not get checked during normal user interactions due to gas constraints.

### Two-Step Verification
The **Verifier** contract should expose two methods: `beforeExploit()` and `assertExploit()`. As the names imply, the former is called before the exploit is executed and the latter is called after.

**Verifier**s *must* implement both `beforeExploit()` and `assertExploit()`, and *both* should verify the protocol's invariants. This redundancy is to prevent an exploiter from actually exploiting the project and then claim the bounty on top of it! A notable quirk is that `beforeExploit()` is expected to revert if the protocol *is* currently exploited and `assertExploit()` is expected to revert if the protocol *is not* currently exploited.

### Verifier Data
Both methods accept an arbitrary `verifierData` bytes array that is *provided by the exploiter* to help identify an exploit. This may be needed if, for example, the exploit occurs on a specific pool that is not easily discoverable onchain. You should document the uses of this data in your **Verifier** as reference to whitehats.

### Verifier State Data
A **Verifier**'s `beforeExploit()` function returns arbitrary data. This will later be passed into `assertExploit()`. If verification requires observing the state delta before and after an exploit, this data can be used to cache information about that state without writing to expensive contract storage. 

### Stateful Verifiers
If the **Verifier** applies any state changes (even transient ones), they should restrict the caller to the HoneyPause contract. Otherwise the **Verifier** may be maliciously invoked before the call to `claim()` to manipulate results.

## Writing Pausers
Because the exploit will be detailed onchain for all to see after the claim tx is made, **Pausers** should pause as much of the protocol to prevent replicating the exploit across related components (pools) of the system. Only the HoneyPause contract should be allowed to call `pause()` on the **Pauser** contract. The pause *must* occur when `Pauser.pause()` is called, and not in the payer, which is called immediately afterwards.

## Writing Payers
The **Payer** contract will be invoked by HoneyPause to transfer the bounty to the whitehat. Bounties can be in either ETH or ERC20. HoneyPause will surround the `payExploiter()` call with balance checks to ensure that payment has been delivered. The **Payer** contract should only allow the HoneyPause contract to call its `payExploiter()` function.

The simplest **Payer** implementation will transfer the bounty directly out of a dedicated fund. Alternatively, a project may choose to keep the bounty value in its protocol and perform the conversion on-the-fly. In that case, the payment mechanism should be distinct from normal user operations on the protocol because the **Payer** will be invoked *after* the **Pauser**. Keep in mind that more complex payment mechanisms can open projects up to a secondary exploit.

## Deployed Addresses

| Chain | Address |
|-------|---------|
| Ethereum Mainnet | `TBD` |
| Ethereum Sepolia | [`0x5cd701310ae6e3185C29de433019C96efd298d60`](https://sepolia.etherscan.io/address/0x5cd701310ae6e3185c29de433019c96efd298d60) |

## Credits

HoneyPause is originally an EthDenver 2024 hack by [@justinschuldt](https://github.com/justinschuldt), [@CryptRillionair](https://twitter.com/CryptRillionair), and [@merklejerk](https://twitter.com/merklejerk), but we ultimately want this project to be community owned, so feedback and contributions are welcome!
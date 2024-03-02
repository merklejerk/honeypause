# HoneyPause

HoneyPause is a permissionless on-chain exploit bounty tied to a circuit breaker. HoneyPause lets whitehats safely and atomically prove a smart contract exploit <i>on-chain</i>, pause the affected protocol, then collect a bounty. Protocols can opt into the system by registering a bounty on the smart contract. The entire system is permissionless, non-custodial, and free!

For Ethereum applications that can be exploited in a single transaction, this adds another form of proactive defense that can supplement traditional (off-chain) bug bounties and monitoring.

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
    1. Run the protocol's **Verifier** to assert that the protocol has not been exploited yet and to track any necessary state.
    2. Call into the **Exploiter**, applying the exploit.
    3. Run the protocol's **Verifier** again to assert that the protocol has reached an exploited state (success means exploited).
    4. Revert the call frame, undoing the exploit and bubbling up the result of 3.
2. If the exploit was successful, we will then:
    1. Call into the protocol's **Pauser** to freeze the protocol.
    2. Call into the protocol's **Payer** to pay the bounty to the whitehat.
    3. Ensure the whitehat received the agreed bounty amount.

> ⚠️ It is critical that the whitehat uses a private mempool to submit the transaction to in order to prevent an MEV bot from extracting the exploit from the unmined transaction and frontrunning the claim!

As a further safeguard against extra clever MEV bots, it is recommended that the deployment of the **Exploiter** contract be performed in the same transaction as (prior to) the `claim()` call.

## Writing Verifiers

Verifiers should essentially confirm that some critical invariants or health checks have been violated by the exploit. Protocols need to do the legwork of identifying a robust and comprehensive set of checks that would be considered critical enough to warrant pausing the entire protocol. These would typically be invariants that do not get checked during normal user interactions due to gas constraints.

The verifier contract should expose two methods: `beforeExploit()` and `assertExploit()`. As the names imply, the former is called before the exploit is executed and the latter is called after. Both methods accept an arbitrary `verifierData` bytes array that is provided by the exploiter to help identify an exploit. This may be needed if, for example, the exploit occurs on a specific pool that is not easily discoverable on-chain. You should document the uses of this data in your verifier.

A verifier's `beforeExploit()` function may also return arbitrary, intermediate state data, which is another bytes array. This will ultimately be passed into `assertExploit()`. A verifier can use this data to remember things between calls without affecting state. 

### Risks
Verifiers should try to ensure that the protocol is not in an exploited state when `beforeExploit()` is called. Otherwise an attacker can exploit a protocol beforehand but still collect the bounty, effectively double-dipping.

If the verifier performs state changes (even transient ones), they should restrict the caller to the HoneyPause contract. Otherwise the verifier may inherit invalid state from a prior call that could affect validation.

## Writing Pausers

Pausers should generally be designed to pause the *entire* protocol. Only the HoneyPause contract should be allowed to call `pause()` on the Pauser contract.

## Writing Payers

Because the system is non-custodial, the Payer contract must be invoked by HoneyPause to transfer the bounty to the whitehat. Only the HoneyPause contract should be allowed to call the `payExploiter()` function. HoneyPause will track the balance of the whitehat to ensure funds have been delivered.

Instead of reserving a pool of payment coins for the bounty, a protocol may choose to perform some kind of just-in-time conversion of its assets towards the bounty. But note that the call to `payExploiter()` actually occurs *after* the protocol has been paused. The delivery mechanism used needs to be distinct from usual operations affected by a pause. Also, be wary of complex conversions as that increases the chances of a secondary exploit occurring in the Payer.

## Deployed Addresses

| Chain | Address |
|-------|---------|
| Ethereum Mainnet | `TBD (will deploy if we get on stage)` |
| Ethereum Sepolia | `0x00a4748f0D0072f65aFe9bb52A723733c5878821` |

## Credits

HoneyPause is an EthDenver hackathon project by the following sleep deprived folks:
* [@CryptRillionair](https://twitter.com/CryptRillionair)
* [@justinschuldt](https://github.com/justinschuldt)
* [@merklejerk](https://github.com/merklejerk)
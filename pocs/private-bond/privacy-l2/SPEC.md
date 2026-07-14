---
title: "Private Bond (Aztec L2)"
status: Complete
version: 1.0.0
authors: ["Yanis"]
created: 2026-01-23
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/use-case-private-bonds.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-bonds.md"
---

# Private Institutional Bond on Aztec L2

## Overview

This protocol implements confidential institutional bonds on Aztec, an Ethereum L2 with native privacy. Aztec enshrines privacy primitives (notes, nullifiers, Merkle trees, ZK proofs) into a distributed network, providing:

- **Privacy**: Encrypted notes, nullifiers, private execution handled by protocol
- **Ethereum security**: ZK rollup settling to L1
- **Programmability**: Contracts mix public and private state/functions
- **Decentralization**: Sequencer network (removes trusted relayer)

The contract implements: bond lifecycle (issuance, transfer, redemption), whitelist enforcement, issuer admin controls, and regulatory viewing key support.

## Identity & Access Model

**Aztec Address**: Each user has an Aztec account (contract wallet) identified by `AztecAddress`. This address is public and used for:

- Whitelist registry entries
- Note recipient identification
- Transaction authorization

**Whitelist**: Public mapping of approved addresses maintained by issuer.

```
whitelist: Map<AztecAddress, bool>
```

**Enforcement**: Transfer functions check whitelist status before execution. For private transfers, the check reads public state (whitelist) from within a private function context.

**Privacy Model**: Sender and recipient addresses are linkable per transaction (visible via whitelist reads). Amounts and balances remain hidden. This aligns with institutional requirements where participant identities are public but positions are confidential.

> **Privacy Enhancement (not in PoC)**: To unlink participants, the whitelist could be stored as a Merkle tree root with users proving membership via private inclusion proofs.

**Issuer Role**: Single privileged address stored in public state. Can:

- Distribute bond notes from initial pool
- Add/remove addresses from whitelist
- Transfer ownership
- Settle redemption requests

## Storage Structure

**Public State:**

```
owner: PublicMutable<AztecAddress>
whitelist: Map<AztecAddress, bool>
total_supply: PublicMutable<u64>
maturity_date: PublicMutable<u64>
```

**Private State:**

```
private_balances: Map<AztecAddress, BalanceSet>
```

`BalanceSet` is Aztec's private balance primitive - a set of encrypted notes representing a user's holdings. Notes are created on receive and consumed on transfer/burn.

**Fixed Supply Model**: Total supply is set once at contract initialization and never changes. The entire supply is minted to the issuer's private balance at deployment. This prevents observers from deducing transaction amounts by watching supply changes.

## Primary Market: Issuance

The issuer deploys contract with `initialize(total_supply, maturity_date)`, minting the total supply to issuer's private balance.

**Distribution Flow:**

1. Investor completes KYC off-chain
2. Issuer adds investor address to whitelist
3. Investor sends fiat payment via traditional rails
4. Issuer confirms payment receipt
5. Issuer calls `distribute_private(investor, amount)`:
   - Checks caller is owner
   - Checks investor is whitelisted
   - Transfers from issuer's private balance to investor
   - Total supply unchanged

Observer can see that the investor received bonds (via whitelist check) but cannot determine how much.

> **PoC Limitation**: On-chain payment requires a stablecoin contract on Aztec L2. For PoC, we use off-chain fiat settlement. In production, Aztec's native shielding enables bridging L1 stablecoins to private L2 tokens for atomic DvP.

## Secondary Market: Trading

Peer-to-peer trading via atomic DvP: bond tokens exchanged for payment tokens in a single transaction.

**RFQ Flow (Off-chain):**

1. Buyer broadcasts Request for Quote to potential sellers
2. Sellers respond with price quotes
3. Buyer selects best quote
4. Both parties create authwits for the agreed terms
5. Either party (or a relayer) executes the atomic swap on-chain

**Simple Transfer** (bond only):

```
transfer_private(to: AztecAddress, amount: u64)
```

- Checks both sender and recipient are whitelisted
- Consumes sender's notes, creates note for recipient

**Atomic DvP** (bond <-> stablecoin):

Uses the [atomic swap pattern](#appendix-authentication-witness-authwit) with a DvP contract. Both parties pre-authorize the swap via authwit, then either party executes:

1. Seller creates authwit: "DvP can transfer X bonds to Buyer"
2. Buyer creates authwit: "DvP can transfer Y stablecoins to Seller"
3. Execute: DvP verifies both authwits, atomically swaps assets

Both parties must be whitelisted. Trade terms are locked in authwits - neither party can modify after signing.

## Redemption & Maturity

At maturity, bondholders redeem notes for par value. Redemption uses the same [atomic swap pattern](#appendix-authentication-witness-authwit) as secondary trading - bonds exchanged for stablecoins - except bonds are burned instead of transferred.

### Flow

```
┌──────────┐                                       ┌──────────┐
│ Investor │                                       │  Issuer  │
│(has bonds)                                       │(has stables)
└────┬─────┘                                       └────┬─────┘
     │                                                  │
     │  1. Create authwit:                              │
     │     "Bond contract can burn X of my bonds       │
     │      if I receive Y stables"                    │
     │──────────────────────────────────────────────────┼──┐
     │                                                  │  │
     │       (Investor can cancel anytime               │  │
     │        before step 4)                            │  │
     │                                                  │  │
     │                        2. Issuer sources         │  │
     │                           liquidity (off-chain)  │  │
     │                                                  │  │
     │                        3. Create authwit:        │  │
     │                           "Bond contract can     │  │
     │                            transfer my Y stables"│  │
     │                                                  │──┼──┐
     │                                                  │  │  │
     │                        4. settle_redemption()    │  │  │
     │                                                  │  │  │
     │              ┌───────────────────────────────────┴──┴──┴──┐
     │              │  Bond Contract (atomic):                   │
     │              │  - Check maturity date reached             │
     │              │  - Verify investor's authwit               │
     │              │  - Verify issuer's authwit                 │
     │              │  - Burn investor's bonds                   │
     │              │  - Transfer issuer's stables to investor   │
     │              │  - Emit nullifiers (consume authwits)      │
     │              └────────────────────────────────────────────┘
     │                                                  │
     ▼                                                  ▼
 receives stables                                bonds redeemed
```

### Why 2-Step?

Real bond economics: issuer receives cash at issuance and uses it (working capital, investment). At maturity, issuer pays from future cash flows - they don't have redemption capital locked upfront.

The investor's authwit is a **signed redemption request** that:

- Proves investor intent to redeem
- Locks exact settlement terms (amounts, stablecoin contract)
- Gives issuer time to source liquidity
- Remains cancellable until issuer settles

### Security Properties

- **Investor protected**: Authwit commits to exact terms. Issuer can only settle with matching parameters.
- **No overcollateralization**: Issuer funds not locked until settlement execution.
- **Atomic**: Either both legs execute (burn + payment) or neither does.
- **Cancellable**: Investor can revoke pending authwit before issuer settles.
- **Replay-safe**: Nonce prevents reuse of authwit.

### Privacy

- Settlement amount hidden (private function)
- Only issuer and investor know redemption details
- Total supply unchanged (bonds burned, not transferred)

> **PoC Limitation**: Full authwit redemption requires a stablecoin contract integration. For PoC, we implement a simple `redeem(amount)` where investor burns their own bonds directly and stablecoin settlement happens off-chain via fiat.

## Regulatory Viewing Keys

Regulators need read-only access to transaction details without participating in trades.

### Aztec Key Architecture

Aztec accounts use a multi-key architecture with separation of concerns:

- **Spending key**: authorizes transactions (spending notes)
- **Incoming viewing key (IVK)**: decrypts notes received by the user
- **Tagging key**: enables efficient note discovery without full decryption

Note encryption uses **ECDH** (Elliptic Curve Diffie-Hellman): sender encrypts with recipient's public viewing key, recipient decrypts with their secret viewing key.

### Disclosure Granularity

Aztec provides **app-siloed keys** - viewing keys are scoped per contract. This enables:

| Scope | What's Revealed | Use Case |
|-------|-----------------|----------|
| Per-contract | All user's notes in one contract | Share bond activity without exposing DEX trades |
| Per-user (full) | All user's notes across all contracts | Full audit of one investor |
| Tagging key only | Note existence, not contents | Delegated note discovery service |

**Native per-note disclosure is not supported.** To share a specific transaction with a regulator without revealing other activity, the application would need to implement custom ECDH encryption of note metadata to the regulator's public key.

### Regulatory Approaches

**Per-contract disclosure (recommended for bonds)**:

1. User shares their app-siloed IVK for the bond contract
2. Regulator decrypts all bond notes for that user
3. Other contract activity remains private

**Issuer-mediated**:

1. Issuer collects viewing keys at KYC onboarding
2. Issuer provides keys to regulator on request
3. Centralized but practical for regulated markets

> **Future Enhancement (not in PoC)**: Per-note selective disclosure via application-level ECDH encryption to regulator keys, or ZK proofs of compliance without revealing underlying data.

## Security Model

**Trust Assumptions**:

- Aztec protocol is secure (ZK proofs, sequencer, L1 settlement)
- Issuer is honest for whitelist management
- Users secure their own keys

**What Aztec Provides** (vs custom-utxo approach):

| Security Property                          | Status                  |
| ------------------------------------------ | ----------------------- |
| Double-spend prevention via nullifiers     | Handled by protocol     |
| Note privacy via encryption                | Handled by protocol     |
| Balance integrity via protocol constraints | Handled by protocol     |
| Sequencer censorship resistance            | Decentralized sequencer |
| Frontrunning mitigation                    | Encrypted mempool       |

**Application-Level Concerns**:

- **Issuer censorship**: Issuer can refuse to whitelist addresses (acceptable for regulated context)
- **Viewing key scope**: Per-contract granularity; per-note disclosure requires custom implementation

**Authwit Security**:

- Authwit hash includes: caller, contract, function selector, all arguments, chain ID
- Investor commits to exact settlement terms - issuer cannot modify
- Nonce prevents replay attacks
- Cancellation possible before execution

## Terminology

Privacy primitives (notes, nullifiers, commitments, Merkle trees) are defined and implemented by Aztec. See [Aztec documentation](https://docs.aztec.network/) for protocol-level details.

**Bond-specific terms:**

| Term         | Definition                                                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| Total Supply | Fixed amount of bonds issued at initialization. Never changes.                                                                        |
| Distribution | Transfer of bonds from issuer's pool to investor (primary market).                                                                    |
| Authwit      | Authentication witness - cryptographic authorization for a specific action. See [Appendix](#appendix-authentication-witness-authwit). |
| Settlement   | Atomic exchange of bonds for stablecoins at redemption.                                                                               |
| Burn         | Destruction of bond notes (nullifiers published, no new notes created).                                                               |

---

## Appendix A: Authentication Witness (Authwit)

Authwit is Aztec's pattern for authorizing contracts to act on behalf of users. It replaces EVM's `approve` pattern with action-specific authorization that works with private state. See [Aztec authwit documentation](https://docs.aztec.network/developers/docs/foundational-topics/advanced/authwit).

### Why Not ERC20 Approve?

Traditional `approve` doesn't work in Aztec's private model:

| Aspect        | ERC20 Approve                                  | Authwit                            |
| ------------- | ---------------------------------------------- | ---------------------------------- |
| Scope         | Blanket allowance (any amount up to limit)     | Specific action (exact parameters) |
| Private state | Cannot access notes (only owner knows secrets) | Works via owner-initiated tx       |
| Revocation    | Requires on-chain tx to set allowance to 0     | Emit nullifier                     |
| Replay        | Allowance persists until changed               | Single-use (nullified after use)   |

Even with authorization, spending private notes requires the owner's participation - they must initiate the transaction so their PXE can provide note secrets to the proving system.

### When Authwit is Required

| Scenario                                                                      | `msg_sender()` | Authwit? |
| ----------------------------------------------------------------------------- | -------------- | -------- |
| Alice calls `bond.transfer(Bob, 100)`                                         | Alice          | No       |
| Alice calls `dvp.execute()` → DvP calls `bond.transfer_from(Alice, Bob, 100)` | DvP contract   | **Yes**  |

When a contract (not the user) calls `transfer_from`, it needs proof the user authorized that specific action.

### Authwit Hash Structure

An authwit commits to exact parameters via a two-level hash:

```
Inner hash:   H(caller, function_selector, args_hash)
Message hash: H(consumer_contract, chain_id, version, inner_hash)
```

This binds authorization to the specific contract, function, arguments, and chain.

### Atomic Swap Pattern

Both secondary market DvP and redemption use the same pattern. The party making an offer (Buyer) creates their authwit first, then the counterparty (Seller) accepts by creating theirs and executing the swap:

```
┌──────────────┐                              ┌─────────────┐
│    Buyer     │                              │   Seller    │
│(has stables) │                              │ (has Bonds) │
└──────┬───────┘                              └──────┬──────┘
       │                                             │
       │  1. Create authwit (offer):                 │
       │     "Swap can transfer my stables"          │
       │────────────────────────────────────────────>│
       │                                             │
       │                                             │  2. Create authwit (accept):
       │                                             │     "Swap can transfer my Bonds"
       │                                             │
       │                     ┌────────────────┐      │
       │                     │  Swap Contract │<─────│
       │                     └───────┬────────┘      │
       │                             │         3. Seller calls execute()
       │                             ▼               │
       │                     ┌────────────────┐      │
       │                     │  Atomically:   │      │
       │                     │  - Verify Buyer's authwit
       │                     │  - Verify Seller's authwit
       │                     │  - Stables: Buyer → Seller
       │                     │  - Bonds: Seller → Buyer
       │                     │  - Emit nullifiers   │
       │                     └────────────────┘      │
       │                             │               │
       ▼                             │               ▼
  receives Bonds <───────────────────┴───────> receives Stables
```

| Use Case         | Party A  | Party B | Asset X | Asset Y     | X Outcome |
| ---------------- | -------- | ------- | ------- | ----------- | --------- |
| Secondary Market | Seller   | Buyer   | Bonds   | Stablecoins | Transfer  |
| Redemption       | Investor | Issuer  | Bonds   | Stablecoins | Burn      |

### Cancellation

Users can cancel unused authwits by directly emitting the nullifier (without executing the authorized action). This invalidates the authwit permanently.

---

## Appendix B: Requirements Coverage

This specification addresses the following requirements from the confidential bond protocol:

| Requirement                           | Status    | Notes                                      |
| ------------------------------------- | --------- | ------------------------------------------ |
| Off-chain settlement (primary market) | Supported | Fiat rails for initial subscription        |
| Issuer minting                        | Supported | Fixed supply at initialization             |
| Bond attributes (maturity)            | Supported | Maturity date enforced on redemption       |
| Bond attributes (ISIN/Asset ID)       | PoC Gap   | Single asset type assumed                  |
| Bond attributes (Coupon)              | N/A       | Zero-coupon bonds only                     |
| Atomic DvP (secondary market)         | Supported | Via authwit pattern                        |
| RFQ matching flow                     | Supported | Off-chain negotiation, on-chain settlement |
| Redemption at maturity                | Supported | Maturity check + burn                      |
| Burn mechanism                        | Supported | Notes destroyed on redeem                  |
| Whitelist (KYC addresses)             | Supported | Public mapping                             |
| Whitelist validation                  | Supported | Checked on all transfers                   |
| Confidential amounts/balances         | Supported | Private notes                              |
| Public participant identities         | Supported | Addresses visible                          |
| Public timestamps                     | Supported | Block timestamps visible                   |
| Viewing keys for regulators           | Supported | App-siloed IVKs; per-note requires custom  |
| Audit trail                           | Partial   | Via viewing keys, no separate log          |
| Double-spend protection               | Supported | Aztec nullifiers                           |
| Access control                        | Supported | Issuer/Investor separation                 |
| Finality                              | Supported | L2 block finality (minutes)                |
| Cost efficiency                       | Supported | L2 gas costs                               |
| Key rotation                          | PoC Gap   | Not implemented                            |

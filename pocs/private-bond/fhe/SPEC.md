---
title: "Private Bond (Zama fhEVM)"
status: Draft
version: 0.1.0
authors: ["Yanis"]
created: 2026-01-28
ethsystems_use_case: "https://github.com/ethsystems/map/blob/master/use-cases/use-case-private-bonds.md"
ethsystems_approach: "https://github.com/ethsystems/map/blob/master/approaches/approach-private-bonds.md"
---

# Private Institutional Bond on Zama fhEVM

## Overview

This protocol implements confidential institutional bonds using Zama's fhEVM - a framework enabling Fully Homomorphic Encryption (FHE) on EVM chains. Unlike UTXO approaches where users generate ZK proofs locally, FHE allows **computations on encrypted data** with computation delegated to off-chain coprocessors while encrypted state remains on-chain.

Key characteristics:

- **Account-based model**: ERC20-like interface with encrypted balances
- **On-chain encrypted computation**: Arithmetic and comparisons on ciphertexts
- **Threshold decryption**: Distributed key management (no single decryption authority)
- **ACL-based access**: Fine-grained control over who can decrypt what

## Identity & Access Model

**Ethereum Address**: Standard EOA used for whitelist registry, balance ownership, transaction authorization, and ACL permissions.

**Whitelist**: Public `mapping(address => bool)` of KYC-approved addresses maintained by issuer. All transfers verify both parties are whitelisted.

**Privacy Model**: Participant addresses are visible on-chain (public whitelist). Balances and transfer amounts are encrypted. This provides value privacy but not graph privacy - observers can see *who* transacts with *whom*, just not *how much*. For institutional bonds, this is often acceptable (and required for AML).

**Issuer Role**: Privileged address that can mint bonds, manage whitelist, transfer ownership, and grant regulatory access.

## FHE Decryption Authorization

In fhEVM, encrypted values (`euint64`, `ebool`) are useless without decryption rights. The ACL system controls who can decrypt:

- `FHE.allow(ciphertext, address)` - Grants address permission to decrypt that ciphertext
- `FHE.allowThis(ciphertext)` - Grants the contract permission for future operations on that ciphertext

**After every state mutation**, the contract must grant decryption rights to affected parties. For example, after a transfer updates `_balances[recipient]`, the contract calls `FHE.allow(_balances[recipient], recipient)` so the recipient can view their new balance. Without this call, the recipient would have encrypted data they cannot decrypt.

**Decryption is pull-based, not automatic.** Authorized addresses must actively request decryption via Zama's Gateway service, which coordinates with the threshold network (2/3 of operators required). Balances remain encrypted until explicitly queried - observers cannot passively monitor values even with ACL permission.

**No revocation**: Once ACL access is granted, it cannot be revoked. The grantee retains decryption rights for that ciphertext permanently.

**Ciphertext handles change on every operation**: When a balance is updated (e.g., `_balances[to] = FHE.add(...)`), a new ciphertext handle is created. Previous permissions do not apply to the new handle - the contract must call `FHE.allow` again after each mutation.

## Bond Identifier

Each bond contract includes a public `bondId` (bytes32) for reconciliation with off-chain systems. This identifier can be:

- **ISIN/CUSIP hash**: `keccak256(abi.encodePacked("US0378331005"))` for standard securities identifiers
- **BDT hash**: `keccak256(abi.encode(bdtData))` where `bdtData` follows the [ICMA Bond Data Taxonomy](https://github.com/ethsystems/map/blob/master/patterns/pattern-icma-bdt-data-model.md)

The `bondId` is public and immutable, enabling external systems (custodians, CSDs, regulators) to match on-chain contracts to off-chain bond records.

## Primary Market: Issuance

The issuer deploys the contract with bond parameters (bond identifier, total supply, maturity date), receiving the full supply as an encrypted balance.

**Distribution Flow:**

1. Investor completes KYC off-chain
2. Issuer adds investor to whitelist
3. Investor sends fiat payment via traditional rails
4. Issuer confirms payment receipt
5. Issuer transfers bonds (encrypted amount - observer sees transfer occurred but not size)

Both issuer and investor can decrypt their resulting balances via ACL.

## Secondary Market: Trading

Peer-to-peer trading uses encrypted approve/transferFrom, similar to ERC20.

**Transfer mechanics**: The contract uses `FHE.select()` to avoid reverts on insufficient balance (which would leak information). Instead, transfers silently become zero if balance is insufficient - the transaction "succeeds" on-chain even if 0 tokens moved. Frontends must request re-encryption via the Gateway post-transaction to confirm whether the transfer actually executed.

```solidity
function _transfer(address from, address to, euint64 amount) internal {
    ebool hasEnough = FHE.le(amount, _balances[from]);
    euint64 transferAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

    _balances[from] = FHE.sub(_balances[from], transferAmount);
    _balances[to] = FHE.add(_balances[to], transferAmount);

    // Grant decryption rights to affected parties
    FHE.allow(_balances[from], from);
    FHE.allow(_balances[to], to);
    FHE.allowThis(_balances[from]);
    FHE.allowThis(_balances[to]);
}
```

**Atomic DvP**: For bond-for-stablecoin swaps, a separate DvP contract can coordinate approve/transferFrom on both token contracts in a single transaction. Requires a confidential stablecoin contract (not included in PoC).

## Redemption & Maturity

At maturity (`block.timestamp >= maturityDate`), bondholders redeem by burning their balance. The contract subtracts from balance without adding elsewhere. Settlement happens off-chain or via atomic swap with stablecoins.

Redemption amounts remain confidential (encrypted). Only the occurrence is visible via emitted event.

## Regulatory Access

The issuer grants regulators decryption rights to specific balances:

```solidity
function grantAuditAccess(address account, address auditor) external onlyOwner {
    FHE.allow(_balances[account], auditor);
}
```

Regulators must actively request decryption via Zama Gateway - access is read-only and on-demand.

**Important**: Access granted to a *current* balance does not automatically apply to *future* balances after trades. Each balance update creates a new ciphertext handle. For continuous audit access, the contract must include the auditor in every `FHE.allow` call after balance mutations - or the issuer must periodically re-grant access.

| Scope              | Support                                                    |
| ------------------ | ---------------------------------------------------------- |
| Per-balance        | Supported (native)                                         |
| Per-account        | Supported                                                  |
| Historical txs     | Requires emitting events with encrypted amounts + ACL grants |
| Revocation         | Not supported (permanent access per ciphertext)            |

## Security Model

### Trust Assumptions

| Component          | Trust Requirement                 |
| ------------------ | --------------------------------- |
| FHE cryptography   | TFHE security (lattice-based)     |
| Threshold network  | 2/3 honest operators (9 of 13)    |
| Coprocessor nodes  | Majority honest for computation   |
| AWS Nitro Enclaves | Hardware attestation integrity    |
| Issuer             | Honest whitelist management       |

### Known Limitations

**Threshold Network Dependency**: Unlike ZK approaches where users hold their own decryption keys, FHE requires the threshold network for any decryption. If unavailable or compromised (>1/3 malicious), users cannot access their balances.

**Hardware Trust**: Current implementation relies on AWS Nitro Enclave attestation. Roadmap targets "ZK-MPC" to remove this.

**Gas Costs**: FHE operations are computationally expensive. Zama optimizes via coprocessors, but costs may exceed ZK approaches.

**Vendor Dependency**: Decryption requires Zama's threshold network. Institutions must rely on Zama's hosted infrastructure or operate their own nodes (significant operational cost).

## Terminology

| Term               | Definition                                                       |
| ------------------ | ---------------------------------------------------------------- |
| euint64            | Encrypted 64-bit unsigned integer                                |
| ebool              | Encrypted boolean                                                |
| externalEuint64    | Encrypted value from off-chain, requires proof validation        |
| FHE.fromExternal() | Validates external encrypted input with coprocessor signatures   |
| ACL                | Access Control List - determines decryption permissions          |
| Threshold network  | MPC network requiring 2/3 cooperation for decryption             |
| Gateway            | Zama component coordinating decryption requests                  |
| TFHE               | Fully Homomorphic Encryption over the Torus                      |

## References

- [Zama fhEVM GitHub](https://github.com/zama-ai/fhevm)
- [Zama Protocol Litepaper](https://docs.zama.org/protocol/zama-protocol-litepaper)
- [Encrypted Operations](https://docs.zama.org/protocol/solidity-guides/smart-contract/operations)
- [Encrypted Inputs](https://docs.zama.org/protocol/solidity-guides/smart-contract/inputs)
- [Confidential ERC20 Reference](https://github.com/zama-ai/fhevm-contracts/blob/main/contracts/token/ERC20/ConfidentialERC20.sol)

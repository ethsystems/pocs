# Changelog

All notable changes to this repository are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/). Since this is a PoC repository (not versioned releases), entries are organized by date.

## How to Update

When making changes, add an entry under the appropriate date heading:

```markdown
## YYYY-MM-DD

### [poc-name] or [repo]
- **Added**: New features or files
- **Changed**: Modifications to existing functionality
- **Fixed**: Bug fixes
- **Removed**: Deleted features or files
```

Use `[repo]` for repository-wide changes (CI, templates, docs).

---

## Unreleased

### [tee_swap]
- **Changed**: the testnet chain indexer folds through `chainfold` 0.3 instead of a hand-rolled poll loop. Total order over (block, log index) and positional dedup are now engine-enforced, and a reorg bisects the observed-block ring to roll back to a retained checkpoint. A watch channel carries fold snapshots in place of the `Notify`/`AtomicBool` signalling; the alloy log source and the poll thread live in the PoC. `ChainIndexer`'s public API is unchanged.
- **Changed**: toolchain moved to 1.95.0, matching `chainfold`'s `rust-version`.

### [shielded-pool-compliance]
- **Changed**: proving links `libbarretenberg` in-process through `barretenberg-rs`'s `ffi` backend instead of spawning the `bb` binary and piping msgpack to it. The `bb` binary is now a prerequisite only for `scripts/generate-verifiers.sh`. Linking the library skips `bb`'s startup, so `BbProver::new` installs the BN254 SRS itself, fetching the prefix it needs into `~/.bb-crs` (the cache `bb` keeps, `BB_CRS_PATH` overrides) when that cache is short. `BbProver::new` no longer takes a `bb` path.
- **Changed**: attestation registry reads fold incrementally through a `chainfold` 0.3 engine, replacing the full event-log rescan that ran on every `current_attestation` call. Each read applies a batch carrying the cursor block's current header, so a reorg is caught by the boundary check and rebuilds from genesis only then.

### [binius-mayo]
- **Breaking**: moved to [ethsystems/mono](https://github.com/ethsystems/mono/pull/17)

### [custom-utxo]
- **Breaking**: the envelope format and the serde shape changed, so any notes/memos/vouchers encrypted or stored on-chain previously are undecryptable by the new code. 

### [resilient-disbursement-rails]
- **Breaking**: the envelope format and the serde shape changed, so any notes/memos/vouchers encrypted or stored on-chain previously are undecryptable by the new code. 

### [shielded-pool-compliance]
- **Breaking**: the envelope format and the serde shape changed, so any notes/memos/vouchers encrypted or stored on-chain previously are undecryptable by the new code. 

### [shielded-pool-extension]
- **Breaking**: the envelope format and the serde shape changed, so any notes/memos/vouchers encrypted or stored on-chain previously are undecryptable by the new code. 

### [shielded-pool]
- **Breaking**: the envelope format and the serde shape changed, so any notes/memos/vouchers encrypted or stored on-chain previously are undecryptable by the new code. 
- **Fixed**: `deposit`, `transfer`, and `withdraw` are `nonReentrant` (OpenZeppelin `ReentrancyGuard`), and `Deposit` is emitted before the ERC-20 pull so a hook-bearing token cannot interleave an insertion ahead of the event (spec 2/SHIELDED-POOL 4.6).
- **Fixed**: the transfer circuit gives each input its own Merkle proof length (`proof_length_0`, `proof_length_1`), and all three circuits range-check the proof length against the tree depth (spec 2/SHIELDED-POOL 5.3).
- **Breaking**: the deposit circuit binds the spending key (`owner_pubkey == poseidon1(spending_key)`) and takes a `funding_address` public input; `ShieldedPool.deposit` gains an `address fundingAddress` parameter, requires `msg.sender == fundingAddress`, and pulls tokens from it. The guard is needed because the circuit does not constrain the funding address: without it any attested key holder could deposit against another address's outstanding approval. Relayed deposits need a funding-address authorisation signature (not implemented). Before, `owner_pubkey` was a free witness and anyone could build a deposit proof for any attested key from public registry data (spec 2/SHIELDED-POOL 5.3, deposit constraint 1). `DepositWitness::new` takes the spending key and funding address. Verifier regenerated.
- **Fixed**: the encrypted payload is bound to the proof. Deposit and transfer circuits take a `payload_hash` public input (`keccak256(payload) mod p`); `ShieldedPool` recomputes it from the submitted bytes (`payloadCommitment`) and passes it to the verifier, so a relayer that garbles the payload cannot land the operation (spec 2/SHIELDED-POOL 4.6). `DepositWitness::new` and `TransferWitness::new` take the encrypted payload. Verifiers regenerated.
- **Fixed**: circuit amounts are now u128 (transfer witnesses, overflow-checked addition) and the public `amount` of deposit and withdraw is range-checked in-circuit to `< 2^128`. Before, transfer amounts were u64 and the deposit amount was an unchecked field element (spec 2/SHIELDED-POOL 5.3). Verifiers regenerated.

### [repo]
- **Changed**: README PoC table synced with current `pocs/` (added `private-identity`, linked published writeups, updated statuses)

### [shielded-pool-compliance]
- **Added**: Compliance extension to the shielded pool: attested-issuer velocity screening compiled into the gated circuits, a per-account per-epoch compliance note chained through the commitment tree, attestation expiry as the revocation mechanism, and a blocked-funds exit for lapsed or policy-blocked accounts. Noir circuits, Solidity contracts, and a Rust wallet/auditor client.

### [diy-validium]
- **Fixed**: `escapeWithdraw` replay at non-canonical leaf indices. `_verifyMerkleProof` consumed only `proof.length` bits of `leafIndex` while `claimed` was keyed on the full `uint256`, so one valid `(leaf, proof)` pair re-verified at `leafIndex + k * 2^depth` and drained the bridge. The verifier now requires the index to be fully consumed. Reported by Semih Civelek.
- **Changed**: IMAGE_IDs from hardcoded `bytes32(0)` constants to immutable constructor params in all contracts
- **Added**: `risc0-ethereum-contracts` for real seal encoding in E2E test
- **Added**: E2E test passes real IMAGE_IDs and encoded seals when guest ELFs are compiled

### [private-bond]
- **Added**: `privacy-l2` — Stablecoin contract (minimal private ERC20 for DvP payment leg)
- **Added**: `privacy-l2` — DvP contract (atomic bond↔stablecoin swap via authwit)
- **Added**: `privacy-l2` — Noir-native tests using Aztec `TestEnvironment` (8 tests)
- **Changed**: `privacy-l2` — Restructured `contracts/` into Nargo workspace
- Pending: `fhe` approach

---

## 2025-01-26

### [private-bond]
- **Added**: `custom-utxo` approach — EVM-based UTXO model with Noir ZK circuits
- **Added**: `privacy-l2` approach — Aztec L2 native privacy implementation
- **Added**: Shared `REQUIREMENTS.md` derived from ethsystems/map use case

### [repo]
- **Added**: Project documentation (`CLAUDE.md`, `CONTRIBUTING.md`)
- **Added**: PoC template structure in `pocs/_template/`
- **Added**: CI workflow for structure validation

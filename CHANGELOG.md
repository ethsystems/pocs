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

### [repo]
- **Changed**: README PoC table synced with current `pocs/` (added `private-identity`, linked published writeups, updated statuses)

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

# Private Payments Benchmarks

Comparison of two implementation approaches.

> Note: these are not precise benchmarks and should not be seen as a point of reference. These are estimates gathered from documentation and code available, that we could have run. It is recommended that an implementer run their own benchmarks with the surrounding domain specific business logic & configuration surrounding it to obtain accurate measurements.


All benchmarks have been run on an m4 mbp, 14c, 48gig


## Gas Costs

### Shielded pool

Generated with:

```
cd shielded-pool && forge test --gas-report
```

| Contract | Function | Min | Mean | Median | Max |
|---|---|---|---|---|---|
| PoseidonT3 | hash | 29,336 | 29,336 | 29,336 | 29,336 |
| PoseidonT5 | hash | 149,508 | 149,508 | 149,508 | 149,508 |
| ShieldedPool | addSupportedToken | 23,735 | 45,878 | 47,518 | 47,518 |
| ShieldedPool | attestationRegistry | 2,448 | 2,448 | 2,448 | 2,448 |
| ShieldedPool | commitmentRoot | 7,835 | 7,835 | 7,835 | 7,835 |
| ShieldedPool | deposit | 25,387 | 154,920 | 155,793 | 243,250 |
| ShieldedPool | getCommitmentCount | 2,379 | 2,379 | 2,379 | 2,379 |
| ShieldedPool | isKnownRoot | 7,897 | 9,197 | 10,064 | 10,064 |
| ShieldedPool | nullifiers | 2,504 | 2,504 | 2,504 | 2,504 |
| ShieldedPool | owner | 2,404 | 2,404 | 2,404 | 2,404 |
| ShieldedPool | removeSupportedToken | 24,017 | 25,225 | 25,640 | 26,019 |
| ShieldedPool | setAttestationRegistry | 23,724 | 26,040 | 23,744 | 30,653 |
| ShieldedPool | setVerifier | 23,779 | 26,095 | 23,799 | 30,708 |
| ShieldedPool | supportedTokens | 2,628 | 2,628 | 2,628 | 2,628 |
| ShieldedPool | transfer | 24,250 | 180,731 | 44,425 | 385,274 |
| ShieldedPool | transferOwnership | 23,810 | 25,399 | 23,842 | 28,547 |
| ShieldedPool | validRoots | 2,526 | 2,526 | 2,526 | 2,526 |
| ShieldedPool | verifier | 2,383 | 2,383 | 2,383 | 2,383 |
| ShieldedPool | withdraw | 25,274 | 47,357 | 32,436 | 99,382 |
| CompositeVerifier | verifyDeposit | 2,587,917 | 2,587,917 | 2,587,917 | 2,587,917 |
| CompositeVerifier | verifyTransfer | 2,656,172 | 2,656,172 | 2,656,172 | 2,656,172 |
| CompositeVerifier | verifyWithdraw | 2,612,628 | 2,612,628 | 2,612,628 | 2,612,628 |
| AttestationRegistry | addAttestation | 24,324 | 268,233 | 296,833 | 334,453 |
| AttestationRegistry | addAttester | 23,666 | 44,123 | 47,233 | 47,233 |
| AttestationRegistry | attestationLeaves | 2,459 | 2,459 | 2,459 | 2,459 |
| AttestationRegistry | attestationRoot | 7,745 | 7,745 | 7,745 | 7,745 |
| AttestationRegistry | getAttestationCount | 2,290 | 2,290 | 2,290 | 2,290 |
| AttestationRegistry | isAuthorizedAttester | 2,567 | 2,567 | 2,567 | 2,567 |
| AttestationRegistry | leafAtIndex | 2,513 | 2,513 | 2,513 | 2,513 |
| AttestationRegistry | owner | 2,447 | 2,447 | 2,447 | 2,447 |
| AttestationRegistry | removeAttester | 23,731 | 25,011 | 25,354 | 25,949 |
| AttestationRegistry | transferOwnership | 23,775 | 25,364 | 23,807 | 28,512 |

### Plasma

Since the intmax2 contracts are not vendored in, these costs come from the integration test, Generated with (100 runs):

```
cd plasma && cargo test --release -- --nocapture
```

**User costs**

| Contract | Function | Min | Mean | Median | Max |
|---|---|---|---|---|---|
| Liquidity | depositERC20 | 135,412 | 137,547 | 137,547 | 139,682 |

There are also additional configurable deposit and withdrawal fees configurable by the intmax operator.

**Operator / infrastructure costs**

| Contract | Function | Min | Mean | Median | Max |
|---|---|---|---|---|---|
| Rollup | postNonRegistrationBlock | 253,198 | 255,776 | 255,891 | 258,119 |
| Rollup | postRegistrationBlock | 240,105 | 242,298 | 242,298 | 244,491 |
| Rollup | processDeposits (via messenger) | 184,320 | 185,995 | 185,995 | 187,670 |
| BlockBuilderRegistry | emitHeartbeat | 29,229 | 29,229 | 29,229 | 29,229 |

> **Note on transfers:** L2 transfers between users are off-chain from a gas perspective. The block builder batches transfers into `postNonRegistrationBlock` / `postRegistrationBlock` calls, amortizing the cost across all senders in the block. In production with full blocks, the amortized cost per transfer drops.

---

## Computation Latency

Generated with (100 runs):
```
cd shielded-pool && cargo run --example bench_proving --release -- --no-capture
```

### Shielded Pool

| Operation | Min | Mean | Median | Max |
|---|---|---|---|---|
| ProofGen(Deposit) | 410ms | 436ms | 428ms | 563ms |
| ProofGen(Transfer) | 891ms | 918ms | 911ms | 991ms |
| ProofGen(Withdraw) | 545ms | 564ms | 561ms | 600ms |

### Plasma

Generated with (100 runs):
```
cd plasma && cargo test --release -- --nocapture
```

**User**

| Operation | Min | Mean | Median | Max |
|---|---|---|---|---|
| ProofGen(Transfer) | 5.94s | 6.78s | 6.65s | 7.82s |
| ProofGen(Withdrawal) | 7.91s | 8.76s | 8.63s | 9.81s |

**Operator / infrastructure**

| Operation | Min | Mean | Median | Max |
|---|---|---|---|---|
| ProofGen(Deposit) | 43.12s | 45.77s | 45.21s | 49.03s |
| ProofGen(BalanceSync/Transfer) | 42.38s | 45.14s | 44.89s | 48.21s |
| ProofGen(WithdrawalSync) | 38.45s | 41.00s | 40.72s | 43.88s |

> **Note:** Plasma proofs are generated server-side by the `balance_prover` service (plonky2-based), not locally. These timings include HTTP round-trip overhead (but they do not dominate overall timings). The balance sync operations (`sync()`, `sync_withdrawals()`) are notably slower as they involve multiple sequential proof generations (e.g., sender balance proof + receiver balance proof for transfers).

---

## Interpretation

These two approaches solve the same problem in very different ways, so comparing raw numbers head-to-head can be misleading.

The shielded pool PoC puts everything on-chain. Each user generates their own proof and pays the full verification cost (~2.6M gas per operation). It's self-contained, no operator needed, but every action is expensive for the individual.

The plasma PoC (intmax) splits the work. Users only touch L1 for deposits and withdrawals (~137K gas). Transfers happen entirely off-chain, and an operator batches them into block roots (~255K gas per block), spreading that cost across everyone in the batch. The more users per block, the cheaper it gets per person.

On proof generation, the shielded pool PoC uses UltraHonk via Noir/Barretenberg (sub-second, client-side, KZG over a universal setup rather than a circuit-specific one), while the plasma PoC (intmax) uses Plonky2 (multi-second, server-side, no trusted setup). The plasma timings also include network round-trips and sequential multi-proof steps (e.g., separate sender and receiver balance proofs for a transfer), so they're not directly comparable to the shielded pool's single local proof.

Put simply: the shielded pool PoC trades higher per-user cost for fewer trust assumptions, while the plasma PoC (intmax) trades operator infrastructure for lower per-user cost at scale.

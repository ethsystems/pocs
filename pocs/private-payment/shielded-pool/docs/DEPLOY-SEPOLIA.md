# Sepolia deployment of the shielded pool

This page records one deployment of the PoC contracts to Sepolia and the check that ran against it.
The deployment is a fixed check target, not a service: real verifiers, a mock token, no funds.

**Superseded on master.** This deployment is of `a04b8b3`, and master has since changed two of its contracts.
#16 changed the transfer circuit and regenerated `TransferVerifier.sol`, so the transfer verifier here does not
accept proofs from master's transfer circuit. #24 replaced `setVerifier` with the timelocked
`proposeVerifier`/`applyVerifier` that SPEC.md describes, so the owner of this pool can still change the verifier at once.
`deployments.toml` keeps the four addresses `Deploy.s.sol` wrote, marked as superseded. The three verifier addresses stay
env placeholders there: `Deploy.s.sol` reads them, and with literal addresses a run at master without `DeployVerifiers.s.sol`
first would wire a new pool to the old transfer verifier. A redeploy at master will replace this record.

## Record

- Source: commit `a04b8b3`. Both broadcast files record commit `ea4d4e3`, the tip of two local docs commits on top of `a04b8b3`
  that were never pushed. They changed only `docs/` and two C1 helper scripts in `scripts/`, not `contracts/`, `circuits/`
  or `foundry.toml`. The C1 check below rebuilds from `a04b8b3` itself, so it does not depend on `ea4d4e3`.
- Chain: Sepolia, chain ID 11155111. Owner and deployer: `0x53D475A7232cFAF06Ff6B63C1B62b689B4DB3906`.
- All addresses are in the table below; four of them are also in `deployments.toml`, table `[11155111.address]`.
  Every transaction except the repair is in `contracts/broadcast/{DeployVerifiers,Deploy}.s.sol/11155111/run-latest.json`.

| Contract | Address | Block | Deployer nonce |
|---|---|---|---|
| ZKTranscriptLib (deposit) | `0x3CbA008e48a098017A4b331F514D5B83a16CDEAC` | 11948523 | 1, CREATE2 factory |
| ZKTranscriptLib (withdraw) | `0x7cd19aac2Cc4491568C93609Ad50BA9Bb675f48a` | 11948524 | 2, CREATE2 factory |
| ZKTranscriptLib (transfer) | `0x5045ed70C25d12da730f11A0F6d80249EbCA152b` | 11948527 | 3, CREATE2 factory |
| HonkVerifier (deposit) | `0x8f43176BeB45505C0b80E0B115F91A1e7b1113fC` | 11948530 | 4 |
| HonkVerifier (transfer) | `0x0283B13DC7af959449D8344De3Caa6C0dEeB90ff` | 11948533 | 5 |
| HonkVerifier (withdraw) | `0xFe5811D3A1918553027F428F56d427FB28c9deF6` | 11948535 | 6 |
| LeanIMT | `0x38b16dAe55Fefb3198b470E6559F76560c0cce19` | 11948547 | 7, CREATE2 factory |
| PoseidonT5 | `0x889010Cdd13Ee425BD7246E05fE872183B3cC39f` | 11948548 | 8, CREATE2 factory |
| AttestationRegistry | `0xE64018Ba103846D7b09b3CB2A8AC06384196b0bA` | 11948549 | 9 |
| CompositeVerifier | `0x6B9785DF1F803C0e5BCAe78DbEb8C2397a0AC548` | 11948551 | 10 |
| ShieldedPool | `0xABefB40982E399F979cfdc712E57e334eA2B10eA` | 11948552 | 11 |
| MockERC20 | `0x9FCe6bCe03F3966B67dA5F666d7aC0DB1ba37e75` | 11948555 | 12 |
| PoseidonT3 | `0x72B98a5ffF1Dd0e7001A6327b5b99d256EbD1ce8` | 11949456 | 13, CREATE2 factory (repair) |

Nonce 0 was a failed first attempt (see "Lessons"). The deployer nonce is 14 after the repair.

**PoseidonT3 repair.** `Deploy.s.sol` sent PoseidonT3 with nonce 6, which the withdraw verifier had already used.
The chain dropped it: the broadcast entry `0xab1a9111…` has no receipt. The repair sent the same input
(salt plus initcode) to the CREATE2 factory `0x4e59b44847b379578588920ca78fbf26c0b4956c` from the deployer. Its receipt:

- tx `0x176756e1dde18f7b074c8639da26ce5ec2202b08f073ccd2b6115780b7e61964`
- status 1, block 11949456, gas used 25,681,985, effective gas price 25 wei

**Gas.** Receipt gas for the 13 transactions that landed: 142,475,669 (`DeployVerifiers`, 6 receipts)
plus 52,913,353 (`Deploy`, 6 receipts) plus 25,681,985 (repair) is 221,071,007.
The failed first attempt is not in that sum.

## Check

C1 is a deployment checker. It rebuilds the contracts from `a04b8b3` offline and compares them byte for byte with the chain.

- Checker: private, driver `188075d`. Its working tree differed from that revision (`c1.log` line 2),
  so the revision alone does not identify the checker source. A public reader cannot repeat the check yet.
- Block: 11949456, hash `0xe2adfa5f7a107f04fd426348301d82be3f72590440a34a0f7cf12f81ce91ea60` (the repair block).
- RPC: a local anvil fork held at that block, upstream `https://sepolia.gateway.tenderly.co`. C1 trusts the RPC and its history.
- Claim: `docs/deploy-sepolia/sepolia/c1-2026-10-19/claim.json`,
  SHA-256 `eeb4de1c910e2175add812e517c624ae06103a3e4ea061af1d1e360a244a563d`. Log: `c1.log` in the same directory.
- Result: `VERDICT PASS failing=[] warnings=[]`, 32 of 32 `CHECK` lines PASS. C1 compared 12 runtime codes.
  MockERC20 is not in the claim, so C1 did not check it.
- An earlier run at block 11948555, before the repair, failed only `CODE:poseidonT3` (no code at that address).

What a PASS shows: at block 11949456, the 12 contracts at the claimed addresses are byte for byte a fresh
offline build of `a04b8b3` (forge 1.8.3, solc 0.8.37). They are wired to each other, use real verifiers and no mock,
had no verifier change, and have the claimed owner and an empty token list.

What a PASS does not show: that the circuits or the proof system are sound, what the owner does later,
or anything after the check block. A later `setVerifier` call shows only if C1 runs again at a later block.

## Deploy recipe

Run from `pocs/private-payment/shielded-pool` at `a04b8b3`, after `forge soldeer install` and
`git checkout foundry.toml` (soldeer reorders the remappings). Use forge 1.8.3 and the deployer keystore.

```bash
Z=0x0000000000000000000000000000000000000000
export USE_MOCK_VERIFIER=false SEPOLIA_RPC_URL=https://sepolia.gateway.tenderly.co
export DEPOSIT_VERIFIER_ADDRESS=$Z TRANSFER_VERIFIER_ADDRESS=$Z WITHDRAW_VERIFIER_ADDRESS=$Z ATTESTATION_REGISTRY_ADDRESS=$Z
KEY=(--account <deployer keystore> --sender <deployer address>)
forge script contracts/script/DeployVerifiers.s.sol "${KEY[@]}" --rpc-url "$SEPOLIA_RPC_URL" --broadcast --slow --skip-simulation
cast nonce <deployer address> --rpc-url "$SEPOLIA_RPC_URL"   # wait until every DeployVerifiers tx has landed
forge script contracts/script/Deploy.s.sol          "${KEY[@]}" --rpc-url "$SEPOLIA_RPC_URL" --broadcast --slow --skip-simulation
```

The scripts write only the `[11155111.address]` table of `deployments.toml`. Leave the `[31337]` table unchanged.

Lessons from this deployment:

- The first attempt used forge's simulated gas limits and ran out of gas (tx `0x733c231d…`, status 0, block 11948034).
  With `--skip-simulation`, forge takes each limit from the node's `eth_estimateGas`.
- Check the nonce between the scripts and the receipt of every tx hash after them. Forge reported success for the dropped PoseidonT3 tx.
  Match receipts to transactions by hash, not by list position.
- A dropped library lands at its expected address only if you send it again with the same CREATE2 factory, salt and initcode.
  If the code changed, build again and expect new addresses.
- Check at a block at or after the last successful deployment or repair. Here the last `Deploy.s.sol` block (11948555) was too early.

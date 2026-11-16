# Avalanche C-Chain mainnet: runbook

16/11/2026. How to take the Fuji stack (see `AVALANCHE-FULL-MODE.md` and `deployments/fuji.json`) to the C-Chain mainnet (chainId 43114, hardhat network `avalanche`).

**Nothing in this document is authorized by being written down.** Every mainnet deploy and every mainnet transaction needs Frederico's explicit OK at the moment it is sent, in his own words in the thread. A relayed or summarized approval does not count.

## 0. Gate: do not start until all of these are true

| # | Prerequisite | How to check | Owner |
|---|---|---|---|
| P1 | Midnight mainnet deploy done: ComplianceRegistry, TravelRuleGate per institution, policy hash known | `deployment-mainnet-*.json` in dpo2u-midnight, contract state readable from the mainnet indexer | Midnight mainnet thread |
| P2 | **Mainnet admin Safe** created on the C-Chain, threshold ≥ 2, **no VPS key among its owners** | Safe `getOwners()` / `getThreshold()` on 43114; every owner key is on a device Frederico holds | Frederico |
| P3 | **Trusted-setup ceremony** done for each proof lane that will be deployed (policy; membership only if used) | `zk/setup.json` says `"setup": "ceremony"` for the lane; `scripts/deploy-travel-rule-gate.ts` refuses anything else on `avalanche` | ZK owner + external contributors |
| P4 | **Two relayers**, each with its own key, its own Midnight mainnet node + indexer (relayer #2's Midnight node takes its Cardano data from Blockfrost), threshold 2 | each relayer process passes `--once` against mainnet in read-only mode; distinct addresses | Operators |
| P5 | **AVAX** in the deployer and in each relayer | balance ≥ the measured budget (§2) | Frederico |
| P6 | Fuji rehearsal of the exact same commit passed: deploy, relay, mirror, handover, watch | `deployments/fuji.json` + `/var/log/dpo2u-fuji-watch.log` without alerts for ≥ 24 h | Infra thread |

Why the VPS key must not be an admin owner on mainnet: on Fuji the Safe is 2-of-3 with a VPS key, so the VPS plus one stolen device can act alone. On mainnet a compromised VPS must not be one signature away from changing routes, relayers or thresholds. The VPS may hold a **relayer** key (one of N, below threshold), never an admin key.

## 1. Pieces and order

Deploy order matters: each step needs the address of the previous one.

| Step | Contract | Script | Admin at deploy | Notes |
|---|---|---|---|---|
| 1 | `DPO2UComplianceRegistry` (+ attestor) | `scripts/deploy.ts` | `ADMIN_ADDRESS=<Safe>` | gateway submitter via `GATEWAY_ADDRESS` |
| 2 | `DPO2UMidnightRelay` | `scripts/deploy-midnight-relay.ts` | deployer, then `transferAdmin(Safe)` | `RELAYER_ADDRESS`, `RELAY_THRESHOLD=2`, `RELAY_ROUTES`; the registry must authorize the relay as submitter |
| 3 | `DPO2UTravelRuleVerdictMirror` | `scripts/deploy-verdict-mirror.ts` | `ADMIN_ADDRESS=<Safe>` (pending, accepted by the Safe) | `MIRROR_SOURCE_CONTRACT=<Midnight mainnet gate>`, `MIRROR_POLICIES=<policy hash>`, `MIRROR_THRESHOLD=2`; source chain is forced to `midnight:mainnet` |
| 4 | Groth16 verifiers + `DPO2UTravelRuleGate` | `scripts/deploy-travel-rule-gate.ts` | `ADMIN_ADDRESS=<Safe>` | `TRG_DEPLOY_VERIFIERS=policy` (add `membership` only with its ceremony), `TRG_OPERATOR` |
| 5 | PassportOracle V2, Solvency, others | their scripts | Safe | only if in the launch scope |

**Caveat on step 2:** `deploy-midnight-relay.ts` assumes deployer = registry admin (it calls `authorizeSubmitter` on the registry itself). Either keep the deployer as registry admin until step 2 is done and hand the registry to the Safe right after, or split the authorize call out of the script and send it from the Safe. Decide before deploy day.

Before each step, dry-run it on a hardhat fork of mainnet (`--network hardhat` with forking) or with `PLAN=1` where the script supports it (`deploy-verdict-mirror.ts` does since dde2d84). Record the output.

## 2. Gas budget

Do not guess. Measure:

1. `npx hardhat run scripts/gas.ts` for gas units per path.
2. The Fuji deploy receipts: for each tx hash in `deployments/fuji.json`, `cast receipt <tx> gasUsed --rpc-url https://api.avax-test.network/ext/bc/C/rpc`.
3. Multiply by the mainnet base fee on the day (`cast base-fee --rpc-url https://api.avax.network/ext/bc/C/rpc`) with a 3x margin.

Fund the deployer with the deploy total; fund each relayer with ≥ 1 month of `confirm`/`submit` calls at the expected volume.

## 3. Deploy day, step by step

For each step: Frederico's OK for that step, then send, then verify, then record.

1. **Freeze the commit.** Tag it (`mainnet-YYYYMMDD`) after the Fuji rehearsal (P6). Deploy only from that tag.
2. **Registry** (step 1). Verify on Routescan (`npx hardhat verify --network avalanche …`). Check `admin() == Safe`.
3. **Relay** (step 2). Then from the deployer: `transferAdmin(Safe)`. From the Safe: `acceptAdmin()`. On the registry, from the Safe: `authorizeSubmitter(relay, true)`; `configureUseCase` for every routed use case.
4. **Mirror** (step 3). From the Safe: `acceptAdmin()`. Check `sourceAllowed`, `policyAllowed`, both relayers `isRelayer`, `threshold() == 2`.
5. **Gate** (step 4). From the Safe: `acceptAdmin()`. Check the verifier addresses match the ceremony verifiers in `zk/`.
6. **Write `deployments/avalanche.json`** with every address, tx, block and admin, same shape as `fuji.json`. Commit on a branch, PR.
7. **Start the relayers** against mainnet (each on its own host) and confirm one pass each with no error.
8. **First real relay**: the first Midnight mainnet seal and the first PASS verdict. Needs both relayers (threshold 2). Check `relayed(digest)` / `getRecord(transferId)` and re-export the verdict from Midnight: the digest must match.
9. **Watch**: run a mainnet instance of `scripts/fuji-watch.ts` (it is Fuji-only today: parameterize `deployments/<net>.json`, `FUJI_RPC_URL`, `LOGS_API` for 43114 and the Midnight mainnet indexer) as its own timer. No mainnet deploy is "done" until the watch runs green for 24 h.

## 4. Verification checklist (every item has a command)

| Check | Command |
|---|---|
| Admin is the Safe | `cast call <c> 'admin()(address)' --rpc-url $AVAX` for registry, relay, mirror, gate |
| No pending admin left | `cast call <c> 'pendingAdmin()(address)'` → zero |
| Safe has no VPS owner | `cast call <Safe> 'getOwners()(address[])'` |
| Relay threshold 2, two relayers | `threshold()`, `isRelayer(r1)`, `isRelayer(r2)` |
| Routes | `routes(<midnightUseCaseId>)` for each route |
| Verifiers are ceremony | `zk/setup.json` + the deployed bytecode matches the compiled ceremony verifier |
| Source code verified | Routescan shows each contract verified |
| Bridge consistent | watch log without `RelayDivergence` / `MirrorDivergence` |

## 5. Rollback and incident response

Contracts are not upgradeable (except PassportOracle V2, UUPS). "Rollback" means stopping a contract from accepting new state and pointing consumers elsewhere, always from the Safe:

| Incident | Action from the Safe |
|---|---|
| Wrong or forged seal relayed | relay `setThreshold(n+1)` with n relayers: relaying pauses (the contract allows a threshold above the relayer count); then `setRelayer(bad, false)`; the registry can drop the relay with `authorizeSubmitter(relay, false)` |
| Wrong verdict mirrored | mirror `setRelayer(bad, false)`, `setSource(chain, contract, false)` or `setPolicy(hash, false)`; consumers stop trusting `isPass` for that source |
| Gate misbehaves | gate `authorizeOperator(op, false)`, `setTarget(0)` if the target must stop; deploy a new gate and keep the old one listed as previous, as done on Fuji |
| Relayer key compromised | `setRelayer(key, false)` on relay and mirror; the threshold keeps a single key from writing in the meantime |
| Safe owner device lost | the remaining owners swap the owner (`swapOwner`) before anything else |

Records already written stay on-chain. Every correction is a new transaction, recorded in `deployments/avalanche.json` and in the F0-LOG.

## 6. What is different from Fuji (and why)

| Fuji | Mainnet | Reason |
|---|---|---|
| Safe 2-of-3 with a VPS owner | Safe ≥ 2 with no VPS owner | a VPS compromise must not reach admin |
| 1 relayer, threshold 1 | ≥ 2 relayers, threshold ≥ 2, separate hosts and indexers | operator trust needs independent operators |
| Dev trusted setup | Ceremony | dev entropy is public; anyone could forge proofs |
| Public preview indexer | Each relayer's own Midnight mainnet node and indexer | the public indexer was unreliable on preview and is a single point of trust |
| Safe app does not support Fuji (approveHash + execTransaction by hand) | Safe app supports 43114 | use the app for review; keep the manual path as a fallback |

## Trust model (state it in every pack)

The verdict mirror and the seal relay are operator trust, not a proof: the C-Chain has no Midnight light client. Their safety is the threshold of independent relayers and the Safe that governs them. The gate's proof lanes are a real proof (Groth16 verified on-chain), only as strong as the ceremony behind them.

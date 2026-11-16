# Avalanche in full mode: what exists, what this branch adds, how to deploy

16/11/2026. Goal: the C-Chain side ready before the Midnight mainnet deploy, so the only thing left on deploy day is pointing it at the Midnight mainnet gate.

## Pieces

| Piece | Contract | State |
|---|---|---|
| DPO2U seal + SP1 attestor + anchor | `DPO2UComplianceRegistry`, `DPO2UZkThresholdAttestor` | Fuji, since 09/11 |
| PSAV passport | `DPO2UPassportOracle` / V2 (UUPS, admin = Safe 2-of-3) | Fuji |
| Midnight ComplianceRegistry seals | `DPO2UMidnightRelay` (k-of-n) | Fuji, 1-of-1, first seal relayed |
| Travel Rule gate, attestation lane | `DPO2UTravelRuleGate` | Fuji (`0xCB53…3834`), no proof lanes |
| **Travel Rule gate, proof lanes** | `DPO2UPolicyGroth16Verifier`, `DPO2UMembershipGroth16Verifier` | **this branch**, dev setup |
| **Midnight Travel Rule verdicts** | `DPO2UTravelRuleVerdictMirror` + `TravelRuleVerdictV1` | **this branch** |
| Solvency, legal sources, sponsorship | `DPO2USolvencyRegistry`, `DPO2ULegalSourceManifest`, `DPO2USponsorshipRegistry` | Solvency on Fuji; the other two merged, not deployed |

## Fuji (testnet) — the infra thread runs it, with Frederico's OK

1. Verdict mirror, pinned to the preview institution gate already used for Stellar:
   ```
   MIRROR_SOURCE_CONTRACT=46a74a45cb0c0a8b336b4cda986886a4d685b5aba72372df518120af8517d62c \
   MIRROR_POLICIES=6c1f46a8fc85ecbf46ab71c9d838931f6a7621101b88e63e2b2473497b089ad4 \
   RELAYER_ADDRESS=<relayer1> npx hardhat run scripts/deploy-verdict-mirror.ts --network fuji
   ```
2. First relay, the same verdict Stellar recorded (digest `72434147…` must match):
   ```
   PRIVATE_KEY=<relayer1 key> MIDNIGHT_REPO=<dpo2u-midnight> TRANSFER=961b2b2ef2f26335377ea0e0205b98adb0d94de460d55cd04e1e78e1921608c5 \
   MIDNIGHT_TX=0024c150e6c71a9f2020da4621b3e4759038c1b4690543510945d334ce7fb80630 \
   npx hardhat run scripts/relay-travel-rule-verdict.ts --network fuji
   ```
3. Gate with proof lanes (new gate; the old one stays listed):
   ```
   TRG_DEPLOY_VERIFIERS=policy,membership TRG_OPERATOR=<operator> npx hardhat run scripts/deploy-travel-rule-gate.ts --network fuji
   ```
4. Hand both admins to the Safe (`ADMIN_ADDRESS=<Safe>` on deploy, then `acceptAdmin` from the Safe).
5. Commit `deployments/fuji.json` and the evidence record.

## C-Chain mainnet — after the Midnight mainnet deploy

Blockers, in order:

1. **Ceremony** for the policy and membership circuits (dpo2u-stellar `scripts/zk-ceremony*`), then `scripts/zk/export-verifiers.sh <lane> <final.zkey> <wasm> ceremony`. The deploy script refuses dev verifiers on `avalanche`.
2. **Midnight mainnet gate address and policy hash** (thread de mainnet, after the 16-contract deploy).
3. **Relayers**: at least 2 operators with their own keys and their own Midnight mainnet indexer; threshold ≥ 2 (`MIDNIGHT-RELAY.md` rule).
4. **AVAX** for the deployer and each relayer; **Safe 2-of-3** as admin of the registry, mirror, gate and relay.
5. Frederico's explicit OK for each mainnet deploy.

Then the same scripts with `--network avalanche` (`MIRROR_SOURCE_CHAIN` defaults to `midnight:mainnet` there and other sources are refused).

## Trust model to state in every pack

The verdict mirror and the seal relay are **operator trust, not a proof**: no Midnight light client on the C-Chain. The proof lanes of the gate are a proof (Groth16 verified on-chain), but only as strong as their trusted setup: dev today, ceremony before mainnet.

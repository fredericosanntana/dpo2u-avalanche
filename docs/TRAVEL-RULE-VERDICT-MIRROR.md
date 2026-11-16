# DPO2UTravelRuleVerdictMirror

Midnight `TravelRuleGate` verdicts, in the common format `dpo2u.travel-rule-verdict/1` (dpo2u-midnight `docs/VERDICT-FORMAT.md`), mirrored on the C-Chain so any contract can gate on them with `ITravelRuleVerdictReader` (`isPass`, `isReleased`, `requirePass`). Same design as the Soroban `travel-rule-gate` in dpo2u-stellar, which relayed its first real preview verdict on 2026-11-16.

## Trust model: operator trust, not a proof

**There is no Midnight light client or state proof on the C-Chain.** The mirror checks the verdict's form but cannot check that Midnight produced it. A dishonest quorum of relayers could record a PASS that never existed on Midnight.

| Checked on-chain | Not checked |
|---|---|
| Format rules (PASS has reason 0, FAIL 1..4, only a PASS is released) | That the verdict is in the Midnight gate's ledger |
| Source gate pinned by the admin (`setSource(chain, contract)`) | That the anchored block and tx are real |
| Non-zero `policy_hash`, allowed by the admin | That the policy was applied in the circuit |
| SHA-256 of the canonical JSON, recomputed on-chain (`TravelRuleVerdictV1`) | |
| `threshold` distinct relayers, re-counted against the current allowlist | |
| Anchored (block + tx); FAIL is final; PASS → PASS released only with the same roots, policy, source and sanctions | |

Lower the trust by raising `threshold` with relayers run by different parties, each reading Midnight through its own indexer (same rule as `MIDNIGHT-RELAY.md`). Anyone can audit a record: `getRecord(transferId)` keeps the Midnight block and tx, and

```
MIDNIGHT_NETWORK=preview npx tsx scripts/export-verdict.ts --transfer <transferId> --tx <tx> --contract <gate>
```

in dpo2u-midnight must give the same digest. Native cross-chain messaging would replace the transport, not the format.

## Vectors

`test/fixtures/verdict-v1-crosschain.json` (11 shared vectors, 6 from the compiled Compact gate in the simulator) and `test/fixtures/verdict-preview-961b2b2e.json` (the real preview verdict relayed to Stellar on 2026-11-16) give the same digests here as on Midnight and Stellar.

## Deploy and relay

```
MIRROR_SOURCE_CONTRACT=<Midnight gate hex> MIRROR_POLICIES=<policy_hash hex32> RELAYER_ADDRESS=0x… \
  npx hardhat run scripts/deploy-verdict-mirror.ts --network fuji

# as the relayer (PRIVATE_KEY = relayer key), from an export or straight from dpo2u-midnight:
VERDICT_IN=export.json npx hardhat run scripts/relay-travel-rule-verdict.ts --network fuji
MIDNIGHT_REPO=/path/dpo2u-midnight TRANSFER=<id> MIDNIGHT_TX=<tx> npx hardhat run scripts/relay-travel-rule-verdict.ts --network fuji
```

The relay script refuses unanchored or zero-policy verdicts, checks the export digest, asks the mirror for its digest and compares, submits, and writes an evidence record (`trust_model: "operator"`, with the reproduce command) to `deployments/evidence/<network>/`. `PLAN=1` sends nothing. On `avalanche` only `midnight:mainnet` verdicts are accepted.

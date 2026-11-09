# DPO2UMidnightRelay — Midnight seals on the C-Chain

A seal written on Midnight (`ComplianceRegistry.attestUseCase`) becomes readable by any
C-Chain contract through the DPO2U registry, without trusting a single relayer.

## On-chain (`contracts/DPO2UMidnightRelay.sol`)

- **Consortium:** the admin (Safe) keeps an allowlist of relayers and a `threshold`. A seal is
  registered only when `threshold` relayers each `confirm` the identical seal: Midnight contract,
  transaction, use case, verdict, evidence hash and metadata hash (`sealDigest`).
- **Routes:** only Midnight use cases mapped by the admin are relayable, each to a C-Chain use
  case with its own validity. Midnight seals carry no expiry; on the C-Chain they expire.
- **Translation:** Midnight verdict 0/1/2 = FAIL/PASS/REVIEW. Midnight stores no subject, so the
  subject is `H("dpo2u:midnight:", evidenceHash)`. `metadataHash` on the C-Chain =
  `keccak256(metadata_hash, midnightContract, midnightTx)`, so provenance is in the record.
- **Conflicts:** two different seals for the same evidence can collect votes; only the first to
  reach the threshold is registered (the registry refuses the second).
- The relay contract must be an authorized submitter in the registry.

## Off-chain (`src/midnight-relayer.ts`)

`relayOnce({ source, relayAddress, signer, cursor })` reads FINAL seals from a
`MidnightSealSource` and confirms each one, skipping relayed, already-confirmed and unmapped
seals (safe to re-run). The `MidnightSealSource` adapter (Midnight indexer query) belongs where
the Midnight tooling runs, next to the DPO2U Midnight daemon; each relayer runs its own key and
its own Midnight node/indexer, otherwise the threshold buys nothing.

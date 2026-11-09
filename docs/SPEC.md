# DPO2U Attestation Interface — spec v0.1 (chain-neutral)

English · [Português](SPEC.pt-BR.md)

Status: draft, written in phase 0 of the Avalanche plan. Avalanche (`contracts/interfaces/IDPO2UAttestation.sol`) is the first full implementation. Stellar (`anticorruption-attestation`) and Midnight (`ComplianceRegistry.compact`) already use the same core model and can be aligned to this spec later.

## Data model

An attestation is keyed by `(useCaseId, evidenceHash)` and is written once.

| Field | Type | Meaning |
|---|---|---|
| `useCaseId` | bytes32 | keccak256 of the use-case string, e.g. `psav-partner-br@1` |
| `evidenceHash` | bytes32 | sha256 of the off-chain evidence or run commitment. Evidence never goes on-chain |
| `subject` | bytes32 | hash of CAIP-10 account, DID or registry id. Never the identity in clear |
| `verdict` | enum | `NONE`, `PASS`, `FAIL`, `REVIEW` |
| `origin` | enum | `MACHINE`, `HUMAN_REVIEWED`, `THIRD_PARTY` (PSAV spec §6.2) |
| `issuedAt`, `expiresAt` | uint64 | expiry is mandatory and bounded by `maxValidity` |
| `metadataHash` | bytes32 | hash of the run summary (rules, verdicts, reviewers) |
| `packHash`, `packVersion` | bytes32, uint32 | the policy pack the verdict was evaluated against, copied from the use case at write time |
| `revoked` | bool | suspension/revocation, visible forever |

## Invariants (every implementation must pass the same tests)

1. Only `PASS` can be valid. `REVIEW` and `FAIL` are never valid.
2. Every attestation expires. Expired = not valid ("silence = non-compliance").
3. `(useCaseId, evidenceHash)` is written once (anti-replay).
4. Only authorized submitters write; only the admin configures use cases and submitters.
5. Revocation is by the admin or the original submitter, and stays visible.
6. A ZK-backed attestation pins its verifier and program key at deploy time. No entrypoint accepts a caller-supplied verifying key.
7. An unreachable chain adapter never yields PASS: the control plane records REVIEW.

## Error codes

`NotAuthorized` (1), `UseCaseInactive` (2), `AttestationExists` (3), `AttestationNotFound` (4), `AdminOnly` (5) keep the numbering of the Soroban contract so SDKs map them the same way.

## Read surface (oracle)

- `isValid(useCaseId, evidenceHash)`: PASS, not revoked, not expired.
- `isSubjectCompliant(useCaseId, subject)`: the subject's latest attestation is valid. A newer FAIL overrides an older PASS.

## Passport oracle (`DPO2UPassportOracle`)

EVM mirror of the control-plane Passport (PSAV spec §3.4). Per `(subject, packId)` there is one current passport: `passportId`, `packHash`, `tier`, `status`, `issuedAt`, `expiresAt`, `issuer` and the seal it rests on (`sealUseCaseId`, `sealEvidenceHash`).

- Tier order matches control-plane `TIER_RANK`: `NONE < TIER1_MACHINE_ONLY < TIER1 < TIER2 < TIER3`. `NONE` means no passport and is refused as `minTier`.
- `issuePassport` (authorized issuers only) requires a seal that exists in the registry, is not revoked, is not FAIL, has not expired, and has the same `subject` and `packHash` as the passport (`SealMismatch` otherwise). A REVIEW seal backs only a `TIER1_MACHINE_ONLY` passport. Validity is capped by `maxValidity` and, for tier2/tier3, also by 31 days (control-plane `TIER_WINDOW_DAYS`). Each `passportId` is usable once. A new passport replaces the current one for that pack.
- `suspendPassport` / `revokePassport` (admin or the issuing issuer) take effect in the same block and cannot be undone. The way back is a new passport with a new seal.
- Read: `isValid(subject, packId, minTier)`, `isAccountValid(address, packId, minTier)`, `isValidAll(subject, packIds[], minTier)` and `subjectOf(address)` = keccak256 of the lowercase CAIP-10 (`eip155:<chainId>:0x…`), the same subject the gateway writes.
- Silence = non-compliance: an expired, suspended, revoked or missing passport is simply not valid.

Example consumer: `contracts/examples/PassportGatedSettlement.sol` moves AVAX only when payer and payee both hold a valid passport for the pinned pack and tier.

## Next interfaces (later phases)

`Solvency` (reserves ≥ liabilities proof), `LegalSource` (citation → statute hash), `TravelRuleGate` (transfer allowed only with an attested IVMS-101 payload hash and valid passports on both ends; port of the Soroban `defindex-rebalance-gate` pattern).

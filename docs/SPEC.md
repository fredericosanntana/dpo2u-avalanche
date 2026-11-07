# DPO2U Attestation Interface — spec v0.1 (chain-neutral)

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

## Next interfaces (later phases)

`Passport` (tier, sponsorship, status), `Solvency` (reserves ≥ liabilities proof), `LegalSource` (citation → statute hash), `TravelRuleGate` (transfer allowed only with an attested IVMS-101 payload hash and valid passports on both ends; port of the Soroban `defindex-rebalance-gate` pattern).

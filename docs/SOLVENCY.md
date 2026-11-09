# DPO2USolvencyRegistry — private proof of reserves

C-Chain port of the Midnight `SolvencyRegistry.compact` and the Stellar `seal_solvency`.
Target regime: BCB Res. 519/520/521 (client-fund segregation and a daily proof of reserve).

## What goes on-chain

Only the verdict and commitments. Reserves and liabilities never leave the prover.

| Public value | Type | Meaning |
|---|---|---|
| `entityId` | bytes32 | H(CNPJ or DID of the VASP). Also the registry `subject`. |
| `reportCommitment` | bytes32 | Hash/CID of the off-chain reserve report |
| `context` | bytes32 | H(entity ‖ period ‖ nonce). Single use (anti-replay). |
| `sourcesHash` | bytes32 | H(signing keys of the reserve and liability feeds) |
| `period` | uint32 | Reporting period, YYYYMMDD. Must move forward per entity. |
| `solvent` | bool | Must be `true` to seal |

ABI: `abi.encode(bytes32,bytes32,bytes32,bytes32,uint32,bool)`, 192 bytes.

## Rules

- **Canonical VK pinning**: verifier and program vkey are immutable.
- **Permissionless, nothing caller-chosen**: evidence hash = `sha256(publicValues)`,
  metadata hash = `keccak256(vkey, evidenceHash)`.
- **Registry-backed**: each seal is a MACHINE PASS in `DPO2UComplianceRegistry`
  (subject = `entityId`). Expiry (`validity`, about 1–2 days for a daily regime),
  revocation and use-case deactivation all flow through the registry, so `isSolvent`
  turns false on silence.
- **No stale snapshots**: `period` must be strictly greater than the entity's last one.

## What the SP1 program must do (not in this PR)

The contract trusts the program pinned by `programVKey`. The program must:

1. verify the signatures of the reserve feed (custodian/wallet attestations) and the
   liability feed (client ledger) over a snapshot that includes `period`;
2. commit `sourcesHash` = hash of exactly those signing keys;
3. assert `reserves >= liabilities` and commit `solvent = true` only then;
4. derive `context` from entity, period and a nonce, and `reportCommitment` from the report.

Binding `period` to the signed snapshot matters: since periods only move forward, a
proof with a far-future period would block later seals for that entity.

Tests use `contracts/test/MockSP1Verifier.sol` (test only). A real proof needs the SP1
program built and its vkey pinned at deploy.

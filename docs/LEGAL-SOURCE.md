# DPO2ULegalSourceManifest — law → pack traceability

Joins the two DPO2U designs that already exist:

| Chain | Contract | Model |
|---|---|---|
| Solana | `legal_source_manifest` (devnet `eb579ftM…`) | one versioned manifest per jurisdiction (16-byte code, content hash, effective date, source URI) |
| Midnight | `LegalSourceManifest.compact` | write-once citation anchors: citation id → statute source hash |
| Avalanche | `DPO2ULegalSourceManifest.sol` | both: append-only manifests per jurisdiction, citations anchored to a manifest version |

## Rules

- **Append-only manifests.** `publishManifest` creates version N+1; version N stays readable,
  so an attestation sealed against N still resolves. Effective dates never go backwards.
- **Write-once citations.** A changed statute gets a new citation id (e.g. `LGPD|Art.18|v2`).
  Each citation records the corpus version it was taken from.
- **Unknown citations revert** in `verifySource(s)`, so a pack cannot cite an unanchored statute.
- **Roles:** admin (two-step transfer, planned for a Safe) sets curators; curators publish and anchor.
- **Jurisdiction codes:** the same NUL-padded ASCII as the Solana seed (`ON_CHAIN_CODE_ALIASES`
  in `mcp-server/src/lib/legal-manifest-onchain.ts`).

## Citation ids

`citationIdOf(j, art) = keccak256("<j>|<art>")`. Midnight currently uses the UTF-8 string padded
to 32 bytes, which truncates long ids. The cross-chain mapping must translate between the two;
the hash form is the one to converge on.

Only hashes of public law go on-chain. No personal data.

# DPO2USponsorshipRegistry — SPSAV sponsorship on-chain

On-chain counterpart of the control-plane `SponsorshipService` (Res. BCB 520 arts. 32–42).

| Step | Who | Rule |
|---|---|---|
| `setLicensedSponsor` | admin (Safe) | allowlist of BCB-licensed SPSAVs |
| `propose(partner, packs, minTier, directorHash)` | licensed SPSAV | no self-sponsorship; director (art. 42) stored only as a hash |
| `grantConsent(id)` | the partner only | needs a valid passport for every required pack at `minTier`, now |
| `revokeConsent(id)` | the partner only | can consent again later |
| `end(id, reasonHash)` | sponsor, partner or admin | terminal |

`isActive(id)` is a live check: consent given, sponsor still licensed, and
`oracle.isValidAll(subjectOf(partner), packs, minTier)` true in this block. A suspended,
revoked or expired passport switches the sponsorship off immediately, with no relayer and
no event to process. Partner subject = `oracle.subjectOf(partner)`, the same CAIP-10 hash the
gateway writes.

Off-chain the control plane still holds the evidence and the diligence trail; on-chain is
the public, counterparty-checkable state.

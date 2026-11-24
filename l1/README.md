# DPO2U L1 (Avalanche, Fuji)

An Avalanche L1 where **a wallet can only send transactions while it holds a proven Midnight PASS**.
The ComplianceGate verifies the Midnight proof and is the Manager of the chain's Transaction AllowList
precompile, so compliance is enforced by the VM, not by each contract remembering to check.

Design: SOTA doc "SOTA: DPO2U Compliance L1 na Avalanche" (requirement IDs L1-*, MVE-*, GE-*, TK-*, ICM-*).
Decisions (Frederico, 2026-11-23): runs in parallel with the Stellar escrow; L1 name **DPO2U**;
validators **in Brazil** (hosting decided later); L1 Safe 2-of-3 signers = the Fuji Safe's (VPS, desktop, phone).

## Status: phases A1 + A2 + A3 local network (this folder + `contracts/l1/`)

| Piece | File | State |
|---|---|---|
| Genesis template | `l1/genesis/dpo2u-l1.genesis.template.json` | Template (with `midnightVerifierConfig`); chain not created |
| ComplianceGate (GE-1..GE-5) | `contracts/l1/DPO2UL1ComplianceGate.sol` | Tested with a mock verifier |
| C-Chain receiver (ICM-1) | `contracts/l1/DPO2UL1VerdictReceiver.sol` | Tested with a mock Teleporter |
| MidnightVerifier (MVE-*) | `l1/precompile/` (precompile at `0x0300…00d2`) | A2: Midnight's own verifier via FFI; tested end to end on a simulated Subnet-EVM chain; accepts the Soroban verifier's proof |
| Test doubles | `contracts/l1/test/L1Mocks.sol` | AllowList, verifier, Teleporter |
| Local network (A3) | `l1/precompile/localnet`, `l1/localnet/` | The gate admits and revokes a wallet on a real AvalancheGo node, using a Midnight proof checked by the precompile (test circuit); the real TravelRuleGate v12 proof passes the gate's Midnight statement lane |

Nothing is deployed. No keys, no AVAX spent.

## Genesis (L1-1..L1-6)

- `contractDeployerAllowListConfig`: only the DPO2U deployer deploys contracts; admin = Safe.
- `txAllowListConfig`: admin = Safe; enabled at genesis = deployer and ICM relayer only.
  After deploying the gate, the Safe calls `setManager(gate)` on
  `0x0200000000000000000000000000000000000002`. Manager (not Admin) is enough: it can only move
  wallets between None and Enabled, and cannot touch the Safe.
- `feeManagerConfig`: admin = Safe.
- `warpConfig`: ICM on, quorum 67%.
- `midnightVerifierConfig`: the MidnightVerifier precompile, with Midnight's `[tau]_2` pinned.
  Needs the DPO2U VM build (`l1/precompile`, see its README) instead of stock Subnet-EVM.
- The validator manager (PoA, ACP-77) and the TeleporterMessenger are added when the chain is
  created with the Avalanche tooling; their owner is the Safe. Check that the Teleporter deployer
  address is enabled on the Transaction AllowList, or pre-allocate the messenger in the genesis.
- RPC (L1-6): no public endpoint. Validators, DPO2U and the regulator only, with access logs.

`__PLACEHOLDER__` values: `__CHAIN_ID__` (pick an unused EVM chain id), `__SAFE__`, `__DEPLOYER__`,
`__ICM_RELAYER__`, and the same two addresses without `0x` in `alloc`. `__WARP_ACTIVATION_UNIX__` (a number, unquoted): the chain creation time, since Subnet-EVM refuses a Warp activation before Durango. Gas token has no value.

## Midnight statement lane (A3)

`admitMidnight` takes the real `evaluateTransfer` statement (417 values in v12). It uses pinned
positions and binds the wallet through `transfer_id = admissionContext(subject, nonce)`; see
`l1/localnet/README.md`. Layout v0 below stays for the test circuit.

## Public input layout v0 (provisional)

`DPO2UL1ComplianceGate` reads 15 BLS12-381 scalars; 32-byte values travel as two 128-bit limbs:
pass, policy_hash, list_root, provider_id, issued_at, valid_until, subject, chain id, gate, nonce,
verdict digest. Phase A3 maps this to the real `evaluateTransfer` statement of the Midnight
TravelRuleGate; the layout may change then.

## Data protection (LGPD)

No personal data or reversible hash on the L1, in events or in ICM messages: the subject is a wallet,
and the wallet <-> person link stays with the VASP. Validators in Brazil keep the L1 data in the
country (LGPD art. 33); the ICM message to the C-Chain (global validators) carries only wallet,
policy hash, verdict digest and expiry. DPO2U operates the demo L1 as processor (operadora).

## Trust model

Proof-carrying admission: the relayer only transports. Not proven: inclusion of the Midnight tx in
the Midnight ledger (no light client), and the truth of the KYC data (VASP's responsibility). In the
demo, the PoA validators are DPO2U's, so the ICM signature is as trustworthy as DPO2U.

## Next phases

A2 MidnightVerifier: done (`l1/precompile/README.md`) · A3 local network: done (`l1/localnet/README.md`); still to do in A3: real `evaluateTransfer` proof + CVM test token with delivery vs
payment · A4 ICM to the Fuji C-Chain + demo video.

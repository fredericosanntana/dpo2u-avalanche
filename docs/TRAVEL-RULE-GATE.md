# DPO2UTravelRuleGate

Solidity port of the Soroban `defindex-rebalance-gate` (dpo2u-stellar, branch `feat/por-ceremony`), used as the Travel Rule adjacent circuit described in dpo2u-stellar `docs/PHASE2-TRAVEL-RULE-ADJACENT-FLOW.md`. The Travel Rule / screening artifact stays off-chain. The gate only sees its hash and the DPO2U verdict, and lets a privileged operator action through only when that verdict is PASS and bound to this exact action.

## Checks, in order

| # | Check | Error |
|---|---|---|
| 1 | `msg.sender` is an authorized operator | `Unauthorized` |
| 2 | `block.timestamp <= expiresAt` of the intent | `EvidenceExpired` |
| 3 | the evidence hash was never consumed | `EvidenceReplay` |
| 4 | `evidenceHash == deriveEvidenceHash(operator, scope, nonce, expiresAt, parties, payload)` | `EvidenceHashMismatch` |
| 5 | if `partyUseCaseId != 0`: originator and beneficiary are `isSubjectCompliant` in the registry | `PartyNotCompliant` |
| 6a | attestation lane (`execute`): the registry has a PASS for `(useCaseId, evidenceHash)`, not revoked, not expired | `AttestationMissing`, `AttestationNotPass`, `AttestationNotValid` |
| 6b | proof lane (`executeWithProof`): a Groth16 proof whose context signal is `deriveZkContext(evidenceHash)` | see below |

Then the evidence is marked consumed and `target.onGatedExecution(operator, evidenceHash, payload)` is called. The target must accept calls only from the gate.

The evidence hash binds `chainid`, the gate, the current target, `useCaseId`, scope, nonce, expiry, operator, both parties and `keccak256(payload)`. Changing the target or the use case invalidates every intent sealed before.

## Proof lanes

The lane is picked by the number of public signals, same as Soroban:

- 3 signals, policy circuit `[pass, commit, context]`: `pass` must be 1 (`ProofNotPass`), context must match (`BadProofContext`).
- 4 signals, membership circuit `[root, nullifier, recipient, context]`: `root` must equal the admitted root (`NonMemberRoot`, `AdmittedRootNotSet`), the nullifier must be unused (`NullifierReplay`), `recipient` must equal `deriveRecipientSignal(beneficiary)` (the beneficiary subject hash masked to 248 bits, `BadProofRecipient`), context must match. The nullifier is burned only after the proof verifies.
- anything else: `BadProofSignals`.

The admitted root comes from `rootProvider.currentRoot()` when a provider is set, otherwise from the root pinned with `setAdmittedRoot`.

## Differences from the Soroban gate

- Verifiers are immutable, one per lane, set at deploy (SPEC invariant 6). On Soroban the admin pins a verifier address and a VK. EVM Groth16 verifiers embed their VK, so each circuit is its own deployment. A zero address disables that lane (`VerifierNotSet`).
- Nullifiers have their own set, separate from consumed evidence.
- The membership lane binds the `recipient` signal to the beneficiary. Soroban leaves it unchecked, which would let a proof for one recipient authorize a transfer to another.
- Verifier interfaces use fixed-size signal arrays (`uint256[3]`, `uint256[4]`), the ABI snarkjs generates, so the ceremony verifiers plug in without an adapter.
- The attestation lane also enforces registry revocation and expiry (`isValid`), not just the verdict.
- Optional party check (step 5), the Travel Rule part: both ends must hold a valid attestation under `partyUseCaseId` (e.g. the PSAV passport use case).
- Hashes are `keccak256(abi.encode(...))` instead of `sha256(XDR)`. The context is masked to 248 bits so it fits the BN254 field.
- Reentrancy guard and two-step admin transfer, as in the registry.

Error names and the numbering 1 to 14 follow the Soroban `GateError`. `BadProofRecipient` (15) is new.

## Relation to the Midnight `TravelRuleGate.compact`

The Compact contract (dpo2u-midnight, branch `feat/midnight-travel-rule-disclosure`) evaluates the transfer itself inside the circuit: required fields, document above the threshold, attested destination VASP, sanctions flag, with FAIL reason codes, plus per-field disclosure grants for a supervisor. This gate does not reimplement that evaluation. It consumes its result as a DPO2U verdict (attestation or proof) and gates the action on it.

## Groth16 verifiers

`contracts/verifiers/` holds the snarkjs-exported verifiers of the two dpo2u-stellar circuits: `DPO2UPolicyGroth16Verifier` (policy lane) and `DPO2UMembershipGroth16Verifier` (membership lane). `test/TravelRuleGateGroth16.test.ts` generates a real policy proof for the context the gate derives from an intent and runs `executeWithProof` against the real verifier.

**They come from a DEV setup** (one contribution with fixed entropy + public beacon, `zk/setup.json`), good for Fuji and tests, not for mainnet: whoever knows the entropy can forge proofs. Before the C-Chain mainnet, run the multi-party ceremony for each circuit (dpo2u-stellar `scripts/zk-ceremony*`) and regenerate with `scripts/zk/export-verifiers.sh <lane> <final.zkey> <circuit.wasm> ceremony`. The deploy script refuses dev verifiers on `avalanche`.

`scripts/deploy-travel-rule-gate.ts` deploys the gate with the lanes asked for (`TRG_DEPLOY_VERIFIERS=policy,membership`, or existing verifier addresses). Verifiers are immutable in the gate, so turning a proof lane on means a new gate; the previous one is kept under `previousTravelRuleGates` in the deployment file.

## Midnight verdicts

The Midnight `TravelRuleGate` verdict reaches the C-Chain through `DPO2UTravelRuleVerdictMirror` (`docs/TRAVEL-RULE-VERDICT-MIRROR.md`), not through this gate.

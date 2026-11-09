# zk/solvency — SP1 program for the DPO2USolvencyRegistry

Private proof of reserves. The program checks a signed snapshot and commits only the
192-byte public values that `DPO2USolvencyRegistry.sealSolvency` decodes
(`docs/SOLVENCY.md`). Reserves, liabilities and the report never leave the prover.

| Crate | What it is |
|---|---|
| `lib` | the rules as plain Rust (`evaluate`), the public-values ABI, test helper `sign_input` |
| `program` | zkVM entrypoint: read `SolvencyInput`, `evaluate`, commit the ABI bytes; any rejection panics |
| `script` | host CLI: `fixture`, `execute`, `vkey`, `prove` |

## Rules

1. Reserve feed and liability feed each sign `sha256(tag ‖ entityId ‖ snapshotAt ‖ amount ‖ sha256(report))`
   with ed25519 (`verify_strict`); the tags `DPO2U/por/reserves/v1` and `DPO2U/por/liabilities/v1`
   keep one feed's signature from being used as the other's.
2. `sourcesHash = sha256(reserveKey ‖ liabilityKey)`.
3. `solvent = reserves >= liabilities`. An insolvent snapshot commits `false`, which the contract refuses.
4. `context = sha256(entityId ‖ snapshotAt (u64 BE) ‖ nonce)`, `reportCommitment = sha256(report)`.
5. `snapshotAt` is covered by both signatures, so the prover cannot move it.

A bad key or signature panics. In SP1 6.1 that is a run with `exit_code != 0` and nothing
committed; both the SDK verifier and `SP1VerifierGroth16` v6.1.0 (`if (exitCode != 0) revert`)
refuse it.

## Versions

SP1 is pinned to **exactly 6.1.0** (`=6.1.0` in the manifests and the whole `sp1-*` family at
6.1.0 in `Cargo.lock`), to match the `SP1VerifierGroth16` v6.1.0 on Fuji. A loose `6.1.0`
requirement resolves to 6.10.x and mixes versions (link error `syscall_halt`).

Program vkey (this tree): `0x00688f3b093722e0c3d322ba5aa5f20f623887215810ee64e2d503d944ac7987`

## Run

```bash
cargo test -p dpo2u-solvency-lib                                  # native rules, 8 tests
cargo test --release -p dpo2u-solvency-script --test execute      # zkVM execute: solvent, insolvent, bad signature
cargo run --release --bin solvency -- fixture --out input.json    # TEST snapshot, throwaway feed keys
cargo run --release --bin solvency -- execute --input input.json
cargo run --release --bin solvency -- vkey
cargo run --release --bin solvency -- prove --input input.json --out-dir out   # Groth16, heavy
```

`fixture` signs with two ed25519 keys generated in memory and discarded; the file holds only
public keys and signatures, and the entity is `sha256("TEST/dpo2u-por/fuji-smoke-entity")`.
Real feeds (custodian attestations, client ledger) are an integration still to be built.

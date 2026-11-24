# MidnightVerifier precompile (phase A2)

A stateful precompile for the DPO2U L1 that verifies **Midnight proofs with Midnight's own
verifier**. It answers the `IMidnightVerifier` interface the ComplianceGate already calls.

| | |
|---|---|
| Address | `0x03000000000000000000000000000000000000d2` (custom precompile range) |
| Genesis key | `midnightVerifierConfig` (`blockTimestamp`, `verifierParams`) |
| Proof system | `midnight-zk-stdlib` 2.4.0 / `midnight-proofs` 0.8.2, without `truncated-challenges`: the stack the Midnight ledger proves with (same pin as the Soroban verifier) |
| VM | Precompile-EVM v0.4.0 template, Subnet-EVM v0.8.0, AvalancheGo v1.14.0 |

## Why Midnight's verifier over FFI

The C-Chain and Fuji do not have the BLS12-381 precompiles (EIP-2537); checked from the VPS on
2026-11-23 (calls to `0x0b`/`0x0f` return empty). So the check runs natively in the L1's VM.

A Go re-implementation was ruled out: a zk-stdlib verifying key stores only the chip architecture,
and the constraint system is rebuilt from it by `ZkStdLib::configure`. A port would have to mirror
the whole standard library and drift with every Midnight release. The precompile calls the official
Rust verifier (`midnight-verifier-ffi/`) through cgo instead, so it is byte-compatible with the
prover by construction.

## Interface

```solidity
function registerVerifyingKey(bytes vk) returns (bytes32 vkHash); // keccak256(vk), emits VerifyingKeyRegistered
function isRegistered(bytes32 vkHash) view returns (bool);
function verify(bytes32 vkHash, bytes proof, uint256[] publicInputs) view returns (bool);
```

- `vk` is a `MidnightVK` in `SerdeFormat::Processed`. Registration is permissionless and content
  addressed: a key that does not parse is refused, the same bytes always give the same hash, and
  nothing can be overwritten. Which key counts is decided by the gate (`setPolicy`, Safe only).
- `publicInputs` are the circuit's BLS12-381 scalars as `uint256`. A value `>= r` is an error, not
  reduced. A wrong count is an error. A proof that does not verify, or does not parse, is `false`.
- `verifierParams` (`[tau]_2`, 96 bytes) come from the genesis or a network upgrade, never from
  callers: they decide soundness. The template pins Midnight's (Filecoin SRS).

## Gas

| Call | Cost |
|---|---|
| `isRegistered` | 5,000 |
| `registerVerifyingKey` | 200,000 + 20,000 per 32-byte word of the key + event (≈1.1M for a 1.3 KB key) |
| `verify` | 500,000 + 5,000 per word of key and params + 2,000 per public input + 16 per proof byte (≈850k end to end for the Poseidon vector) |

Native verification takes ~7.5 ms, about 150k gas at 20 Mgas/s, so the base cost has a 3x margin;
`TestVerifyGasCalibration` fails if that margin is lost. Keys declaring `k > 24` are refused before
any work, and inputs are capped (key 32 KiB, proof 64 KiB, 256 public inputs).

## Build and test

```sh
cd l1/precompile
./build-ffi.sh                 # Rust verifier -> midnightverifier/lib/libdpo2u_midnight_verifier.a
go test ./midnightverifier/    # unit + end-to-end on a simulated Subnet-EVM chain
go build -o build/dpo2u-subnet-evm ./plugin   # the VM binary for AvalancheGo
(cd midnight-verifier-ffi && cargo test --release)
```

`build-ffi.sh` relinks the Rust archive into one object and makes every symbol local except the
three C functions. Without that, the node does not link: AvalancheGo also carries blst (Go bindings)
and firewood (another Rust static library), and the symbols collide.

## Test vectors (`testdata/`)

| Vector | Source | SRS |
|---|---|---|
| `poseidon-k6-filecoin` | The proof of the Soroban verifier (dpo2u-stellar-compliance-escrow PR #3, `fixtures/midnight/poseidon/proof.bin`) byte for byte; the key is rebuilt here from the same circuit | Filecoin (Midnight's) |
| `membership-k12` | zk-stdlib's membership example, proved by `gen-vectors` | INSECURE test SRS (seed in the file) |

The same proof is accepted by the Soroban contract and by this precompile, which is the
cross-chain check that both read Midnight proofs the same way. Regenerate with
`cargo run --release --bin gen-vectors` and
`SRS_DIR=<dir with bls_filecoin_2p19> cargo run --release --bin cross-vectors -- <stellar fixture dir>`.

## Trust model and data protection

A `true` means: the public inputs satisfy the circuit behind that key. It does not prove the
Midnight transaction was accepted on the Midnight ledger (no light client) nor that the KYC data is
true (the VASP's responsibility). Validators can change `verifierParams` only through a network
upgrade. The precompile stores only verifying keys and params: no personal data (LGPD art. 6 III,
minimisation); public inputs are hashes and limbs chosen by the circuit, checked in phase A3.

## Licenses

`midnight-verifier-ffi/` is MIT and links midnight-zk (Apache-2.0). The Go module (`midnightverifier/`,
`plugin/`) is generated from Ava Labs' Precompile-EVM templates and links Subnet-EVM, both LGPL-3.0;
it is distributed under the same terms (`LICENSE-LGPL-3.0`).

## Next (phase A3)

Real `evaluateTransfer` proof from the Midnight TravelRuleGate, mapping of its statement to the
gate's public input layout, and a local AvalancheGo network running this VM with the A1 gate.

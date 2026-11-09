//! Execute-mode tests: the real program in the zkVM, no proof.
//! Cases: solvent, insolvent (never commits solvent = true), bad signature (rejected).

use dpo2u_solvency_lib::{sign_input, PublicValues, SolvencyInput};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf, SP1Stdin,
};

const ELF: Elf = include_elf!("dpo2u-solvency-program");

fn snapshot(reserves: u128, liabilities: u128) -> SolvencyInput {
    let r = SigningKey::generate(&mut OsRng);
    let l = SigningKey::generate(&mut OsRng);
    sign_input(&r, &l, [7u8; 32], 1_794_240_000, [9u8; 32], b"TEST report".to_vec(), reserves, liabilities)
}

/// Ok(public values) only for a clean exit. In SP1 6 a guest panic does not make `execute`
/// return Err: it ends with exit_code != 0 and nothing committed. Both the SDK verifier and the
/// on-chain SP1VerifierGroth16 v6.1.0 (`if (exitCode != 0) revert`) refuse such a proof, so a
/// non-zero exit code is "rejected".
fn run(input: &SolvencyInput) -> Result<PublicValues, String> {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);
    let client = ProverClient::from_env();
    match client.execute(ELF, stdin).run() {
        Ok((out, report)) if report.exit_code == 0 => {
            assert_eq!(out.as_slice().len(), 192, "public values must be 192 bytes");
            Ok(PublicValues::abi_decode(out.as_slice()).expect("decode"))
        }
        Ok((out, report)) => {
            assert!(out.as_slice().is_empty(), "a rejected run must commit nothing");
            Err(format!("exit_code={}", report.exit_code))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

#[test]
fn solvent_snapshot_commits_true() {
    let i = snapshot(1_000_000, 900_000);
    let pv = run(&i).expect("solvent snapshot must execute");
    assert!(pv.solvent);
    assert_eq!(pv.entity_id, [7u8; 32]);
    assert_eq!(pv.snapshot_at, 1_794_240_000);
    assert_eq!(pv, dpo2u_solvency_lib::evaluate(&i).unwrap(), "zkVM and native agree");
}

#[test]
fn insolvent_snapshot_never_commits_true() {
    let pv = run(&snapshot(899_999, 900_000)).expect("executes");
    assert!(!pv.solvent, "an insolvent snapshot must commit solvent = false");
}

#[test]
fn bad_signature_is_rejected() {
    let mut i = snapshot(1_000_000, 900_000);
    i.reserve_sig[0] ^= 1;
    assert!(run(&i).is_err(), "a tampered reserve signature must not execute");
    let mut j = snapshot(1_000_000, 900_000);
    j.reserves = 5_000_000; // inflated after signing
    assert!(run(&j).is_err(), "reserves changed after signing must not execute");
}

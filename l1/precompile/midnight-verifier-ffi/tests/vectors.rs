use std::{fs, path::PathBuf};

use dpo2u_midnight_verifier_ffi::{verify, InputError};

fn load() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/membership-k12");
    let meta = fs::read_to_string(d.join("vector.json")).unwrap();
    let mut pi = vec![];
    for part in meta.split("\"0x").skip(1) {
        let hex = &part[..64];
        for i in 0..32 {
            pi.push(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
        }
    }
    (
        fs::read(d.join("params.bin")).unwrap(),
        fs::read(d.join("vk.bin")).unwrap(),
        pi,
        fs::read(d.join("proof.bin")).unwrap(),
    )
}

#[test]
fn accepts_the_valid_proof() {
    let (p, vk, pi, proof) = load();
    assert_eq!(pi.len(), 64);
    assert_eq!(verify(&p, &vk, &pi, &proof), Ok(true));
}

#[test]
fn rejects_tampered_proof_bytes() {
    let (p, vk, pi, proof) = load();
    for i in [0usize, 100, proof.len() / 2, proof.len() - 1] {
        let mut bad = proof.clone();
        bad[i] ^= 1;
        assert_eq!(verify(&p, &vk, &pi, &bad), Ok(false), "byte {i}");
    }
    assert_eq!(verify(&p, &vk, &pi, &proof[..proof.len() - 1]), Ok(false));
    let mut longer = proof.clone();
    longer.push(0);
    assert_eq!(verify(&p, &vk, &pi, &longer), Ok(false));
}

#[test]
fn rejects_changed_public_input() {
    let (p, vk, mut pi, proof) = load();
    pi[63] ^= 1; // proven set 0x88 -> 0x89
    assert_eq!(verify(&p, &vk, &pi, &proof), Ok(false));
}

#[test]
fn rejects_other_params() {
    let (p, vk, pi, proof) = load();
    let mut other = p.clone();
    other[95] ^= 1;
    // Either not a valid G2 point (Params) or a different tau (proof fails).
    let r = verify(&other, &vk, &pi, &proof);
    assert!(r == Err(InputError::Params) || r == Ok(false), "{r:?}");
}

#[test]
fn malformed_inputs_are_errors_not_passes() {
    let (p, vk, pi, proof) = load();
    assert_eq!(verify(&p, &vk[..vk.len() - 1], &pi, &proof), Err(InputError::VerifyingKey));
    assert_eq!(verify(&p, &vk, &pi[..63], &proof), Err(InputError::PublicInputLength));
    assert_eq!(verify(&p, &vk, &pi[..32], &proof), Err(InputError::PublicInputCount));
    let mut big = pi.clone();
    big[..32].copy_from_slice(&[0xff; 32]);
    assert_eq!(verify(&p, &vk, &big, &proof), Err(InputError::PublicInputNotCanonical));
}

#[test]
fn c_abi_and_key_checks() {
    use dpo2u_midnight_verifier_ffi::{dpo2u_midnight_check_params, dpo2u_midnight_check_vk, dpo2u_midnight_verify};
    let (p, vk, pi, proof) = load();
    unsafe {
        let call = |p: &[u8], vk: &[u8], pi: &[u8], pr: &[u8]| {
            dpo2u_midnight_verify(p.as_ptr(), p.len(), vk.as_ptr(), vk.len(), pi.as_ptr(), pi.len(), pr.as_ptr(), pr.len())
        };
        assert_eq!(call(&p, &vk, &pi, &proof), 1);
        let mut bad = proof.clone();
        bad[7] ^= 0x80;
        assert_eq!(call(&p, &vk, &pi, &bad), 0);
        assert_eq!(call(&p, &vk, &pi[..32], &proof), -5);
        assert_eq!(dpo2u_midnight_verify(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0), -1);
        assert_eq!(dpo2u_midnight_check_vk(vk.as_ptr(), vk.len()), 2);
        assert_eq!(dpo2u_midnight_check_vk(vk.as_ptr(), vk.len() - 1), -2);
        assert_eq!(dpo2u_midnight_check_params(p.as_ptr(), p.len()), 1);
        assert_eq!(dpo2u_midnight_check_params(p.as_ptr(), 95), -1);
    }
}

#[test]
fn verification_time() {
    let (p, vk, pi, proof) = load();
    let t = std::time::Instant::now();
    for _ in 0..10 {
        assert_eq!(verify(&p, &vk, &pi, &proof), Ok(true));
    }
    eprintln!("verify avg: {:?}", t.elapsed() / 10);
}

#[test]
fn oversized_k_is_refused_before_any_work() {
    let (_, vk, _, _) = load();
    // k (12) sits right after the architecture, before the public input count (2, u32 LE).
    let at = vk.windows(5).position(|w| w == [12, 2, 0, 0, 0]).unwrap();
    for bad_k in [0u8, dpo2u_midnight_verifier_ffi::MAX_K + 1, 255] {
        let mut bad = vk.clone();
        bad[at] = bad_k;
        assert_eq!(dpo2u_midnight_verifier_ffi::check_vk(&bad), Err(InputError::VerifyingKey), "k={bad_k}");
    }
}

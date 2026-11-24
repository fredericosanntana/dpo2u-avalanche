//! Vectors from real Compact circuits, proved by the Midnight ledger's own prover (ZKIR v2 via
//! `Zkir::prove`, midnight-transient-crypto 3.1.0) in the Stellar thread's pipeline.
//!
//! Usage: `ledger-vectors <params.bin> <stellar fixture dir> <out name>`
//!
//! `ledger.verifier` is the ledger's `VerifierKey` (`tagged_serialize`: the tag
//! `midnight:verifier-key[v7]:`, a length, then a `MidnightVK` in `SerdeFormat::Processed`). The
//! precompile registers the inner `MidnightVK`; this tool finds it after the tag and checks that it
//! takes the rest of the file exactly.

use std::{env, fs, io::Write, path::PathBuf};

use dpo2u_midnight_verifier_ffi::{check_vk, verify};

const TAG: &[u8] = b"midnight:verifier-key[v7]:";

fn main() {
    let args: Vec<String> = env::args().collect();
    let params = fs::read(&args[1]).unwrap();
    let src = PathBuf::from(&args[2]);
    let name = &args[3];

    let ledger = fs::read(src.join("ledger.verifier")).unwrap();
    assert!(ledger.starts_with(TAG), "unexpected ledger key tag");
    // The length prefix is short; the key is the unique suffix that parses whole.
    let vk = (TAG.len()..TAG.len() + 16)
        .map(|at| &ledger[at..])
        .find(|vk| check_vk(vk).is_ok())
        .expect("no MidnightVK after the tag")
        .to_vec();

    let proof = fs::read(src.join("proof.bin")).unwrap();
    // pi.hex: one little-endian scalar (Fq::to_repr) per line; the precompile takes big-endian.
    let pis: Vec<String> = fs::read_to_string(src.join("pi.hex"))
        .unwrap()
        .split_whitespace()
        .map(|h| {
            let mut b: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
            b.reverse();
            format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
        })
        .collect();
    let pi_be: Vec<u8> = pis
        .iter()
        .flat_map(|h| (0..32).map(move |i| u8::from_str_radix(&h[2 + 2 * i..4 + 2 * i], 16).unwrap()))
        .collect();
    assert_eq!(check_vk(&vk), Ok(pis.len()), "public input count");
    assert_eq!(verify(&params, &vk, &pi_be, &proof), Ok(true), "ledger proof must verify");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata").join(name);
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("params.bin"), &params).unwrap();
    fs::write(out.join("vk.bin"), &vk).unwrap();
    fs::write(out.join("proof.bin"), &proof).unwrap();
    let mut meta = fs::File::create(out.join("vector.json")).unwrap();
    write!(
        meta,
        "{{\n  \"relation\": \"Compact circuit {name} (ZKIR v2), proved with the ledger prover (Zkir::prove, midnight-transient-crypto 3.1.0)\",\n  \"source\": \"dpo2u-stellar-compliance-escrow fixtures/midnight/{name} (branch feat/fase-3-travel-rule-gate), proof byte for byte; vk = MidnightVK inside ledger.verifier\",\n  \"srs\": \"Midnight bls_midnight_2p14\",\n  \"publicInputs\": [\"{}\"],\n  \"sizes\": {{ \"params\": {}, \"vk\": {}, \"proof\": {} }}\n}}\n",
        pis.join("\", \""),
        params.len(),
        vk.len(),
        proof.len()
    )
    .unwrap();
    println!("wrote {}: {} public inputs, ledger proof verifies", out.display(), pis.len());
}

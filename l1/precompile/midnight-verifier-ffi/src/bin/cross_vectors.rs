//! Cross-implementation vector: the Poseidon proof the Stellar (Soroban) verifier was built against
//! must also verify here, under a verifying key we derive ourselves from the same circuit and SRS.
//!
//! Usage: `cross-vectors <bls_midnight_2p14> <stellar fixtures/midnight/poseidon>`
//! Writes `../testdata/poseidon-k6-midnight/`.
//!
//! The relation is copied from dpo2u-stellar-compliance-escrow `tools/midnight-export` (Apache-2.0).
//! SRS: Midnight's own (`bls_midnight_2p14`, shipped in midnight-transient-crypto 3.1.0 `static/`,
//! what the proof server and the ledger use). `params.bin` is therefore Midnight's real `[tau]_2`.
//! It is NOT the Filecoin SRS: a ledger proof does not verify under that one.

use std::{env, fs, io::{BufReader, Write}, path::PathBuf};

use midnight_circuits::instructions::{AssignmentInstructions, PublicInputInstructions};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
    utils::SerdeFormat,
};
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
struct PoseidonPreimage;

impl Relation for PoseidonPreimage {
    type Instance = F;
    type Witness = [F; 3];
    type Error = Error;

    fn format_instance(instance: &F) -> Result<Vec<F>, Error> {
        Ok(vec![*instance])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<F>,
        witness: Value<[F; 3]>,
    ) -> Result<(), Error> {
        let msg = std_lib.assign_many(layouter, &witness.transpose_array())?;
        let out = std_lib.poseidon(layouter, &msg)?;
        std_lib.constrain_as_public_input(layouter, &out)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch { poseidon: true, ..ZkStdLibArch::default() }
    }

    fn write_relation<W: std::io::Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_r: &mut R) -> std::io::Result<Self> {
        Ok(PoseidonPreimage)
    }
}

fn main() {
    let srs_path = env::args().nth(1).expect("path to bls_midnight_2p14");
    let src = PathBuf::from(env::args().nth(2).expect("path to the Stellar poseidon fixture"));
    // Same reader as midnight-transient-crypto's ParamsProver::read.
    let mut srs = ParamsKZG::<Bls12>::read_custom(
        &mut BufReader::new(fs::File::open(srs_path).unwrap()),
        SerdeFormat::RawBytesUnchecked,
    )
    .unwrap();
    srs.downsize(6);
    let vk = midnight_zk_stdlib::setup_vk(&srs, &PoseidonPreimage);

    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes, SerdeFormat::Processed).unwrap();
    let mut params = vec![];
    srs.verifier_params().write(&mut params, SerdeFormat::Processed).unwrap();

    let proof = fs::read(src.join("proof.bin")).unwrap();
    // pi.hex holds little-endian scalars (Fq::to_repr); the precompile takes EVM big-endian words.
    let pi_le = fs::read_to_string(src.join("pi.hex")).unwrap();
    let pis: Vec<String> = pi_le
        .split_whitespace()
        .map(|h| {
            let mut b: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
            b.reverse();
            format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
        })
        .collect();
    let pi_be: Vec<u8> = pis.iter().flat_map(|h| (0..32).map(move |i| u8::from_str_radix(&h[2 + 2 * i..4 + 2 * i], 16).unwrap())).collect();

    assert_eq!(
        dpo2u_midnight_verifier_ffi::verify(&params, &vk_bytes, &pi_be, &proof),
        Ok(true),
        "the Stellar fixture proof must verify under our key"
    );

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/poseidon-k6-midnight");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("params.bin"), &params).unwrap();
    fs::write(out.join("vk.bin"), &vk_bytes).unwrap();
    fs::write(out.join("proof.bin"), &proof).unwrap();
    let mut meta = fs::File::create(out.join("vector.json")).unwrap();
    write!(
        meta,
        "{{\n  \"relation\": \"Poseidon preimage (dpo2u-stellar-compliance-escrow tools/midnight-export)\",\n  \"midnightZkStdlib\": \"2.4.0 (midnight-proofs 0.8.2, the ledger stack)\",\n  \"k\": 6,\n  \"srs\": \"Midnight bls_midnight_2p14 (midnight-transient-crypto 3.1.0 static/), downsized to k=6\",\n  \"proofSource\": \"dpo2u-stellar-compliance-escrow fixtures/midnight/poseidon/proof.bin (branch feat/fase-3-travel-rule-gate), byte for byte\",\n  \"publicInputs\": [\"{}\"],\n  \"sizes\": {{ \"params\": {}, \"vk\": {}, \"proof\": {} }}\n}}\n",
        pis.join("\", \""),
        params.len(),
        vk_bytes.len(),
        proof.len()
    )
    .unwrap();
    println!("wrote {}: the Stellar proof verifies with Midnight's own verifier", out.display());
}

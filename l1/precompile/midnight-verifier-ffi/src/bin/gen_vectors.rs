//! Writes the test vectors of the DPO2U L1 Midnight verifier to `../testdata/membership-k12/`.
//!
//! Relation: the multi-set membership example of midnight-zk (midnight-zk-stdlib 2.4.0
//! examples/membership.rs, Apache-2.0, copied below), k = 12.
//! SRS: `ParamsKZG::unsafe_setup` with a fixed seed. INSECURE, test only: whoever knows the seed
//! knows τ. Phase A3 switches to Midnight's ceremony SRS.

use std::{fs, path::PathBuf};

use ff::{Field, PrimeField};
use midnight_circuits::{
    field::AssignedNative,
    hash::poseidon::PoseidonChip,
    instructions::{
        map::{MapCPU, MapInstructions},
        AssertionInstructions, AssignmentInstructions, BitwiseInstructions, PublicInputInstructions,
    },
    map::cpu::MapMt,
};
use midnight_curves::Bls12;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
    poly::kzg::params::ParamsKZG,
    utils::SerdeFormat,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type F = midnight_curves::Fq;
type Map = MapMt<F, PoseidonChip<F>>;

#[derive(Clone, Default)]
struct MembershipExample;

impl Relation for MembershipExample {
    type Instance = (F, F);
    type Witness = (F, F, Map);
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![instance.0, instance.1])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let element = std_lib.assign(layouter, witness.clone().map(|(e, _, _)| e))?;
        let member_sets = std_lib.assign(layouter, witness.clone().map(|(_, s, _)| s))?;
        let mut map = std_lib.map_gadget().clone();
        map.init(layouter, witness.map(|(_, _, m)| m))?;
        std_lib.constrain_as_public_input(layouter, &map.succinct_repr())?;
        let proven_sets: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, p)| p))?;
        let value = map.get(layouter, &element)?;
        std_lib.assert_equal(layouter, &value, &member_sets)?;
        let res = std_lib.band(layouter, &proven_sets, &member_sets, F::NUM_BITS as usize)?;
        std_lib.assert_equal(layouter, &res, &proven_sets)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch { poseidon: true, ..ZkStdLibArch::default() }
    }

    fn write_relation<W: std::io::Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_r: &mut R) -> std::io::Result<Self> {
        Ok(MembershipExample)
    }
}

fn be_hex(x: &F) -> String {
    let repr = x.to_repr();
    let mut s = String::from("0x");
    for b in repr.as_ref().iter().rev() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() {
    const K: u32 = 12;
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/membership-k12");
    fs::create_dir_all(&out).unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(0xD902_u64);
    let srs = ParamsKZG::<Bls12>::unsafe_setup(K, &mut rng);
    let relation = MembershipExample;
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut mt = Map::new(&F::ZERO);
    for i in 0..100u64 {
        mt.insert(&F::from(1000 + i), &F::from(0b1000_0000));
    }
    mt.insert(&F::ONE, &F::from(0b1010_1000));
    let proof_set = F::from(0b1000_1000);
    let sets = F::from(0b1010_1000);
    let instance = (mt.succinct_repr(), proof_set);

    let proof = midnight_zk_stdlib::prove::<MembershipExample, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, (F::ONE, sets, mt.clone()), &mut rng,
    )
    .expect("prove");
    let params_v = srs.verifier_params();
    midnight_zk_stdlib::verify::<MembershipExample, blake2b_simd::State>(&params_v, &vk, &instance, None, &proof)
        .expect("native verify");

    let mut params_bytes = vec![];
    params_v.write(&mut params_bytes, SerdeFormat::Processed).unwrap();
    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes, SerdeFormat::Processed).unwrap();
    let pis = MembershipExample::format_instance(&instance).unwrap();

    fs::write(out.join("params.bin"), &params_bytes).unwrap();
    fs::write(out.join("vk.bin"), &vk_bytes).unwrap();
    fs::write(out.join("proof.bin"), &proof).unwrap();

    // Valid params of another (also insecure) SRS: the proof must not verify under them.
    let other = ParamsKZG::<Bls12>::unsafe_setup(K, &mut ChaCha20Rng::seed_from_u64(0x0BAD_u64)).verifier_params();
    let mut other_bytes = vec![];
    other.write(&mut other_bytes, SerdeFormat::Processed).unwrap();
    fs::write(out.join("other-params.bin"), &other_bytes).unwrap();
    let pi_json: Vec<String> = pis.iter().map(be_hex).collect();
    let meta = format!(
        "{{\n  \"relation\": \"midnight-zk zk_stdlib membership example\",\n  \"midnightZkStdlib\": \"2.4.0 (crates.io; midnight-proofs 0.8.2, the ledger stack)\",\n  \"k\": {K},\n  \"srs\": \"INSECURE unsafe_setup, ChaCha20 seed 0xD902 (test only)\",\n  \"publicInputs\": [\"{}\"],\n  \"sizes\": {{ \"params\": {}, \"vk\": {}, \"proof\": {} }}\n}}\n",
        pi_json.join("\", \""),
        params_bytes.len(),
        vk_bytes.len(),
        proof.len()
    );
    fs::write(out.join("vector.json"), meta).unwrap();
    println!("wrote {}: params {} B, vk {} B, proof {} B", out.display(), params_bytes.len(), vk_bytes.len(), proof.len());
}

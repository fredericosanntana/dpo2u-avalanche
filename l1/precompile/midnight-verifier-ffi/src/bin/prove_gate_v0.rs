//! Test prover for the gate's public input layout v0 (phase A3 local network only).
//!
//! The circuit exposes 15 public inputs and constrains only `pass == 1`. It stands in for the
//! TravelRuleGate `evaluateTransfer` circuit until its real proof and statement arrive, so the
//! ComplianceGate -> MidnightVerifier precompile -> Transaction AllowList path can be exercised on
//! a running L1 with a genuine Midnight (zk-stdlib 2.4.0) proof. It proves nothing about Travel Rule
//! compliance: never pin its key in a real policy.
//!
//! Usage: `prove-gate-v0 <bls_midnight_2p14> vk <out vk.bin>`
//!        `prove-gate-v0 <bls_midnight_2p14> prove <pi0> ... <pi14>`  (hex uint256, prints proof hex)

use std::{env, fs, io::BufReader};

use ff::PrimeField;
use midnight_circuits::{
    field::AssignedNative,
    instructions::{AssertionInstructions, PublicInputInstructions},
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
const K: u32 = 8;

#[derive(Clone, Default)]
struct GateLayoutV0;

impl Relation for GateLayoutV0 {
    type Instance = Vec<F>;
    type Witness = ();
    type Error = Error;

    fn format_instance(instance: &Vec<F>) -> Result<Vec<F>, Error> {
        Ok(instance.clone())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Vec<F>>,
        _witness: Value<()>,
    ) -> Result<(), Error> {
        let mut first = None;
        for i in 0..15 {
            let x: AssignedNative<F> = std_lib.assign_as_public_input(layouter, instance.as_ref().map(|v| v[i]))?;
            if i == 0 {
                first = Some(x);
            }
        }
        std_lib.assert_equal_to_fixed(layouter, &first.unwrap(), F::from(1))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch::default()
    }

    fn write_relation<W: std::io::Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_r: &mut R) -> std::io::Result<Self> {
        Ok(GateLayoutV0)
    }
}

fn scalar(h: &str) -> F {
    let h = h.trim_start_matches("0x");
    let h = format!("{h:0>64}");
    let mut repr = <F as PrimeField>::Repr::default();
    for i in 0..32 {
        repr.as_mut()[31 - i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    Option::from(F::from_repr(repr)).expect("public input >= r")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut srs = ParamsKZG::<Bls12>::read_custom(
        &mut BufReader::new(fs::File::open(&args[1]).unwrap()),
        SerdeFormat::RawBytesUnchecked,
    )
    .unwrap();
    srs.downsize(K);
    let vk = midnight_zk_stdlib::setup_vk(&srs, &GateLayoutV0);
    match args[2].as_str() {
        "vk" => {
            let mut b = vec![];
            vk.write(&mut b, SerdeFormat::Processed).unwrap();
            fs::write(&args[3], &b).unwrap();
        }
        "prove" => {
            let pi: Vec<F> = args[3..].iter().map(|h| scalar(h)).collect();
            assert_eq!(pi.len(), 15, "15 public inputs");
            let pk = midnight_zk_stdlib::setup_pk(&GateLayoutV0, &vk);
            let proof = midnight_zk_stdlib::prove::<GateLayoutV0, blake2b_simd::State>(
                &srs,
                &pk,
                &GateLayoutV0,
                &pi,
                (),
                ChaCha20Rng::from_entropy(),
            )
            .expect("prove");
            print!("0x{}", proof.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        _ => panic!("vk | prove"),
    }
}

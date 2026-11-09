//! DPO2U proof of reserves — host script.
//!
//!   solvency fixture --out <input.json> [--reserves N --liabilities M]
//!       Builds a TEST snapshot signed by two ed25519 feed keys generated in memory.
//!       The private keys are never written or printed; the file holds only public keys
//!       and signatures. The entity is sha256("TEST/dpo2u-por/fuji-smoke-entity").
//!   solvency execute --input <input.json>
//!       Runs the program in the zkVM (no proof) and prints the public values and cycles.
//!   solvency vkey
//!       Prints the program vkey (bytes32) to pin in the DPO2USolvencyRegistry.
//!   solvency prove --input <input.json> --out-dir <dir>
//!       Generates a Groth16 proof (SP1 v6.1.0) and writes proof.bin, public_values.bin
//!       and vkey.hex.

use clap::{Parser, Subcommand};
use dpo2u_solvency_lib::{sign_input, PublicValues, SolvencyInput};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const SOLVENCY_ELF: Elf = include_elf!("dpo2u-solvency-program");

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Fixture {
        #[arg(long)]
        out: String,
        #[arg(long, default_value_t = 1_000_000)]
        reserves: u128,
        #[arg(long, default_value_t = 900_000)]
        liabilities: u128,
    },
    Execute {
        #[arg(long)]
        input: String,
    },
    Vkey,
    Prove {
        #[arg(long)]
        input: String,
        #[arg(long, default_value = ".")]
        out_dir: String,
    },
}

fn read_input(path: &str) -> SolvencyInput {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read input")).expect("parse input")
}

fn stdin_for(input: &SolvencyInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);
    stdin
}

fn print_pv(pv: &PublicValues) {
    println!("  entityId:         0x{}", hex::encode(pv.entity_id));
    println!("  reportCommitment: 0x{}", hex::encode(pv.report_commitment));
    println!("  context:          0x{}", hex::encode(pv.context));
    println!("  sourcesHash:      0x{}", hex::encode(pv.sources_hash));
    println!("  snapshotAt:       {}", pv.snapshot_at);
    println!("  solvent:          {}", pv.solvent);
}

fn main() {
    sp1_sdk::utils::setup_logger();
    match Cli::parse().cmd {
        Cmd::Fixture { out, reserves, liabilities } => {
            let reserve_feed = SigningKey::generate(&mut OsRng);
            let liability_feed = SigningKey::generate(&mut OsRng);
            let entity: [u8; 32] = Sha256::digest(b"TEST/dpo2u-por/fuji-smoke-entity").into();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let report = format!(
                "TEST reserve report - DPO2U Fuji smoke test, not a real VASP. snapshotAt={now} reserves={reserves} liabilities={liabilities}"
            )
            .into_bytes();
            let input = sign_input(&reserve_feed, &liability_feed, entity, now, nonce, report, reserves, liabilities);
            std::fs::write(&out, serde_json::to_string_pretty(&input).unwrap()).expect("write fixture");
            println!("TEST fixture -> {out} (snapshotAt={now}; feed private keys discarded)");
        }
        Cmd::Execute { input } => {
            let input = read_input(&input);
            let client = ProverClient::from_env();
            let (output, report) = client.execute(SOLVENCY_ELF, stdin_for(&input)).run().expect("execute failed");
            let pv = PublicValues::abi_decode(output.as_slice()).expect("decode");
            println!("-- solvency executed in zkVM --");
            print_pv(&pv);
            println!("  public values:    {} bytes", output.as_slice().len());
            println!("  zkVM cycles:      {}", report.total_instruction_count());
        }
        Cmd::Vkey => {
            let client = ProverClient::from_env();
            let pk = client.setup(SOLVENCY_ELF).expect("setup");
            println!("{}", pk.verifying_key().bytes32());
        }
        Cmd::Prove { input, out_dir } => {
            let input = read_input(&input);
            let client = ProverClient::from_env();
            let pk = client.setup(SOLVENCY_ELF).expect("setup");
            let vk = pk.verifying_key().clone();
            let t = Instant::now();
            let proof = client.prove(&pk, stdin_for(&input)).groth16().run().expect("prove failed");
            let secs = t.elapsed().as_secs();
            client.verify(&proof, &vk, None).expect("verify failed");
            let pv = PublicValues::abi_decode(proof.public_values.as_slice()).expect("decode");
            println!("-- solvency Groth16 proof ({secs}s) --");
            print_pv(&pv);
            let vk_hex = vk.bytes32();
            println!("  vkey:             {vk_hex}");
            std::fs::create_dir_all(&out_dir).unwrap();
            std::fs::write(format!("{out_dir}/proof.bin"), proof.bytes()).unwrap();
            std::fs::write(format!("{out_dir}/public_values.bin"), proof.public_values.as_slice()).unwrap();
            std::fs::write(format!("{out_dir}/vkey.hex"), vk_hex.as_bytes()).unwrap();
            println!("  -> {out_dir}/proof.bin, public_values.bin, vkey.hex");
        }
    }
}

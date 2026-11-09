//! DPO2U proof of reserves (zkVM). Reads a signed snapshot, checks both feed signatures,
//! and commits the 192-byte public values the DPO2USolvencyRegistry decodes.
//! A bad key or signature panics: no proof exists for it.
#![no_main]
sp1_zkvm::entrypoint!(main);

use dpo2u_solvency_lib::{evaluate, SolvencyInput};

pub fn main() {
    let input: SolvencyInput = sp1_zkvm::io::read::<SolvencyInput>();
    let pv = match evaluate(&input) {
        Ok(pv) => pv,
        Err(e) => panic!("rejected: {:?}", e),
    };
    sp1_zkvm::io::commit_slice(&pv.abi_encode());
}

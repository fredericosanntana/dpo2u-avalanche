//! DPO2U proof of reserves: what the zkVM program checks, as plain Rust.
//!
//! The SP1 program (`../program`) reads a [`SolvencyInput`], calls [`evaluate`] and commits
//! [`PublicValues::abi_encode`]. Keeping the logic here lets it be tested natively and
//! keeps the program and the host script on the exact same encoding.
//!
//! Public values match `DPO2USolvencyRegistry.decodePublicValues`:
//! `abi.encode(bytes32 entityId, bytes32 reportCommitment, bytes32 context,
//!             bytes32 sourcesHash, uint64 snapshotAt, bool solvent)`, 192 bytes.
//!
//! Rules (docs/SOLVENCY.md, "What the SP1 program must do"):
//! 1. both feeds are ed25519-signed over the same snapshot (entity, snapshotAt, report);
//! 2. `sourcesHash` = sha256(reserve feed key || liability feed key);
//! 3. `solvent` = reserves >= liabilities (an insolvent snapshot commits `false`, which
//!    the contract refuses to seal);
//! 4. `context` = sha256(entityId || snapshotAt (u64 BE) || nonce) and
//!    `reportCommitment` = sha256(report).
//! `snapshotAt` is never chosen by the prover alone: both signatures cover it.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::vec::Vec;
use alloy_sol_types::{sol, SolValue};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tags. A signature for one feed can never be replayed as the other.
pub const RESERVES_TAG: &[u8] = b"DPO2U/por/reserves/v1";
pub const LIABILITIES_TAG: &[u8] = b"DPO2U/por/liabilities/v1";

sol! {
    /// Same layout and order as the contract's abi.decode.
    struct PublicValuesStruct {
        bytes32 entityId;
        bytes32 reportCommitment;
        bytes32 context;
        bytes32 sourcesHash;
        uint64 snapshotAt;
        bool solvent;
    }
}

/// Private input of the program. Amounts and the report never leave the prover.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolvencyInput {
    /// H(CNPJ or DID of the VASP), computed off-chain. Also the registry subject.
    pub entity_id: [u8; 32],
    /// Unix time of the snapshot, signed by both feeds.
    pub snapshot_at: u64,
    /// Fresh per proof; makes `context` single use.
    pub nonce: [u8; 32],
    /// The off-chain reserve report. Only its sha256 is public.
    pub report: Vec<u8>,
    pub reserves: u128,
    pub liabilities: u128,
    pub reserve_key: [u8; 32],
    /// 64-byte ed25519 signature (Vec because serde has no impl for [u8; 64]).
    pub reserve_sig: Vec<u8>,
    pub liability_key: [u8; 32],
    pub liability_sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicValues {
    pub entity_id: [u8; 32],
    pub report_commitment: [u8; 32],
    pub context: [u8; 32],
    pub sources_hash: [u8; 32],
    pub snapshot_at: u64,
    pub solvent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolvencyError {
    ZeroEntity,
    BadReserveKey,
    BadLiabilityKey,
    BadReserveSignature,
    BadLiabilitySignature,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Message a feed signs: sha256(tag || entityId || snapshotAt (u64 BE) || amount (u128 BE)
/// || reportCommitment).
pub fn feed_message(tag: &[u8], entity_id: &[u8; 32], snapshot_at: u64, amount: u128, report_commitment: &[u8; 32]) -> [u8; 32] {
    sha256(&[tag, entity_id, &snapshot_at.to_be_bytes(), &amount.to_be_bytes(), report_commitment])
}

pub fn report_commitment(report: &[u8]) -> [u8; 32] {
    sha256(&[report])
}

pub fn context(entity_id: &[u8; 32], snapshot_at: u64, nonce: &[u8; 32]) -> [u8; 32] {
    sha256(&[entity_id, &snapshot_at.to_be_bytes(), nonce])
}

pub fn sources_hash(reserve_key: &[u8; 32], liability_key: &[u8; 32]) -> [u8; 32] {
    sha256(&[reserve_key, liability_key])
}

fn check(key: &[u8; 32], sig: &[u8], msg: &[u8; 32], bad_key: SolvencyError, bad_sig: SolvencyError) -> Result<(), SolvencyError> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| bad_key)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| bad_sig)?;
    // verify_strict: rejects small-order keys and malleable signatures.
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).map_err(|_| bad_sig)
}

/// Everything the program asserts. An error means no proof can be produced.
pub fn evaluate(input: &SolvencyInput) -> Result<PublicValues, SolvencyError> {
    if input.entity_id == [0u8; 32] {
        return Err(SolvencyError::ZeroEntity);
    }
    let rc = report_commitment(&input.report);
    let reserves_msg = feed_message(RESERVES_TAG, &input.entity_id, input.snapshot_at, input.reserves, &rc);
    let liabilities_msg = feed_message(LIABILITIES_TAG, &input.entity_id, input.snapshot_at, input.liabilities, &rc);
    check(&input.reserve_key, &input.reserve_sig, &reserves_msg, SolvencyError::BadReserveKey, SolvencyError::BadReserveSignature)?;
    check(&input.liability_key, &input.liability_sig, &liabilities_msg, SolvencyError::BadLiabilityKey, SolvencyError::BadLiabilitySignature)?;
    Ok(PublicValues {
        entity_id: input.entity_id,
        report_commitment: rc,
        context: context(&input.entity_id, input.snapshot_at, &input.nonce),
        sources_hash: sources_hash(&input.reserve_key, &input.liability_key),
        snapshot_at: input.snapshot_at,
        solvent: input.reserves >= input.liabilities,
    })
}

impl PublicValues {
    pub fn to_sol(&self) -> PublicValuesStruct {
        PublicValuesStruct {
            entityId: self.entity_id.into(),
            reportCommitment: self.report_commitment.into(),
            context: self.context.into(),
            sourcesHash: self.sources_hash.into(),
            snapshotAt: self.snapshot_at,
            solvent: self.solvent,
        }
    }

    /// 192 bytes, as the contract decodes them.
    pub fn abi_encode(&self) -> Vec<u8> {
        self.to_sol().abi_encode()
    }

    pub fn abi_decode(bytes: &[u8]) -> Option<Self> {
        let s = PublicValuesStruct::abi_decode(bytes).ok()?;
        Some(Self {
            entity_id: s.entityId.0,
            report_commitment: s.reportCommitment.0,
            context: s.context.0,
            sources_hash: s.sourcesHash.0,
            snapshot_at: s.snapshotAt,
            solvent: s.solvent,
        })
    }
}

/// Test helper: signs a snapshot with the given feed keys. Used by the tests and by the
/// script's `fixture` command (test keys only).
pub fn sign_input(
    reserve_signer: &ed25519_dalek::SigningKey,
    liability_signer: &ed25519_dalek::SigningKey,
    entity_id: [u8; 32],
    snapshot_at: u64,
    nonce: [u8; 32],
    report: Vec<u8>,
    reserves: u128,
    liabilities: u128,
) -> SolvencyInput {
    use ed25519_dalek::Signer;
    let rc = report_commitment(&report);
    let rs = reserve_signer.sign(&feed_message(RESERVES_TAG, &entity_id, snapshot_at, reserves, &rc));
    let ls = liability_signer.sign(&feed_message(LIABILITIES_TAG, &entity_id, snapshot_at, liabilities, &rc));
    SolvencyInput {
        entity_id,
        snapshot_at,
        nonce,
        report,
        reserves,
        liabilities,
        reserve_key: reserve_signer.verifying_key().to_bytes(),
        reserve_sig: rs.to_bytes().to_vec(),
        liability_key: liability_signer.verifying_key().to_bytes(),
        liability_sig: ls.to_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn input(reserves: u128, liabilities: u128) -> (SolvencyInput, SigningKey, SigningKey) {
        let r = SigningKey::generate(&mut OsRng);
        let l = SigningKey::generate(&mut OsRng);
        let i = sign_input(&r, &l, [7u8; 32], 1_794_240_000, [9u8; 32], b"TEST report".to_vec(), reserves, liabilities);
        (i, r, l)
    }

    #[test]
    fn solvent_snapshot_commits_true_and_192_bytes() {
        let (i, _, _) = input(1_000, 900);
        let pv = evaluate(&i).unwrap();
        assert!(pv.solvent);
        assert_eq!(pv.snapshot_at, 1_794_240_000);
        assert_eq!(pv.context, context(&[7u8; 32], 1_794_240_000, &[9u8; 32]));
        assert_eq!(pv.report_commitment, report_commitment(b"TEST report"));
        assert_eq!(pv.sources_hash, sources_hash(&i.reserve_key, &i.liability_key));
        let enc = pv.abi_encode();
        assert_eq!(enc.len(), 192);
        assert_eq!(PublicValues::abi_decode(&enc), Some(pv));
    }

    #[test]
    fn equal_reserves_and_liabilities_is_solvent() {
        let (i, _, _) = input(500, 500);
        assert!(evaluate(&i).unwrap().solvent);
    }

    #[test]
    fn insolvent_snapshot_never_commits_true() {
        let (i, _, _) = input(899, 900);
        assert!(!evaluate(&i).unwrap().solvent);
    }

    #[test]
    fn bad_signature_is_rejected() {
        let (mut i, _, _) = input(1_000, 900);
        i.reserve_sig[0] ^= 1;
        assert_eq!(evaluate(&i), Err(SolvencyError::BadReserveSignature));
        let (mut j, _, _) = input(1_000, 900);
        j.liability_sig[63] ^= 1;
        assert_eq!(evaluate(&j), Err(SolvencyError::BadLiabilitySignature));
    }

    #[test]
    fn prover_cannot_change_signed_values() {
        // Inflating reserves, shrinking liabilities, moving the snapshot or swapping the
        // report all break a signature.
        let (base, _, _) = input(100, 900);
        let mut a = base.clone();
        a.reserves = 10_000;
        assert_eq!(evaluate(&a), Err(SolvencyError::BadReserveSignature));
        let mut b = base.clone();
        b.liabilities = 1;
        assert_eq!(evaluate(&b), Err(SolvencyError::BadLiabilitySignature));
        let mut c = base.clone();
        c.snapshot_at += 86_400;
        assert_eq!(evaluate(&c), Err(SolvencyError::BadReserveSignature));
        let mut d = base.clone();
        d.report = b"another report".to_vec();
        assert_eq!(evaluate(&d), Err(SolvencyError::BadReserveSignature));
    }

    #[test]
    fn feeds_cannot_be_swapped() {
        // A liability-feed signature presented as the reserve feed fails: the tags differ.
        let r = SigningKey::generate(&mut OsRng);
        let i = sign_input(&r, &r, [7u8; 32], 1, [0u8; 32], b"r".to_vec(), 5, 5);
        let mut s = i.clone();
        core::mem::swap(&mut s.reserve_sig, &mut s.liability_sig);
        // same amounts, same key: only the domain tag separates them
        assert_eq!(evaluate(&s), Err(SolvencyError::BadReserveSignature));
    }

    #[test]
    fn zero_entity_is_rejected() {
        let r = SigningKey::generate(&mut OsRng);
        let i = sign_input(&r, &r, [0u8; 32], 1, [0u8; 32], b"r".to_vec(), 5, 5);
        assert_eq!(evaluate(&i), Err(SolvencyError::ZeroEntity));
    }

    #[test]
    fn short_signature_is_rejected() {
        let (mut i, _, _) = input(1, 1);
        i.reserve_sig.truncate(10);
        assert_eq!(evaluate(&i), Err(SolvencyError::BadReserveSignature));
    }
}

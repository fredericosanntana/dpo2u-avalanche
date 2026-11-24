//! Midnight proof verifier for the DPO2U L1 precompile (phase A2).
//!
//! Wraps `midnight_zk_stdlib::batch_verify` (2.4.0, the stack the Midnight ledger proves with) (Plonk/KZG over BLS12-381, Blake2b transcript) for one
//! proof, with raw public inputs, and exposes it over a C ABI that the Go precompile calls via cgo.
//! Using Midnight's own verifier (not a re-implementation) keeps the L1 byte-compatible with the
//! prover: a zk_stdlib verifying key carries its architecture, and the constraint system is rebuilt
//! from it exactly as Midnight does.
//!
//! Inputs, all bytes:
//! - `params`: KZG verifier parameters, `[τ]₂` (G2 point, `SerdeFormat::Processed`). Pinned by the
//!   precompile: it decides soundness, so callers never choose it.
//! - `vk`: a `MidnightVK` written with `SerdeFormat::Processed`.
//! - `public_inputs`: concatenated 32-byte **big-endian** scalars (EVM `uint256` order), each `< r`.
//! - `proof`: the transcript bytes produced by `midnight_zk_stdlib::prove` with Blake2b.

use std::io::Cursor;

use ff::PrimeField;
use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsVerifierKZG, utils::SerdeFormat};
use midnight_zk_stdlib::{batch_verify, MidnightVK, ZkStdLibArch};

pub type F = midnight_curves::Fq;

/// Why an input was refused before the proof itself was checked.
#[derive(Debug, PartialEq, Eq)]
pub enum InputError {
    Params,
    VerifyingKey,
    PublicInputLength,
    PublicInputNotCanonical,
    PublicInputCount,
}

impl InputError {
    pub fn code(&self) -> i32 {
        match self {
            InputError::Params => -1,
            InputError::VerifyingKey => -2,
            InputError::PublicInputLength => -3,
            InputError::PublicInputNotCanonical => -4,
            InputError::PublicInputCount => -5,
        }
    }
}

pub fn read_params(bytes: &[u8]) -> Result<ParamsVerifierKZG<Bls12>, InputError> {
    let mut c = Cursor::new(bytes);
    let p = ParamsVerifierKZG::<Bls12>::read(&mut c, SerdeFormat::Processed).map_err(|_| InputError::Params)?;
    if c.position() as usize != bytes.len() {
        return Err(InputError::Params);
    }
    Ok(p)
}

pub fn read_vk(bytes: &[u8]) -> Result<MidnightVK, InputError> {
    header(bytes)?;
    let mut c = Cursor::new(bytes);
    let vk = MidnightVK::read(&mut c, SerdeFormat::Processed).map_err(|_| InputError::VerifyingKey)?;
    if c.position() as usize != bytes.len() {
        return Err(InputError::VerifyingKey);
    }
    Ok(vk)
}

/// Largest circuit (log2 rows) a key may declare. Reading a key rebuilds its constraint system,
/// so the size is bounded before any work is done on caller-supplied bytes.
pub const MAX_K: u8 = 24;

/// `(k, public input count)` from a serialized key's header (architecture, k: u8, count: u32 LE);
/// zk-stdlib 2.4.0 keeps these fields private.
fn header(vk: &[u8]) -> Result<(u8, usize), InputError> {
    let mut c = Cursor::new(vk);
    ZkStdLibArch::read(&mut c).map_err(|_| InputError::VerifyingKey)?;
    let at = c.position() as usize;
    let h = vk.get(at..at + 5).ok_or(InputError::VerifyingKey)?;
    let k = h[0];
    if k == 0 || k > MAX_K {
        return Err(InputError::VerifyingKey);
    }
    Ok((k, u32::from_le_bytes([h[1], h[2], h[3], h[4]]) as usize))
}

fn nb_public_inputs(vk: &[u8]) -> Result<usize, InputError> {
    header(vk).map(|(_, n)| n)
}

/// 32-byte big-endian words -> scalars. Refuses non-canonical values (>= r) instead of reducing.
pub fn read_public_inputs(bytes: &[u8]) -> Result<Vec<F>, InputError> {
    if bytes.len() % 32 != 0 {
        return Err(InputError::PublicInputLength);
    }
    bytes
        .chunks(32)
        .map(|w| {
            let mut repr = <F as PrimeField>::Repr::default();
            let r = repr.as_mut();
            for (i, b) in w.iter().enumerate() {
                r[31 - i] = *b; // big-endian word -> little-endian repr
            }
            Option::<F>::from(F::from_repr(repr)).ok_or(InputError::PublicInputNotCanonical)
        })
        .collect()
}

/// `Ok(true)` valid proof, `Ok(false)` invalid proof, `Err` malformed inputs.
pub fn verify(params: &[u8], vk: &[u8], public_inputs: &[u8], proof: &[u8]) -> Result<bool, InputError> {
    let params = read_params(params)?;
    let vk_bytes = vk;
    let vk = read_vk(vk)?;
    let pi = read_public_inputs(public_inputs)?;
    if pi.len() != nb_public_inputs(vk_bytes)? {
        return Err(InputError::PublicInputCount);
    }
    Ok(batch_verify::<blake2b_simd::State>(&params, &[vk], &[pi], &[proof.to_vec()]).is_ok())
}

/// Number of public inputs the verifying key expects, or `Err` if it does not parse.
pub fn check_vk(vk: &[u8]) -> Result<usize, InputError> {
    read_vk(vk)?;
    nb_public_inputs(vk)
}

/// Panics become `on_panic`: a panic must never cross the C ABI or stop the node.
fn guarded<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(on_panic)
}

/// Code returned when the verifier panicked on an input (treated as malformed).
pub const PANIC_CODE: i32 = -100;

unsafe fn slice<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

/// C ABI. Returns 1 valid, 0 invalid, negative `InputError::code()` for malformed inputs and
/// `PANIC_CODE` if the verifier panicked.
///
/// # Safety
/// Each pointer must be valid for reads of its length (a null pointer is allowed with length 0).
#[no_mangle]
pub unsafe extern "C" fn dpo2u_midnight_verify(
    params: *const u8,
    params_len: usize,
    vk: *const u8,
    vk_len: usize,
    public_inputs: *const u8,
    public_inputs_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let (params, vk) = (slice(params, params_len), slice(vk, vk_len));
    let (pi, proof) = (slice(public_inputs, public_inputs_len), slice(proof, proof_len));
    guarded(PANIC_CODE, || match verify(params, vk, pi, proof) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => e.code(),
    })
}

/// C ABI. Returns the verifying key's public input count (>= 0), or a negative code if it does
/// not parse. Used at registration so only well-formed keys are stored on chain.
///
/// # Safety
/// `vk` must be valid for reads of `vk_len` bytes (null allowed with length 0).
#[no_mangle]
pub unsafe extern "C" fn dpo2u_midnight_check_vk(vk: *const u8, vk_len: usize) -> i64 {
    let vk = slice(vk, vk_len);
    guarded(PANIC_CODE as i64, || match check_vk(vk) {
        Ok(n) => n as i64,
        Err(e) => e.code() as i64,
    })
}

/// C ABI. Returns 1 if `params` parse as KZG verifier parameters, else a negative code.
///
/// # Safety
/// `params` must be valid for reads of `params_len` bytes (null allowed with length 0).
#[no_mangle]
pub unsafe extern "C" fn dpo2u_midnight_check_params(params: *const u8, params_len: usize) -> i32 {
    let params = slice(params, params_len);
    guarded(PANIC_CODE, || match read_params(params) {
        Ok(_) => 1,
        Err(e) => e.code(),
    })
}

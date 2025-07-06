//! FFI between the C++ zcashd codebase and the Rust Zcash crates.
//!
//! This is internal to zcashd and is not an officially-supported API.

// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]
// Clippy has a default-deny lint to prevent dereferencing raw pointer arguments
// in a non-unsafe function. However, declaring a function as unsafe has the
// side-effect that the entire function body is treated as an unsafe {} block,
// and rustc will not enforce full safety checks on the parts of the function
// that would otherwise be safe.
//
// The functions in this crate are all for FFI usage, so it's obvious to the
// caller (which is only ever zcashd) that the arguments must satisfy the
// necessary assumptions. We therefore ignore this lint to retain the benefit of
// explicitly annotating the parts of each function that must themselves satisfy
// assumptions of underlying code.
//
// See https://github.com/rust-lang/rfcs/pull/2585 for more background.
#![allow(clippy::not_unsafe_ptr_arg_deref)]


use bellman::groth16::{self, Parameters, PreparedVerifyingKey, Proof, prepare_verifying_key, VerifyingKey};
use blake2s_simd::Params as Blake2sParams;
use bls12_381::Bls12;
use tracing::info;
use group::{cofactor::CofactorGroup, GroupEncoding};
use libc::{c_uchar, size_t};
use rand_core::{OsRng, RngCore};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::Once;
use std::convert::TryFrom;
use subtle::CtOption;

//Bip32 HDseed crates
use libc::c_char;
use bip39::{Language, Mnemonic};
use std::ffi::{CString,CStr};

#[cfg(not(target_os = "windows"))]
use std::ffi::OsStr;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

use zcash_primitives::{
    block::equihash,
    constants::{CRH_IVK_PERSONALIZATION, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    merkle_tree::{HashSer,merkle_path_from_slice},
    sapling::{
        merkle_hash,
        note::ExtractedNoteCommitment,
        note_encryption::sapling_ka_agree,
        value::{NoteValue, ValueCommitment},
        redjubjub::{self, Signature},
        spend_sig,
        Diversifier, Node, Note, NullifierDerivingKey, PaymentAddress, ProofGenerationKey, Rseed},
    transaction::components::Amount,
    zip32,
};
use zcash_proofs::{
    sapling::{SaplingProvingContext, SaplingVerificationContext},
    sprout as old_sprout,
};

use zcash_primitives::consensus::BranchId;

use incrementalmerkletree::Hashable;

mod blake2b;
mod ed25519;
mod metrics_ffi;
mod streams_ffi;
mod tracing_ffi;
mod zcashd_orchard;

mod bridge;

mod builder_ffi;
mod bundlecache;
mod history;
mod incremental_merkle_tree;
mod merkle_frontier;
mod orchard_actions;
mod orchard_bundle;
mod orchard_ffi;
mod orchard_keys_ffi;
mod orchard_keys;
mod params;
mod sapling;
mod sprout;
mod streams;
mod transaction_ffi;
mod sapling_wallet;
mod orchard_wallet;

mod test_harness_ffi;

const SAPLING_TREE_DEPTH: usize = 32;

#[cfg(test)]
mod tests;

static PROOF_PARAMETERS_LOADED: Once = Once::new();
static mut SAPLING_SPEND_VK: Option<groth16::VerifyingKey<Bls12>> = None;
static mut SAPLING_OUTPUT_VK: Option<groth16::VerifyingKey<Bls12>> = None;
static mut SPROUT_GROTH16_VK: Option<PreparedVerifyingKey<Bls12>> = None;

static mut SAPLING_SPEND_PARAMS: Option<Parameters<Bls12>> = None;
static mut SAPLING_OUTPUT_PARAMS: Option<Parameters<Bls12>> = None;
static mut SPROUT_GROTH16_PARAMS_PATH: Option<PathBuf> = None;

static mut ORCHARD_PK: Option<orchard::circuit::ProvingKey> = None;
static mut ORCHARD_VK: Option<orchard::circuit::VerifyingKey> = None;

/// Converts CtOption<t> into Option<T>
fn de_ct<T>(ct: CtOption<T>) -> Option<T> {
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// Reads an FsRepr from a [u8; 32]
/// and multiplies it by the given base.
fn fixed_scalar_mult(from: &[u8; 32], p_g: &jubjub::SubgroupPoint) -> jubjub::SubgroupPoint {
    // We only call this with `from` being a valid jubjub::Scalar.
    let f = jubjub::Scalar::from_bytes(from).unwrap();

    p_g * f
}

/// Loads the zk-SNARK parameters into memory and saves paths as necessary.
/// Only called once.
///
/// If `load_proving_keys` is `false`, the proving keys will not be loaded, making it
/// impossible to create proofs. This flag is for the Boost test suite, which never
/// creates shielded transactions, but exercises code that requires the verifying keys to
/// be present even if there are no shielded components to verify.
#[no_mangle]
pub extern "C" fn librustzcash_init_zksnark_params(
    #[cfg(not(target_os = "windows"))] sprout_path: *const u8,
    #[cfg(target_os = "windows")] sprout_path: *const u16,
    sprout_path_len: usize,
    load_proving_keys: bool,
) {
    PROOF_PARAMETERS_LOADED.call_once(|| {
        #[cfg(not(target_os = "windows"))]
        let sprout_path = if sprout_path.is_null() {
            None
        } else {
            Some(OsStr::from_bytes(unsafe {
                slice::from_raw_parts(sprout_path, sprout_path_len)
            }))
        };

        #[cfg(target_os = "windows")]
        let sprout_path = if sprout_path.is_null() {
            None
        } else {
            Some(OsString::from_wide(unsafe {
                slice::from_raw_parts(sprout_path, sprout_path_len)
            }))
        };

        let sprout_path = sprout_path.as_ref().map(Path::new);

        let sprout_vk = {
            let sprout_vk_bytes = include_bytes!("sprout-groth16.vk");
            let vk = VerifyingKey::<Bls12>::read(&sprout_vk_bytes[..])
                .expect("should be able to parse Sprout verification key");
            prepare_verifying_key(&vk)
        };

        // Load params
        let (sapling_spend_params, sapling_output_params) = {
            let (spend_buf, output_buf) = wagyu_zcash_parameters::load_sapling_parameters();
            let spend_params = Parameters::<Bls12>::read(&spend_buf[..], false)
                .expect("couldn't deserialize Sapling spend parameters");
            let output_params = Parameters::<Bls12>::read(&output_buf[..], false)
                .expect("couldn't deserialize Sapling spend parameters");
            (spend_params, output_params)
        };

        // We need to clone these because we aren't necessarily storing the proving
        // parameters in memory.
        let sapling_spend_vk = sapling_spend_params.vk.clone();
        let sapling_output_vk = sapling_output_params.vk.clone();

        // Generate Orchard parameters.
        info!(target: "main", "Loading Orchard parameters");
        let orchard_pk = load_proving_keys.then(orchard::circuit::ProvingKey::build);
        let orchard_vk = orchard::circuit::VerifyingKey::build();

        // Caller is responsible for calling this function once, so
        // these global mutations are safe.
        unsafe {
            SAPLING_SPEND_PARAMS = load_proving_keys.then_some(sapling_spend_params);
            SAPLING_OUTPUT_PARAMS = load_proving_keys.then_some(sapling_output_params);
            SPROUT_GROTH16_PARAMS_PATH = sprout_path.map(|p| p.to_owned());

            SAPLING_SPEND_VK = Some(sapling_spend_vk);
            SAPLING_OUTPUT_VK = Some(sapling_output_vk);
            SPROUT_GROTH16_VK = Some(sprout_vk);

            ORCHARD_PK = orchard_pk;
            ORCHARD_VK = Some(orchard_vk);
        }
    });
}

/// Writes the "uncommitted" note value for empty leaves of the Merkle tree.
///
/// `result` must be a valid pointer to 32 bytes which will be written.
#[no_mangle]
pub extern "C" fn librustzcash_tree_uncommitted(result: *mut [c_uchar; 32]) {
    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };
    Node::empty_leaf()
        .write(&mut result[..])
        .expect("Sapling leaves are 32 bytes");
}

/// Computes a merkle tree hash for a given depth. The `depth` parameter should
/// not be larger than 62.
///
/// `a` and `b` each must be of length 32, and must each be scalars of BLS12-381.
///
/// The result of the merkle tree hash is placed in `result`, which must also be
/// of length 32.
#[no_mangle]
pub extern "C" fn librustzcash_merkle_hash(
    depth: size_t,
    a: *const [c_uchar; 32],
    b: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    // Should be okay, because caller is responsible for ensuring
    // the pointers are valid pointers to 32 bytes.
    let tmp = merkle_hash(depth, unsafe { &*a }, unsafe { &*b });

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };
    *result = tmp;
}

#[no_mangle] // ToScalar
pub extern "C" fn librustzcash_to_scalar(input: *const [c_uchar; 64], result: *mut [c_uchar; 32]) {
    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    let scalar = jubjub::Scalar::from_bytes_wide(unsafe { &*input });

    let result = unsafe { &mut *result };

    *result = scalar.to_bytes();
}

#[no_mangle]
pub extern "C" fn librustzcash_ask_to_ak(ask: *const [c_uchar; 32], result: *mut [c_uchar; 32]) {
    let ask = unsafe { &*ask };
    let ak = fixed_scalar_mult(ask, &SPENDING_KEY_GENERATOR);

    let result = unsafe { &mut *result };

    *result = ak.to_bytes();
}

#[no_mangle]
pub extern "C" fn librustzcash_nsk_to_nk(nsk: *const [c_uchar; 32], result: *mut [c_uchar; 32]) {
    let nsk = unsafe { &*nsk };
    let nk = fixed_scalar_mult(nsk, &PROOF_GENERATION_KEY_GENERATOR);

    let result = unsafe { &mut *result };

    *result = nk.to_bytes();
}

#[no_mangle]
pub extern "C" fn librustzcash_crh_ivk(
    ak: *const [c_uchar; 32],
    nk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    let ak = unsafe { &*ak };
    let nk = unsafe { &*nk };

    let mut h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    h.update(ak);
    h.update(nk);
    let mut h = h.finalize().as_ref().to_vec();

    // Drop the last five bits, so it can be interpreted as a scalar.
    h[31] &= 0b0000_0111;

    let result = unsafe { &mut *result };

    result.copy_from_slice(&h);
}

#[no_mangle]
pub extern "C" fn librustzcash_check_diversifier(diversifier: *const [c_uchar; 11]) -> bool {
    let diversifier = Diversifier(unsafe { *diversifier });
    diversifier.g_d().is_some()
}

#[no_mangle]
pub extern "C" fn librustzcash_ivk_to_pkd(
    ivk: *const [c_uchar; 32],
    diversifier: *const [c_uchar; 11],
    result: *mut [c_uchar; 32],
) -> bool {
    let ivk = de_ct(jubjub::Scalar::from_bytes(unsafe { &*ivk }));
    let diversifier = Diversifier(unsafe { *diversifier });
    if let (Some(ivk), Some(g_d)) = (ivk, diversifier.g_d()) {
        let pk_d = g_d * ivk;

        let result = unsafe { &mut *result };

        *result = pk_d.to_bytes();

        true
    } else {
        false
    }
}

/// Test generation of commitment randomness
#[test]
fn test_gen_r() {
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];

    // Verify different r values are generated
    librustzcash_sapling_generate_r(&mut r1);
    librustzcash_sapling_generate_r(&mut r2);
    assert_ne!(r1, r2);

    // Verify r values are valid in the field
    let _ = jubjub::Scalar::from_bytes(&r1).unwrap();
    let _ = jubjub::Scalar::from_bytes(&r2).unwrap();
}

/// Generate uniformly random scalar in Jubjub. The result is of length 32.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_generate_r(result: *mut [c_uchar; 32]) {
    // create random 64 byte buffer
    let mut rng = OsRng;
    let mut buffer = [0u8; 64];
    rng.fill_bytes(&mut buffer);

    // reduce to uniform value
    let r = jubjub::Scalar::from_bytes_wide(&buffer);
    let result = unsafe { &mut *result };
    *result = r.to_bytes();
}

// Private utility function to get Note from C parameters
fn priv_get_note(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    value: u64,
    rcm: *const [c_uchar; 32],
) -> Result<Note, ()> {
    let recipient_bytes = {
        let mut tmp = [0; 43];
        tmp[..11].copy_from_slice(unsafe { &*diversifier });
        tmp[11..].copy_from_slice(unsafe { &*pk_d });
        tmp
    };
    let recipient = PaymentAddress::from_bytes(&recipient_bytes).ok_or(())?;

    // Deserialize randomness
    // If this is after ZIP 212, the caller has calculated rcm, and we don't need to call
    // Note::derive_esk, so we just pretend the note was using this rcm all along.
    let rseed = Rseed::BeforeZip212(de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })).ok_or(())?);

    Ok(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rseed,
    ))
}

/// Compute a Sapling nullifier.
///
/// The `diversifier` parameter must be 11 bytes in length.
/// The `pk_d`, `r`, `ak` and `nk` parameters must be of length 32.
/// The result is also of length 32 and placed in `result`.
/// Returns false if `diversifier` or `pk_d` is not valid.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_compute_nf(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    value: u64,
    rcm: *const [c_uchar; 32],
    ak: *const [c_uchar; 32],
    nk: *const [c_uchar; 32],
    position: u64,
    result: *mut [c_uchar; 32],
) -> bool {
    // ZIP 216: Nullifier derivation is not consensus-critical
    // (nullifiers are revealed, not calculated by consensus).
    // In any case, ZIP 216 is now enabled retroactively.
    let note = match priv_get_note(diversifier, pk_d, value, rcm) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let nk = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*nk })) {
        Some(p) => p,
        None => return false,
    };

    let nk = match de_ct(nk.into_subgroup()) {
        Some(nk) => NullifierDerivingKey(nk),
        None => return false,
    };

    let nf = note.nf(&nk, position);
    let result = unsafe { &mut *result };
    result.copy_from_slice(&nf.0);

    true
}

/// Compute a Sapling commitment.
///
/// The `diversifier` parameter must be 11 bytes in length.
/// The `pk_d` and `r` parameters must be of length 32.
/// The result is also of length 32 and placed in `result`.
/// Returns false if `diversifier` or `pk_d` is not valid.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_compute_cmu(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    value: u64,
    rcm: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    let note = match priv_get_note(diversifier, pk_d, value, rcm) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let result = unsafe { &mut *result };
    *result = note.cmu().to_bytes();

    true
}

#[no_mangle]
pub extern "C" fn librustzcash_sapling_ka_agree(
    p: *const [c_uchar; 32],
    sk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    // Deserialize p
    let p = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*p })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize sk
    let sk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*sk })) {
        Some(p) => p,
        None => return false,
    };

    // Compute key agreement
    let ka = sapling_ka_agree(&sk, &p);

    // Produce result
    let result = unsafe { &mut *result };
    *result = ka.to_bytes();

    true
}

/// Compute g_d = GH(diversifier) and returns false if the diversifier is
/// invalid. Computes \[esk\] g_d and writes the result to the 32-byte `result`
/// buffer. Returns false if `esk` is not a valid scalar.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_ka_derivepublic(
    diversifier: *const [c_uchar; 11],
    esk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    let diversifier = Diversifier(unsafe { *diversifier });

    // Compute g_d from the diversifier
    let g_d = match diversifier.g_d() {
        Some(g) => g,
        None => return false,
    };

    // Deserialize esk
    let esk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*esk })) {
        Some(p) => p,
        None => return false,
    };

    let p = g_d * esk;

    let result = unsafe { &mut *result };
    *result = p.to_bytes();

    true
}

/// Validates the provided Equihash solution against the given parameters, input
/// and nonce.
#[no_mangle]
pub extern "C" fn librustzcash_eh_isvalid(
    n: u32,
    k: u32,
    input: *const c_uchar,
    input_len: size_t,
    nonce: *const c_uchar,
    nonce_len: size_t,
    soln: *const c_uchar,
    soln_len: size_t,
) -> bool {
    if (k >= n) || (n % 8 != 0) || (soln_len != (1 << k) * ((n / (k + 1)) as usize + 1) / 8) {
        return false;
    }
    let rs_input = unsafe { slice::from_raw_parts(input, input_len) };
    let rs_nonce = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let rs_soln = unsafe { slice::from_raw_parts(soln, soln_len) };
    equihash::is_valid_solution(n, k, rs_input, rs_nonce, rs_soln).is_ok()
}

/// Creates a Sapling verification context. Please free this when you're done.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_verification_ctx_init() -> *mut SaplingVerificationContext {
    let ctx = Box::new(SaplingVerificationContext::new(false));

    Box::into_raw(ctx)
}

/// Frees a Sapling verification context returned from
/// [`librustzcash_sapling_verification_ctx_init`].
#[no_mangle]
pub extern "C" fn librustzcash_sapling_verification_ctx_free(ctx: *mut SaplingVerificationContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C

/// Check the validity of a Sapling Spend description, accumulating the value
/// commitment into the context.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_check_spend(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    anchor: *const [c_uchar; 32],
    nullifier: *const [c_uchar; 32],
    rk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
    spend_auth_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    // Deserialize the value commitment
    let cv = match de_ct(ValueCommitment::from_bytes_not_small_order(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the anchor, which should be an element
    // of Fr.
    let anchor = match de_ct(bls12_381::Scalar::from_bytes(unsafe { &*anchor })) {
        Some(a) => a,
        None => return false,
    };

    // Deserialize rk
    let rk = match redjubjub::PublicKey::read(&(unsafe { &*rk })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Deserialize the signature
    let spend_auth_sig = match Signature::read(&(unsafe { &*spend_auth_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Deserialize the proof
    let zkproof = match Proof::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    unsafe { &mut *ctx }.check_spend(
        &cv,
        anchor,
        unsafe { &*nullifier },
        rk,
        unsafe { &*sighash_value },
        spend_auth_sig,
        zkproof,
        &prepare_verifying_key(
                unsafe { SAPLING_SPEND_VK.as_ref() }
                    .expect("Parameters not loaded: SAPLING_SPEND_VK should have been initialized"),
        ),
    )

}

/// Check the validity of a Sapling Output description, accumulating the value
/// commitment into the context.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_check_output(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    cm: *const [c_uchar; 32],
    epk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Deserialize the value commitment
    let cv = match de_ct(ValueCommitment::from_bytes_not_small_order(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the commitment, which should be an element
    // of Fr.
    let cm = match Option::from(ExtractedNoteCommitment::from_bytes(unsafe { &*cm })) {
        Some(a) => a,
        None => return false,
    };

    // Deserialize the ephemeral key
    let epk = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*epk })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the proof
    let zkproof = match Proof::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    unsafe { &mut *ctx }.check_output(
        &cv,
        cm,
        epk,
        zkproof,
        &prepare_verifying_key(
                unsafe { SAPLING_OUTPUT_VK.as_ref() }.expect(
                    "Parameters not loaded: SAPLING_OUTPUT_VK should have been initialized",
                ),
            ),
    )
}

#[no_mangle]
pub extern "C" fn librustzcash_add_sapling_spend_to_context(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32]
) -> bool {
    let cv = match de_ct(ValueCommitment::from_bytes_not_small_order(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    unsafe { &mut *ctx }.add_spend_to_context(&cv);
    return true
}

#[no_mangle]
pub extern "C" fn librustzcash_add_sapling_output_to_context(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32]
) -> bool {
    let cv = match de_ct(ValueCommitment::from_bytes_not_small_order(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    unsafe { &mut *ctx }.add_output_to_context(&cv);
    return true
}

/// Finally checks the validity of the entire Sapling transaction given
/// valueBalance and the binding signature.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_final_check(
    ctx: *mut SaplingVerificationContext,
    value_balance: i64,
    binding_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    let value_balance = match Amount::from_i64(value_balance) {
        Ok(vb) => vb,
        Err(()) => return false,
    };

    // Deserialize the signature
    let binding_sig = match Signature::read(&(unsafe { &*binding_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    unsafe { &*ctx }.final_check(value_balance, unsafe { &*sighash_value }, binding_sig)
}

/// Sprout JoinSplit proof generation.
#[no_mangle]
pub extern "C" fn librustzcash_sprout_prove(
    proof_out: *mut [c_uchar; GROTH_PROOF_SIZE],

    phi: *const [c_uchar; 32],
    rt: *const [c_uchar; 32],
    h_sig: *const [c_uchar; 32],

    // First input
    in_sk1: *const [c_uchar; 32],
    in_value1: u64,
    in_rho1: *const [c_uchar; 32],
    in_r1: *const [c_uchar; 32],
    in_auth1: *const [c_uchar; old_sprout::WITNESS_PATH_SIZE],

    // Second input
    in_sk2: *const [c_uchar; 32],
    in_value2: u64,
    in_rho2: *const [c_uchar; 32],
    in_r2: *const [c_uchar; 32],
    in_auth2: *const [c_uchar; old_sprout::WITNESS_PATH_SIZE],

    // First output
    out_pk1: *const [c_uchar; 32],
    out_value1: u64,
    out_r1: *const [c_uchar; 32],

    // Second output
    out_pk2: *const [c_uchar; 32],
    out_value2: u64,
    out_r2: *const [c_uchar; 32],

    // Public value
    vpub_old: u64,
    vpub_new: u64,
) {
    // Load parameters from disk
    let sprout_fs = File::open(
        unsafe { &SPROUT_GROTH16_PARAMS_PATH }
            .as_ref()
            .expect("parameters should have been initialized"),
    )
    .expect("couldn't load Sprout groth16 parameters file");

    let mut sprout_fs = BufReader::with_capacity(1024 * 1024, sprout_fs);

    let params = Parameters::read(&mut sprout_fs, false)
        .expect("couldn't deserialize Sprout JoinSplit parameters file");

    drop(sprout_fs);

    let proof = old_sprout::create_proof(
        unsafe { *phi },
        unsafe { *rt },
        unsafe { *h_sig },
        unsafe { *in_sk1 },
        in_value1,
        unsafe { *in_rho1 },
        unsafe { *in_r1 },
        unsafe { &*in_auth1 },
        unsafe { *in_sk2 },
        in_value2,
        unsafe { *in_rho2 },
        unsafe { *in_r2 },
        unsafe { &*in_auth2 },
        unsafe { *out_pk1 },
        out_value1,
        unsafe { *out_r1 },
        unsafe { *out_pk2 },
        out_value2,
        unsafe { *out_r2 },
        vpub_old,
        vpub_new,
        &params,
    );

    proof
        .write(&mut (unsafe { &mut *proof_out })[..])
        .expect("should be able to serialize a proof");
}

/// Sprout JoinSplit proof verification.
#[no_mangle]
pub extern "C" fn librustzcash_sprout_verify(
    proof: *const [c_uchar; GROTH_PROOF_SIZE],
    rt: *const [c_uchar; 32],
    h_sig: *const [c_uchar; 32],
    mac1: *const [c_uchar; 32],
    mac2: *const [c_uchar; 32],
    nf1: *const [c_uchar; 32],
    nf2: *const [c_uchar; 32],
    cm1: *const [c_uchar; 32],
    cm2: *const [c_uchar; 32],
    vpub_old: u64,
    vpub_new: u64,
) -> bool {
    old_sprout::verify_proof(
        unsafe { &*proof },
        unsafe { &*rt },
        unsafe { &*h_sig },
        unsafe { &*mac1 },
        unsafe { &*mac2 },
        unsafe { &*nf1 },
        unsafe { &*nf2 },
        unsafe { &*cm1 },
        unsafe { &*cm2 },
        vpub_old,
        vpub_new,
        unsafe { SPROUT_GROTH16_VK.as_ref() }.expect("parameters should have been initialized"),
    )
}

/// This function (using the proving context) constructs an Output proof given
/// the necessary witness information. It outputs `cv` and the `zkproof`.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_output_proof(
    ctx: *mut SaplingProvingContext,
    esk: *const [c_uchar; 32],
    payment_address: *const [c_uchar; 43],
    rcm: *const [c_uchar; 32],
    value: u64,
    cv: *mut [c_uchar; 32],
    zkproof: *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `esk`, which the caller should have constructed for the DH key exchange.
    let esk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*esk })) {
        Some(p) => p,
        None => return false,
    };

    // Grab the payment address from the caller
    let payment_address = match PaymentAddress::from_bytes(unsafe { &*payment_address }) {
        Some(pa) => pa,
        None => return false,
    };

    // The caller provides the commitment randomness for the output note
    let rcm = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })) {
        Some(p) => p,
        None => return false,
    };

    // Create proof
    let (proof, value_commitment) = unsafe { &mut *ctx }.output_proof(
        esk,
        payment_address,
        rcm,
        value,
        unsafe { SAPLING_OUTPUT_PARAMS.as_ref() }.unwrap(),
    );

    // Write the proof out to the caller
    proof
        .write(&mut (unsafe { &mut *zkproof })[..])
        .expect("should be able to serialize a proof");

    // Write the value commitment to the caller
    *unsafe { &mut *cv } = value_commitment.to_bytes();

    true
}

/// Computes the signature for each Spend description, given the key `ask`, the
/// re-randomization `ar`, the 32-byte sighash `sighash`, and an output `result`
/// buffer of 64-bytes for the signature.
///
/// This function will fail if the provided `ask` or `ar` are invalid.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_spend_sig(
    ask: *const [c_uchar; 32],
    ar: *const [c_uchar; 32],
    sighash: *const [c_uchar; 32],
    result: *mut [c_uchar; 64],
) -> bool {
    // The caller provides the re-randomization of `ak`.
    let ar = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*ar })) {
        Some(p) => p,
        None => return false,
    };

    // The caller provides `ask`, the spend authorizing key.
    let ask = match redjubjub::PrivateKey::read(&(unsafe { &*ask })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Initialize secure RNG
    let mut rng = OsRng;

    // Do the signing
    let sig = spend_sig(ask, ar, unsafe { &*sighash }, &mut rng);

    // Write out the signature
    sig.write(&mut (unsafe { &mut *result })[..])
        .expect("result should be 64 bytes");

    true
}

/// This function (using the proving context) constructs a binding signature.
///
/// You must provide the intended valueBalance so that we can internally check
/// consistency.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_binding_sig(
    ctx: *const SaplingProvingContext,
    value_balance: i64,
    sighash: *const [c_uchar; 32],
    result: *mut [c_uchar; 64],
) -> bool {
    let value_balance = match Amount::from_i64(value_balance) {
        Ok(vb) => vb,
        Err(()) => return false,
    };

    // Sign
    let sig = match unsafe { &*ctx }.binding_sig(value_balance, unsafe { &*sighash }) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Write out signature
    sig.write(&mut (unsafe { &mut *result })[..])
        .expect("result should be 64 bytes");

    true
}

/// This function (using the proving context) constructs a Spend proof given the
/// necessary witness information. It outputs `cv` (the value commitment) and
/// `rk` (so that you don't have to compute it) along with the proof.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_spend_proof(
    ctx: *mut SaplingProvingContext,
    ak: *const [c_uchar; 32],
    nsk: *const [c_uchar; 32],
    diversifier: *const [c_uchar; 11],
    rcm: *const [c_uchar; 32],
    ar: *const [c_uchar; 32],
    value: u64,
    anchor: *const [c_uchar; 32],
    merkle_path: *const [c_uchar; 1 + 33 * SAPLING_TREE_DEPTH + 8],
    cv: *mut [c_uchar; 32],
    rk_out: *mut [c_uchar; 32],
    zkproof: *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `ak` from the caller, which should be a point.
    let ak = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*ak })) {
        Some(p) => p,
        None => return false,
    };

    // `ak` should be prime order.
    let ak = match de_ct(ak.into_subgroup()) {
        Some(p) => p,
        None => return false,
    };

    // Grab `nsk` from the caller
    let nsk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*nsk })) {
        Some(p) => p,
        None => return false,
    };

    // Construct the proof generation key
    let proof_generation_key = ProofGenerationKey {
        ak: ak.clone(),
        nsk,
    };

    // Grab the diversifier from the caller
    let diversifier = Diversifier(unsafe { *diversifier });

    // The caller chooses the note randomness
    // If this is after ZIP 212, the caller has calculated rcm, and we don't need to call
    // Note::derive_esk, so we just pretend the note was using this rcm all along.
    let rseed = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })) {
        Some(p) => Rseed::BeforeZip212(p),
        None => return false,
    };

    // The caller also chooses the re-randomization of ak
    let ar = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*ar })) {
        Some(p) => p,
        None => return false,
    };

    // We need to compute the anchor of the Spend.
    let anchor = match de_ct(bls12_381::Scalar::from_bytes(unsafe { &*anchor })) {
        Some(p) => p,
        None => return false,
    };

    // Parse the Merkle path from the caller
    let merkle_path = match merkle_path_from_slice(unsafe { &(&*merkle_path)[..] }) {
        Ok(w) => w,
        Err(_) => return false,
    };

    // Create proof
    let (proof, value_commitment, rk) = unsafe { &mut *ctx }
        .spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            merkle_path,
            unsafe { SAPLING_SPEND_PARAMS.as_ref() }.unwrap(),
            &prepare_verifying_key(
                    unsafe { SAPLING_SPEND_VK.as_ref() }
                        .expect("Parameters not loaded: SAPLING_SPEND_VK should have been initialized"),
            ),
        )
        .expect("proving should not fail");

    // Write value commitment to caller
    *unsafe { &mut *cv } = value_commitment.to_bytes();

    // Write proof out to caller
    proof
        .write(&mut (unsafe { &mut *zkproof })[..])
        .expect("should be able to serialize a proof");

    // Write out `rk` to the caller
    rk.write(&mut unsafe { &mut *rk_out }[..])
        .expect("should be able to write to rk_out");

    true
}

/// Creates a Sapling proving context. Please free this when you're done.
#[no_mangle]
pub extern "C" fn librustzcash_sapling_proving_ctx_init() -> *mut SaplingProvingContext {
    let ctx = Box::new(SaplingProvingContext::new());

    Box::into_raw(ctx)
}

/// Frees a Sapling proving context returned from
/// [`librustzcash_sapling_proving_ctx_init`].
#[no_mangle]
pub extern "C" fn librustzcash_sapling_proving_ctx_free(ctx: *mut SaplingProvingContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

/// Derive the master ExtendedSpendingKey from a seed.
#[no_mangle]
pub extern "C" fn librustzcash_zip32_xsk_master(
    seed: *const c_uchar,
    seedlen: size_t,
    xsk_master: *mut [c_uchar; 169],
) {
    let seed = unsafe { std::slice::from_raw_parts(seed, seedlen) };

    let xsk = zip32::ExtendedSpendingKey::master(seed);

    xsk.write(&mut (unsafe { &mut *xsk_master })[..])
        .expect("should be able to serialize an ExtendedSpendingKey");
}

/// Derive a child ExtendedSpendingKey from a parent.
#[no_mangle]
pub extern "C" fn librustzcash_zip32_xsk_derive(
    xsk_parent: *const [c_uchar; 169],
    i: u32,
    xsk_i: *mut [c_uchar; 169],
) {
    let xsk_parent = zip32::ExtendedSpendingKey::read(&unsafe { *xsk_parent }[..])
        .expect("valid ExtendedSpendingKey");
    let i = zip32::ChildIndex::from_index(i);

    let xsk = xsk_parent.derive_child(i);

    xsk.write(&mut (unsafe { &mut *xsk_i })[..])
        .expect("should be able to serialize an ExtendedSpendingKey");
}

/// Derive a child ExtendedFullViewingKey from a parent.
#[no_mangle]
pub extern "C" fn librustzcash_zip32_xfvk_derive(
    xfvk_parent: *const [c_uchar; 169],
    i: u32,
    xfvk_i: *mut [c_uchar; 169],
) -> bool {
    let xfvk_parent = zip32::ExtendedFullViewingKey::read(&unsafe { *xfvk_parent }[..])
        .expect("valid ExtendedFullViewingKey");
    let i = zip32::ChildIndex::from_index(i);

    let xfvk = match xfvk_parent.derive_child(i) {
        Ok(xfvk) => xfvk,
        Err(_) => return false,
    };

    xfvk.write(&mut (unsafe { &mut *xfvk_i })[..])
        .expect("should be able to serialize an ExtendedFullViewingKey");

    true
}

/// Derive a PaymentAddress from an ExtendedFullViewingKey.
#[no_mangle]
pub extern "C" fn librustzcash_zip32_xfvk_address(
    xfvk: *const [c_uchar; 169],
    j: *const [c_uchar; 11],
    j_ret: *mut [c_uchar; 11],
    addr_ret: *mut [c_uchar; 43],
) -> bool {
    let xfvk = match zip32::ExtendedFullViewingKey::read(&unsafe { *xfvk }[..]) {
        Ok(xfvk) => xfvk,
        Err(_) => return false,
    };
    let j = zip32::DiversifierIndex(unsafe { *j });

    let addr = match xfvk.find_address(j) {
        Some(addr) => addr,
        None => return false,
    };

    let j_ret = unsafe { &mut *j_ret };
    let addr_ret = unsafe { &mut *addr_ret };

    j_ret.copy_from_slice(&(addr.0).0);
    addr_ret.copy_from_slice(&addr.1.to_bytes());

    true
}

#[no_mangle]
pub extern "C" fn librustzcash_getrandom(buf: *mut u8, buf_len: usize) {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };
    OsRng.fill_bytes(buf);
}

#[no_mangle]
pub extern "C" fn librustzcash_restore_seed_from_phase(buf: *mut u8, buf_len: usize, seed_phrase: *const c_char) -> u32 {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    let c_str: &CStr = unsafe { CStr::from_ptr(seed_phrase)};
    let rust_seed_phrase = c_str.to_str().unwrap().to_string();

    let phrase = match Mnemonic::from_phrase(rust_seed_phrase.clone(), Language::English) {
        Ok(p) =>   p ,
        Err(_) =>  return 0
    };

    buf.copy_from_slice(&phrase.entropy());
    std::mem::forget(phrase);

    1
}

#[no_mangle]
pub extern "C" fn librustzcash_get_bip39_seed(buf: *mut u8, buf_len: usize) -> *const c_uchar {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    let tmp_seed = bip39::Seed::new(&Mnemonic::from_entropy(&buf, Language::English).unwrap(), "");
    let bip39_seed = tmp_seed.as_bytes().as_ptr();
    std::mem::forget(tmp_seed);
    bip39_seed
}

#[no_mangle]
pub extern "C" fn librustzcash_get_seed_phrase(seed: *const c_uchar, length: u8) -> *const c_char {
    //16 byte = 12 word mnemonic
    //24 byte = 18 word mnemonic
    //32 byte = 24 word mnemonic (default for PirateChain)
    if (length!=16) && (length!=24) && (length!=32) {
      let result="Internal error: The HDseed length is invalid.";
      let c_str = CString::new(result).unwrap();
      let phrase = c_str.as_ptr();
      std::mem::forget(c_str);
      return phrase;
    }

    let seed = unsafe { std::slice::from_raw_parts(seed, length.into()) };


    let s_mnemonic = Mnemonic::from_entropy(&seed, Language::English).unwrap();

    let s = s_mnemonic.phrase().to_string();
    let c_str = CString::new(s).unwrap();
    let phrase = c_str.as_ptr();

    std::mem::forget(c_str);
    phrase
}

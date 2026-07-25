#![no_std]
//! Immutable mobile-v2 batch-root helper.
//!
//! The contract has no constructor, mutable storage, admin, or upgrade
//! entrypoint. Its three exported functions are therefore fixed by the
//! deployed Wasm hash.

mod params;

use params::POSEIDON_T3_BLS12_381_PARAMS;
use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, symbol_short, vec, Bytes, BytesN, Env,
    Vec, U256,
};

const VERSION: u32 = 1;
const MIN_K: u32 = 2;
const MAX_K: u32 = 5;
const CAPACITY: u32 = 8;
const HASH_ID: [u8; 32] = [
    0x84, 0x16, 0x7d, 0xe2, 0x9f, 0x1d, 0xc9, 0x7c, 0x57, 0x36, 0xcb, 0xdd, 0xda, 0xeb, 0xde, 0x0e,
    0x1a, 0x18, 0xf3, 0xb6, 0x25, 0xe9, 0x21, 0x3e, 0xea, 0x01, 0x01, 0xee, 0xa7, 0x08, 0x6f, 0xe3,
];
const FR_MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HasherError {
    BatchTooSmall = 1,
    BatchTooLarge = 2,
    ZeroCommitment = 3,
    DuplicateCommitment = 4,
    NonCanonical = 5,
}

#[contract]
pub struct MobileV2Hasher;

#[contractimpl]
impl MobileV2Hasher {
    pub fn version() -> u32 {
        VERSION
    }

    pub fn hash_id(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &HASH_ID)
    }

    pub fn root(env: Env, ordered_scms: Vec<BytesN<32>>) -> BytesN<32> {
        if let Err(error) = validate_ordered_scms(&ordered_scms) {
            panic_with_error!(&env, error);
        }
        compute_root(&env, &ordered_scms)
    }
}

fn validate_ordered_scms(ordered_scms: &Vec<BytesN<32>>) -> Result<(), HasherError> {
    let k = ordered_scms.len();
    if k < MIN_K {
        return Err(HasherError::BatchTooSmall);
    }
    if k > MAX_K {
        return Err(HasherError::BatchTooLarge);
    }

    let mut i = 0u32;
    while i < k {
        let scm = ordered_scms.get_unchecked(i);
        let bytes = scm.to_array();
        if bytes == [0u8; 32] {
            return Err(HasherError::ZeroCommitment);
        }
        if !is_canonical(&bytes) {
            return Err(HasherError::NonCanonical);
        }

        let mut j = 0u32;
        while j < i {
            if ordered_scms.get_unchecked(j) == scm {
                return Err(HasherError::DuplicateCommitment);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

fn is_canonical(bytes: &[u8; 32]) -> bool {
    let mut i = 0usize;
    while i < 32 {
        if bytes[i] < FR_MODULUS[i] {
            return true;
        }
        if bytes[i] > FR_MODULUS[i] {
            return false;
        }
        i += 1;
    }
    false
}

fn compute_root(env: &Env, ordered_scms: &Vec<BytesN<32>>) -> BytesN<32> {
    let parameter_bytes = Bytes::from_array(env, &POSEIDON_T3_BLS12_381_PARAMS);
    let mds = decode_matrix(env, &parameter_bytes, 0, 3);
    let round_constants = decode_matrix(env, &parameter_bytes, 9, 64);

    let zero = U256::from_u32(env, 0);
    let mut level = Vec::<U256>::new(env);
    for scm in ordered_scms.iter() {
        level.push_back(U256::from_be_bytes(env, scm.as_ref()));
    }
    while level.len() < CAPACITY {
        level.push_back(zero.clone());
    }

    while level.len() > 1 {
        let mut next = Vec::<U256>::new(env);
        let mut i = 0u32;
        while i < level.len() {
            next.push_back(hash_pair(
                env,
                &mds,
                &round_constants,
                level.get_unchecked(i),
                level.get_unchecked(i + 1),
            ));
            i += 2;
        }
        level = next;
    }

    level
        .get_unchecked(0)
        .to_be_bytes()
        .try_into()
        .expect("U256 is exactly 32 bytes")
}

fn decode_matrix(
    env: &Env,
    parameter_bytes: &Bytes,
    start_element: u32,
    rows: u32,
) -> Vec<Vec<U256>> {
    let mut matrix = Vec::new(env);
    let mut element = start_element;
    let mut row_index = 0u32;
    while row_index < rows {
        let mut row = Vec::new(env);
        let mut column = 0u32;
        while column < 3 {
            let offset = element * 32;
            row.push_back(U256::from_be_bytes(
                env,
                &parameter_bytes.slice(offset..offset + 32),
            ));
            element += 1;
            column += 1;
        }
        matrix.push_back(row);
        row_index += 1;
    }
    matrix
}

fn hash_pair(
    env: &Env,
    mds: &Vec<Vec<U256>>,
    round_constants: &Vec<Vec<U256>>,
    left: U256,
    right: U256,
) -> U256 {
    env.crypto_hazmat()
        .poseidon_permutation(
            &vec![env, U256::from_u32(env, 0), left, right],
            symbol_short!("BLS12_381"),
            3,
            5,
            8,
            56,
            mds,
            round_constants,
        )
        .get_unchecked(0)
}

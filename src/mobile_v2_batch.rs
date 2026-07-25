//! Canonical depth-3 batch-root boundary for the mobile-v2 writer.
//!
//! The fixed Poseidon parameters live in a tiny immutable helper contract so
//! the upgradeable pool remains below Soroban's contract-size limit. The pool
//! validates every leaf itself and binds the helper address/hash identity in
//! `MobileV2Config` before this call is reachable.

use soroban_sdk::{vec, Address, BytesN, Env, IntoVal, Symbol, Vec};

use super::{canonical, PoolError, MOBILE_V2_BATCH_CAPACITY, MOBILE_V2_MAX_K, MOBILE_V2_MIN_K};

pub(crate) fn root(
    env: &Env,
    hasher: &Address,
    ordered_scms: &Vec<BytesN<32>>,
) -> Result<BytesN<32>, PoolError> {
    validate_ordered_scms(env, ordered_scms)?;
    Ok(env.invoke_contract(
        hasher,
        &Symbol::new(env, "root"),
        vec![env, ordered_scms.clone().into_val(env)],
    ))
}

fn validate_ordered_scms(env: &Env, ordered_scms: &Vec<BytesN<32>>) -> Result<(), PoolError> {
    let k = ordered_scms.len();
    if k < MOBILE_V2_MIN_K {
        return Err(PoolError::BadAmount);
    }
    if k > MOBILE_V2_MAX_K || k > MOBILE_V2_BATCH_CAPACITY {
        return Err(PoolError::BatchFull);
    }

    let mut i = 0u32;
    while i < k {
        let scm = ordered_scms.get_unchecked(i);
        canonical(env, &scm)?;
        if scm.to_array() == [0u8; 32] {
            return Err(PoolError::BadAmount);
        }

        let mut j = 0u32;
        while j < i {
            if ordered_scms.get_unchecked(j) == scm {
                return Err(PoolError::DoubleSpend);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

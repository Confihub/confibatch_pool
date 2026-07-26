#![no_std]
//! Shielded note pool and confidential batch-swap contract for ConfiBatch.
//!
//! Balances are immutable, asset-tagged UTXO **notes** committed as
//! `Poseidon(asset_id, amount, pk_d, rho, r)` and accumulated in a Poseidon
//! Merkle tree. The contract never recomputes the existing tree hash: its
//! circomlib/BLS permutation is not compatible with standard host Poseidon.
//! Instead it stores the current root + next free index and advances them only
//! via a Groth16 proof binding its stored `oldRoot`/`startIndex`, the exact
//! proof-authorized leaf, and the claimed `newRoot`.
//! A forged root simply fails verification. Double-spends are stopped by an
//! on-chain nullifier set. Deposit and withdrawal move real SAC balances;
//! transfers, splits, swaps, and confidential LP operations are proof-gated.

mod mobile_v2_batch;

#[cfg(test)]
mod mobile_v2_writer_test;

use groth16_verifier::Groth16VerifierClient;
use soroban_sdk::auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, vec, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, Val, Vec,
};

// The root window must exceed the dwell floor so eligible anchors remain available.
const RING_SIZE: u32 = 32;
// Roots created before frontier tracking use this sentinel.
const DWELL_LEGACY: u64 = u64::MAX;
const TREE_CAPACITY: u64 = 1u64 << 16;
const MOBILE_V2_BATCH_DEPTH: u32 = 3;
const MOBILE_V2_BATCH_CAPACITY: u32 = 1 << MOBILE_V2_BATCH_DEPTH;
const MOBILE_V2_MIN_K: u32 = 2;
const MOBILE_V2_MAX_K: u32 = 5;
const MOBILE_V2_MAX_ORDER_AMOUNT: u64 = 50_000_000_000;
// SHA-256("confi.cash/mobile-v2/batch-root/poseidon-bls12381-t3-v1").
// This identifies the batch-only standard BLS Poseidon hash; it is not a
// field element and is never supplied to a proof verifier.
const MOBILE_V2_BATCH_HASH_ID: [u8; 32] = [
    0x84, 0x16, 0x7d, 0xe2, 0x9f, 0x1d, 0xc9, 0x7c, 0x57, 0x36, 0xcb, 0xdd, 0xda, 0xeb, 0xde, 0x0e,
    0x1a, 0x18, 0xf3, 0xb6, 0x25, 0xe9, 0x21, 0x3e, 0xea, 0x01, 0x01, 0xee, 0xa7, 0x08, 0x6f, 0xe3,
];

// BLS12-381 Fr modulus, big-endian. Public-input field elements must be < this.
const FR_MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

#[contracterror]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum PoolError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NotAdmin = 3,
    BadAmount = 4,
    NoReserve = 5,
    NonCanonical = 6,
    MalformedProof = 7,
    InvalidProof = 8,
    BadAnchorRoot = 9,
    DoubleSpend = 10,
    NoVerifier = 11,
    CtTooLong = 12,
    Frozen = 13,
    BadDenom = 14,
    DwellNotMet = 15,
    SlippageExceeded = 16,
    NoBatch = 17,
    LpAmmNotSet = 18,
    BatchFull = 19,
    PairExists = 20,
    ReserveConflict = 21,
    Insolvent = 22,
    LiabilityUnderflow = 23,
    TreeFull = 24,
    WrongProtocol = 25,
}

#[contractevent(data_format = "single-value", topics = ["nfspent"])]
pub struct NullifierSpentEvent {
    pub nullifier: BytesN<32>,
}

#[contractevent(data_format = "vec", topics = ["deposit"])]
pub struct DepositEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub note_ct: Bytes,
}

#[contractevent(data_format = "vec", topics = ["transfer"])]
pub struct TransferEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub nullifier: BytesN<32>,
    pub note_ct: Bytes,
}

#[contractevent(data_format = "vec", topics = ["withdraw"])]
pub struct WithdrawEvent {
    pub nullifier: BytesN<32>,
    pub amount: i128,
    pub fee: i128,
}

#[contractevent(data_format = "vec", topics = ["settle"])]
pub struct SettleEvent {
    pub nf_buy: BytesN<32>,
    pub nf_sell: BytesN<32>,
    pub cm_buy: BytesN<32>,
    pub cm_sell: BytesN<32>,
    pub index: u64,
    pub ct_buy: Bytes,
    pub ct_sell: Bytes,
}

#[contractevent(data_format = "vec", topics = ["swapcm"])]
pub struct SwapCommitEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub note_ct: Bytes,
}

#[contractevent(data_format = "vec", topics = ["swapcm"])]
pub struct BoundSwapCommitEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub note_ct: Bytes,
    pub ct_hash: BytesN<32>,
    pub asset_in: BytesN<32>,
    pub asset_out: BytesN<32>,
}

// Mobile-v2 commits use a distinct topic so indexers never infer protocol
// version from proof ABI or an opaque commitment value.
#[contractevent(data_format = "vec", topics = ["swapcmv2"])]
pub struct BoundSwapCommitV2Event {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub note_ct: Bytes,
    pub ct_hash: BytesN<32>,
    pub asset_in: BytesN<32>,
    pub asset_out: BytesN<32>,
}

#[contractevent(data_format = "vec", topics = ["swapclaim"])]
pub struct SwapClaimEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub nullifier: BytesN<32>,
    pub note_ct: Bytes,
}

#[contractevent(data_format = "vec", topics = ["lpadd"])]
pub struct LpAddEvent {
    pub commitment: BytesN<32>,
    pub index: u64,
    pub note_ct: Bytes,
}

#[contractevent(data_format = "vec", topics = ["lpremove"])]
pub struct LpRemoveEvent {
    pub nullifier: BytesN<32>,
    pub amount_a: i128,
    pub amount_b: i128,
}

#[contractevent(data_format = "vec", topics = ["paircreat"])]
pub struct PairCreatedEvent {
    pub pair_id: BytesN<32>,
    pub lp_note_tag: u64,
}

#[contractevent(data_format = "vec", topics = ["batchexec"])]
pub struct BatchExecutedEvent {
    pub batch_id: BytesN<32>,
    pub asset_in: BytesN<32>,
    pub asset_out: BytesN<32>,
    pub sum_in: i128,
    pub sum_out: i128,
    pub swap_root: BytesN<32>,
    pub participants: u32,
    pub fee: i128,
    pub fee_bps: u32,
    pub fee_asset: Address,
}

#[contractevent(data_format = "vec", topics = ["batchexecv2"])]
pub struct BatchExecutedV2Event {
    pub batch_id: BytesN<32>,
    pub ordered_scms: Vec<BytesN<32>>,
}

#[contractevent(data_format = "vec", topics = ["vfreeze"])]
pub struct VerifiersFrozenEvent {}

#[contractevent(data_format = "vec", topics = ["ufreeze"])]
pub struct UpgradeFrozenEvent {}

#[contractevent(data_format = "single-value", topics = ["upgrade"])]
pub struct UpgradeEvent {
    pub wasm_hash: BytesN<32>,
}

fn emit_nullifier_spent(env: &Env, nullifier: &BytesN<32>) {
    NullifierSpentEvent { nullifier: nullifier.clone() }.publish(env);
}

fn emit_deposit(env: &Env, commitment: &BytesN<32>, index: u64, note_ct: &Bytes) {
    DepositEvent { commitment: commitment.clone(), index, note_ct: note_ct.clone() }.publish(env);
}

fn emit_transfer(env: &Env, commitment: &BytesN<32>, index: u64, nullifier: &BytesN<32>, note_ct: &Bytes) {
    TransferEvent {
        commitment: commitment.clone(),
        index,
        nullifier: nullifier.clone(),
        note_ct: note_ct.clone(),
    }.publish(env);
}

fn emit_withdraw(env: &Env, nullifier: &BytesN<32>, amount: i128, fee: i128) {
    WithdrawEvent { nullifier: nullifier.clone(), amount, fee }.publish(env);
}

fn emit_settle(
    env: &Env,
    nf_buy: &BytesN<32>,
    nf_sell: &BytesN<32>,
    cm_buy: &BytesN<32>,
    cm_sell: &BytesN<32>,
    index: u64,
    ct_buy: &Bytes,
    ct_sell: &Bytes,
) {
    SettleEvent {
        nf_buy: nf_buy.clone(),
        nf_sell: nf_sell.clone(),
        cm_buy: cm_buy.clone(),
        cm_sell: cm_sell.clone(),
        index,
        ct_buy: ct_buy.clone(),
        ct_sell: ct_sell.clone(),
    }.publish(env);
}

fn emit_swap_commit(env: &Env, commitment: &BytesN<32>, index: u64, note_ct: &Bytes) {
    SwapCommitEvent { commitment: commitment.clone(), index, note_ct: note_ct.clone() }.publish(env);
}

fn emit_bound_swap_commit(
    env: &Env,
    commitment: &BytesN<32>,
    index: u64,
    note_ct: &Bytes,
    ct_hash: &BytesN<32>,
    asset_in: &BytesN<32>,
    asset_out: &BytesN<32>,
) {
    BoundSwapCommitEvent {
        commitment: commitment.clone(),
        index,
        note_ct: note_ct.clone(),
        ct_hash: ct_hash.clone(),
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
    }.publish(env);
}

fn emit_bound_swap_commit_v2(
    env: &Env,
    commitment: &BytesN<32>,
    index: u64,
    note_ct: &Bytes,
    ct_hash: &BytesN<32>,
    asset_in: &BytesN<32>,
    asset_out: &BytesN<32>,
) {
    BoundSwapCommitV2Event {
        commitment: commitment.clone(),
        index,
        note_ct: note_ct.clone(),
        ct_hash: ct_hash.clone(),
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
    }.publish(env);
}

fn emit_swap_claim(env: &Env, commitment: &BytesN<32>, index: u64, nullifier: &BytesN<32>, note_ct: &Bytes) {
    SwapClaimEvent {
        commitment: commitment.clone(),
        index,
        nullifier: nullifier.clone(),
        note_ct: note_ct.clone(),
    }.publish(env);
}

fn emit_lp_add(env: &Env, commitment: &BytesN<32>, index: u64, note_ct: &Bytes) {
    LpAddEvent { commitment: commitment.clone(), index, note_ct: note_ct.clone() }.publish(env);
}

fn emit_lp_remove(env: &Env, nullifier: &BytesN<32>, amount_a: i128, amount_b: i128) {
    LpRemoveEvent { nullifier: nullifier.clone(), amount_a, amount_b }.publish(env);
}

fn emit_pair_created(env: &Env, pair_id: &BytesN<32>, lp_note_tag: u64) {
    PairCreatedEvent { pair_id: pair_id.clone(), lp_note_tag }.publish(env);
}

#[allow(clippy::too_many_arguments)]
fn emit_batch_executed(
    env: &Env,
    batch_id: &BytesN<32>,
    asset_in: &BytesN<32>,
    asset_out: &BytesN<32>,
    sum_in: i128,
    sum_out: i128,
    swap_root: &BytesN<32>,
    participants: u32,
    fee: i128,
    fee_bps: u32,
    fee_asset: &Address,
) {
    BatchExecutedEvent {
        batch_id: batch_id.clone(),
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
        sum_in,
        sum_out,
        swap_root: swap_root.clone(),
        participants,
        fee,
        fee_bps,
        fee_asset: fee_asset.clone(),
    }.publish(env);
}

fn emit_batch_executed_v2(
    env: &Env,
    batch_id: &BytesN<32>,
    ordered_scms: &Vec<BytesN<32>>,
) {
    BatchExecutedV2Event {
        batch_id: batch_id.clone(),
        ordered_scms: ordered_scms.clone(),
    }
    .publish(env);
}

// Maximum opaque encrypted-note payload size. The contract does not inspect it.
const NOTE_CT_MAX: u32 = 256;
const VENUE_FEE_MAX_BPS: u32 = 25;
// Soroban storage must be renewed before archival. Mutating paths and
// permissionless keeper entrypoints extend the relevant entries.
const TTL_DAY: u32 = 17280;
const TTL_BUMP: u32 = 30 * TTL_DAY;
const TTL_THRESH: u32 = 20 * TTL_DAY;

// A spent nullifier is a permanent safety invariant, not ordinary session state. Keep it
// live for a much longer window and let a permissionless keeper renew it before expiry.
// Keep a deliberate margin below the network's max_entry_ttl. Requesting the
// exact ceiling is malformed because extend_to must be strictly lower.
const NULLIFIER_TTL_BUMP: u32 = 3_000_000;
const NULLIFIER_TTL_THRESH: u32 = 150 * TTL_DAY;
const MAX_NULLIFIER_TTL_BATCH: u32 = 64;
const MAX_PAIR_TTL_BATCH: u32 = 64;

// Reserved note class for the legacy single-pair confidential LP position.
// It is never registered as a fungible reserve asset, so these notes can only
// be redeemed through confidential LP removal.
const LP_ASSET_ID: u64 = 1_000_000;
// Per-pair LP note classes are assigned monotonically in the reserved namespace.
const LP_TAG_BASE: u64 = 1_000_001;

#[contracttype]
enum DataKey {
    Admin,
    DepositVerifier,
    TransferVerifier,
    WithdrawVerifier,
    WithdrawChangeVerifier,
    BatchVerifier,
    OrderSpendVerifier,
    ClearingVerifier,
    ClearingNbuyVerifier,
    CmRoot,
    NextIndex,
    Epoch,
    RootRing,
    Reserve(BytesN<32>),
    Nullifier(BytesN<32>),
    PairX,
    PairY,
    ReserveX,
    ReserveY,
    RoutePair,
    RouteTokenX,
    RouteTokenY,
    VerifiersFrozen,
    UpgradeFrozen,
    ProtocolFeeBps,
    Treasury,
    Denoms,
    RootIdxRing,
    MinDwell,
    RouteSlipBps,
    MmFunders,
    OutstandingNoteValue(BytesN<32>),
    SwapCommitVerifier,
    SwapCommitBoundVerifier,
    SwapClaimVerifier,
    BatchOut(BytesN<32>),
    LpAmm,
    LpTokenA,
    LpTokenB,
    LpTokenATag,
    LpTokenBTag,
    SplitVerifier,
    BatchCap(BytesN<32>),
    LpPair(BytesN<32>),
    NextLpTag,
    LpPairList,
    SwapFeeAccrued(Address),
    BoundCommit(BytesN<32>),
    SolvencyEnforced,
    ReserveAsset(Address),
    // Mobile-v2 keys are appended to preserve every existing enum discriminant
    // and therefore every v1 instance/persistent storage key.
    SwapCommitBoundV2Verifier,
    SwapClaimV2Verifier,
    AppendV2Verifier,
    BatchV2(BytesN<32>),
    MobileV2Active,
    BoundCommitV2(BytesN<32>),
    // Version-12 canonical writer state. Appended to preserve all prior XDR
    // discriminants and storage compatibility.
    MobileV2Config,
    V2BatchExecutionLock,
}

// Each pair receives a unique LP note class, preventing a note created for one
// pair from being redeemed against another pair.
#[contracttype]
#[derive(Clone)]
pub struct LpPairCfg {
    pub amm: Address,
    pub token_a: Address,
    pub token_b: Address,
    pub tag_a: u64,
    pub tag_b: u64,
    pub lp_note_tag: u64,
}

// Public batch totals and the commitment root used to price and authorize claims.
#[contracttype]
#[derive(Clone)]
pub struct BatchOut {
    pub asset_in: BytesN<32>,
    pub asset_out: BytesN<32>,
    pub sum_in: i128,
    pub sum_out: i128,
    pub swap_root: BytesN<32>,
}

// BatchCap remains a separate key so capacity accounting cannot be reset by rewriting BatchOut.
// BatchOut itself now includes the asset pair, which intentionally changes its XDR layout and is
// therefore fresh-pool only; the deployment flags and preflight refuse to use it on the frozen pool.
// Only batches created via batch_execute_scoped get a BatchCap, and swap_claim requires it.
#[contracttype]
#[derive(Clone)]
pub struct BatchCap {
    pub k: u32,
    pub claimed: u32,
}

// The complete v2 claim statement and its monotonic claim count share one
// persistent value. Selective restoration can therefore never expose a v2
// BatchOut/BatchCap pair while omitting its protocol marker.
#[contracttype]
#[derive(Clone)]
pub struct V2BatchRecord {
    pub output: BatchOut,
    pub cap: BatchCap,
}

// Public receipt for an accepted amount-bound commitment. Remote decrypt signers
// query this before releasing a share, so a relay cannot ask them to decrypt an
// arbitrary individual ciphertext that never passed the pool verifier.
#[contracttype]
#[derive(Clone)]
pub struct BoundCommit {
    pub ct_hash: BytesN<32>,
    pub asset_in: BytesN<32>,
    pub asset_out: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct MobileV2Config {
    pub protocol_version: u32,
    pub writer_revision: u32,
    pub batch_depth: u32,
    pub circuit_capacity: u32,
    pub min_k: u32,
    pub max_k: u32,
    pub max_order_amount: u64,
    pub batch_hash_id: BytesN<32>,
    pub profile_hash: BytesN<32>,
    pub batch_hasher: Address,
    pub batch_executor: Address,
    pub commit_verifier: Address,
    pub claim_verifier: Address,
    pub append_verifier: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct V2MemberUse {
    pub batch_id: BytesN<32>,
    pub position: u32,
}

// The availability bit and its terminal assignment deliberately share the
// same persistent entry. If archived state is restored, callers cannot restore
// a receipt while omitting a separate "already used" marker and reuse it in a
// second batch.
#[contracttype]
#[derive(Clone)]
pub enum V2CommitState {
    Available,
    Assigned(V2MemberUse),
}

#[contract]
pub struct ConfibatchPool;

#[cfg(not(test))]
#[contractimpl]
impl ConfibatchPool {
    /// Fresh deployments initialize atomically with contract creation. `init`
    /// remains available for compatible upgrades.
    pub fn __constructor(env: Env, admin: Address, empty_root: BytesN<32>) {
        initialize_pool(&env, &admin, &empty_root).unwrap();
    }
}

#[contractimpl]
impl ConfibatchPool {
    /// Initialize with the admin and the empty-tree root (Poseidon zero-hash root
    /// for TREE_DEPTH, computed off-chain — the contract never hashes the tree).
    pub fn init(env: Env, admin: Address, empty_root: BytesN<32>) -> Result<(), PoolError> {
        initialize_pool(&env, &admin, &empty_root)
    }

    pub fn set_deposit_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::DepositVerifier, &v);
        Ok(())
    }
    pub fn set_transfer_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::TransferVerifier, &v);
        Ok(())
    }
    pub fn set_withdraw_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::WithdrawVerifier, &v);
        Ok(())
    }
    // Configure the one-input, two-output split verifier.
    pub fn set_split_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::SplitVerifier, &v);
        Ok(())
    }
    pub fn set_withdraw_change_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::WithdrawChangeVerifier, &v);
        Ok(())
    }

    pub fn set_batch_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::BatchVerifier, &v);
        Ok(())
    }

    pub fn set_order_spend_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::OrderSpendVerifier, &v);
        Ok(())
    }

    pub fn set_clearing_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::ClearingVerifier, &v);
        Ok(())
    }

    pub fn set_clearing_nbuy_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::ClearingNbuyVerifier, &v);
        Ok(())
    }

    // Configure the decoupled swap commitment and claim verifiers.
    pub fn set_swap_commit_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::SwapCommitVerifier, &v);
        Ok(())
    }

    pub fn set_swap_commit_bound_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::SwapCommitBoundVerifier, &v);
        Ok(())
    }

    pub fn set_swap_claim_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::SwapClaimVerifier, &v);
        Ok(())
    }

    // Configure the frontier-independent amount-bound commit verifier.
    // Kept separate because its six-signal ABI is incompatible with v1.
    pub fn set_swap_commit_v2_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_mobile_v2_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage()
            .instance()
            .set(&DataKey::SwapCommitBoundV2Verifier, &v);
        Ok(())
    }

    // Configure the depth-3, frontier-independent claim verifier.
    pub fn set_swap_claim_v2_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_mobile_v2_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage()
            .instance()
            .set(&DataKey::SwapClaimV2Verifier, &v);
        Ok(())
    }

    // Relay-generated depth-16 append verifier, with fixed ABI
    // [oldRoot, startIndex, newRoot, leaf].
    pub fn set_append_v2_verifier(env: Env, v: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        require_mobile_v2_verifiers_mutable(&env)?;
        validate_verifier(&env, &v)?;
        env.storage().instance().set(&DataKey::AppendV2Verifier, &v);
        Ok(())
    }

    // One-way activation of the exact v2 profile. It locks only the versioned
    // identities and leaves both global freeze keys absent.
    pub fn activate_mobile_v2(
        env: Env,
        profile_hash: BytesN<32>,
        batch_hasher: Address,
        batch_executor: Address,
    ) -> Result<MobileV2Config, PoolError> {
        require_init(&env)?;
        require_admin(&env)?;
        if !solvency_is_enforced(&env)
            || profile_hash.to_array() == [0u8; 32]
            || env.storage().instance().has(&DataKey::MobileV2Config)
            || env.storage().instance().has(&DataKey::MobileV2Active)
        {
            return Err(PoolError::WrongProtocol);
        }
        let commit_verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::SwapCommitBoundV2Verifier)
            .ok_or(PoolError::NoVerifier)?;
        let claim_verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::SwapClaimV2Verifier)
            .ok_or(PoolError::NoVerifier)?;
        let append_verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::AppendV2Verifier)
            .ok_or(PoolError::NoVerifier)?;
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PoolError::NotInitialized)?;
        validate_verifier(&env, &commit_verifier)?;
        validate_verifier(&env, &claim_verifier)?;
        validate_verifier(&env, &append_verifier)?;
        validate_verifier(&env, &batch_hasher)?;
        validate_account_address(&env, &batch_executor)?;
        if commit_verifier == claim_verifier
            || commit_verifier == append_verifier
            || claim_verifier == append_verifier
            || batch_hasher == commit_verifier
            || batch_hasher == claim_verifier
            || batch_hasher == append_verifier
            || batch_executor == env.current_contract_address()
            || batch_executor == admin
            || batch_executor == batch_hasher
            || batch_executor == commit_verifier
            || batch_executor == claim_verifier
            || batch_executor == append_verifier
        {
            return Err(PoolError::WrongProtocol);
        }
        let observed_hash_id: BytesN<32> = env.invoke_contract(
            &batch_hasher,
            &Symbol::new(&env, "hash_id"),
            Vec::new(&env),
        );
        let observed_version: u32 = env.invoke_contract(
            &batch_hasher,
            &Symbol::new(&env, "version"),
            Vec::new(&env),
        );
        if observed_hash_id.to_array() != MOBILE_V2_BATCH_HASH_ID || observed_version != 1 {
            return Err(PoolError::WrongProtocol);
        }
        env.deployer().extend_ttl(
            batch_hasher.clone(),
            TTL_THRESH,
            NULLIFIER_TTL_BUMP,
        );
        let config = MobileV2Config {
            protocol_version: 2,
            writer_revision: 1,
            batch_depth: MOBILE_V2_BATCH_DEPTH,
            circuit_capacity: MOBILE_V2_BATCH_CAPACITY,
            min_k: MOBILE_V2_MIN_K,
            max_k: MOBILE_V2_MAX_K,
            max_order_amount: MOBILE_V2_MAX_ORDER_AMOUNT,
            batch_hash_id: BytesN::from_array(&env, &MOBILE_V2_BATCH_HASH_ID),
            profile_hash,
            batch_hasher,
            batch_executor,
            commit_verifier,
            claim_verifier,
            append_verifier,
        };
        env.storage()
            .instance()
            .set(&DataKey::MobileV2Config, &config);
        env.storage()
            .instance()
            .set(&DataKey::MobileV2Active, &true);
        bump_instance(&env);
        Ok(config)
    }

    /// Admin: set the protocol fee (basis points, capped at 100 = 1%) + the treasury
    /// that receives it. The fee is zero unless both values are configured.
    pub fn set_protocol_fee(env: Env, bps: u32, treasury: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        if bps > 100 {
            return Err(PoolError::BadAmount);
        }
        env.storage().instance().set(&DataKey::ProtocolFeeBps, &bps);
        env.storage().instance().set(&DataKey::Treasury, &treasury);
        Ok(())
    }

    /// Public view of the protocol fee config.
    pub fn protocol_fee_bps(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::ProtocolFeeBps).unwrap_or(0)
    }

    /// Public view of venue swap fees accrued for a quote SAC by `batch_execute_scoped`.
    pub fn swap_fee_accrued(env: Env, fee_asset: Address) -> i128 {
        env.storage().persistent().get(&DataKey::SwapFeeAccrued(fee_asset)).unwrap_or(0)
    }

    /// Admin: sweep venue swap fees already retained in the pool balance to Treasury.
    pub fn sweep_fees(env: Env, fee_asset: Address) -> Result<i128, PoolError> {
        require_init(&env)?;
        require_admin(&env)?;
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::SwapFeeAccrued(fee_asset.clone()))
            .unwrap_or(0);
        if amount <= 0 {
            return Ok(0);
        }
        let asset_id: Option<BytesN<32>> = if solvency_is_enforced(&env) {
            let asset = env
                .storage()
                .persistent()
                .get(&DataKey::ReserveAsset(fee_asset.clone()))
                .ok_or(PoolError::NoReserve)?;
            enforce_asset_solvency(&env, &asset)?;
            Some(asset)
        } else {
            None
        };
        let (_, treasury) = protocol_fee_cfg(&env);
        let treasury = treasury.ok_or(PoolError::BadAmount)?;
        env.storage().persistent().set(&DataKey::SwapFeeAccrued(fee_asset.clone()), &0i128);
        env.storage().persistent().extend_ttl(
            &DataKey::SwapFeeAccrued(fee_asset.clone()),
            TTL_THRESH,
            TTL_BUMP,
        );
        token::TokenClient::new(&env, &fee_asset).transfer(
            &env.current_contract_address(),
            &treasury,
            &amount,
        );
        if let Some(asset) = asset_id {
            enforce_asset_solvency(&env, &asset)?;
        }
        Ok(amount)
    }

    /// Admin: set the privacy dwell floor (in appends) for swaps. A swap's buyer
    /// note must be anchored to a root that trails the current frontier by at least
    /// `n` leaves, forcing each traded note to mix under `n` newer notes first.
    /// Zero disables the rule. The value must remain below `RING_SIZE` so an
    /// eligible anchor remains inside the recent-root window.
    /// A dwell-`n` swap anchors to a root `n` appends old; under concurrent traffic, more
    /// appends land between prove and submit and push that anchor further back — if it was
    /// already near `RING_SIZE - 1` it can be evicted before submission. Keep the
    /// configured value well below `RING_SIZE` to preserve a prove-to-submit margin.
    pub fn set_min_dwell(env: Env, n: u64) -> Result<(), PoolError> {
        require_admin(&env)?;
        if n >= RING_SIZE as u64 {
            return Err(PoolError::BadAmount);
        }
        env.storage().instance().set(&DataKey::MinDwell, &n);
        Ok(())
    }

    /// Admin: set the allowed user-deposit denominations. An empty vector
    /// disables the rule. Enforced only on the public `deposit` path; the MM's
    /// value-matched mints use the denom-exempt `deposit_internal`.
    pub fn set_denominations(env: Env, denoms: Vec<i128>) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Denoms, &denoms);
        Ok(())
    }

    pub fn denominations(env: Env) -> Vec<i128> {
        env.storage().instance().get(&DataKey::Denoms).unwrap_or(Vec::new(&env))
    }

    /// Admin: define the batch swap pair (both assets must be registered reserves).
    pub fn set_pair(env: Env, asset_x: BytesN<32>, asset_y: BytesN<32>) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::PairX, &asset_x);
        env.storage().instance().set(&DataKey::PairY, &asset_y);
        if !env.storage().instance().has(&DataKey::ReserveX) {
            env.storage().instance().set(&DataKey::ReserveX, &0i128);
            env.storage().instance().set(&DataKey::ReserveY, &0i128);
        }
        Ok(())
    }

    /// Admin: set compatibility reserve accounting without moving tokens. This
    /// does not establish custody; backed liquidity must use `seed_liquidity`.
    pub fn set_reserves(env: Env, x: i128, y: i128) -> Result<(), PoolError> {
        require_admin(&env)?;
        if x < 0 || y < 0 {
            return Err(PoolError::BadAmount);
        }
        env.storage().instance().set(&DataKey::ReserveX, &x);
        env.storage().instance().set(&DataKey::ReserveY, &y);
        Ok(())
    }

    /// Admin: seed AMM liquidity by pulling real tokens for both pair assets.
    pub fn seed_liquidity(env: Env, amount_x: i128, amount_y: i128) -> Result<(), PoolError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PoolError::NotInitialized)?;
        admin.require_auth();
        if amount_x < 0 || amount_y < 0 {
            return Err(PoolError::BadAmount);
        }
        let px: BytesN<32> = env.storage().instance().get(&DataKey::PairX).ok_or(PoolError::NoReserve)?;
        let py: BytesN<32> = env.storage().instance().get(&DataKey::PairY).ok_or(PoolError::NoReserve)?;
        let sac_x: Address = env.storage().persistent().get(&DataKey::Reserve(px)).ok_or(PoolError::NoReserve)?;
        let sac_y: Address = env.storage().persistent().get(&DataKey::Reserve(py)).ok_or(PoolError::NoReserve)?;
        let rx: i128 = env.storage().instance().get(&DataKey::ReserveX).unwrap_or(0);
        let ry: i128 = env.storage().instance().get(&DataKey::ReserveY).unwrap_or(0);
        let next_rx = rx.checked_add(amount_x).ok_or(PoolError::BadAmount)?;
        let next_ry = ry.checked_add(amount_y).ok_or(PoolError::BadAmount)?;
        let here = env.current_contract_address();
        if amount_x > 0 {
            token::TokenClient::new(&env, &sac_x).transfer(&admin, &here, &amount_x);
        }
        if amount_y > 0 {
            token::TokenClient::new(&env, &sac_y).transfer(&admin, &here, &amount_y);
        }
        env.storage().instance().set(&DataKey::ReserveX, &next_rx);
        env.storage().instance().set(&DataKey::ReserveY, &next_ry);
        Ok(())
    }

    /// Admin: register an asset tag -> its SAC reserve address (e.g. USDC).
    pub fn register_asset(env: Env, asset_id: BytesN<32>, sac: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        set_reserve_checked(&env, &asset_id, &sac)
    }

    // ---- views ----
    pub fn root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::CmRoot).unwrap()
    }
    pub fn next_index(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0)
    }
    /// Privacy dwell floor (in appends): a swap may only spend a note whose anchor
    /// root trails the current frontier by >= this many leaves. 0 = disabled.
    pub fn get_min_dwell(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::MinDwell).unwrap_or(0)
    }

    /// Admin: set the max slippage (bps) tolerated on the settle auto-route versus
    /// the proven reserve snapshot. Capped at 1000 (10%); a live route drifting beyond the
    /// band reverts the settle with SlippageExceeded. Unset reads as 100 (1%).
    pub fn set_route_slip_bps(env: Env, bps: u32) -> Result<(), PoolError> {
        require_admin(&env)?;
        if bps > 1000 {
            return Err(PoolError::BadAmount);
        }
        env.storage().instance().set(&DataKey::RouteSlipBps, &bps);
        Ok(())
    }
    pub fn get_route_slip_bps(env: Env) -> u32 {
        route_slip_bps(&env)
    }

    /// Admin: allow `funder` to self-authorize and self-fund denomination-exempt
    /// counter-leg notes through `deposit_internal`. Idempotent.
    pub fn add_mm_funder(env: Env, funder: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        if !is_mm_funder(&env, &funder) {
            let mut funders: Vec<Address> = env
                .storage()
                .instance()
                .get(&DataKey::MmFunders)
                .unwrap_or(Vec::new(&env));
            funders.push_back(funder);
            env.storage().instance().set(&DataKey::MmFunders, &funders);
        }
        Ok(())
    }

    /// Admin: revoke `funder` from the independent-MM allowlist.
    pub fn remove_mm_funder(env: Env, funder: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        let funders: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::MmFunders)
            .unwrap_or(Vec::new(&env));
        let mut kept: Vec<Address> = Vec::new(&env);
        for f in funders.iter() {
            if f != funder {
                kept.push_back(f);
            }
        }
        env.storage().instance().set(&DataKey::MmFunders, &kept);
        Ok(())
    }

    pub fn mm_funders(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::MmFunders)
            .unwrap_or(Vec::new(&env))
    }

    /// Running total of outstanding shielded-note value for `asset_id` (0 if unset).
    /// Fresh pools enforce this against live SAC custody after every value transition.
    /// Upgraded legacy pools remain observe-only because their pre-upgrade notes cannot
    /// be reconstructed trustlessly from encrypted events; they must migrate to a fresh pool.
    pub fn outstanding_of(env: Env, asset_id: BytesN<32>) -> i128 {
        // Restrict this exact liability value because it can reveal individual
        // flows for low-traffic assets.
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage()
            .persistent()
            .get(&DataKey::OutstandingNoteValue(asset_id))
            .unwrap_or(0)
    }
    pub fn nullifier_spent(env: Env, nf: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::Nullifier(nf))
    }
    pub fn solvency_enforced(env: Env) -> bool {
        env.storage().instance().get(&DataKey::SolvencyEnforced).unwrap_or(false)
    }
    pub fn reserve_of(env: Env, asset_id: BytesN<32>) -> Result<Address, PoolError> {
        env.storage()
            .persistent()
            .get(&DataKey::Reserve(asset_id))
            .ok_or(PoolError::NoReserve)
    }
    pub fn route_config(env: Env) -> Result<(Address, Address, Address), PoolError> {
        let pair: Address = env.storage().instance().get(&DataKey::RoutePair).ok_or(PoolError::NoReserve)?;
        let token_x: Address = env.storage().instance().get(&DataKey::RouteTokenX).ok_or(PoolError::NoReserve)?;
        let token_y: Address = env.storage().instance().get(&DataKey::RouteTokenY).ok_or(PoolError::NoReserve)?;
        Ok((pair, token_x, token_y))
    }
    pub fn bound_commit(env: Env, scm: BytesN<32>) -> Option<BoundCommit> {
        env.storage().persistent().get(&DataKey::BoundCommit(scm))
    }
    pub fn bound_commit_v2(env: Env, scm: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::BoundCommitV2(scm))
    }
    pub fn batch_v2(env: Env, batch_id: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::BatchV2(batch_id))
    }
    pub fn mobile_v2_batch(env: Env, batch_id: BytesN<32>) -> Option<V2BatchRecord> {
        env.storage().persistent().get(&DataKey::BatchV2(batch_id))
    }
    pub fn mobile_v2_config(env: Env) -> Option<MobileV2Config> {
        env.storage().instance().get(&DataKey::MobileV2Config)
    }
    pub fn v2_member_use(env: Env, scm: BytesN<32>) -> Option<V2MemberUse> {
        match env
            .storage()
            .persistent()
            .get(&DataKey::BoundCommitV2(scm))
        {
            Some(V2CommitState::Assigned(member_use)) => Some(member_use),
            _ => None,
        }
    }
    pub fn mobile_v2_active(env: Env) -> bool {
        mobile_v2_is_active(&env)
    }
    // On-chain code version for guarded in-place upgrade readback.
    pub fn version() -> u32 {
        12
    }

    // Permissionless instance/code keeper for this pool and its immutable v2
    // hash helper. It changes no protocol value.
    pub fn bump_ttl(env: Env) -> Result<(), PoolError> {
        require_init(&env)?;
        bump_instance(&env);
        if let Some(config) = env
            .storage()
            .instance()
            .get::<_, MobileV2Config>(&DataKey::MobileV2Config)
        {
            env.deployer().extend_ttl(
                config.batch_hasher,
                TTL_THRESH,
                NULLIFIER_TTL_BUMP,
            );
        }
        Ok(())
    }

    // Bounded, permissionless spent-nullifier keeper.
    pub fn bump_nullifier_ttl(env: Env, nullifiers: Vec<BytesN<32>>) -> Result<u32, PoolError> {
        require_init(&env)?;
        if nullifiers.len() > MAX_NULLIFIER_TTL_BATCH {
            return Err(PoolError::BadAmount);
        }
        let mut renewed = 0u32;
        for nf in nullifiers.iter() {
            canonical(&env, &nf)?;
            if renew_nullifier_ttl(&env, &nf) {
                renewed += 1;
            }
        }
        bump_instance(&env);
        Ok(renewed)
    }

    // Bounded, permissionless persistent pair-config keeper.
    pub fn bump_pair_ttl(env: Env, pair_ids: Vec<BytesN<32>>) -> Result<u32, PoolError> {
        require_init(&env)?;
        if pair_ids.len() > MAX_PAIR_TTL_BATCH {
            return Err(PoolError::BadAmount);
        }
        let mut renewed = 0u32;
        for pair_id in pair_ids.iter() {
            canonical(&env, &pair_id)?;
            let key = DataKey::LpPair(pair_id);
            if env.storage().persistent().has(&key) {
                env.storage().persistent().extend_ttl(&key, TTL_THRESH, TTL_BUMP);
                renewed += 1;
            }
        }
        bump_instance(&env);
        Ok(renewed)
    }

    /// DEPOSIT — pull `amount` of the real reserve for `asset_id` and proof-gated
    /// mint one note `cm`, advancing the tree to `new_root`.
    /// Public-input order: [asset_id, amount, oldRoot, startIndex, newRoot, cm].
    pub fn deposit(
        env: Env,
        owner: Address,
        asset_id: BytesN<32>,
        amount: i128,
        new_root: BytesN<32>,
        cm: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        owner.require_auth();
        require_denom(&env, amount)?;
        mint_deposit(&env, &owner, &asset_id, amount, &new_root, &cm, &proof, &note_ct)
    }

    /// DEPOSIT_INTERNAL — authorized proof-gated mint that is exempt from the
    /// public denomination rule. Counter-leg notes may contain arbitrary
    /// value-matched amounts but use the same proof checks as `deposit`.
    pub fn deposit_internal(
        env: Env,
        owner: Address,
        asset_id: BytesN<32>,
        amount: i128,
        new_root: BytesN<32>,
        cm: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        // The admin or an allowlisted funder may authorize this path. The
        // allowlist is empty by default, and every funder supplies its own tokens.
        if is_mm_funder(&env, &owner) {
            owner.require_auth();
        } else {
            require_admin(&env)?;
        }
        mint_deposit(&env, &owner, &asset_id, amount, &new_root, &cm, &proof, &note_ct)
    }

    /// TRANSFER — spend one note (nullifier `nf`, membership under `anchor_root`)
    /// into one fresh note `cm_out`, amount hidden, value-conserving in-circuit.
    /// No `require_auth`: authority is the proof (unlinkable); any relayer submits.
    /// Public-input order: [anchor_root, nf, oldRoot, startIndex, newRoot, cm_out].
    pub fn transfer(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        new_root: BytesN<32>,
        cm_out: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if note_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &new_root)?;
        canonical(&env, &cm_out)?;

        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }

        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        let pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            old_root,
            u64_to_be32(&env, idx),
            new_root.clone(),
            cm_out.clone(),
        ];
        verify(&env, &DataKey::TransferVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        advance_root(&env, &new_root, idx);
        emit_transfer(&env, &cm_out, idx, &nf, &note_ct);
        Ok(())
    }

    // Spend one note and append two value-conserving shielded notes without
    // moving tokens across the public boundary. One proof binds the spend, the
    // hidden split, and both sequential appends. Public-input order:
    //   [anchor_root, nf, asset_id, current_index, old_root, start_index, mid_root, new_root, cm_hi, cm_lo].
    pub fn split(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        asset_id: u64,
        current_index: u64,
        mid_root: BytesN<32>,
        new_root: BytesN<32>,
        cm_hi: BytesN<32>,
        cm_lo: BytesN<32>,
        proof: Bytes,
        ct_hi: Bytes,
        ct_lo: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if ct_hi.len() > NOTE_CT_MAX || ct_lo.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &mid_root)?;
        canonical(&env, &new_root)?;
        canonical(&env, &cm_hi)?;
        canonical(&env, &cm_lo)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        let idx0: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        if current_index > idx0 {
            return Err(PoolError::BadAmount);
        }
        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();

        let pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            u64_to_be32(&env, asset_id),
            u64_to_be32(&env, current_index),
            old_root,
            u64_to_be32(&env, idx0),
            mid_root.clone(),
            new_root.clone(),
            cm_hi.clone(),
            cm_lo.clone(),
        ];
        verify(&env, &DataKey::SplitVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        // Append `cm_hi`, followed by `cm_lo`, against consecutive frontiers.
        advance_root(&env, &mid_root, idx0);
        emit_transfer(&env, &cm_hi, idx0, &nf, &ct_hi);
        let idx1: u64 = idx0 + 1;
        advance_root(&env, &new_root, idx1);
        emit_transfer(&env, &cm_lo, idx1, &nf, &ct_lo);
        Ok(())
    }

    // Decoupled swap: commit, execute, then claim.
    // SWAP_COMMIT — spend one input note (nullifier `nf`) and append a swap-commitment `scm`, joining the
    // open batch. Proof-gated by the swap_commit circuit (binds scm to the spent note's amount/asset/owner).
    // Structurally a transfer whose appended leaf is a swap-commitment, not a note.
    // Public-input order: [anchor_root, nf, oldRoot, startIndex, newRoot, scm].
    pub fn swap_commit(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        scm: BytesN<32>,
        new_root: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        swap_commit_impl(env, anchor_root, nf, scm, new_root, proof, note_ct, None)
    }

    /// Amount-bound commit. `ct_hash` is the seventh public signal of
    /// swap_commit_bound and commits to the exact Jubjub ciphertext whose
    /// plaintext amount is also committed in `scm`.
    pub fn swap_commit_bound(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        scm: BytesN<32>,
        new_root: BytesN<32>,
        ct_hash: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        swap_commit_impl(
            env,
            anchor_root,
            nf,
            scm,
            new_root,
            proof,
            note_ct,
            Some((ct_hash, asset_in, asset_out)),
        )
    }

    // Frontier-independent v2 semantic proof plus a relay-generated append
    // proof. Both verify before any state write.
    #[allow(clippy::too_many_arguments)]
    pub fn swap_commit_bound_v2(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        scm: BytesN<32>,
        ct_hash: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
        new_root: BytesN<32>,
        semantic_proof: Bytes,
        append_proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        // Configuration alone never activates v2: the one-way activation
        // profile must also match the exact verifier identities and hash rules.
        if !mobile_v2_is_active(&env) || !solvency_is_enforced(&env) {
            return Err(PoolError::WrongProtocol);
        }
        if note_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &scm)?;
        canonical(&env, &ct_hash)?;
        canonical(&env, &asset_in)?;
        canonical(&env, &asset_out)?;
        canonical(&env, &new_root)?;
        if scm.to_array() == [0u8; 32] || asset_in == asset_out {
            return Err(PoolError::BadAmount);
        }
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Reserve(asset_in.clone()))
            || !env
                .storage()
                .persistent()
                .has(&DataKey::Reserve(asset_out.clone()))
        {
            return Err(PoolError::NoReserve);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::BoundCommit(scm.clone()))
            || env
                .storage()
                .persistent()
                .has(&DataKey::BoundCommitV2(scm.clone()))
        {
            return Err(PoolError::PairExists);
        }
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nf.clone()))
        {
            return Err(PoolError::DoubleSpend);
        }
        let idx: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextIndex)
            .unwrap_or(0);
        if idx >= TREE_CAPACITY {
            return Err(PoolError::TreeFull);
        }
        if !dwell_ok(&env, &anchor_root, idx) {
            return Err(PoolError::DwellNotMet);
        }
        verify_mobile_v2_append(&env, &new_root, &scm, &append_proof)?;
        let pi: Vec<BytesN<32>> = vec![
            &env,
            ct_hash.clone(),
            anchor_root,
            nf.clone(),
            scm.clone(),
            asset_in.clone(),
            asset_out.clone(),
        ];
        verify(
            &env,
            &DataKey::SwapCommitBoundV2Verifier,
            &semantic_proof,
            pi,
        )?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        advance_root(&env, &new_root, idx);
        let key = DataKey::BoundCommit(scm.clone());
        env.storage().persistent().set(
            &key,
            &BoundCommit {
                ct_hash: ct_hash.clone(),
                asset_in: asset_in.clone(),
                asset_out: asset_out.clone(),
            },
        );
        env.storage()
            .persistent()
            .extend_ttl(&key, NULLIFIER_TTL_THRESH, NULLIFIER_TTL_BUMP);
        let v2_key = DataKey::BoundCommitV2(scm.clone());
        env.storage()
            .persistent()
            .set(&v2_key, &V2CommitState::Available);
        env.storage().persistent().extend_ttl(
            &v2_key,
            NULLIFIER_TTL_THRESH,
            NULLIFIER_TTL_BUMP,
        );
        emit_bound_swap_commit_v2(
            &env,
            &scm,
            idx,
            &note_ct,
            &ct_hash,
            &asset_in,
            &asset_out,
        );
        Ok(())
    }

    // Deprecated unscoped execution entrypoint retained for ABI compatibility.
    // It always rejects because a global tree root cannot prove batch membership.
    pub fn batch_execute(
        env: Env,
        _batch_id: BytesN<32>,
        _sum_in: i128,
        _sum_out: i128,
        _swap_root: BytesN<32>,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        require_admin(&env)?;
        Err(PoolError::BadAmount)
    }

    // Scoped execution stores a Merkle root over exactly the `k` commitments
    // assigned to this batch. Claim membership, the capacity counter, and
    // single-use claim nullifiers jointly prevent cross-batch or excess claims.
    pub fn batch_execute_scoped(
        env: Env,
        batch_id: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
        sum_in: i128,
        sum_out: i128,
        swap_root: BytesN<32>,
        k: u32,
        fee_bps: u32,
        fee_asset: Address,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        require_admin(&env)?;
        record_batch_out(&env, batch_id, asset_in, asset_out, sum_in, sum_out, swap_root, k, fee_bps, fee_asset, false)?;
        Ok(())
    }

    /// Fresh-pool amount-blind execution. Routes the committee-attested aggregate
    /// through the configured AMM and records the exact returned output in one
    /// Soroban invocation. A route failure, slippage failure, or BatchOut failure
    /// reverts the token movement and batch record together.
    pub fn batch_execute_routed(
        env: Env,
        batch_id: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
        sum_in: i128,
        min_out: i128,
        swap_root: BytesN<32>,
        k: u32,
        fee_bps: u32,
        fee_asset: Address,
    ) -> Result<i128, PoolError> {
        require_init(&env)?;
        require_admin(&env)?;
        // Validate storage and fee preconditions before invoking the external AMM.
        validate_batch_out(&env, &batch_id, &asset_in, &asset_out, sum_in, min_out, &swap_root, k, fee_bps, &fee_asset)?;
        if min_out <= 0 {
            return Err(PoolError::BadAmount);
        }
        let input_sac: Address = env.storage().persistent().get(&DataKey::Reserve(asset_in.clone())).ok_or(PoolError::NoReserve)?;
        let output_sac: Address = env.storage().persistent().get(&DataKey::Reserve(asset_out.clone())).ok_or(PoolError::NoReserve)?;
        let pair: Address = env.storage().instance().get(&DataKey::RoutePair).ok_or(PoolError::NoReserve)?;
        let route_x: Address = env.storage().instance().get(&DataKey::RouteTokenX).ok_or(PoolError::NoReserve)?;
        let route_y: Address = env.storage().instance().get(&DataKey::RouteTokenY).ok_or(PoolError::NoReserve)?;
        let route_matches = (input_sac == route_x && output_sac == route_y)
            || (input_sac == route_y && output_sac == route_x);
        if !route_matches {
            return Err(PoolError::NoReserve);
        }
        let here = env.current_contract_address();
        let output_token = token::TokenClient::new(&env, &output_sac);
        let output_before = output_token.balance(&here);
        let _requested_out = do_route_pair_checked(&env, &pair, &input_sac, sum_in, min_out)?;
        let output_after = output_token.balance(&here);
        // Adapters may forward more than the low-level requested minimum. Record
        // the exact custody delta so every landed output unit is claimable.
        let gross_sum_out = output_after.checked_sub(output_before).ok_or(PoolError::BadAmount)?;
        if gross_sum_out < min_out || gross_sum_out <= 0 {
            return Err(PoolError::SlippageExceeded);
        }
        record_batch_out(
            &env,
            batch_id,
            asset_in,
            asset_out,
            sum_in,
            gross_sum_out,
            swap_root,
            k,
            fee_bps,
            fee_asset,
            false,
        )
    }

    // Canonical v2 writer: derive k/root/output, enforce ordered receipts, and
    // assign every member atomically with the route and BatchOut write.
    #[allow(clippy::too_many_arguments)]
    pub fn batch_execute_routed_v2(
        env: Env,
        batch_id: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
        expected_route_pair: Address,
        sum_in: i128,
        min_out: i128,
        ordered_scms: Vec<BytesN<32>>,
        fee_bps: u32,
    ) -> Result<i128, PoolError> {
        require_init(&env)?;
        if !mobile_v2_is_active(&env) || !solvency_is_enforced(&env) {
            return Err(PoolError::WrongProtocol);
        }
        let config: MobileV2Config = env
            .storage()
            .instance()
            .get(&DataKey::MobileV2Config)
            .ok_or(PoolError::WrongProtocol)?;
        require_admin(&env)?;
        // The threshold executor signs the exact invocation tree, binding the
        // committee-attested sum, member order, slippage floor, route pair,
        // and fee. The admin cannot execute unilaterally.
        config.batch_executor.require_auth();
        if env
            .storage()
            .instance()
            .get(&DataKey::V2BatchExecutionLock)
            .unwrap_or(false)
        {
            return Err(PoolError::WrongProtocol);
        }
        canonical(&env, &batch_id)?;
        canonical(&env, &asset_in)?;
        canonical(&env, &asset_out)?;
        if batch_id.to_array() == [0u8; 32] || asset_in == asset_out {
            return Err(PoolError::BadAmount);
        }
        validate_mobile_v2_totals(sum_in, min_out)?;
        let k = ordered_scms.len();
        if k < MOBILE_V2_MIN_K || k > MOBILE_V2_MAX_K {
            return Err(PoolError::WrongProtocol);
        }
        let max_sum_in = (k as i128)
            .checked_mul(MOBILE_V2_MAX_ORDER_AMOUNT as i128)
            .ok_or(PoolError::BadAmount)?;
        if sum_in < k as i128 || sum_in > max_sum_in {
            return Err(PoolError::BadAmount);
        }
        let swap_root = mobile_v2_batch::root(&env, &config.batch_hasher, &ordered_scms)?;
        let input_sac: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Reserve(asset_in.clone()))
            .ok_or(PoolError::NoReserve)?;
        let output_sac: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Reserve(asset_out.clone()))
            .ok_or(PoolError::NoReserve)?;
        if fee_bps > 0 && protocol_fee_cfg(&env).1.is_none() {
            return Err(PoolError::BadAmount);
        }
        validate_batch_out(
            &env,
            &batch_id,
            &asset_in,
            &asset_out,
            sum_in,
            min_out,
            &swap_root,
            k,
            fee_bps,
            &output_sac,
        )?;

        let mut position = 0u32;
        while position < k {
            let scm = ordered_scms.get_unchecked(position);
            let state: Option<V2CommitState> = env
                .storage()
                .persistent()
                .get(&DataKey::BoundCommitV2(scm.clone()));
            if !matches!(state, Some(V2CommitState::Available)) {
                return Err(PoolError::WrongProtocol);
            }
            let receipt: BoundCommit = env
                .storage()
                .persistent()
                .get(&DataKey::BoundCommit(scm))
                .ok_or(PoolError::WrongProtocol)?;
            if receipt.asset_in != asset_in || receipt.asset_out != asset_out {
                return Err(PoolError::WrongProtocol);
            }
            position += 1;
        }

        let pair: Address = env
            .storage()
            .instance()
            .get(&DataKey::RoutePair)
            .ok_or(PoolError::NoReserve)?;
        if pair != expected_route_pair {
            return Err(PoolError::WrongProtocol);
        }
        let route_x: Address = env
            .storage()
            .instance()
            .get(&DataKey::RouteTokenX)
            .ok_or(PoolError::NoReserve)?;
        let route_y: Address = env
            .storage()
            .instance()
            .get(&DataKey::RouteTokenY)
            .ok_or(PoolError::NoReserve)?;
        if !((input_sac == route_x && output_sac == route_y)
            || (input_sac == route_y && output_sac == route_x))
        {
            return Err(PoolError::NoReserve);
        }

        env.storage()
            .instance()
            .set(&DataKey::V2BatchExecutionLock, &true);
        position = 0;
        while position < k {
            let scm = ordered_scms.get_unchecked(position);
            let key = DataKey::BoundCommitV2(scm.clone());
            env.storage().persistent().set(
                &key,
                &V2CommitState::Assigned(V2MemberUse {
                    batch_id: batch_id.clone(),
                    position,
                }),
            );
            env.storage().persistent().extend_ttl(
                &key,
                NULLIFIER_TTL_THRESH,
                NULLIFIER_TTL_BUMP,
            );
            position += 1;
        }

        let here = env.current_contract_address();
        let output_token = token::TokenClient::new(&env, &output_sac);
        let output_before = output_token.balance(&here);
        let _requested_out = do_route_pair_checked(&env, &pair, &input_sac, sum_in, min_out)?;
        let output_after = output_token.balance(&here);
        let gross_sum_out = output_after
            .checked_sub(output_before)
            .ok_or(PoolError::BadAmount)?;
        validate_mobile_v2_totals(sum_in, gross_sum_out)?;
        if gross_sum_out < min_out {
            return Err(PoolError::SlippageExceeded);
        }
        let net_sum_out = record_batch_out(
            &env,
            batch_id.clone(),
            asset_in.clone(),
            asset_out.clone(),
            sum_in,
            gross_sum_out,
            swap_root.clone(),
            k,
            fee_bps,
            output_sac,
            true,
        )?;
        env.storage()
            .instance()
            .remove(&DataKey::V2BatchExecutionLock);
        emit_batch_executed_v2(
            &env,
            &batch_id,
            &ordered_scms,
        );
        Ok(net_sum_out)
    }

    // A claim proves a pro-rata share of stored batch output, nullifies the
    // commitment, and appends one fresh shielded note. Contract-derived totals
    // prevent callers from substituting their own pricing inputs.
    // Public-input order: [batchId, assetIn, assetOut, sumIn, sumOut, swapRoot,
    // nfClaim, oldRoot, startIndex, newRoot, cmOut].
    pub fn swap_claim(
        env: Env,
        batch_id: BytesN<32>,
        nf_claim: BytesN<32>,
        cm_out: BytesN<32>,
        new_root: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if note_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &batch_id)?;
        canonical(&env, &nf_claim)?;
        canonical(&env, &cm_out)?;
        canonical(&env, &new_root)?;
        // A canonical v2 batch must only be consumed by the v2 semantic and
        // append verifiers, never by the legacy frontier-bound claim verifier.
        if env
            .storage()
            .persistent()
            .has(&DataKey::BatchV2(batch_id.clone()))
        {
            return Err(PoolError::WrongProtocol);
        }
        let bod: BatchOut = env
            .storage()
            .persistent()
            .get(&DataKey::BatchOut(batch_id.clone()))
            .ok_or(PoolError::NoBatch)?;
        // Only scoped batches have capacity records and are claimable.
        let mut cap: BatchCap = env
            .storage()
            .persistent()
            .get(&DataKey::BatchCap(batch_id.clone()))
            .ok_or(PoolError::NoBatch)?;
        if env.storage().persistent().has(&DataKey::Nullifier(nf_claim.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        // Bound claims to the committed participant count. Membership and
        // single-use claim nullifiers provide the remaining claim constraints.
        if cap.claimed >= cap.k {
            return Err(PoolError::BatchFull);
        }
        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        let pi: Vec<BytesN<32>> = vec![
            &env,
            batch_id.clone(),
            bod.asset_in.clone(),
            bod.asset_out.clone(),
            i128_to_be32(&env, bod.sum_in),
            i128_to_be32(&env, bod.sum_out),
            bod.swap_root.clone(),
            nf_claim.clone(),
            old_root,
            u64_to_be32(&env, idx),
            new_root.clone(),
            cm_out.clone(),
        ];
        verify(&env, &DataKey::SwapClaimVerifier, &proof, pi)?;
        mark_nullifier_spent(&env, &nf_claim);
        cap.claimed += 1;
        env.storage().persistent().set(&DataKey::BatchCap(batch_id.clone()), &cap);
        emit_nullifier_spent(&env, &nf_claim);
        advance_root(&env, &new_root, idx);
        emit_swap_claim(&env, &cm_out, idx, &nf_claim, &note_ct);
        Ok(())
    }

    // Frontier-independent v2 claim plus refreshable append authorization.
    // The batch statement is loaded only from contract-derived storage.
    pub fn swap_claim_v2(
        env: Env,
        batch_id: BytesN<32>,
        nf_claim: BytesN<32>,
        cm_out: BytesN<32>,
        new_root: BytesN<32>,
        semantic_proof: Bytes,
        append_proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if !mobile_v2_is_active(&env) || !solvency_is_enforced(&env) {
            return Err(PoolError::WrongProtocol);
        }
        if note_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &batch_id)?;
        canonical(&env, &nf_claim)?;
        canonical(&env, &cm_out)?;
        canonical(&env, &new_root)?;
        if cm_out.to_array() == [0u8; 32] {
            return Err(PoolError::BadAmount);
        }
        let batch_v2_key = DataKey::BatchV2(batch_id.clone());
        let mut record: V2BatchRecord = env
            .storage()
            .persistent()
            .get(&batch_v2_key)
            .ok_or(PoolError::WrongProtocol)?;
        if record.cap.k < MOBILE_V2_MIN_K || record.cap.k > MOBILE_V2_MAX_K {
            return Err(PoolError::WrongProtocol);
        }
        validate_mobile_v2_totals(record.output.sum_in, record.output.sum_out)?;
        if env
            .storage()
            .persistent()
            .has(&DataKey::Nullifier(nf_claim.clone()))
        {
            return Err(PoolError::DoubleSpend);
        }
        if record.cap.claimed >= record.cap.k {
            return Err(PoolError::BatchFull);
        }
        let idx: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextIndex)
            .unwrap_or(0);
        if idx >= TREE_CAPACITY {
            return Err(PoolError::TreeFull);
        }
        verify_mobile_v2_append(&env, &new_root, &cm_out, &append_proof)?;
        let pi: Vec<BytesN<32>> = vec![
            &env,
            batch_id.clone(),
            record.output.asset_in.clone(),
            record.output.asset_out.clone(),
            i128_to_be32(&env, record.output.sum_in),
            i128_to_be32(&env, record.output.sum_out),
            record.output.swap_root.clone(),
            nf_claim.clone(),
            cm_out.clone(),
        ];
        verify(&env, &DataKey::SwapClaimV2Verifier, &semantic_proof, pi)?;

        mark_nullifier_spent(&env, &nf_claim);
        record.cap.claimed = record
            .cap
            .claimed
            .checked_add(1)
            .ok_or(PoolError::BatchFull)?;
        env.storage().persistent().set(&batch_v2_key, &record);
        env.storage().persistent().extend_ttl(
            &batch_v2_key,
            NULLIFIER_TTL_THRESH,
            NULLIFIER_TTL_BUMP,
        );
        emit_nullifier_spent(&env, &nf_claim);
        advance_root(&env, &new_root, idx);
        emit_swap_claim(&env, &cm_out, idx, &nf_claim, &note_ct);
        Ok(())
    }

    /// Configure the AMM and token SACs used by the legacy confidential LP path.
    /// The contract rejects additions until this admin-controlled route exists.
    pub fn set_lp_amm(env: Env, amm: Address, token_a: Address, token_b: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::LpAmm, &amm);
        env.storage().instance().set(&DataKey::LpTokenA, &token_a);
        env.storage().instance().set(&DataKey::LpTokenB, &token_b);
        Ok(())
    }

    /// Configure the note asset tags for the legacy AMM's two tokens. Shielded
    /// removal binds these contract-controlled tags into its output notes.
    pub fn set_lp_amm_tags(env: Env, tag_a: u64, tag_b: u64) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::LpTokenATag, &tag_a);
        env.storage().instance().set(&DataKey::LpTokenBTag, &tag_b);
        Ok(())
    }

    /// Configure a new pair and return its unique LP note-class tag. Existing
    /// pair identifiers cannot be repointed because doing so would orphan or
    /// mis-back outstanding LP notes.
    pub fn set_lp_pair(
        env: Env,
        pair_id: BytesN<32>,
        amm: Address,
        token_a: Address,
        token_b: Address,
        tag_a: u64,
        tag_b: u64,
    ) -> Result<u64, PoolError> {
        require_admin(&env)?;
        wire_lp_pair(&env, &pair_id, &amm, &token_a, &token_b, tag_a, tag_b)
    }

    /// Register both underlying assets and configure their confidential-LP AMM
    /// in one admin call. Existing pair or reserve mappings cannot be repointed.
    pub fn create_pair(
        env: Env,
        pair_id: BytesN<32>,
        asset_x: BytesN<32>,
        asset_y: BytesN<32>,
        sac_x: Address,
        sac_y: Address,
        amm: Address,
        lp_token_a: Address,
        lp_token_b: Address,
        tag_a: u64,
        tag_b: u64,
    ) -> Result<u64, PoolError> {
        require_admin(&env)?;
        // Reject duplicate pair identifiers before writing state.
        if env.storage().persistent().has(&DataKey::LpPair(pair_id.clone())) {
            return Err(PoolError::PairExists);
        }
        // Reusing the same asset/SAC binding is idempotent; repointing an asset
        // to a different SAC is rejected.
        set_reserve_checked(&env, &asset_x, &sac_x)?;
        set_reserve_checked(&env, &asset_y, &sac_y)?;
        // Wire the LP config + assign the unique note-class tag.
        wire_lp_pair(&env, &pair_id, &amm, &lp_token_a, &lp_token_b, tag_a, tag_b)
    }

    /// Return a pair's confidential-LP configuration, if registered.
    pub fn lp_pair(env: Env, pair_id: BytesN<32>) -> Option<LpPairCfg> {
        env.storage().persistent().get(&DataKey::LpPair(pair_id))
    }

    /// Return all registered pair identifiers.
    pub fn lp_pairs(env: Env) -> Vec<BytesN<32>> {
        env.storage().instance().get(&DataKey::LpPairList).unwrap_or(Vec::new(&env))
    }

    /// Add public AMM liquidity while representing the LP position as an
    /// owner-bound shielded note:
    ///   lpCm = NoteCommit(LP_ASSET_ID, minted, pkd, rho, r)
    /// The pool remains the AMM's sole LP of record and binds the exact minted
    /// shares into the proof. Contribution amounts are public; position
    /// ownership and subsequent note spends remain shielded.
    pub fn add_liquidity_confidential(
        env: Env,
        from: Address,
        amount_a: i128,
        amount_b: i128,
        lp_cm: BytesN<32>,
        new_root: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        // Preserve the original entrypoint with a zero slippage floor.
        add_liquidity_confidential_impl(env, from, amount_a, amount_b, 0, lp_cm, new_root, proof, note_ct, None)
    }

    /// Add confidential liquidity with a caller-signed minimum-share floor.
    /// The operation reverts before token movement if live reserves would mint
    /// fewer shares than requested.
    pub fn add_liquidity_confidential_min(
        env: Env,
        from: Address,
        amount_a: i128,
        amount_b: i128,
        min_shares: i128,
        lp_cm: BytesN<32>,
        new_root: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        if min_shares <= 0 {
            // This entrypoint requires a positive floor.
            return Err(PoolError::BadAmount);
        }
        add_liquidity_confidential_impl(env, from, amount_a, amount_b, min_shares, lp_cm, new_root, proof, note_ct, None)
    }

    /// Per-pair confidential LP add. Identical to add_liquidity_confidential but routes into the AMM wired
    /// for `pair_id` by create_pair, and mints the LP note under that pair's unique note-class tag, so the
    /// resulting note is redeemable only against `pair_id`'s AMM (cross-pair isolation). `min_shares` is the
    /// slippage floor (0 = none). Fails closed (LpAmmNotSet) if `pair_id` was never created.
    pub fn add_lp_confidential_for(
        env: Env,
        pair_id: BytesN<32>,
        from: Address,
        amount_a: i128,
        amount_b: i128,
        min_shares: i128,
        lp_cm: BytesN<32>,
        new_root: BytesN<32>,
        proof: Bytes,
        note_ct: Bytes,
    ) -> Result<(), PoolError> {
        if min_shares < 0 {
            return Err(PoolError::BadAmount);
        }
        add_liquidity_confidential_impl(env, from, amount_a, amount_b, min_shares, lp_cm, new_root, proof, note_ct, Some(pair_id))
    }

    /// Spend one owner-bound LP-position note and return its pro-rata reserves
    /// to `recipient`. The proof binds note membership, shares, nullifier, and
    /// recipient; no exit-age floor is applied. Returned amounts and recipient
    /// are public at the boundary. Public-input order:
    /// [anchor_root, nf, LP_ASSET_ID, shares,
    /// recipient_tag, current_index].
    pub fn remove_liquidity_confidential(
        env: Env,
        recipient: Address,
        shares: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        proof: Bytes,
    ) -> Result<(), PoolError> {
        // Use the reserved legacy pair note class and configured singleton AMM.
        remove_liquidity_confidential_impl(env, recipient, shares, 0, 0, anchor_root, nf, current_index, proof, None)
    }

    /// Per-pair confidential LP removal. Spends an LP note minted by add_liquidity_confidential_for(pair_id):
    /// the proof MUST bind `pair_id`'s unique note-class tag, so a note from another pair can never satisfy it
    /// (isolation) — and the pro-rata reserves come from `pair_id`'s own AMM. Fails closed if `pair_id` is unknown.
    pub fn remove_lp_confidential_for(
        env: Env,
        pair_id: BytesN<32>,
        recipient: Address,
        shares: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        proof: Bytes,
    ) -> Result<(), PoolError> {
        remove_liquidity_confidential_impl(env, recipient, shares, 0, 0, anchor_root, nf, current_index, proof, Some(pair_id))
    }

    /// Fresh-pool confidential LP removal with per-leg minimum outputs. The proof
    /// still binds the pair-specific LP note, shares, nullifier, and recipient;
    /// `min_a`/`min_b` additionally protect the public boundary payout from reserve
    /// drift while the client builds the proof. Both floors must be positive.
    pub fn remove_lp_confidential_for_min(
        env: Env,
        pair_id: BytesN<32>,
        recipient: Address,
        shares: i128,
        min_a: i128,
        min_b: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        proof: Bytes,
    ) -> Result<(), PoolError> {
        if min_a <= 0 || min_b <= 0 {
            return Err(PoolError::BadAmount);
        }
        remove_liquidity_confidential_impl(
            env,
            recipient,
            shares,
            min_a,
            min_b,
            anchor_root,
            nf,
            current_index,
            proof,
            Some(pair_id),
        )
    }

    /// Partially remove confidential liquidity. Spend an LP-position note of
    /// `remove_shares + change_shares`, return the pro-rata reserves for `remove_shares` to `recipient`, and
    /// keep the remainder as a fresh shielded LP note (`change_cm`). The change
    /// note is emitted as a `transfer` leaf. Public-input order matches
    /// withdraw_with_change: [anchor_root, nf, LP_ASSET_ID, remove_shares, 0, recipient_tag, current_index,
    /// old_root, start_index, new_root, change_cm].
    pub fn remove_liquidity_partial(
        env: Env,
        recipient: Address,
        remove_shares: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        new_root: BytesN<32>,
        change_cm: BytesN<32>,
        proof: Bytes,
        change_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if remove_shares <= 0 {
            return Err(PoolError::BadAmount);
        }
        if change_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &new_root)?;
        canonical(&env, &change_cm)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        if current_index > idx {
            return Err(PoolError::BadAmount);
        }
        let amm: Address = env.storage().instance().get(&DataKey::LpAmm).ok_or(PoolError::LpAmmNotSet)?;
        let token_a: Address = env.storage().instance().get(&DataKey::LpTokenA).ok_or(PoolError::LpAmmNotSet)?;
        let token_b: Address = env.storage().instance().get(&DataKey::LpTokenB).ok_or(PoolError::LpAmmNotSet)?;

        // The proof attests: inputAmount(hidden LP note) = remove_shares + 0(fee) + change(hidden). The input is
        // spent, and change_cm commits the remainder — bound to `recipient`. LP path ⇒ fee is 0 (not policy).
        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let tag = recipient_tag_of(&env, &recipient);
        let pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            u64_to_be32(&env, LP_ASSET_ID),
            i128_to_be32(&env, remove_shares),
            i128_to_be32(&env, 0),
            tag,
            u64_to_be32(&env, current_index),
            old_root,
            u64_to_be32(&env, idx),
            new_root.clone(),
            change_cm.clone(),
        ];
        verify(&env, &DataKey::WithdrawChangeVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        advance_root(&env, &new_root, idx); // append the shielded LP change note (reduced private stake)

        let here = env.current_contract_address();
        let args: Vec<Val> = vec![&env, here.into_val(&env), remove_shares.into_val(&env)];
        let (out_a, out_b): (i128, i128) = env.invoke_contract(&amm, &Symbol::new(&env, "remove_liquidity"), args);
        if out_a <= 0 || out_b <= 0 {
            return Err(PoolError::BadAmount);
        }
        token::TokenClient::new(&env, &token_a).transfer(&here, &recipient, &out_a);
        token::TokenClient::new(&env, &token_b).transfer(&here, &recipient, &out_b);
        // shielded side = a transfer-shaped append so the scanner discovers the LP change note
        emit_transfer(&env, &change_cm, idx, &nf, &change_ct);
        emit_lp_remove(&env, &nf, out_a, out_b);
        Ok(())
    }

    /// Remove confidential LP value into two owner-bound shielded notes instead
    /// of paying a public recipient. The spend uses a zero recipient tag, and
    /// each output proof binds the exact amount returned by the AMM. Asset tags
    /// come from contract configuration.
    /// Sequential appends: cm_out_a at (CmRoot, idx) → mid_root; cm_out_b at (mid_root, idx+1) → new_root.
    pub fn remove_liquidity_shielded(
        env: Env,
        shares: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        cm_out_a: BytesN<32>,
        cm_out_b: BytesN<32>,
        mid_root: BytesN<32>,
        new_root: BytesN<32>,
        spend_proof: Bytes,
        dep_proof_a: Bytes,
        dep_proof_b: Bytes,
        ct_a: Bytes,
        ct_b: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if shares <= 0 {
            return Err(PoolError::BadAmount);
        }
        if ct_a.len() > NOTE_CT_MAX || ct_b.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &cm_out_a)?;
        canonical(&env, &cm_out_b)?;
        canonical(&env, &mid_root)?;
        canonical(&env, &new_root)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        let idx0: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        if current_index > idx0 {
            return Err(PoolError::BadAmount);
        }
        let amm: Address = env.storage().instance().get(&DataKey::LpAmm).ok_or(PoolError::LpAmmNotSet)?;
        let tag_a: u64 = env.storage().instance().get(&DataKey::LpTokenATag).ok_or(PoolError::LpAmmNotSet)?;
        let tag_b: u64 = env.storage().instance().get(&DataKey::LpTokenBTag).ok_or(PoolError::LpAmmNotSet)?;

        // 1) spend the LP note (recipient_tag = 0: the value re-enters the shield, no external recipient).
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let spend_pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            u64_to_be32(&env, LP_ASSET_ID),
            i128_to_be32(&env, shares),
            zero,
            u64_to_be32(&env, current_index),
        ];
        verify(&env, &DataKey::WithdrawVerifier, &spend_proof, spend_pi)?;
        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);

        // 2) Burn `shares` in the AMM; the reserves return to this pool.
        let here = env.current_contract_address();
        let args: Vec<Val> = vec![&env, here.into_val(&env), shares.into_val(&env)];
        let (out_a, out_b): (i128, i128) = env.invoke_contract(&amm, &Symbol::new(&env, "remove_liquidity"), args);
        if out_a <= 0 || out_b <= 0 {
            return Err(PoolError::BadAmount);
        }

        // 3) Mint two shielded output notes bound to the exact returned amounts.
        let asset_a = u64_to_be32(&env, tag_a);
        let asset_b = u64_to_be32(&env, tag_b);
        let r0: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let pi_a: Vec<BytesN<32>> = vec![
            &env, asset_a.clone(), i128_to_be32(&env, out_a), r0, u64_to_be32(&env, idx0), mid_root.clone(), cm_out_a.clone(),
        ];
        verify(&env, &DataKey::DepositVerifier, &dep_proof_a, pi_a)?;
        advance_root(&env, &mid_root, idx0);
        outstanding_add(&env, &asset_a, out_a)?;
        emit_deposit(&env, &cm_out_a, idx0, &ct_a);

        let idx1: u64 = idx0 + 1;
        let pi_b: Vec<BytesN<32>> = vec![
            &env, asset_b.clone(), i128_to_be32(&env, out_b), mid_root, u64_to_be32(&env, idx1), new_root.clone(), cm_out_b.clone(),
        ];
        verify(&env, &DataKey::DepositVerifier, &dep_proof_b, pi_b)?;
        advance_root(&env, &new_root, idx1);
        outstanding_add(&env, &asset_b, out_b)?;
        enforce_asset_solvency(&env, &asset_a)?;
        enforce_asset_solvency(&env, &asset_b)?;
        emit_deposit(&env, &cm_out_b, idx1, &ct_b);

        emit_lp_remove(&env, &nf, out_a, out_b);
        Ok(())
    }

    /// Partially remove an LP note while returning the removed token-A and
    /// token-B value as shielded notes. Three sequential
    /// appends: change_cm at idx, cm_out_a at idx+1, cm_out_b at idx+2.
    pub fn remove_partial_shielded(
        env: Env,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        remove_shares: i128,
        current_index: u64,
        change_cm: BytesN<32>,
        root_after_change: BytesN<32>,
        cm_out_a: BytesN<32>,
        cm_out_b: BytesN<32>,
        mid_root: BytesN<32>,
        new_root: BytesN<32>,
        spend_proof: Bytes,
        dep_proof_a: Bytes,
        dep_proof_b: Bytes,
        change_ct: Bytes,
        ct_a: Bytes,
        ct_b: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if remove_shares <= 0 {
            return Err(PoolError::BadAmount);
        }
        if change_ct.len() > NOTE_CT_MAX || ct_a.len() > NOTE_CT_MAX || ct_b.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &change_cm)?;
        canonical(&env, &root_after_change)?;
        canonical(&env, &cm_out_a)?;
        canonical(&env, &cm_out_b)?;
        canonical(&env, &mid_root)?;
        canonical(&env, &new_root)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        let idx0: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        if current_index > idx0 {
            return Err(PoolError::BadAmount);
        }
        let amm: Address = env.storage().instance().get(&DataKey::LpAmm).ok_or(PoolError::LpAmmNotSet)?;
        let tag_a: u64 = env.storage().instance().get(&DataKey::LpTokenATag).ok_or(PoolError::LpAmmNotSet)?;
        let tag_b: u64 = env.storage().instance().get(&DataKey::LpTokenBTag).ok_or(PoolError::LpAmmNotSet)?;

        // 1) spend the LP note + append the change LP note (WITHDRAW_CHANGE, recipient_tag=0: removed value → shielded).
        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let spend_pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            u64_to_be32(&env, LP_ASSET_ID),
            i128_to_be32(&env, remove_shares),
            i128_to_be32(&env, 0),
            zero,
            u64_to_be32(&env, current_index),
            old_root,
            u64_to_be32(&env, idx0),
            root_after_change.clone(),
            change_cm.clone(),
        ];
        verify(&env, &DataKey::WithdrawChangeVerifier, &spend_proof, spend_pi)?;
        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        advance_root(&env, &root_after_change, idx0);
        emit_transfer(&env, &change_cm, idx0, &nf, &change_ct);

        // 2) remove the liquidity for the removed shares.
        let here = env.current_contract_address();
        let args: Vec<Val> = vec![&env, here.into_val(&env), remove_shares.into_val(&env)];
        let (out_a, out_b): (i128, i128) = env.invoke_contract(&amm, &Symbol::new(&env, "remove_liquidity"), args);
        if out_a <= 0 || out_b <= 0 {
            return Err(PoolError::BadAmount);
        }

        // 3) Mint two shielded output notes with sequential appends.
        let idx1: u64 = idx0 + 1;
        let asset_a = u64_to_be32(&env, tag_a);
        let pi_a: Vec<BytesN<32>> = vec![
            &env, asset_a.clone(), i128_to_be32(&env, out_a), root_after_change, u64_to_be32(&env, idx1), mid_root.clone(), cm_out_a.clone(),
        ];
        verify(&env, &DataKey::DepositVerifier, &dep_proof_a, pi_a)?;
        advance_root(&env, &mid_root, idx1);
        outstanding_add(&env, &asset_a, out_a)?;
        emit_deposit(&env, &cm_out_a, idx1, &ct_a);

        let idx2: u64 = idx0 + 2;
        let asset_b = u64_to_be32(&env, tag_b);
        let pi_b: Vec<BytesN<32>> = vec![
            &env, asset_b.clone(), i128_to_be32(&env, out_b), mid_root, u64_to_be32(&env, idx2), new_root.clone(), cm_out_b.clone(),
        ];
        verify(&env, &DataKey::DepositVerifier, &dep_proof_b, pi_b)?;
        advance_root(&env, &new_root, idx2);
        outstanding_add(&env, &asset_b, out_b)?;
        enforce_asset_solvency(&env, &asset_a)?;
        enforce_asset_solvency(&env, &asset_b)?;
        emit_deposit(&env, &cm_out_b, idx2, &ct_b);

        emit_lp_remove(&env, &nf, out_a, out_b);
        Ok(())
    }

    /// WITHDRAW — spend one full note and release its `amount` of real `asset_id`
    /// reserve to `recipient`. `amount`/`asset_id` are public at this boundary.
    /// The payout is bound to `recipient` via `recipient_tag` (a proof public
    /// input the contract recomputes), so a relayer cannot redirect the funds.
    /// Public-input order: [anchor_root, nf, asset_id, amount, recipient_tag].
    pub fn withdraw(
        env: Env,
        recipient: Address,
        asset_id: BytesN<32>,
        amount: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        proof: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        bump_instance(&env);
        if amount <= 0 {
            return Err(PoolError::BadAmount);
        }
        // A basic exit publishes `amount`, so it must use a standard
        // standard denomination — otherwise a non-denom note (e.g. a withdraw_change
        // remainder) could be basic-withdrawn, fingerprinting the boundary and
        // re-linking deposit->...->withdraw. Non-denom value must exit via
        // withdraw_with_change (which re-denominates). Matches withdraw_with_change.
        require_denom(&env, amount)?;
        canonical(&env, &asset_id)?;
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        // Reject a caller-supplied index beyond the current tree frontier.
        let next_index: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        if current_index > next_index {
            return Err(PoolError::BadAmount);
        }
        let reserve: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Reserve(asset_id.clone()))
            .ok_or(PoolError::NoReserve)?;

        outstanding_add(&env, &asset_id, -amount)?;
        let tag = recipient_tag_of(&env, &recipient);
        let pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            asset_id.clone(),
            i128_to_be32(&env, amount),
            tag,
            u64_to_be32(&env, current_index),
        ];
        verify(&env, &DataKey::WithdrawVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        // The recipient gets `amount - fee`; the treasury receives the fee.
        // The proof attests the spent note value = amount; splitting the payout is a
        // protocol policy the proof does not constrain. The public payout is the
        // fee base, consistent with `withdraw_with_change`.
        let (_bps, treasury) = protocol_fee_cfg(&env);
        let fee: i128 = protocol_fee_on(&env, amount)?;
        let here = env.current_contract_address();
        let tok = token::TokenClient::new(&env, &reserve);
        tok.transfer(&here, &recipient, &(amount - fee));
        if fee > 0 {
            tok.transfer(&here, &treasury.unwrap(), &fee);
        }
        enforce_asset_solvency(&env, &asset_id)?;
        emit_withdraw(&env, &nf, amount, fee);
        Ok(())
    }

    /// WITHDRAW-WITH-CHANGE — spend one full note and split it at the
    /// boundary: pay `amount_out` using a standard denomination of real
    /// `asset_id` to `recipient`, send `fee` to the treasury, and append a fresh
    /// shielded CHANGE note (`change_cm`) for the remainder. The circuit enforces
    /// value conservation inputAmount = amount_out + fee + change, with the fee
    /// charged IN-CIRCUIT; the contract validates `fee` matches policy and never
    /// deducts again (recipient gets the full denomination). The shielded effect
    /// (one nullifier spent + one commitment appended) is emitted as a `transfer`
    /// event so the existing indexer/scanner discovers the change note unchanged.
    /// Public-input order: [anchor_root, nf, asset_id, amount_out, fee,
    ///   recipient_tag, current_index, old_root, start_index, new_root, change_cm].
    pub fn withdraw_with_change(
        env: Env,
        recipient: Address,
        asset_id: BytesN<32>,
        amount_out: i128,
        fee: i128,
        anchor_root: BytesN<32>,
        nf: BytesN<32>,
        current_index: u64,
        new_root: BytesN<32>,
        change_cm: BytesN<32>,
        proof: Bytes,
        change_ct: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if amount_out <= 0 || fee < 0 {
            return Err(PoolError::BadAmount);
        }
        if change_ct.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        // The public payout must use a standard denomination.
        require_denom(&env, amount_out)?;
        canonical(&env, &asset_id)?;
        canonical(&env, &anchor_root)?;
        canonical(&env, &nf)?;
        canonical(&env, &new_root)?;
        canonical(&env, &change_cm)?;
        if !ring_contains(&env, &anchor_root) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
            return Err(PoolError::DoubleSpend);
        }
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        // The supplied index cannot exceed the current tree frontier.
        if current_index > idx {
            return Err(PoolError::BadAmount);
        }
        // Only the public payout and fee exit; the change note keeps the
        // hidden remainder shielded. (Reverts with the tx if the proof fails below.)
        let exiting = amount_out.checked_add(fee).ok_or(PoolError::BadAmount)?;
        outstanding_add(&env, &asset_id, -exiting)?;
        // The fee must match protocol policy; the recipient gets the full
        // denomination, treasury gets the fee, the change note holds the rest).
        // `amount_out` is the fee base, matching `withdraw`.
        let (_bps, treasury) = protocol_fee_cfg(&env);
        let expected_fee: i128 = protocol_fee_on(&env, amount_out)?;
        if fee != expected_fee {
            return Err(PoolError::BadAmount);
        }
        let reserve: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Reserve(asset_id.clone()))
            .ok_or(PoolError::NoReserve)?;

        let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let tag = recipient_tag_of(&env, &recipient);
        let pi: Vec<BytesN<32>> = vec![
            &env,
            anchor_root,
            nf.clone(),
            asset_id.clone(),
            i128_to_be32(&env, amount_out),
            i128_to_be32(&env, fee),
            tag,
            u64_to_be32(&env, current_index),
            old_root,
            u64_to_be32(&env, idx),
            new_root.clone(),
            change_cm.clone(),
        ];
        verify(&env, &DataKey::WithdrawChangeVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf);
        emit_nullifier_spent(&env, &nf);
        advance_root(&env, &new_root, idx);
        let here = env.current_contract_address();
        let tok = token::TokenClient::new(&env, &reserve);
        tok.transfer(&here, &recipient, &amount_out);
        if fee > 0 {
            tok.transfer(&here, &treasury.unwrap(), &fee);
        }
        enforce_asset_solvency(&env, &asset_id)?;
        // shielded side = a transfer-shaped append (existing scanner discovers it)
        emit_transfer(&env, &change_cm, idx, &nf, &change_ct);
        Ok(())
    }

    /// Display-only view of the legacy single-pair X/Y accounting slot. This is
    /// not custody and is not used for route pricing or solvency. Consumers must
    /// read token balances for true per-asset custody.
    pub fn reserves(env: Env) -> (i128, i128) {
        (
            env.storage().instance().get(&DataKey::ReserveX).unwrap_or(0),
            env.storage().instance().get(&DataKey::ReserveY).unwrap_or(0),
        )
    }

    /// NET-ROUTE: execute the batch's net imbalance on an external public AMM
    /// (Soroswap-compatible). Only the NET (one trade) touches the public AMM —
    /// individual order amounts stay hidden in the batch. Pushes `amount_in` of
    /// `token_in` to the AMM (a contract auto-authorizes moving its own funds),
    /// then calls the AMM swap; the output returns to this pool. Returns
    /// amount_out. This manual entrypoint is admin-gated; batch settlement uses
    /// the configured automatic route.
    pub fn route_net(
        env: Env,
        amm: Address,
        token_in: Address,
        amount_in: i128,
        min_out: i128,
    ) -> Result<i128, PoolError> {
        require_admin(&env)?;
        if amount_in <= 0 {
            return Err(PoolError::BadAmount);
        }
        // Only the admin-configured route may receive pool funds.
        let allowed: Address = env
            .storage()
            .instance()
            .get(&DataKey::RoutePair)
            .ok_or(PoolError::NoVerifier)?;
        if amm != allowed {
            return Err(PoolError::BadAnchorRoot);
        }
        let here = env.current_contract_address();
        // push the net input to the AMM (auto-authorized: own funds)
        token::TokenClient::new(&env, &token_in).transfer(&here, &amm, &amount_in);
        // call amm.swap(token_in, amount_in, min_out, to = this pool) -> i128
        let args: Vec<Val> = vec![
            &env,
            token_in.into_val(&env),
            amount_in.into_val(&env),
            min_out.into_val(&env),
            here.into_val(&env),
        ];
        let out: i128 = env.invoke_contract(&amm, &Symbol::new(&env, "swap"), args);
        // Reject a nonpositive AMM output.
        if out <= 0 {
            return Err(PoolError::BadAmount);
        }
        // Do not emit an amount-bearing route event. Publishing
        // (token_in, amount_in, out) would hand observers the exact net routed to the
        // venue in cleartext; nothing consumes this event, and the value is at most
        // inferrable from reserve deltas — we don't broadcast it for free.
        Ok(out)
    }

    /// NET-ROUTE through a Soroswap pair using its low-level swap interface. Reads the
    /// pair's reserves, computes the 0.3%-fee output, pushes `amount_in` of
    /// `token_in` to the pair, and calls its `swap(amount_0_out, amount_1_out, to)`
    /// so the output returns to this pool. Only the net touches the public pair.
    pub fn route_net_pair(
        env: Env,
        pair: Address,
        token_in: Address,
        amount_in: i128,
    ) -> Result<i128, PoolError> {
        require_admin(&env)?;
        if amount_in <= 0 {
            return Err(PoolError::BadAmount);
        }
        // This ABI-compatible manual rebalance has no automated floor. Automatic
        // settlement uses the proof-derived slippage guard.
        let out = do_route_pair_checked(&env, &pair, &token_in, amount_in, 0)?;
        if out <= 0 {
            return Err(PoolError::BadAmount);
        }
        Ok(out)
    }

    /// Admin: configure the Soroswap pair + its two token SACs that settle_batch
    /// auto-routes the batch net through.
    pub fn set_route(env: Env, pair: Address, token_x: Address, token_y: Address) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::RoutePair, &pair);
        env.storage().instance().set(&DataKey::RouteTokenX, &token_x);
        env.storage().instance().set(&DataKey::RouteTokenY, &token_y);
        Ok(())
    }

    /// SETTLE one batch (1 buy + 1 sell) in a single aggregate proof. Verifies the
    /// clearing + both spends (nullifiers) + both output-note appends, then burns
    /// the nullifiers, advances the commitment root, and updates the AMM reserves.
    /// A confidential swap moves no real tokens; spent notes and output notes net
    /// against the reserve shift, so this is a pure state update.
    /// Public-input order: [anchorRoot, oldRoot, startIndex, newRoot, nfBuy, nfSell,
    ///   cmOutBuy, cmOutSell, x, y, p, x2, y2, assetX, assetY].
    pub fn settle_batch(
        env: Env,
        new_root: BytesN<32>,
        nf_buy: BytesN<32>,
        nf_sell: BytesN<32>,
        cm_out_buy: BytesN<32>,
        cm_out_sell: BytesN<32>,
        p: i128,
        x2: i128,
        y2: i128,
        proof: Bytes,
        ct_buy: Bytes,
        ct_sell: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if ct_buy.len() > NOTE_CT_MAX || ct_sell.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &new_root)?;
        canonical(&env, &nf_buy)?;
        canonical(&env, &nf_sell)?;
        canonical(&env, &cm_out_buy)?;
        canonical(&env, &cm_out_sell)?;
        if p <= 0 || x2 <= 0 || y2 <= 0 {
            return Err(PoolError::BadAmount);
        }
        if nf_buy == nf_sell {
            return Err(PoolError::DoubleSpend);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf_buy.clone()))
            || env.storage().persistent().has(&DataKey::Nullifier(nf_sell.clone()))
        {
            return Err(PoolError::DoubleSpend);
        }

        let cm_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        // This legacy path anchors spends to the current root. Reject it whenever
        // a positive dwell floor is configured.
        if !dwell_ok(&env, &cm_root, idx) {
            return Err(PoolError::DwellNotMet);
        }
        let (rx, ry) = current_reserves(&env);
        let px: BytesN<32> = env.storage().instance().get(&DataKey::PairX).ok_or(PoolError::NoReserve)?;
        let py: BytesN<32> = env.storage().instance().get(&DataKey::PairY).ok_or(PoolError::NoReserve)?;

        let pi: Vec<BytesN<32>> = vec![
            &env,
            cm_root.clone(),              // anchorRoot
            cm_root,                      // oldRoot (append base)
            u64_to_be32(&env, idx),       // startIndex
            new_root.clone(),
            nf_buy.clone(),
            nf_sell.clone(),
            cm_out_buy.clone(),
            cm_out_sell.clone(),
            i128_to_be32(&env, rx),       // x
            i128_to_be32(&env, ry),       // y
            i128_to_be32(&env, p),
            i128_to_be32(&env, x2),
            i128_to_be32(&env, y2),
            px,
            py,
        ];
        verify(&env, &DataKey::BatchVerifier, &proof, pi)?;

        mark_nullifier_spent(&env, &nf_buy);
        mark_nullifier_spent(&env, &nf_sell);
        emit_nullifier_spent(&env, &nf_buy);
        emit_nullifier_spent(&env, &nf_sell);
        // two output notes appended at idx, idx+1
        let next_idx = idx.checked_add(2).ok_or(PoolError::BadAmount)?;
        env.storage().instance().set(&DataKey::CmRoot, &new_root);
        env.storage().instance().set(&DataKey::NextIndex, &next_idx);
        ring_push(&env, &new_root, next_idx);
        env.storage().instance().set(&DataKey::ReserveX, &x2);
        env.storage().instance().set(&DataKey::ReserveY, &y2);
        settle_outstanding_move(&env, rx, ry, x2, y2)?;

        // AUTO-ROUTE the batch net through the configured Soroswap pair (if set):
        // the batch shifted reserves rx->x2 / ry->y2; route the surplus side to the
        // public pool so the net executes on real external liquidity. Only the net
        // (one trade) touches Soroswap.
        // Auto-route the batch net through the configured pair, slippage-guarded
        // against the proven (rx,ry) snapshot — reverts the settle if the live route drifts.
        auto_route(&env, rx, ry, x2, y2)?;
        enforce_configured_pair_solvency(&env)?;

        emit_settle(&env, &nf_buy, &nf_sell, &cm_out_buy, &cm_out_sell, idx, &ct_buy, &ct_sell);
        Ok(())
    }

    /// Non-custodial batch swap. Verifies two client `order_spend` proofs
    /// and one
    /// keyless `clearing` proof, and CROSS-BINDS them: each `order_commit_*` is fed
    /// into both its order proof AND the clearing proof, so the keyless clearing can
    /// only settle orders that real owners authorized — no spend key is ever held by
    /// the contract or the sequencer. Then burns the order nullifiers, appends the
    /// two output notes, advances the root, and updates the AMM reserves. Emits the
    /// same `settle` event as the custodial path so the indexer/witness are unchanged.
    /// order_spend public: [anchorRoot, nf, orderCommit].
    /// clearing public: [oldRoot, startIndex, newRoot, cmOutBuy, cmOutSell, x, y, p,
    ///   x2, y2, assetX, assetY, orderCommitBuy, orderCommitSell].
    pub fn settle_batch_v2(
        env: Env,
        anchor_root_buy: BytesN<32>,
        nf_buy: BytesN<32>,
        order_commit_buy: BytesN<32>,
        proof_buy: Bytes,
        anchor_root_sell: BytesN<32>,
        nf_sell: BytesN<32>,
        order_commit_sell: BytesN<32>,
        proof_sell: Bytes,
        new_root: BytesN<32>,
        cm_out_buy: BytesN<32>,
        cm_out_sell: BytesN<32>,
        p: i128,
        x2: i128,
        y2: i128,
        clearing_proof: Bytes,
        ct_buy: Bytes,
        ct_sell: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        if ct_buy.len() > NOTE_CT_MAX || ct_sell.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        canonical(&env, &anchor_root_buy)?;
        canonical(&env, &nf_buy)?;
        canonical(&env, &order_commit_buy)?;
        canonical(&env, &anchor_root_sell)?;
        canonical(&env, &nf_sell)?;
        canonical(&env, &order_commit_sell)?;
        canonical(&env, &new_root)?;
        canonical(&env, &cm_out_buy)?;
        canonical(&env, &cm_out_sell)?;
        if p <= 0 || x2 <= 0 || y2 <= 0 {
            return Err(PoolError::BadAmount);
        }
        if nf_buy == nf_sell {
            return Err(PoolError::DoubleSpend);
        }
        if !ring_contains(&env, &anchor_root_buy) || !ring_contains(&env, &anchor_root_sell) {
            return Err(PoolError::BadAnchorRoot);
        }
        if env.storage().persistent().has(&DataKey::Nullifier(nf_buy.clone()))
            || env.storage().persistent().has(&DataKey::Nullifier(nf_sell.clone()))
        {
            return Err(PoolError::DoubleSpend);
        }

        let cm_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        let (rx, ry) = current_reserves(&env);
        let px: BytesN<32> = env.storage().instance().get(&DataKey::PairX).ok_or(PoolError::NoReserve)?;
        let py: BytesN<32> = env.storage().instance().get(&DataKey::PairY).ok_or(PoolError::NoReserve)?;

        // privacy dwell: the buyer's spent note must have aged >= min_dwell appends
        // behind the current frontier (the MM/sell leg is protocol-internal & exempt).
        if !dwell_ok(&env, &anchor_root_buy, idx) {
            return Err(PoolError::DwellNotMet);
        }

        // 1. each client order_spend proof authorizes spending one note + commits to
        //    its order. order_commit_* is reused in the clearing proof below — that
        //    shared value is the cross-binding.
        let pi_buy: Vec<BytesN<32>> = vec![&env, anchor_root_buy, nf_buy.clone(), order_commit_buy.clone()];
        verify(&env, &DataKey::OrderSpendVerifier, &proof_buy, pi_buy)?;
        let pi_sell: Vec<BytesN<32>> = vec![&env, anchor_root_sell, nf_sell.clone(), order_commit_sell.clone()];
        verify(&env, &DataKey::OrderSpendVerifier, &proof_sell, pi_sell)?;

        // 2. the keyless clearing proof: oldRoot/startIndex/x/y/assets come from
        //    contract state; orderCommitBuy/Sell must equal the order proofs' values.
        let pi_clear: Vec<BytesN<32>> = vec![
            &env,
            cm_root.clone(),          // oldRoot
            u64_to_be32(&env, idx),   // startIndex
            new_root.clone(),
            cm_out_buy.clone(),
            cm_out_sell.clone(),
            i128_to_be32(&env, rx),   // x
            i128_to_be32(&env, ry),   // y
            i128_to_be32(&env, p),
            i128_to_be32(&env, x2),
            i128_to_be32(&env, y2),
            px,                       // assetX
            py,                       // assetY
            order_commit_buy,         // == buyer order proof's orderCommit
            order_commit_sell,        // == seller order proof's orderCommit
        ];
        verify(&env, &DataKey::ClearingVerifier, &clearing_proof, pi_clear)?;

        // 3. commit: burn nullifiers, append two output notes, advance root, set reserves
        mark_nullifier_spent(&env, &nf_buy);
        mark_nullifier_spent(&env, &nf_sell);
        emit_nullifier_spent(&env, &nf_buy);
        emit_nullifier_spent(&env, &nf_sell);
        let next_idx = idx.checked_add(2).ok_or(PoolError::BadAmount)?;
        env.storage().instance().set(&DataKey::CmRoot, &new_root);
        env.storage().instance().set(&DataKey::NextIndex, &next_idx);
        ring_push(&env, &new_root, next_idx);
        env.storage().instance().set(&DataKey::ReserveX, &x2);
        env.storage().instance().set(&DataKey::ReserveY, &y2);
        settle_outstanding_move(&env, rx, ry, x2, y2)?;

        // auto-route the net through the configured Soroswap pair (same as settle_batch)
        // Auto-route the batch net through the configured pair, slippage-guarded
        // against the proven (rx,ry) snapshot — reverts the settle if the live route drifts.
        auto_route(&env, rx, ry, x2, y2)?;
        enforce_configured_pair_solvency(&env)?;

        // reuse the `settle` event so the existing indexer/witness pick up both outputs
        emit_settle(&env, &nf_buy, &nf_sell, &cm_out_buy, &cm_out_sell, idx, &ct_buy, &ct_sell);
        Ok(())
    }

    /// Multi-user non-custodial batch: N buyer order_spend proofs and one MM
    /// sell order_spend + 1 keyless N-buyer clearing, cross-bound via orderCommit.
    /// Several real users buying the same pair settle in one tx (bigger anonymity
    /// set). Each output is emitted as a `transfer` event so the existing indexer/
    /// witness append every leaf + record every nullifier with no decoder change.
    /// clearing public: [oldRoot, startIndex, newRoot, x, y, p, x2, y2, assetX,
    ///   assetY, cmOutBuy[N], cmOutSell, orderCommitBuy[N], orderCommitSell].
    pub fn settle_batch_vn(
        env: Env,
        anchor_roots_buy: Vec<BytesN<32>>,
        nfs_buy: Vec<BytesN<32>>,
        order_commits_buy: Vec<BytesN<32>>,
        proofs_buy: Vec<Bytes>,
        anchor_root_sell: BytesN<32>,
        nf_sell: BytesN<32>,
        order_commit_sell: BytesN<32>,
        proof_sell: Bytes,
        new_root: BytesN<32>,
        cm_outs_buy: Vec<BytesN<32>>,
        cm_out_sell: BytesN<32>,
        p: i128,
        x2: i128,
        y2: i128,
        clearing_proof: Bytes,
        cts_buy: Vec<Bytes>,
        ct_sell: Bytes,
    ) -> Result<(), PoolError> {
        require_init(&env)?;
        let n = cm_outs_buy.len();
        if n == 0
            || anchor_roots_buy.len() != n
            || nfs_buy.len() != n
            || order_commits_buy.len() != n
            || proofs_buy.len() != n
            || cts_buy.len() != n
        {
            return Err(PoolError::BadAmount);
        }
        if ct_sell.len() > NOTE_CT_MAX {
            return Err(PoolError::CtTooLong);
        }
        if p <= 0 || x2 <= 0 || y2 <= 0 {
            return Err(PoolError::BadAmount);
        }
        canonical(&env, &new_root)?;
        canonical(&env, &cm_out_sell)?;
        canonical(&env, &nf_sell)?;
        canonical(&env, &order_commit_sell)?;
        canonical(&env, &anchor_root_sell)?;
        if !ring_contains(&env, &anchor_root_sell) {
            return Err(PoolError::BadAnchorRoot);
        }

        // collect all nullifiers (buys + sell); validate canonical/ring/ct + fresh + distinct
        let mut all_nf: Vec<BytesN<32>> = Vec::new(&env);
        for i in 0..n {
            let ar = anchor_roots_buy.get(i).unwrap();
            let nf = nfs_buy.get(i).unwrap();
            canonical(&env, &ar)?;
            canonical(&env, &nf)?;
            canonical(&env, &order_commits_buy.get(i).unwrap())?;
            canonical(&env, &cm_outs_buy.get(i).unwrap())?;
            if cts_buy.get(i).unwrap().len() > NOTE_CT_MAX {
                return Err(PoolError::CtTooLong);
            }
            if !ring_contains(&env, &ar) {
                return Err(PoolError::BadAnchorRoot);
            }
            all_nf.push_back(nf);
        }
        all_nf.push_back(nf_sell.clone());
        for i in 0..all_nf.len() {
            let nf = all_nf.get(i).unwrap();
            if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
                return Err(PoolError::DoubleSpend);
            }
            for j in (i + 1)..all_nf.len() {
                if all_nf.get(j).unwrap() == nf {
                    return Err(PoolError::DoubleSpend);
                }
            }
        }

        let cm_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
        let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
        let (rx, ry) = current_reserves(&env);
        let px: BytesN<32> = env.storage().instance().get(&DataKey::PairX).ok_or(PoolError::NoReserve)?;
        let py: BytesN<32> = env.storage().instance().get(&DataKey::PairY).ok_or(PoolError::NoReserve)?;

        // 1. each buyer's order_spend proof; orderCommit reused in the clearing (bind).
        //    privacy dwell: each buyer's note must have aged >= min_dwell appends
        //    (the MM/sell leg is protocol-internal & exempt).
        for i in 0..n {
            if !dwell_ok(&env, &anchor_roots_buy.get(i).unwrap(), idx) {
                return Err(PoolError::DwellNotMet);
            }
            let pi: Vec<BytesN<32>> = vec![&env, anchor_roots_buy.get(i).unwrap(), nfs_buy.get(i).unwrap(), order_commits_buy.get(i).unwrap()];
            verify(&env, &DataKey::OrderSpendVerifier, &proofs_buy.get(i).unwrap(), pi)?;
        }
        // 2. the MM sell order_spend
        let pi_sell: Vec<BytesN<32>> = vec![&env, anchor_root_sell, nf_sell.clone(), order_commit_sell.clone()];
        verify(&env, &DataKey::OrderSpendVerifier, &proof_sell, pi_sell)?;

        // 3. The keyless N-buyer clearing; orderCommits equal the order proofs'
        let mut pi: Vec<BytesN<32>> = vec![
            &env,
            cm_root.clone(),
            u64_to_be32(&env, idx),
            new_root.clone(),
            i128_to_be32(&env, rx),
            i128_to_be32(&env, ry),
            i128_to_be32(&env, p),
            i128_to_be32(&env, x2),
            i128_to_be32(&env, y2),
            px,
            py,
        ];
        for i in 0..n {
            pi.push_back(cm_outs_buy.get(i).unwrap());
        }
        pi.push_back(cm_out_sell.clone());
        for i in 0..n {
            pi.push_back(order_commits_buy.get(i).unwrap());
        }
        pi.push_back(order_commit_sell.clone());
        verify(&env, &DataKey::ClearingNbuyVerifier, &clearing_proof, pi)?;

        // 4. commit: burn nullifiers, append n+1 outputs, advance root, set reserves
        for i in 0..all_nf.len() {
            let nf = all_nf.get(i).unwrap();
            mark_nullifier_spent(&env, &nf);
            emit_nullifier_spent(&env, &nf);
        }
        // Append `n` buyer outputs and one seller output with checked arithmetic.
        let next_idx = idx
            .checked_add(n as u64)
            .and_then(|v| v.checked_add(1))
            .ok_or(PoolError::BadAmount)?;
        env.storage().instance().set(&DataKey::CmRoot, &new_root);
        env.storage().instance().set(&DataKey::NextIndex, &next_idx);
        ring_push(&env, &new_root, next_idx);
        env.storage().instance().set(&DataKey::ReserveX, &x2);
        env.storage().instance().set(&DataKey::ReserveY, &y2);
        settle_outstanding_move(&env, rx, ry, x2, y2)?;

        // Auto-route the batch net through the configured pair, slippage-guarded
        // against the proven (rx,ry) snapshot — reverts the settle if the live route drifts.
        auto_route(&env, rx, ry, x2, y2)?;
        enforce_configured_pair_solvency(&env)?;

        // emit each output as a `transfer` event (cm, index, nf, ct) — existing
        // indexer/witness append every leaf + record every nullifier, no change.
        for i in 0..n {
            let cm = cm_outs_buy.get(i).unwrap();
            let nf = nfs_buy.get(i).unwrap();
            let ct = cts_buy.get(i).unwrap();
            emit_transfer(&env, &cm, idx + (i as u64), &nf, &ct);
        }
        emit_transfer(&env, &cm_out_sell, idx + (n as u64), &nf_sell, &ct_sell);
        Ok(())
    }

    /// The proof-bound recipient tag for an address (sha256 of its XDR, top byte
    /// masked to stay < Fr). The prover reads this to set its public input, so JS
    /// never has to replicate the address encoding.
    pub fn recipient_tag(env: Env, recipient: Address) -> BytesN<32> {
        recipient_tag_of(&env, &recipient)
    }

    /// Permanently freeze the verifier set. After this, no
    /// set_*_verifier can repoint a verifier to a malicious always-true contract.
    /// Also freezes upgrades: otherwise a frozen verifier set could be bypassed by
    /// uploading new wasm that re-opens or swaps the verifier slots.
    pub fn freeze_verifiers(env: Env) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::VerifiersFrozen, &true);
        env.storage().instance().set(&DataKey::UpgradeFrozen, &true);
        VerifiersFrozenEvent {}.publish(&env);
        Ok(())
    }

    /// Permanently freeze upgrades. After this, the Wasm is immutable.
    pub fn freeze_upgrade(env: Env) -> Result<(), PoolError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::UpgradeFrozen, &true);
        UpgradeFrozenEvent {}.publish(&env);
        Ok(())
    }

    /// Admin: upgrade the contract Wasm. This is blocked once frozen and emits
    /// an event for public observability.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), PoolError> {
        require_admin(&env)?;
        if env.storage().instance().has(&DataKey::UpgradeFrozen) {
            return Err(PoolError::Frozen);
        }
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        UpgradeEvent { wasm_hash: new_wasm_hash }.publish(&env);
        Ok(())
    }
}

fn recipient_tag_of(env: &Env, recipient: &Address) -> BytesN<32> {
    let xdr = recipient.clone().to_xdr(env);
    let h = env.crypto().sha256(&xdr);
    let mut b = h.to_array();
    b[0] = 0; // ensure < Fr modulus
    BytesN::from_array(env, &b)
}

fn initialize_pool(env: &Env, admin: &Address, empty_root: &BytesN<32>) -> Result<(), PoolError> {
    if env.storage().instance().has(&DataKey::Admin) {
        return Err(PoolError::AlreadyInitialized);
    }
    canonical(env, empty_root)?;
    env.storage().instance().set(&DataKey::Admin, admin);
    env.storage().instance().set(&DataKey::CmRoot, empty_root);
    env.storage().instance().set(&DataKey::NextIndex, &0u64);
    env.storage().instance().set(&DataKey::Epoch, &0u64);
    // The liability counter starts exact only on a new empty tree. Existing upgraded
    // pools have no flag and therefore remain observe-only until value migrates.
    env.storage().instance().set(&DataKey::SolvencyEnforced, &true);
    let ring: Vec<BytesN<32>> = vec![env, empty_root.clone()];
    env.storage().instance().set(&DataKey::RootRing, &ring);
    Ok(())
}

fn swap_commit_impl(
    env: Env,
    anchor_root: BytesN<32>,
    nf: BytesN<32>,
    scm: BytesN<32>,
    new_root: BytesN<32>,
    proof: Bytes,
    note_ct: Bytes,
    bound: Option<(BytesN<32>, BytesN<32>, BytesN<32>)>,
) -> Result<(), PoolError> {
    require_init(&env)?;
    if note_ct.len() > NOTE_CT_MAX {
        return Err(PoolError::CtTooLong);
    }
    canonical(&env, &anchor_root)?;
    canonical(&env, &nf)?;
    canonical(&env, &scm)?;
    canonical(&env, &new_root)?;
    if let Some((ref hash, ref asset_in, ref asset_out)) = bound {
        canonical(&env, hash)?;
        canonical(&env, asset_in)?;
        canonical(&env, asset_out)?;
        if asset_in == asset_out {
            return Err(PoolError::BadAmount);
        }
        // Route metadata is now proof-bound. Requiring both tags to be registered
        // also prevents a commitment that can never be settled or claimed.
        if !env.storage().persistent().has(&DataKey::Reserve(asset_in.clone()))
            || !env.storage().persistent().has(&DataKey::Reserve(asset_out.clone()))
        {
            return Err(PoolError::NoReserve);
        }
        if env.storage().persistent().has(&DataKey::BoundCommit(scm.clone()))
            || env
                .storage()
                .persistent()
                .has(&DataKey::BoundCommitV2(scm.clone()))
        {
            return Err(PoolError::PairExists);
        }
    }
    if !ring_contains(&env, &anchor_root) {
        return Err(PoolError::BadAnchorRoot);
    }
    if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
        return Err(PoolError::DoubleSpend);
    }
    let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
    let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
    if !dwell_ok(&env, &anchor_root, idx) {
        return Err(PoolError::DwellNotMet);
    }
    // Circom exposes output signals before listed public inputs, so the bound
    // circuit's verifier order is [ctHash, anchorRoot, nf, oldRoot,
    // startIndex, newRoot, scm, assetIn, assetOut].
    let (verifier, pi): (DataKey, Vec<BytesN<32>>) = if let Some((ref hash, ref asset_in, ref asset_out)) = bound {
        (DataKey::SwapCommitBoundVerifier, vec![
            &env,
            hash.clone(),
            anchor_root.clone(),
            nf.clone(),
            old_root.clone(),
            u64_to_be32(&env, idx),
            new_root.clone(),
            scm.clone(),
            asset_in.clone(),
            asset_out.clone(),
        ])
    } else {
        (DataKey::SwapCommitVerifier, vec![
            &env,
            anchor_root.clone(),
            nf.clone(),
            old_root.clone(),
            u64_to_be32(&env, idx),
            new_root.clone(),
            scm.clone(),
        ])
    };
    verify(&env, &verifier, &proof, pi)?;
    mark_nullifier_spent(&env, &nf);
    emit_nullifier_spent(&env, &nf);
    advance_root(&env, &new_root, idx);
    if let Some((hash, asset_in, asset_out)) = bound {
        let key = DataKey::BoundCommit(scm.clone());
        env.storage().persistent().set(&key, &BoundCommit {
            ct_hash: hash.clone(),
            asset_in: asset_in.clone(),
            asset_out: asset_out.clone(),
        });
        env.storage().persistent().extend_ttl(&key, TTL_THRESH, TTL_BUMP);
        emit_bound_swap_commit(&env, &scm, idx, &note_ct, &hash, &asset_in, &asset_out);
    } else {
        emit_swap_commit(&env, &scm, idx, &note_ct);
    }
    Ok(())
}

fn validate_batch_out(
    env: &Env,
    batch_id: &BytesN<32>,
    asset_in: &BytesN<32>,
    asset_out: &BytesN<32>,
    sum_in: i128,
    sum_out: i128,
    swap_root: &BytesN<32>,
    k: u32,
    fee_bps: u32,
    fee_asset: &Address,
) -> Result<(), PoolError> {
    if sum_in <= 0 || sum_out < 0 || k == 0 {
        return Err(PoolError::BadAmount);
    }
    canonical(env, batch_id)?;
    canonical(env, asset_in)?;
    canonical(env, asset_out)?;
    canonical(env, swap_root)?;
    if asset_in == asset_out {
        return Err(PoolError::BadAmount);
    }
    let _input_sac: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Reserve(asset_in.clone()))
        .ok_or(PoolError::NoReserve)?;
    let output_sac: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Reserve(asset_out.clone()))
        .ok_or(PoolError::NoReserve)?;
    if env.storage().persistent().has(&DataKey::BatchOut(batch_id.clone()))
        || env.storage().persistent().has(&DataKey::BatchCap(batch_id.clone()))
        || env.storage().persistent().has(&DataKey::BatchV2(batch_id.clone()))
    {
        return Err(PoolError::PairExists);
    }
    let fee = venue_swap_fee_on(sum_out, fee_bps)?;
    if fee > 0 {
        let (_, treasury) = protocol_fee_cfg(env);
        if treasury.is_none() || output_sac != *fee_asset {
            return Err(PoolError::BadAmount);
        }
    }
    Ok(())
}

fn record_batch_out(
    env: &Env,
    batch_id: BytesN<32>,
    asset_in: BytesN<32>,
    asset_out: BytesN<32>,
    sum_in: i128,
    sum_out: i128,
    swap_root: BytesN<32>,
    k: u32,
    fee_bps: u32,
    fee_asset: Address,
    mobile_v2: bool,
) -> Result<i128, PoolError> {
    validate_batch_out(
        env,
        &batch_id,
        &asset_in,
        &asset_out,
        sum_in,
        sum_out,
        &swap_root,
        k,
        fee_bps,
        &fee_asset,
    )?;
    let fee = venue_swap_fee_on(sum_out, fee_bps)?;
    let net_sum_out = sum_out.checked_sub(fee).ok_or(PoolError::BadAmount)?;
    if fee > 0 {
        accrue_swap_fee(env, &fee_asset, fee)?;
    }
    // The committed input notes become an output-asset batch liability at execution
    // time. Claims only materialize that already-accounted liability as note leaves.
    outstanding_add(env, &asset_in, -sum_in)?;
    outstanding_add(env, &asset_out, net_sum_out)?;
    enforce_asset_solvency(env, &asset_in)?;
    enforce_asset_solvency(env, &asset_out)?;
    let bod = BatchOut {
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
        sum_in,
        sum_out: net_sum_out,
        swap_root: swap_root.clone(),
    };
    bump_instance(env);
    let cap = BatchCap { k, claimed: 0 };
    if mobile_v2 {
        let key = DataKey::BatchV2(batch_id.clone());
        env.storage().persistent().set(
            &key,
            &V2BatchRecord {
                output: bod,
                cap,
            },
        );
        env.storage().persistent().extend_ttl(
            &key,
            NULLIFIER_TTL_THRESH,
            NULLIFIER_TTL_BUMP,
        );
    } else {
        env.storage().persistent().set(&DataKey::BatchOut(batch_id.clone()), &bod);
        env.storage().persistent().set(&DataKey::BatchCap(batch_id.clone()), &cap);
        env.storage().persistent().extend_ttl(&DataKey::BatchOut(batch_id.clone()), TTL_THRESH, TTL_BUMP);
        env.storage().persistent().extend_ttl(&DataKey::BatchCap(batch_id.clone()), TTL_THRESH, TTL_BUMP);
    }
    emit_batch_executed(
        env,
        &batch_id,
        &asset_in,
        &asset_out,
        sum_in,
        net_sum_out,
        &swap_root,
        k,
        fee,
        fee_bps,
        &fee_asset,
    );
    Ok(net_sum_out)
}

// Route `amount_in` of `token_in` through a Soroswap pair (low-level swap, push
// model): read reserves, compute the 0.3%-fee output, push the input to the pair,
// call its swap so the output returns here. Returns amount_out.
// Pure UniswapV2 output math shared by live routing and the proof-derived
// slippage floor. Computes the 0.3%-fee output for `amount_in` against
// reserves (rin, rout), then under-asks by ~0.5%+1 so the pair's K check passes on the
// rounding edge. Ok(0) = dust net (nothing to route); Err(BadAmount) = bad reserves /
// arithmetic overflow (a corrupt read or pathological amount rejects instead of wrapping).
fn routed_out_checked(rin: i128, rout: i128, amount_in: i128) -> Result<i128, PoolError> {
    if amount_in <= 0 {
        return Ok(0);
    }
    // Both reserves must be positive for the constant-product calculation.
    if rin <= 0 || rout <= 0 {
        return Err(PoolError::BadAmount);
    }
    let fee_in = amount_in.checked_mul(997).ok_or(PoolError::BadAmount)?;
    let numer = rout.checked_mul(fee_in).ok_or(PoolError::BadAmount)?;
    let denom = rin
        .checked_mul(1000)
        .ok_or(PoolError::BadAmount)?
        .checked_add(fee_in)
        .ok_or(PoolError::BadAmount)?;
    if denom <= 0 {
        return Err(PoolError::BadAmount);
    }
    // Request slightly less than the canonical output to accommodate integer
    // rounding differences in external pair K checks. The retained difference
    // remains in the pair and accrues to its LPs.
    let raw_out = numer.checked_div(denom).ok_or(PoolError::BadAmount)?;
    let amount_out = raw_out
        .checked_sub(raw_out / 200)
        .ok_or(PoolError::BadAmount)?
        .checked_sub(1)
        .ok_or(PoolError::BadAmount)?;
    if amount_out <= 0 {
        return Ok(0);
    }
    Ok(amount_out)
}

// Route `amount_in` through the Soroswap pair using live reserves.
// `min_out` is a token-output slippage floor. If live reserves drift below it,
// the call returns `SlippageExceeded` and settlement rolls back atomically.
// Returns Ok(amount_out) on a routable trade, Ok(0) for a dust net, Err on bad reserves.
fn do_route_pair_checked(
    env: &Env,
    pair: &Address,
    token_in: &Address,
    amount_in: i128,
    min_out: i128,
) -> Result<i128, PoolError> {
    if amount_in <= 0 {
        return Ok(0);
    }
    let here = env.current_contract_address();
    let t0: Address = env.invoke_contract(pair, &Symbol::new(env, "token_0"), Vec::new(env));
    let (r0, r1): (i128, i128) =
        env.invoke_contract(pair, &Symbol::new(env, "get_reserves"), Vec::new(env));
    let token_in_is_0 = *token_in == t0;
    let (rin, rout) = if token_in_is_0 { (r0, r1) } else { (r1, r0) };
    let amount_out = routed_out_checked(rin, rout, amount_in)?;
    // Reject a nonpositive output before moving tokens.
    if amount_out <= 0 {
        return Ok(0);
    }
    // Enforce the slippage floor before moving tokens.
    if amount_out < min_out {
        return Err(PoolError::SlippageExceeded);
    }
    token::TokenClient::new(env, token_in).transfer(&here, pair, &amount_in);
    let (a0, a1): (i128, i128) = if token_in_is_0 { (0, amount_out) } else { (amount_out, 0) };
    let args: Vec<Val> = vec![env, a0.into_val(env), a1.into_val(env), here.into_val(env)];
    let _: () = env.invoke_contract(pair, &Symbol::new(env, "swap"), args);
    // Do not emit an amount-bearing route event; the net
    // routed to the public pair is not published in cleartext here.
    Ok(amount_out)
}

// Default automatic-route slippage tolerance is 100 basis points.
fn route_slip_bps(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::RouteSlipBps).unwrap_or(100u32)
}

// Route the batch net through the configured public pair with a slippage floor
// derived from the reserve snapshot bound by the clearing proof. Reverts the
// whole settlement with `SlippageExceeded` if the live route would pay below
// `proven_out * (1 - slip_bps)`.
//
// Only a proof-priced dust result skips routing. An unpriceable snapshot,
// unreadable live reserve, route error, or price shortfall fails closed and
// reverts the settlement.
fn route_net_guarded(
    env: &Env,
    pair: &Address,
    token_in: &Address,
    amount_in: i128,
    rin_proven: i128,
    rout_proven: i128,
    slip_bps: u32,
) -> Result<(), PoolError> {
    if amount_in <= 0 {
        return Ok(());
    }
    // An unpriceable proven snapshot returns an error. A zero output is dust.
    let expected = routed_out_checked(rin_proven, rout_proven, amount_in)?;
    if expected <= 0 {
        return Ok(());
    }
    let floor = expected - expected.saturating_mul(slip_bps as i128) / 10000;
    // Propagate every route error so settlement reverts atomically.
    let routed = do_route_pair_checked(env, pair, token_in, amount_in, floor)?;
    // A live output that rounds to dust still fails a positive floor.
    if routed < floor {
        return Err(PoolError::SlippageExceeded);
    }
    Ok(())
}

// Shared settle auto-route: route the surplus side of the batch (rx->x2 / ry->y2) to the
// configured public pair, slippage-guarded against the proven (rx,ry) snapshot the clearing
// proof bound. Called by settle_batch / settle_batch_v2 / settle_batch_vn so all three share
// one routing path. Returns Err(SlippageExceeded) to revert the settle on a drifted route.
fn auto_route(env: &Env, rx: i128, ry: i128, x2: i128, y2: i128) -> Result<(), PoolError> {
    if !env.storage().instance().has(&DataKey::RoutePair) {
        return Ok(());
    }
    let pair: Address = env.storage().instance().get(&DataKey::RoutePair).unwrap();
    let slip_bps = route_slip_bps(env);
    if x2 > rx {
        let tx: Address = env.storage().instance().get(&DataKey::RouteTokenX).unwrap();
        route_net_guarded(env, &pair, &tx, x2 - rx, rx, ry, slip_bps)?;
    } else if y2 > ry {
        let ty: Address = env.storage().instance().get(&DataKey::RouteTokenY).unwrap();
        route_net_guarded(env, &pair, &ty, y2 - ry, ry, rx, slip_bps)?;
    }
    Ok(())
}

// Shared implementation for confidential liquidity additions. A zero
// `min_shares` preserves the original entrypoint's behavior.
fn add_liquidity_confidential_impl(
    env: Env,
    from: Address,
    amount_a: i128,
    amount_b: i128,
    min_shares: i128,
    lp_cm: BytesN<32>,
    new_root: BytesN<32>,
    proof: Bytes,
    note_ct: Bytes,
    pair_id: Option<BytesN<32>>,
) -> Result<(), PoolError> {
    require_init(&env)?;
    from.require_auth();
    if amount_a <= 0 || amount_b <= 0 {
        return Err(PoolError::BadAmount);
    }
    if note_ct.len() > NOTE_CT_MAX {
        return Err(PoolError::CtTooLong);
    }
    canonical(&env, &lp_cm)?;
    canonical(&env, &new_root)?;
    // Resolve the target AMM and LP note class after authorization and input checks.
    let (amm, token_a, token_b, lp_note_tag): (Address, Address, Address, u64) = match &pair_id {
        None => (
            env.storage().instance().get(&DataKey::LpAmm).ok_or(PoolError::LpAmmNotSet)?,
            env.storage().instance().get(&DataKey::LpTokenA).ok_or(PoolError::LpAmmNotSet)?,
            env.storage().instance().get(&DataKey::LpTokenB).ok_or(PoolError::LpAmmNotSet)?,
            LP_ASSET_ID,
        ),
        Some(pid) => {
            let key = DataKey::LpPair(pid.clone());
            let cfg: LpPairCfg = env.storage().persistent().get(&key).ok_or(PoolError::LpAmmNotSet)?;
            env.storage().persistent().extend_ttl(&key, TTL_THRESH, TTL_BUMP);
            (cfg.amm, cfg.token_a, cfg.token_b, cfg.lp_note_tag)
        }
    };
    let here = env.current_contract_address();
    // Pull the provider's public contribution. The pool is the AMM's sole LP
    // of record, so all AMM shares accrue to the pool.
    // The user (`from`) authorizes these two transfers via their signed tx.
    token::TokenClient::new(&env, &token_a).transfer(&from, &here, &amount_a);
    token::TokenClient::new(&env, &token_b).transfer(&from, &here, &amount_b);
    // The AMM pulls both tokens through nested SAC calls, which require explicit
    // authorization from the pool as the current contract.
    let transfer_fn = Symbol::new(&env, "transfer");
    env.authorize_as_current_contract(vec![
        &env,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: token_a.clone(),
                fn_name: transfer_fn.clone(),
                args: vec![&env, here.into_val(&env), amm.into_val(&env), amount_a.into_val(&env)],
            },
            sub_invocations: vec![&env],
        }),
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: token_b.clone(),
                fn_name: transfer_fn,
                args: vec![&env, here.into_val(&env), amm.into_val(&env), amount_b.into_val(&env)],
            },
            sub_invocations: vec![&env],
        }),
    ]);
    let args: Vec<Val> = vec![&env, here.into_val(&env), amount_a.into_val(&env), amount_b.into_val(&env)];
    let minted: i128 = env.invoke_contract(&amm, &Symbol::new(&env, "add_liquidity"), args);
    if minted <= 0 {
        return Err(PoolError::BadAmount);
    }
    // Revert if live reserves produce fewer shares than the signed floor.
    if minted < min_shares {
        return Err(PoolError::SlippageExceeded);
    }
    // Bind the exact minted shares and pair-specific LP note class into the proof.
    // The legacy pair uses `LP_ASSET_ID`; each configured pair uses a unique tag, so the note
    // can only ever be removed against the same pair (its removal proof binds the identical tag).
    let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
    let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
    let pi: Vec<BytesN<32>> = vec![
        &env,
        u64_to_be32(&env, lp_note_tag),
        i128_to_be32(&env, minted),
        old_root,
        u64_to_be32(&env, idx),
        new_root.clone(),
        lp_cm.clone(),
    ];
    verify(&env, &DataKey::DepositVerifier, &proof, pi)?;
    advance_root(&env, &new_root, idx);
    emit_lp_add(&env, &lp_cm, idx, &note_ct);
    Ok(())
}

// Shared body for remove_liquidity_confidential{,_for}. `pair_id` selects the AMM + LP note-class:
// None = legacy singleton LpAmm (LP_ASSET_ID); Some(pid) = the per-pair LpPair(pid) config (unique tag).
// The bound note-class tag is what gives cross-pair isolation — a note minted for one pair commits to
// that pair's tag, so its removal proof can only be verified against the same pair here.
fn remove_liquidity_confidential_impl(
    env: Env,
    recipient: Address,
    shares: i128,
    min_a: i128,
    min_b: i128,
    anchor_root: BytesN<32>,
    nf: BytesN<32>,
    current_index: u64,
    proof: Bytes,
    pair_id: Option<BytesN<32>>,
) -> Result<(), PoolError> {
    require_init(&env)?;
    if shares <= 0 || min_a < 0 || min_b < 0 {
        return Err(PoolError::BadAmount);
    }
    canonical(&env, &anchor_root)?;
    canonical(&env, &nf)?;
    if !ring_contains(&env, &anchor_root) {
        return Err(PoolError::BadAnchorRoot);
    }
    if env.storage().persistent().has(&DataKey::Nullifier(nf.clone())) {
        return Err(PoolError::DoubleSpend);
    }
    // The caller-supplied index cannot exceed the current tree frontier.
    let next_index: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
    if current_index > next_index {
        return Err(PoolError::BadAmount);
    }
    let (amm, token_a, token_b, lp_note_tag): (Address, Address, Address, u64) = match &pair_id {
        None => (
            env.storage().instance().get(&DataKey::LpAmm).ok_or(PoolError::LpAmmNotSet)?,
            env.storage().instance().get(&DataKey::LpTokenA).ok_or(PoolError::LpAmmNotSet)?,
            env.storage().instance().get(&DataKey::LpTokenB).ok_or(PoolError::LpAmmNotSet)?,
            LP_ASSET_ID,
        ),
        Some(pid) => {
            let key = DataKey::LpPair(pid.clone());
            let cfg: LpPairCfg = env.storage().persistent().get(&key).ok_or(PoolError::LpAmmNotSet)?;
            env.storage().persistent().extend_ttl(&key, TTL_THRESH, TTL_BUMP);
            (cfg.amm, cfg.token_a, cfg.token_b, cfg.lp_note_tag)
        }
    };

    // The proof attests ownership of an LP note committing to `shares` under this pair's note-class tag
    // (bound to `recipient`). A note from a different pair commits to a different tag -> verify fails-closed.
    let tag = recipient_tag_of(&env, &recipient);
    let pi: Vec<BytesN<32>> = vec![
        &env,
        anchor_root,
        nf.clone(),
        u64_to_be32(&env, lp_note_tag),
        i128_to_be32(&env, shares),
        tag,
        u64_to_be32(&env, current_index),
    ];
    verify(&env, &DataKey::WithdrawVerifier, &proof, pi)?;

    mark_nullifier_spent(&env, &nf);
    emit_nullifier_spent(&env, &nf);

    // The pool (AMM's sole confidential LP-of-record) burns `shares` and receives the pro-rata reserves
    // (the AMM PUSHES them to the pool — its own funds — so no authorize_as_current_contract is needed),
    // then forwards both tokens to the recipient.
    let here = env.current_contract_address();
    let (remove_fn, args): (Symbol, Vec<Val>) = if min_a > 0 || min_b > 0 {
        (
            Symbol::new(&env, "remove_liquidity_min"),
            vec![
                &env,
                here.into_val(&env),
                shares.into_val(&env),
                min_a.into_val(&env),
                min_b.into_val(&env),
            ],
        )
    } else {
        (
            Symbol::new(&env, "remove_liquidity"),
            vec![&env, here.into_val(&env), shares.into_val(&env)],
        )
    };
    let (out_a, out_b): (i128, i128) = env.invoke_contract(&amm, &remove_fn, args);
    if out_a <= 0 || out_b <= 0 {
        return Err(PoolError::BadAmount);
    }
    if out_a < min_a || out_b < min_b {
        return Err(PoolError::SlippageExceeded);
    }
    token::TokenClient::new(&env, &token_a).transfer(&here, &recipient, &out_a);
    token::TokenClient::new(&env, &token_b).transfer(&here, &recipient, &out_b);
    emit_lp_remove(&env, &nf, out_a, out_b);
    Ok(())
}

// Assign a new pair configuration and unique note class without repointing
// existing pairs or orphaning outstanding LP notes.
// Idempotent, bijective Reserve(asset_id) <-> ReserveAsset(SAC) writer. Re-declaring
// the same pair is a no-op; repointing either side reverts so fresh-pool liabilities
// cannot be double-counted against one token balance.
fn set_reserve_checked(env: &Env, asset: &BytesN<32>, sac: &Address) -> Result<(), PoolError> {
    if asset.clone() >= u64_to_be32(env, LP_ASSET_ID) {
        return Err(PoolError::BadAmount);
    }
    let enforced = solvency_is_enforced(env);
    let reverse_key = DataKey::ReserveAsset(sac.clone());
    if enforced {
        if let Some(existing_asset) = env.storage().persistent().get::<_, BytesN<32>>(&reverse_key) {
            if existing_asset != *asset {
                return Err(PoolError::ReserveConflict);
            }
        }
    }
    let reserve_key = DataKey::Reserve(asset.clone());
    if let Some(existing) = env.storage().persistent().get::<_, Address>(&reserve_key) {
        if existing != *sac {
            return Err(PoolError::ReserveConflict);
        }
        env.storage().persistent().extend_ttl(&reserve_key, TTL_THRESH, TTL_BUMP);
        if enforced {
            env.storage().persistent().set(&reverse_key, asset);
            env.storage().persistent().extend_ttl(&reverse_key, TTL_THRESH, TTL_BUMP);
        }
        return Ok(());
    }
    env.storage().persistent().set(&reserve_key, sac);
    env.storage().persistent().extend_ttl(&reserve_key, TTL_THRESH, TTL_BUMP);
    if enforced {
        env.storage().persistent().set(&reverse_key, asset);
        env.storage().persistent().extend_ttl(&reverse_key, TTL_THRESH, TTL_BUMP);
    }
    Ok(())
}

fn wire_lp_pair(
    env: &Env,
    pair_id: &BytesN<32>,
    amm: &Address,
    token_a: &Address,
    token_b: &Address,
    tag_a: u64,
    tag_b: u64,
) -> Result<u64, PoolError> {
    if env.storage().persistent().has(&DataKey::LpPair(pair_id.clone())) {
        return Err(PoolError::PairExists);
    }
    let lp_note_tag: u64 = env.storage().instance().get(&DataKey::NextLpTag).unwrap_or(LP_TAG_BASE);
    let cfg = LpPairCfg {
        amm: amm.clone(),
        token_a: token_a.clone(),
        token_b: token_b.clone(),
        tag_a,
        tag_b,
        lp_note_tag,
    };
    let pair_key = DataKey::LpPair(pair_id.clone());
    env.storage().persistent().set(&pair_key, &cfg);
    env.storage().persistent().extend_ttl(&pair_key, TTL_THRESH, TTL_BUMP);
    env.storage().instance().set(&DataKey::NextLpTag, &(lp_note_tag + 1));
    let mut list: Vec<BytesN<32>> = env.storage().instance().get(&DataKey::LpPairList).unwrap_or(Vec::new(env));
    list.push_back(pair_id.clone());
    env.storage().instance().set(&DataKey::LpPairList, &list);
    emit_pair_created(env, pair_id, lp_note_tag);
    Ok(lp_note_tag)
}

// Extend the instance entry that contains configuration and tree state.
fn bump_instance(env: &Env) {
    env.storage().instance().extend_ttl(TTL_THRESH, TTL_BUMP);
}

// Each nullifier must remain live for as long as the pool may accept its note's
// anchor. Unlike instance storage, persistent entries are not renewed by writes
// elsewhere, so every spend goes through this one long-lived write path.
fn mark_nullifier_spent(env: &Env, nf: &BytesN<32>) {
    let key = DataKey::Nullifier(nf.clone());
    env.storage().persistent().set(&key, &());
    env.storage()
        .persistent()
        .extend_ttl(&key, NULLIFIER_TTL_THRESH, NULLIFIER_TTL_BUMP);
}

fn renew_nullifier_ttl(env: &Env, nf: &BytesN<32>) -> bool {
    let key = DataKey::Nullifier(nf.clone());
    if !env.storage().persistent().has(&key) {
        return false;
    }
    env.storage()
        .persistent()
        .extend_ttl(&key, NULLIFIER_TTL_THRESH, NULLIFIER_TTL_BUMP);
    true
}

fn advance_root(env: &Env, new_root: &BytesN<32>, idx: u64) {
    bump_instance(env);
    env.storage().instance().set(&DataKey::CmRoot, new_root);
    env.storage().instance().set(&DataKey::NextIndex, &(idx + 1));
    ring_push(env, new_root, idx + 1);
}

// Push a new root and its frontier onto the parallel recent-root rings,
// trimming both to `RING_SIZE`. The frontier ring
// is append-only and was added in a later upgrade: roots that predate it have no
// entry and read back as DWELL_LEGACY (dwell-lenient) via ring_frontier.
fn ring_push(env: &Env, new_root: &BytesN<32>, frontier: u64) {
    let mut ring: Vec<BytesN<32>> = env.storage().instance().get(&DataKey::RootRing).unwrap_or(Vec::new(env));
    let mut idxr: Vec<u64> = env.storage().instance().get(&DataKey::RootIdxRing).unwrap_or(Vec::new(env));
    ring.push_back(new_root.clone());
    idxr.push_back(frontier);
    while ring.len() > RING_SIZE {
        ring.remove(0);
    }
    while idxr.len() > RING_SIZE {
        idxr.remove(0);
    }
    // RootIdxRing is append-only and may trail RootRing by
    // exactly the number of legacy front roots that predate it. It must never
    // run ahead of RootRing because the frontier offset would underflow,
    // silently corrupting the dwell window. A corrupted ring must fail closed instead of
    // quietly mis-anchor swaps, so we assert the invariant before persisting.
    if idxr.len() > ring.len() {
        panic!("ring parity violation: RootIdxRing longer than RootRing");
    }
    env.storage().instance().set(&DataKey::RootRing, &ring);
    env.storage().instance().set(&DataKey::RootIdxRing, &idxr);
}

fn ring_contains(env: &Env, root: &BytesN<32>) -> bool {
    let ring: Vec<BytesN<32>> = env
        .storage()
        .instance()
        .get(&DataKey::RootRing)
        .unwrap_or(Vec::new(env));
    ring.iter().any(|r| &r == root)
}

// Frontier (NextIndex when created) of a ring root, or DWELL_LEGACY if the root
// predates RootIdxRing. RootIdxRing trails RootRing only by legacy front entries
// (it starts empty on the dwell upgrade and is trimmed in lockstep thereafter), so a
// root at ring position i maps to idx position i-offset.
fn ring_frontier(env: &Env, root: &BytesN<32>) -> u64 {
    let ring: Vec<BytesN<32>> = env.storage().instance().get(&DataKey::RootRing).unwrap_or(Vec::new(env));
    let idxr: Vec<u64> = env.storage().instance().get(&DataKey::RootIdxRing).unwrap_or(Vec::new(env));
    // The invariant is `idxr.len() <= ring.len()`; `ring_push` panics if
    // violated. If corrupted state is read anyway, an unsigned
    // `ring.len() - idxr.len()` would underflow — wrapping to a huge offset that makes
    // every root read as DWELL_LEGACY and silently bypass the floor,
    // or panicking under overflow-checks. saturating_sub clamps offset to 0 so frontiers
    // still resolve against the over-long index ring and dwell remains enforced.
    let offset = ring.len().saturating_sub(idxr.len());
    let mut i = 0u32;
    while i < ring.len() {
        if ring.get(i).unwrap() == *root {
            if i < offset {
                return DWELL_LEGACY;
            }
            return idxr.get(i - offset).unwrap_or(DWELL_LEGACY);
        }
        i += 1;
    }
    DWELL_LEGACY
}

fn min_dwell(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::MinDwell).unwrap_or(0)
}

// Privacy dwell: a swap may only spend a note whose anchor root is at least
// `min_dwell` appends behind the current frontier — i.e. the spent note has been
// buried under >= min_dwell newer leaves before it can be traded. Legacy anchors
// (DWELL_LEGACY) and min_dwell==0 (feature off) always pass.
fn dwell_ok(env: &Env, anchor: &BytesN<32>, current_idx: u64) -> bool {
    let md = min_dwell(env);
    if md == 0 {
        return true;
    }
    let f = ring_frontier(env, anchor);
    // `DWELL_LEGACY` is the sentinel for a root
    // that predates RootIdxRing, so any frontier at the u64 max reads as legacy and
    // short-circuits here — the subtraction below never sees f == u64::MAX. Even so,
    // we use saturating_sub so that if current_idx < f (a frontier somehow ahead of
    // the current index, e.g. a corrupted ring) the age clamps to 0 and the swap is
    // blocked rather than underflowing to a huge apparent age.
    if f == DWELL_LEGACY {
        return true;
    }
    current_idx.saturating_sub(f) >= md
}

fn verify(env: &Env, key: &DataKey, proof: &Bytes, pi: Vec<BytesN<32>>) -> Result<(), PoolError> {
    let verifier: Address = env
        .storage()
        .instance()
        .get(key)
        .ok_or(PoolError::NoVerifier)?;
    let decoded = groth16_verifier::decode_proof(env, proof).ok_or(PoolError::MalformedProof)?;
    let client = Groth16VerifierClient::new(env, &verifier);
    if client.verify(&decoded, &pi) {
        Ok(())
    } else {
        Err(PoolError::InvalidProof)
    }
}

/// Verify the refreshable append half of a mobile-v2 operation. The caller
/// cannot choose `oldRoot` or `startIndex`; they are read at invocation time.
/// The fourth signal is the exact leaf already bound by the semantic proof.
fn verify_mobile_v2_append(
    env: &Env,
    new_root: &BytesN<32>,
    leaf: &BytesN<32>,
    proof: &Bytes,
) -> Result<(), PoolError> {
    let old_root: BytesN<32> = env
        .storage()
        .instance()
        .get(&DataKey::CmRoot)
        .ok_or(PoolError::NotInitialized)?;
    let idx: u64 = env
        .storage()
        .instance()
        .get(&DataKey::NextIndex)
        .ok_or(PoolError::NotInitialized)?;
    if idx >= TREE_CAPACITY {
        return Err(PoolError::TreeFull);
    }
    let pi: Vec<BytesN<32>> = vec![
        env,
        old_root,
        u64_to_be32(env, idx),
        new_root.clone(),
        leaf.clone(),
    ];
    verify(env, &DataKey::AppendV2Verifier, proof, pi)
}

fn validate_mobile_v2_totals(sum_in: i128, sum_out: i128) -> Result<(), PoolError> {
    if sum_in <= 0 || sum_out <= 0 || sum_in > u64::MAX as i128 || sum_out > u64::MAX as i128 {
        return Err(PoolError::BadAmount);
    }
    Ok(())
}

// Reject a 32-byte public input whose big-endian value is >= the Fr modulus
// (the non-canonical second representative that would alias a field element).
fn canonical(env: &Env, b: &BytesN<32>) -> Result<(), PoolError> {
    let _ = env;
    let v = b.to_array();
    let mut i = 0usize;
    while i < 32 {
        if v[i] < FR_MODULUS[i] {
            return Ok(());
        }
        if v[i] > FR_MODULUS[i] {
            return Err(PoolError::NonCanonical);
        }
        i += 1;
    }
    // exactly equal to the modulus -> not canonical
    Err(PoolError::NonCanonical)
}

fn require_admin(env: &Env) -> Result<(), PoolError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(PoolError::NotInitialized)?;
    admin.require_auth();
    Ok(())
}

// An empty funder allowlist preserves admin-only behavior.
fn is_mm_funder(env: &Env, addr: &Address) -> bool {
    let funders: Vec<Address> = env
        .storage()
        .instance()
        .get(&DataKey::MmFunders)
        .unwrap_or(Vec::new(env));
    for f in funders.iter() {
        if &f == addr {
            return true;
        }
    }
    false
}

fn solvency_is_enforced(env: &Env) -> bool {
    env.storage().instance().get(&DataKey::SolvencyEnforced).unwrap_or(false)
}

fn mobile_v2_is_active(env: &Env) -> bool {
    if !env
        .storage()
        .instance()
        .get(&DataKey::MobileV2Active)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(config): Option<MobileV2Config> = env
        .storage()
        .instance()
        .get(&DataKey::MobileV2Config)
    else {
        return false;
    };
    mobile_v2_config_matches(env, &config)
}

fn mobile_v2_config_matches(env: &Env, config: &MobileV2Config) -> bool {
    if config.protocol_version != 2
        || config.writer_revision != 1
        || config.batch_depth != MOBILE_V2_BATCH_DEPTH
        || config.circuit_capacity != MOBILE_V2_BATCH_CAPACITY
        || config.min_k != MOBILE_V2_MIN_K
        || config.max_k != MOBILE_V2_MAX_K
        || config.max_order_amount != MOBILE_V2_MAX_ORDER_AMOUNT
        || config.batch_hash_id.to_array() != MOBILE_V2_BATCH_HASH_ID
        || config.profile_hash.to_array() == [0u8; 32]
        || config.batch_hasher == env.current_contract_address()
        || validate_verifier(env, &config.batch_hasher).is_err()
        || validate_account_address(env, &config.batch_executor).is_err()
        || config.commit_verifier == config.claim_verifier
        || config.commit_verifier == config.append_verifier
        || config.claim_verifier == config.append_verifier
        || config.batch_hasher == config.commit_verifier
        || config.batch_hasher == config.claim_verifier
        || config.batch_hasher == config.append_verifier
        || config.batch_executor == env.current_contract_address()
        || config.batch_executor == config.batch_hasher
        || config.batch_executor == config.commit_verifier
        || config.batch_executor == config.claim_verifier
        || config.batch_executor == config.append_verifier
    {
        return false;
    }
    env.storage()
        .instance()
        .get::<_, Address>(&DataKey::Admin)
        .map(|value| value != config.batch_executor)
        .unwrap_or(false)
        && env.storage()
        .instance()
        .get::<_, Address>(&DataKey::SwapCommitBoundV2Verifier)
        .map(|value| value == config.commit_verifier)
        .unwrap_or(false)
        && env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::SwapClaimV2Verifier)
            .map(|value| value == config.claim_verifier)
            .unwrap_or(false)
        && env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::AppendV2Verifier)
            .map(|value| value == config.append_verifier)
            .unwrap_or(false)
}

// Fresh pools start from an empty tree, so this counter is exact and checked. Legacy
// upgraded pools lack SolvencyEnforced and retain saturating observe-only accounting:
// their pre-upgrade encrypted notes cannot be backfilled trustlessly, and allowing an
// incomplete counter to block withdrawals would strand funds.
fn outstanding_add(env: &Env, asset_id: &BytesN<32>, delta: i128) -> Result<(), PoolError> {
    let k = DataKey::OutstandingNoteValue(asset_id.clone());
    let cur: i128 = env.storage().persistent().get(&k).unwrap_or(0);
    let next = if solvency_is_enforced(env) {
        let exact = cur.checked_add(delta).ok_or(PoolError::BadAmount)?;
        if exact < 0 {
            return Err(PoolError::LiabilityUnderflow);
        }
        exact
    } else {
        cur.saturating_add(delta)
    };
    env.storage().persistent().set(&k, &next);
    env.storage().persistent().extend_ttl(&k, TTL_THRESH, TTL_BUMP);
    Ok(())
}

fn enforce_asset_solvency(env: &Env, asset_id: &BytesN<32>) -> Result<(), PoolError> {
    if !solvency_is_enforced(env) {
        return Ok(());
    }
    let outstanding: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::OutstandingNoteValue(asset_id.clone()))
        .unwrap_or(0);
    if outstanding < 0 {
        return Err(PoolError::LiabilityUnderflow);
    }
    let reserve: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Reserve(asset_id.clone()))
        .ok_or(PoolError::NoReserve)?;
    let accrued: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::SwapFeeAccrued(reserve.clone()))
        .unwrap_or(0);
    if accrued < 0 {
        return Err(PoolError::LiabilityUnderflow);
    }
    let required = outstanding.checked_add(accrued).ok_or(PoolError::BadAmount)?;
    let held = token::TokenClient::new(env, &reserve).balance(&env.current_contract_address());
    if held < required {
        return Err(PoolError::Insolvent);
    }
    Ok(())
}

fn enforce_configured_pair_solvency(env: &Env) -> Result<(), PoolError> {
    if !solvency_is_enforced(env) {
        return Ok(());
    }
    let asset_x: BytesN<32> = env.storage().instance().get(&DataKey::PairX).ok_or(PoolError::NoReserve)?;
    let asset_y: BytesN<32> = env.storage().instance().get(&DataKey::PairY).ok_or(PoolError::NoReserve)?;
    enforce_asset_solvency(env, &asset_x)?;
    enforce_asset_solvency(env, &asset_y)
}

// Settlement moves net value between the two asset liability buckets. Per-note amounts are
// hidden; only the public reserve deltas (rx->x2, ry->y2) are known, so move the net — the
// asset whose reserve grew was net-sold (its notes were spent => bucket down), the other was
// net-bought (notes minted => bucket up). Total shielded value is conserved; this only shifts
// the per-asset split. Fresh pools enforce the resulting exact liabilities after
// routing; upgraded legacy pools keep this as observe-only compatibility state.
fn settle_outstanding_move(env: &Env, rx: i128, ry: i128, x2: i128, y2: i128) -> Result<(), PoolError> {
    // Self-contained: re-read the pair asset ids (px/py are moved into the clearing proof's
    // public inputs before this runs). Outstanding change per asset = -(reserve change): the
    // X taken into reserve came from SPENT X notes (bucket down), the Y paid out went to
    // MINTED Y notes (bucket up) — and vice-versa for the other swap direction. So (pre -
    // post) is the right signed delta for either direction; a zero net is a no-op.
    let px: Option<BytesN<32>> = env.storage().instance().get(&DataKey::PairX);
    let py: Option<BytesN<32>> = env.storage().instance().get(&DataKey::PairY);
    if let (Some(px), Some(py)) = (px, py) {
        outstanding_add(env, &px, rx.checked_sub(x2).ok_or(PoolError::BadAmount)?)?;
        outstanding_add(env, &py, ry.checked_sub(y2).ok_or(PoolError::BadAmount)?)?;
    }
    Ok(())
}

// A fully initialized pool has an admin and both tree anchors.
// Requiring all three means entry guards reject a
// half-initialized contract with NotInitialized instead of letting a later
// `.unwrap()` on CmRoot/NextIndex panic. (init() sets all of them atomically, so
// this never rejects a properly-initialized pool.)
fn require_init(env: &Env) -> Result<(), PoolError> {
    let inst = env.storage().instance();
    if inst.has(&DataKey::Admin)
        && inst.has(&DataKey::CmRoot)
        && inst.has(&DataKey::NextIndex)
    {
        Ok(())
    } else {
        Err(PoolError::NotInitialized)
    }
}

// The fee applies only when both basis points and treasury are configured.
fn protocol_fee_cfg(env: &Env) -> (u32, Option<Address>) {
    (
        env.storage().instance().get(&DataKey::ProtocolFeeBps).unwrap_or(0),
        env.storage().instance().get(&DataKey::Treasury),
    )
}

// Compute the protocol fee from the public payout amount (`amount` in
// `withdraw`, `amount_out` in `withdraw_with_change`). Checked arithmetic
// rejects overflow instead of wrapping.
// Fee is zero unless both basis points and treasury are configured.
//
// Integer division floors, so a small base where
// `base * bps < 10_000` yields a zero fee. Dust payouts remain valid rather
// than being rejected solely because the fee rounds down.
fn protocol_fee_on(env: &Env, base: i128) -> Result<i128, PoolError> {
    let (bps, treasury) = protocol_fee_cfg(env);
    if bps == 0 || treasury.is_none() {
        return Ok(0);
    }
    let prod = base.checked_mul(bps as i128).ok_or(PoolError::BadAmount)?;
    let fee = prod.checked_div(10_000).ok_or(PoolError::BadAmount)?;
    Ok(fee)
}

fn venue_swap_fee_on(gross_sum_out: i128, fee_bps: u32) -> Result<i128, PoolError> {
    if fee_bps > VENUE_FEE_MAX_BPS {
        return Err(PoolError::BadAmount);
    }
    if fee_bps == 0 || gross_sum_out == 0 {
        return Ok(0);
    }
    let prod = gross_sum_out
        .checked_mul(fee_bps as i128)
        .ok_or(PoolError::BadAmount)?;
    prod.checked_div(10_000).ok_or(PoolError::BadAmount)
}

fn accrue_swap_fee(env: &Env, fee_asset: &Address, fee: i128) -> Result<(), PoolError> {
    if fee <= 0 {
        return Ok(());
    }
    let key = DataKey::SwapFeeAccrued(fee_asset.clone());
    let prior: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    let next = prior.checked_add(fee).ok_or(PoolError::BadAmount)?;
    env.storage().persistent().set(&key, &next);
    env.storage().persistent().extend_ttl(&key, TTL_THRESH, TTL_BUMP);
    Ok(())
}

// User deposits must match a configured denomination; an empty set disables the rule.
fn require_denom(env: &Env, amount: i128) -> Result<(), PoolError> {
    let denoms: Vec<i128> = match env.storage().instance().get(&DataKey::Denoms) {
        Some(d) => d,
        None => return Ok(()),
    };
    if denoms.len() == 0 {
        return Ok(());
    }
    for d in denoms.iter() {
        if d == amount {
            return Ok(());
        }
    }
    Err(PoolError::BadDenom)
}

// shared proof-gated mint for deposit / deposit_internal (caller does auth + denom).
fn mint_deposit(
    env: &Env,
    owner: &Address,
    asset_id: &BytesN<32>,
    amount: i128,
    new_root: &BytesN<32>,
    cm: &BytesN<32>,
    proof: &Bytes,
    note_ct: &Bytes,
) -> Result<(), PoolError> {
    // Reject a self-transfer mint. If `owner` is the pool, the transfer is a
    // net-zero operation that would still mint a spendable note against other
    // depositors' reserves.
    if owner == &env.current_contract_address() {
        return Err(PoolError::BadAmount);
    }
    if amount <= 0 {
        return Err(PoolError::BadAmount);
    }
    if note_ct.len() > NOTE_CT_MAX {
        return Err(PoolError::CtTooLong);
    }
    canonical(env, asset_id)?;
    canonical(env, new_root)?;
    canonical(env, cm)?;
    let reserve: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Reserve(asset_id.clone()))
        .ok_or(PoolError::NoReserve)?;
    let old_root: BytesN<32> = env.storage().instance().get(&DataKey::CmRoot).unwrap();
    let idx: u64 = env.storage().instance().get(&DataKey::NextIndex).unwrap_or(0);
    let pi: Vec<BytesN<32>> = vec![
        env,
        asset_id.clone(),
        i128_to_be32(env, amount),
        old_root,
        u64_to_be32(env, idx),
        new_root.clone(),
        cm.clone(),
    ];
    verify(env, &DataKey::DepositVerifier, proof, pi)?;
    token::TokenClient::new(env, &reserve).transfer(owner, &env.current_contract_address(), &amount);
    advance_root(env, new_root, idx);
    outstanding_add(env, asset_id, amount)?;
    enforce_asset_solvency(env, asset_id)?;
    emit_deposit(env, cm, idx, note_ct);
    Ok(())
}

// Reject verifier changes after the set is frozen.
fn require_verifiers_mutable(env: &Env) -> Result<(), PoolError> {
    if env.storage().instance().has(&DataKey::VerifiersFrozen) {
        return Err(PoolError::Frozen);
    }
    Ok(())
}

// Active protocol versions keep their verifier identity stable while the pool
// Wasm remains upgradeable. Before activation, the three v2 slots may be
// changed in place; after activation, a circuit or verifying-key
// change must use a new versioned slot and entrypoint so queued recovery proofs
// remain valid. The global one-way freeze still governs the final stable pool.
fn require_mobile_v2_verifiers_mutable(env: &Env) -> Result<(), PoolError> {
    require_verifiers_mutable(env)?;
    if env.storage().instance().has(&DataKey::MobileV2Config) {
        return Err(PoolError::Frozen);
    }
    Ok(())
}

// A verifier must be a separate contract address. Reject the pool's own address,
// which would re-enter this contract instead of invoking a verifier,
// and reject classic account addresses, which cannot host `verify`.
// Soroban serializes a contract address to XDR with discriminant 1 (ScAddressType
// ScAddressTypeContract); an account address uses discriminant 0. The discriminant
// is the last byte of the 4-byte big-endian union tag at the start of the XDR.
fn validate_verifier(env: &Env, v: &Address) -> Result<(), PoolError> {
    if *v == env.current_contract_address() {
        return Err(PoolError::BadAmount);
    }
    // Address::to_xdr serializes an ScVal: byte[3] is the ScValType tag (18 ==
    // ScvAddress), then an ScAddress union whose 4-byte big-endian discriminant
    // occupies bytes[4..8]. 0 == ScAddressTypeAccount (a classic G... account,
    // which can never host a `verify` fn), 1 == ScAddressTypeContract. Require a
    // contract address; reject an account address.
    let xdr = v.clone().to_xdr(env);
    if xdr.len() < 8 {
        return Err(PoolError::BadAmount);
    }
    let is_contract = xdr.get(4).unwrap_or(0) == 0
        && xdr.get(5).unwrap_or(0) == 0
        && xdr.get(6).unwrap_or(0) == 0
        && xdr.get(7).unwrap_or(0) == 1;
    if !is_contract {
        return Err(PoolError::BadAmount);
    }
    Ok(())
}

// The v2 executor is intentionally a classic Stellar account so its auth can
// be governed by the account's native signer weights and threshold. A contract
// address would move that policy into mutable smart-account code and could
// silently authorize every batch invocation.
fn validate_account_address(env: &Env, v: &Address) -> Result<(), PoolError> {
    let xdr = v.clone().to_xdr(env);
    if xdr.len() < 8 {
        return Err(PoolError::BadAmount);
    }
    let is_account = xdr.get(4).unwrap_or(1) == 0
        && xdr.get(5).unwrap_or(1) == 0
        && xdr.get(6).unwrap_or(1) == 0
        && xdr.get(7).unwrap_or(1) == 0;
    if !is_account {
        return Err(PoolError::BadAmount);
    }
    Ok(())
}

// Clearing reserves used for pricing come from live on-chain liquidity rather
// than an admin-writable slot. When a route pair is configured,
// read its live reserves (in this pool's X/Y orientation, same as do_route_pair);
// otherwise fall back to the stored compatibility ReserveX/Y values.
fn current_reserves(env: &Env) -> (i128, i128) {
    if env.storage().instance().has(&DataKey::RoutePair) {
        let pair: Address = env.storage().instance().get(&DataKey::RoutePair).unwrap();
        let tx: Address = env.storage().instance().get(&DataKey::RouteTokenX).unwrap();
        let t0: Address = env.invoke_contract(&pair, &Symbol::new(env, "token_0"), Vec::new(env));
        let (r0, r1): (i128, i128) =
            env.invoke_contract(&pair, &Symbol::new(env, "get_reserves"), Vec::new(env));
        return if tx == t0 { (r0, r1) } else { (r1, r0) };
    }
    (
        env.storage().instance().get(&DataKey::ReserveX).unwrap_or(0),
        env.storage().instance().get(&DataKey::ReserveY).unwrap_or(0),
    )
}

fn u64_to_be32(env: &Env, n: u64) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(env, &b)
}

fn i128_to_be32(env: &Env, n: i128) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[16..32].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(env, &b)
}

#[cfg(test)]
mod nullifier_ttl_test {
    use super::*;
    use soroban_sdk::testutils::{storage::Persistent as _, Address as _};

    fn nf(env: &Env, n: u8) -> BytesN<32> {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        BytesN::from_array(env, &bytes)
    }

    fn setup(env: &Env) -> Address {
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::Admin, &Address::generate(env));
            env.storage().instance().set(&DataKey::CmRoot, &nf(env, 1));
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
        });
        id
    }

    #[test]
    fn spent_nullifiers_receive_long_lived_ttl() {
        let env = Env::default();
        let id = setup(&env);
        let spent = nf(&env, 2);
        env.as_contract(&id, || {
            mark_nullifier_spent(&env, &spent);
            let ttl = env
                .storage()
                .persistent()
                .get_ttl(&DataKey::Nullifier(spent.clone()));
            assert_eq!(ttl, NULLIFIER_TTL_BUMP);
        });
    }

    #[test]
    fn nullifier_ttl_keeper_is_idempotent_and_bounded() {
        let env = Env::default();
        let id = setup(&env);
        let spent = nf(&env, 2);
        let missing = nf(&env, 3);
        env.as_contract(&id, || mark_nullifier_spent(&env, &spent));

        let client = ConfibatchPoolClient::new(&env, &id);
        assert_eq!(client.bump_nullifier_ttl(&vec![&env, spent.clone(), missing]), 1);

        let mut too_many = Vec::new(&env);
        for i in 0..(MAX_NULLIFIER_TTL_BATCH + 1) {
            too_many.push_back(nf(&env, (i % 255) as u8));
        }
        assert_eq!(
            client.try_bump_nullifier_ttl(&too_many),
            Err(Ok(PoolError::BadAmount))
        );
    }
}

#[cfg(test)]
mod route_math_test {
    use super::*;

    // Canonical UniswapV2/Soroswap 0.3%-fee output — what the pair itself pays and K-checks.
    fn canonical_get_amount_out(rin: i128, rout: i128, amount_in: i128) -> i128 {
        let fee_in = amount_in * 997;
        (rout * fee_in) / (rin * 1000 + fee_in)
    }

    // routed_out_checked must return the canonical 0.3%-fee output UNDER-ASKED by ~0.5%+1 — the
    // deliberate safety margin that keeps a REAL Soroswap pair's K-check from reverting the settle
    // (#114). The under-ask is NOT a fee: the difference stays in the pair's reserves. (Restored after
    // a P0 change wrongly pared it to -1 and broke live Soroswap-routed swaps.)
    #[test]
    fn routed_out_is_canonical_minus_kcheck_cushion() {
        // A spread of reserve depths and trade sizes.
        let cases: [(i128, i128, i128); 5] = [
            (1_000_000_000, 1_000_000_000, 1_000_000),
            (5_000_000, 3_000_000, 250_000),
            (10_000_000_000, 7_500_000_000, 40_000_000),
            (1_000_000, 1_000_000, 100), // small but non-dust (canonical ~99)
            (123_456_789, 987_654_321, 5_555_555),
        ];
        for (rin, rout, amount_in) in cases {
            let got = routed_out_checked(rin, rout, amount_in).unwrap();
            let canonical = canonical_get_amount_out(rin, rout, amount_in);
            // Exactly the canonical output minus the ~0.5% + 1-unit K-check under-ask.
            assert_eq!(got, canonical - canonical / 200 - 1, "routed out must be canonical getAmountOut minus the 0.5%+1 cushion");
            // The under-ask is strictly below the canonical output (never asks for MORE than the pair can give).
            assert!(got < canonical, "routed out must under-ask the canonical output");
        }
    }

    // Bad reserves / non-positive inputs fail closed, dust nets return 0.
    #[test]
    fn routed_out_edge_cases() {
        assert_eq!(routed_out_checked(1_000, 1_000, 0).unwrap(), 0, "zero in -> dust");
        assert_eq!(routed_out_checked(1_000, 1_000, -5).unwrap(), 0, "negative in -> dust");
        assert_eq!(routed_out_checked(0, 1_000, 10).unwrap_err(), PoolError::BadAmount, "zero rin -> reject");
        assert_eq!(routed_out_checked(1_000, 0, 10).unwrap_err(), PoolError::BadAmount, "zero rout -> reject");
        // A trade so tiny the canonical output is 1 -> after the -1 cushion it's dust (0).
        assert_eq!(routed_out_checked(1_000_000_000, 1_000_000_000, 1).unwrap(), 0, "sub-unit -> dust");
    }
}

#[cfg(test)]
mod dwell_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn root(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }

    // Exercises the privacy dwell helpers directly (ring_push / ring_frontier /
    // dwell_ok), including the backward-compat path where RootRing already holds
    // legacy roots from before RootIdxRing existed (the dwell upgrade).
    #[test]
    fn dwell_window_and_legacy_backfill() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // Simulate a PRE-UPGRADE pool: RootRing has two roots, no RootIdxRing yet.
            let mut ring: Vec<BytesN<32>> = Vec::new(&env);
            ring.push_back(root(&env, 1));
            ring.push_back(root(&env, 2));
            env.storage().instance().set(&DataKey::RootRing, &ring);
            env.storage().instance().set(&DataKey::MinDwell, &3u64);

            // Legacy roots have no recorded frontier -> dwell-lenient (never block).
            assert_eq!(ring_frontier(&env, &root(&env, 1)), DWELL_LEGACY);
            assert!(dwell_ok(&env, &root(&env, 1), 10));

            // Post-upgrade advances stamp the frontier alongside each new root.
            ring_push(&env, &root(&env, 3), 11); // root3 became current at frontier 11
            ring_push(&env, &root(&env, 4), 14); // root4 at frontier 14 (a settle added 3)

            // Offset mapping: legacy entries sit ahead of the (shorter) idx ring.
            assert_eq!(ring_frontier(&env, &root(&env, 3)), 11);
            assert_eq!(ring_frontier(&env, &root(&env, 4)), 14);
            assert_eq!(ring_frontier(&env, &root(&env, 1)), DWELL_LEGACY); // still lenient

            // root3 (frontier 11) at current idx 14 -> aged 3 >= 3 -> allowed.
            assert!(dwell_ok(&env, &root(&env, 3), 14));
            // root4 (frontier 14) at current idx 14 -> aged 0 < 3 -> BLOCKED (too fresh).
            assert!(!dwell_ok(&env, &root(&env, 4), 14));
            // ...but once 3 more leaves land (idx 17) root4 ages in.
            assert!(dwell_ok(&env, &root(&env, 4), 17));
            // legacy anchor is never blocked regardless of idx.
            assert!(dwell_ok(&env, &root(&env, 1), 14));

            // min_dwell == 0 disables the rule entirely (the default / pre-enable state).
            env.storage().instance().set(&DataKey::MinDwell, &0u64);
            assert!(dwell_ok(&env, &root(&env, 4), 14));
        });
    }

    // A clean pool (no legacy roots): every advance is stamped, offset is always 0.
    #[test]
    fn dwell_clean_pool_no_legacy() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::MinDwell, &2u64);
            advance_root(&env, &root(&env, 10), 0); // frontier 1
            advance_root(&env, &root(&env, 11), 1); // frontier 2
            advance_root(&env, &root(&env, 12), 2); // frontier 3
            assert_eq!(ring_frontier(&env, &root(&env, 10)), 1);
            // root10 (frontier 1) at current next_index 3 -> aged 2 >= 2 -> ok.
            assert!(dwell_ok(&env, &root(&env, 10), 3));
            // root12 (frontier 3) at current 3 -> aged 0 -> blocked.
            assert!(!dwell_ok(&env, &root(&env, 12), 3));
        });
    }

    #[test]
    fn swap_commit_enforces_dwell_before_verifier_work() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        let admin = Address::generate(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        client.init(&admin, &root(&env, 1));
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::MinDwell, &2u64);
            advance_root(&env, &root(&env, 2), 0); // root2 frontier=1, current next_index=1
        });

        let result = client.try_swap_commit(
            &root(&env, 2),
            &root(&env, 3),
            &root(&env, 4),
            &root(&env, 5),
            &Bytes::new(&env),
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::DwellNotMet)));
    }

    // #5: misaligned rings (RootIdxRing LONGER than RootRing) must not underflow the
    // offset in ring_frontier. ring_push panics on this invariant break, but a corrupt
    // read still has to fail SAFE: dwell must stay enforced, never silently flipped open.
    // Pre-fix, `ring.len() - idxr.len()` underflowed -> offset huge -> every root read as
    // DWELL_LEGACY (lenient) -> the dwell floor was bypassed (or it panicked under
    // overflow-checks). saturating_sub clamps offset to 0 so frontiers still resolve.
    #[test]
    fn dwell_misaligned_ring_fails_safe() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::MinDwell, &3u64);
            // Inject a corrupted ring: idxr (2 entries) LONGER than ring (1 entry).
            let mut ring: Vec<BytesN<32>> = Vec::new(&env);
            ring.push_back(root(&env, 20));
            let mut idxr: Vec<u64> = Vec::new(&env);
            idxr.push_back(5);
            idxr.push_back(8);
            env.storage().instance().set(&DataKey::RootRing, &ring);
            env.storage().instance().set(&DataKey::RootIdxRing, &idxr);

            // Must NOT underflow/panic and must NOT mis-classify the root as legacy:
            // offset clamps to 0, so root20 (ring pos 0) resolves to idxr[0] == 5.
            assert_eq!(ring_frontier(&env, &root(&env, 20)), 5);
            // dwell stays ENFORCED off that frontier (fail-safe, not bypassed):
            // current_idx 6 -> aged 1 < 3 -> blocked.
            assert!(!dwell_ok(&env, &root(&env, 20), 6));
            // current_idx 9 -> aged 4 >= 3 -> allowed once it has aged in.
            assert!(dwell_ok(&env, &root(&env, 20), 9));
            // An unknown root in a misaligned ring still reads as legacy (lenient),
            // matching the not-found path — no underflow on the offset computation.
            assert_eq!(ring_frontier(&env, &root(&env, 99)), DWELL_LEGACY);
        });
    }
}

// Hardening guards (v4): overflow rejection, route output validation, ring parity,
// init guard, dwell boundary, verifier-address validation.
#[cfg(test)]
mod hardening_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn root(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }

    // #2/#3/#9: protocol fee uses checked math on a consistent base, floors small
    // fees to zero (no reject), and is zero unless bps+treasury are both configured.
    #[test]
    fn protocol_fee_checked_and_rounding() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // unconfigured -> always zero
            assert_eq!(protocol_fee_on(&env, 1_000_000).unwrap(), 0);

            // configure 100 bps (1%) + a treasury
            env.storage().instance().set(&DataKey::ProtocolFeeBps, &100u32);
            let treasury = Address::generate(&env);
            env.storage().instance().set(&DataKey::Treasury, &treasury);

            // normal: 10_000 * 100 / 10_000 = 100
            assert_eq!(protocol_fee_on(&env, 10_000).unwrap(), 100);
            // #9 rounding floor: tiny base where base*bps < 10_000 -> fee 0, NOT reject
            assert_eq!(protocol_fee_on(&env, 50).unwrap(), 0);
            // #2 overflow: i128::MAX * 100 overflows -> rejected (not wrapped)
            assert_eq!(protocol_fee_on(&env, i128::MAX), Err(PoolError::BadAmount));
        });
    }

    // #8: do_route_pair_checked rejects non-positive reserves and overflow via the
    // checked arithmetic helper (covered here without a live AMM by feeding the math
    // boundary directly through the public/dust paths).
    #[test]
    fn route_pair_dust_and_amount_guard() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // amount_in <= 0 is a no-op dust net -> Ok(0), never touches the pair
            let pair = Address::generate(&env);
            let tok = Address::generate(&env);
            assert_eq!(do_route_pair_checked(&env, &pair, &tok, 0, 0).unwrap(), 0);
            assert_eq!(do_route_pair_checked(&env, &pair, &tok, -5, 0).unwrap(), 0);
        });
    }

    // #5: ring_push keeps RootIdxRing length <= RootRing length (parity invariant)
    // across many appends and trims both in lockstep at RING_SIZE.
    #[test]
    fn ring_push_parity_maintained() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            for i in 0..(RING_SIZE + 10) {
                ring_push(&env, &root(&env, (i % 200) as u8), i as u64);
                let ring: Vec<BytesN<32>> =
                    env.storage().instance().get(&DataKey::RootRing).unwrap();
                let idxr: Vec<u64> =
                    env.storage().instance().get(&DataKey::RootIdxRing).unwrap();
                assert!(idxr.len() <= ring.len()); // parity holds every step
                assert!(ring.len() <= RING_SIZE);
                assert!(idxr.len() <= RING_SIZE);
            }
        });
    }

    // #5: a corrupted ring where RootIdxRing is LONGER than RootRing must panic in
    // ring_push (fail-loud) instead of silently mis-mapping frontiers.
    #[test]
    #[should_panic(expected = "ring parity violation")]
    fn ring_push_rejects_corrupt_parity() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // RootRing empty, but RootIdxRing already has 2 entries -> after a push,
            // idxr (3) > ring (1) -> parity violation -> panic.
            let ring: Vec<BytesN<32>> = Vec::new(&env);
            let mut idxr: Vec<u64> = Vec::new(&env);
            idxr.push_back(1);
            idxr.push_back(2);
            env.storage().instance().set(&DataKey::RootRing, &ring);
            env.storage().instance().set(&DataKey::RootIdxRing, &idxr);
            ring_push(&env, &root(&env, 9), 3);
        });
    }

    // #7: require_init rejects a half-initialized pool (Admin set but CmRoot/NextIndex
    // missing) with NotInitialized instead of letting a later unwrap panic.
    #[test]
    fn require_init_needs_tree_anchors() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // nothing set
            assert_eq!(require_init(&env), Err(PoolError::NotInitialized));
            // only Admin -> still not fully initialized
            let admin = Address::generate(&env);
            env.storage().instance().set(&DataKey::Admin, &admin);
            assert_eq!(require_init(&env), Err(PoolError::NotInitialized));
            // Admin + CmRoot, missing NextIndex -> still rejected
            env.storage().instance().set(&DataKey::CmRoot, &root(&env, 1));
            assert_eq!(require_init(&env), Err(PoolError::NotInitialized));
            // all three -> ok
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
            assert_eq!(require_init(&env), Ok(()));
        });
    }

    #[test]
    fn init_rejects_noncanonical_empty_root_without_partial_state() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        let client = ConfibatchPoolClient::new(&env, &id);
        let admin = Address::generate(&env);
        let bad = BytesN::from_array(&env, &FR_MODULUS);

        assert_eq!(client.try_init(&admin, &bad), Err(Ok(PoolError::NonCanonical)));
        client.init(&admin, &root(&env, 1));
        assert_eq!(client.next_index(), 0);
    }

    // #11: dwell age clamps at the u64 boundary. A frontier of u64::MAX is the legacy
    // sentinel (lenient); a frontier ahead of current_idx clamps to age 0 (blocked,
    // fail-closed) via saturating_sub rather than underflowing.
    #[test]
    fn dwell_u64_boundary_fail_closed() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::MinDwell, &3u64);
            // stamp root with a frontier AHEAD of the queried current_idx
            ring_push(&env, &root(&env, 7), 100);
            // current_idx 50 < frontier 100 -> saturating_sub = 0 < 3 -> blocked
            assert!(!dwell_ok(&env, &root(&env, 7), 50));
            // a legacy (u64::MAX) frontier is always lenient
            let mut ring: Vec<BytesN<32>> = Vec::new(&env);
            ring.push_back(root(&env, 8)); // legacy front root, no idx entry
            ring.push_back(root(&env, 7));
            env.storage().instance().set(&DataKey::RootRing, &ring);
            assert_eq!(ring_frontier(&env, &root(&env, 8)), DWELL_LEGACY);
            assert!(dwell_ok(&env, &root(&env, 8), 0));
        });
    }

    // #1: settle-style index advance uses checked_add — at the u64 frontier it would
    // reject (BadAmount) instead of wrapping. Verified at the arithmetic boundary.
    #[test]
    fn settle_index_checked_add_overflow() {
        // idx + n + 1 where idx near u64::MAX must NOT wrap.
        let idx = u64::MAX - 1;
        let n: u64 = 3;
        let res = idx.checked_add(n).and_then(|v| v.checked_add(1));
        assert!(res.is_none()); // overflow detected -> caller returns BadAmount
        // a normal advance is fine
        let ok = 10u64.checked_add(2).and_then(|v| v.checked_add(1));
        assert_eq!(ok, Some(13));
    }

    // #10: validate_verifier rejects the pool's own address and a classic account
    // (G...) address, and accepts a real, separate contract address.
    #[test]
    fn validate_verifier_self_account_contract() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // self-reference rejected
            let me = env.current_contract_address();
            assert_eq!(validate_verifier(&env, &me), Err(PoolError::BadAmount));
            // a classic account address (discriminant 0) is rejected — can't host verify
            let acct = Address::from_str(
                &env,
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            );
            assert_eq!(validate_verifier(&env, &acct), Err(PoolError::BadAmount));
            // a distinct contract address (discriminant 1) is accepted
            let other = Address::generate(&env); // generate() yields a contract address
            assert_eq!(validate_verifier(&env, &other), Ok(()));
        });
    }

    // canonical() rejects every 32-byte big-endian value >= the Fr modulus (the
    // non-canonical second representative that would alias a field element) and
    // accepts the largest valid one. Boundary cases: == modulus, modulus+1, and
    // 2^256-1 must all be NonCanonical; modulus-1 must be Ok.
    #[test]
    fn canonical_rejects_at_and_above_fr_modulus() {
        // big-endian +/- 1 on a 32-byte value (no wrap at these inputs).
        fn add_one(mut a: [u8; 32]) -> [u8; 32] {
            let mut i = 31i32;
            while i >= 0 {
                let (v, carry) = a[i as usize].overflowing_add(1);
                a[i as usize] = v;
                if !carry {
                    break;
                }
                i -= 1;
            }
            a
        }
        fn sub_one(mut a: [u8; 32]) -> [u8; 32] {
            let mut i = 31i32;
            while i >= 0 {
                let (v, borrow) = a[i as usize].overflowing_sub(1);
                a[i as usize] = v;
                if !borrow {
                    break;
                }
                i -= 1;
            }
            a
        }

        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            let bn = |a: [u8; 32]| BytesN::from_array(&env, &a);

            // == modulus -> non-canonical (exact-equal falls through the loop)
            assert_eq!(canonical(&env, &bn(FR_MODULUS)), Err(PoolError::NonCanonical));
            // modulus + 1 -> non-canonical
            assert_eq!(
                canonical(&env, &bn(add_one(FR_MODULUS))),
                Err(PoolError::NonCanonical)
            );
            // 2^256 - 1 (all 0xFF), the max 32-byte value -> non-canonical
            assert_eq!(canonical(&env, &bn([0xFFu8; 32])), Err(PoolError::NonCanonical));
            // modulus - 1, the largest canonical field element -> accepted
            assert_eq!(canonical(&env, &bn(sub_one(FR_MODULUS))), Ok(()));
            // a small value (zero) is trivially canonical
            assert_eq!(canonical(&env, &bn([0u8; 32])), Ok(()));
        });
    }
}

// settle_batch_vn off-chain rejection path: the per-buyer Vec lengths must all
// equal n == cm_outs_buy.len(), and n must be > 0 (lib.rs:926-935). These cases
// reject with BadAmount BEFORE any canonical/ring/proof/verifier work, so they
// need no verifier wiring — only the minimal init anchors (Admin/CmRoot/NextIndex)
// to clear require_init. The idx+n+1 overflow at the commit step is a separate
// deploy item; this module is the vector-length rejection coverage only.
#[cfg(test)]
mod settle_batch_vn_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn b32(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }

    // Minimal init so require_init passes; the length checks run before anything
    // that would touch a verifier or the ring, so nothing else needs setting.
    fn init_minimal(env: &Env, id: &Address) {
        env.as_contract(id, || {
            let admin = Address::generate(env);
            env.storage().instance().set(&DataKey::Admin, &admin);
            env.storage().instance().set(&DataKey::CmRoot, &b32(env, 1));
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
        });
    }

    // Build a settle_batch_vn arg set whose buyer Vecs have length `n`, except the
    // single Vec named by `short` is one element short (or n=0 leaves them empty),
    // then call try_settle_batch_vn so the BadAmount error returns for assertion.
    fn call_with(
        env: &Env,
        client: &ConfibatchPoolClient,
        n: u32,
        short: &str,
    ) -> Result<
        Result<(), soroban_sdk::ConversionError>,
        Result<PoolError, soroban_sdk::InvokeError>,
    > {
        let len = |name: &str| if name == short { n.saturating_sub(1) } else { n };
        let bytes_vec = |count: u32| {
            let mut v: Vec<Bytes> = Vec::new(env);
            for _ in 0..count {
                v.push_back(Bytes::new(env));
            }
            v
        };
        let bn_vec = |count: u32, base: u8| {
            let mut v: Vec<BytesN<32>> = Vec::new(env);
            for i in 0..count {
                v.push_back(b32(env, base.wrapping_add(i as u8)));
            }
            v
        };
        client.try_settle_batch_vn(
            &bn_vec(len("roots"), 2),  // anchor_roots_buy
            &bn_vec(len("nfs"), 50),   // nfs_buy
            &bn_vec(len("ocs"), 100),  // order_commits_buy
            &bytes_vec(len("proofs")), // proofs_buy
            &b32(env, 200),            // anchor_root_sell
            &b32(env, 201),            // nf_sell
            &b32(env, 202),            // order_commit_sell
            &Bytes::new(env),          // proof_sell
            &b32(env, 203),            // new_root
            &bn_vec(len("cms"), 150),  // cm_outs_buy (its len defines n)
            &b32(env, 204),            // cm_out_sell
            &1i128,                    // p
            &1i128,                    // x2
            &1i128,                    // y2
            &Bytes::new(env),          // clearing_proof
            &bytes_vec(len("cts")),    // cts_buy
            &Bytes::new(env),          // ct_sell
        )
    }

    // n == 0 (every buyer Vec empty) -> BadAmount, before any proof work.
    #[test]
    fn rejects_n_zero() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        init_minimal(&env, &id);
        let client = ConfibatchPoolClient::new(&env, &id);
        assert_eq!(call_with(&env, &client, 0, ""), Err(Ok(PoolError::BadAmount)));
    }

    // Each per-buyer Vec being one element short of n (cm_outs_buy.len()) must
    // reject with BadAmount — one case per validated Vec (lib.rs:928-933).
    #[test]
    fn rejects_each_vector_length_mismatch() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        init_minimal(&env, &id);
        let client = ConfibatchPoolClient::new(&env, &id);
        for short in ["roots", "nfs", "ocs", "proofs", "cts"] {
            assert_eq!(
                call_with(&env, &client, 3, short),
                Err(Ok(PoolError::BadAmount)),
                "vector {} length != n must reject with BadAmount",
                short
            );
        }
    }
}

// deposit_internal auth + denomination-exemption boundaries (item:
// e2e-deposit-internal-access-and-denom). Driven through the PUBLIC client
// entrypoints so the contract's own auth/denom gating is what is exercised, with
// per-address mock_auths for deterministic authorization assertions (no live
// chain / verifier needed — the boundary checks all run BEFORE any verifier or
// reserve work). NOTE: deposit_internal is NOT dead — the MM sequencer calls it
// (server/src/lib/sequencer_v2.js); it is intentionally retained.
//
// Check ordering relied on here:
//   deposit:          require_init -> owner.require_auth -> require_denom -> mint_deposit
//   deposit_internal: require_init -> require_admin(auth) -> mint_deposit  (NO denom gate)
// mint_deposit's first storage touch is the Reserve lookup, so an authorized,
// denom-exempt call lands on NoReserve — never BadDenom — which is exactly the
// signal that the denomination rule was waived on the internal path.
#[cfg(test)]
mod deposit_internal_access_test {
    use super::*;
    use soroban_sdk::testutils::{storage::Persistent as _, Address as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    fn b32(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }

    // A fully-initialized pool (clears require_init) with a denomination set so the
    // denom rule is ACTIVE. No reserve / verifier is wired — every assertion below
    // resolves before mint_deposit would need them.
    fn setup(env: &Env) -> (Address, Address) {
        let id = env.register(ConfibatchPool, ());
        let admin = Address::generate(env);
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::Admin, &admin);
            env.storage().instance().set(&DataKey::CmRoot, &b32(env, 1));
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
            // Active denomination set: only 100 is a valid public-deposit amount.
            let denoms: Vec<i128> = vec![env, 100i128];
            env.storage().instance().set(&DataKey::Denoms, &denoms);
        });
        (id, admin)
    }

    // Args for both deposit and deposit_internal share the same shape/order.
    fn deposit_args(env: &Env, owner: &Address, amount: i128) -> Vec<Val> {
        vec![
            env,
            owner.into_val(env),       // owner
            b32(env, 9).into_val(env), // asset_id
            amount.into_val(env),      // amount
            b32(env, 7).into_val(env), // new_root
            b32(env, 8).into_val(env), // cm
            Bytes::new(env).into_val(env), // proof
            Bytes::new(env).into_val(env), // note_ct
        ]
    }

    // create_pair wires the per-pair LP config in ONE call and assigns each pair a UNIQUE, monotonic
    // LP note-class tag from the reserved (>LP_ASSET_ID) namespace — the tag that gives cross-pair note
    // isolation. lp_pair/lp_pairs read it back; the tag is distinct from LP_ASSET_ID and from other pairs.
    #[test]
    fn create_pair_assigns_unique_isolating_tags() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let amm1 = Address::generate(&env);
        let (ta1, tb1) = (Address::generate(&env), Address::generate(&env));
        let tag1 = client.create_pair(&b32(&env, 10), &b32(&env, 1), &b32(&env, 2), &ta1, &tb1, &amm1, &ta1, &tb1, &1u64, &2u64);
        assert_eq!(tag1, LP_TAG_BASE, "first pair gets the base LP note-class tag");
        assert_ne!(tag1, LP_ASSET_ID, "per-pair tag is distinct from the legacy single-pair tag");

        let amm2 = Address::generate(&env);
        let (ta2, tb2) = (Address::generate(&env), Address::generate(&env));
        let tag2 = client.create_pair(&b32(&env, 11), &b32(&env, 3), &b32(&env, 4), &ta2, &tb2, &amm2, &ta2, &tb2, &3u64, &4u64);
        assert_eq!(tag2, LP_TAG_BASE + 1, "second pair gets the NEXT tag — unique per pair");
        assert_ne!(tag1, tag2, "the two pairs' LP note-classes are disjoint (isolation invariant)");

        // views read back the config + enumerate the pairs
        let cfg1 = client.lp_pair(&b32(&env, 10)).unwrap();
        assert_eq!(cfg1.amm, amm1);
        assert_eq!(cfg1.lp_note_tag, LP_TAG_BASE);
        assert_eq!(client.lp_pairs().len(), 2, "both created pairs are enumerable");
    }

    #[test]
    fn pair_ttl_keeper_is_permissionless_bounded_and_idempotent() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let pair_id = b32(&env, 12);
        let missing = b32(&env, 13);
        let addr = Address::generate(&env);
        client.create_pair(&pair_id, &b32(&env, 1), &b32(&env, 2), &addr, &addr, &addr, &addr, &addr, &1u64, &2u64);

        assert_eq!(client.bump_pair_ttl(&vec![&env, pair_id.clone(), missing]), 1);
        env.as_contract(&id, || {
            assert_eq!(env.storage().persistent().get_ttl(&DataKey::LpPair(pair_id.clone())), TTL_BUMP);
        });

        let mut too_many = Vec::new(&env);
        for i in 0..(MAX_PAIR_TTL_BATCH + 1) {
            too_many.push_back(b32(&env, (i % 255) as u8));
        }
        assert_eq!(client.try_bump_pair_ttl(&too_many), Err(Ok(PoolError::BadAmount)));
    }

    #[test]
    fn fresh_pool_solvency_guard_rejects_underbacking_and_underflow() {
        let env = Env::default();
        env.mock_all_auths();
        let token_admin = Address::generate(&env);
        let token_id = env.register_stellar_asset_contract_v2(token_admin.clone()).address();
        let pool_id = env.register(ConfibatchPool, ());
        let asset_id = b32(&env, 22);

        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::SolvencyEnforced, &true);
            env.storage().persistent().set(&DataKey::Reserve(asset_id.clone()), &token_id);
            outstanding_add(&env, &asset_id, 100).unwrap();
            assert_eq!(enforce_asset_solvency(&env, &asset_id), Err(PoolError::Insolvent));
            assert_eq!(outstanding_add(&env, &asset_id, -101), Err(PoolError::LiabilityUnderflow));
        });

        soroban_sdk::token::StellarAssetClient::new(&env, &token_id).mint(&pool_id, &100);
        env.as_contract(&pool_id, || {
            assert_eq!(enforce_asset_solvency(&env, &asset_id), Ok(()));
            env.storage().persistent().set(&DataKey::SwapFeeAccrued(token_id.clone()), &1i128);
            assert_eq!(enforce_asset_solvency(&env, &asset_id), Err(PoolError::Insolvent));
            env.storage().persistent().set(&DataKey::SwapFeeAccrued(token_id.clone()), &0i128);
            assert_eq!(outstanding_add(&env, &asset_id, -100), Ok(()));
            assert_eq!(enforce_asset_solvency(&env, &asset_id), Ok(()));
        });
    }

    #[test]
    fn fresh_pool_rejects_two_asset_tags_backed_by_one_sac() {
        let env = Env::default();
        let pool_id = env.register(ConfibatchPool, ());
        let token_id = Address::generate(&env);
        let asset_a = b32(&env, 30);
        let asset_b = b32(&env, 31);
        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::SolvencyEnforced, &true);
            assert_eq!(set_reserve_checked(&env, &asset_a, &token_id), Ok(()));
            assert_eq!(set_reserve_checked(&env, &asset_a, &token_id), Ok(()));
            assert_eq!(set_reserve_checked(&env, &asset_b, &token_id), Err(PoolError::ReserveConflict));
            let reverse: BytesN<32> = env
                .storage()
                .persistent()
                .get(&DataKey::ReserveAsset(token_id.clone()))
                .unwrap();
            assert_eq!(reverse, asset_a);
        });
    }

    // create_pair refuses to clobber an existing pair_id — repointing a live pair would orphan its notes.
    #[test]
    fn create_pair_refuses_clobber() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let a = Address::generate(&env);
        client.create_pair(&b32(&env, 20), &b32(&env, 1), &b32(&env, 2), &a, &a, &a, &a, &a, &1u64, &2u64);
        let res = client.try_create_pair(&b32(&env, 20), &b32(&env, 1), &b32(&env, 2), &a, &a, &a, &a, &a, &1u64, &2u64);
        assert_eq!(res, Err(Ok(PoolError::PairExists)), "second create with same pair_id must revert PairExists");
    }

    // create_pair's Reserve write is guarded: reusing a base asset across pairs with the SAME SAC is
    // idempotent (allowed), but re-pointing an already-registered asset to a DIFFERENT SAC reverts
    // (ReserveConflict) — so a self-serve pair can never silently repoint the shared asset->SAC mapping.
    #[test]
    fn create_pair_reserve_conflict_guard() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let (sac_usdc, sac_other, amm) = (Address::generate(&env), Address::generate(&env), Address::generate(&env));
        // pair 40 registers asset tag 1 -> sac_usdc (fresh)
        client.create_pair(&b32(&env, 40), &b32(&env, 1), &b32(&env, 2), &sac_usdc, &sac_usdc, &amm, &amm, &amm, &1u64, &2u64);
        // pair 41 REUSES asset tag 1 with the SAME sac -> idempotent, allowed
        let tag = client.create_pair(&b32(&env, 41), &b32(&env, 1), &b32(&env, 3), &sac_usdc, &sac_other, &amm, &amm, &amm, &1u64, &3u64);
        assert!(tag >= LP_TAG_BASE, "reusing a base asset with the SAME SAC across pairs is allowed");
        // pair 42 reuses asset tag 1 with a DIFFERENT sac -> ReserveConflict (revert, no partial write)
        let res = client.try_create_pair(&b32(&env, 42), &b32(&env, 1), &b32(&env, 4), &sac_other, &sac_other, &amm, &amm, &amm, &1u64, &4u64);
        assert_eq!(res, Err(Ok(PoolError::ReserveConflict)), "re-pointing asset 1 to a different SAC must revert");
        assert!(client.lp_pair(&b32(&env, 42)).is_none(), "the conflicting create wrote nothing (tx rolled back)");
    }

    // The direct admin registration path uses the same no-repoint guard as create_pair. Re-registering the
    // same asset to the same SAC is idempotent, but changing its SAC would orphan or misroute existing notes.
    #[test]
    fn register_asset_refuses_reserve_repoint() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let asset = b32(&env, 50);
        let sac_a = Address::generate(&env);
        let sac_b = Address::generate(&env);

        client.register_asset(&asset, &sac_a);
        client.register_asset(&asset, &sac_a);
        let res = client.try_register_asset(&asset, &sac_b);

        assert_eq!(res, Err(Ok(PoolError::ReserveConflict)), "register_asset must not repoint a live asset tag");
        assert_eq!(client.reserve_of(&asset), sac_a, "failed repoint leaves the original reserve in place");
    }

    // LP note-class ids live in a reserved namespace. They must never be registered as ordinary fungible
    // reserves, or an LP-position note could be misrouted through the withdraw/deposit asset map.
    #[test]
    fn register_asset_rejects_reserved_lp_namespace() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let sac = Address::generate(&env);

        assert_eq!(
            client.try_register_asset(&u64_to_be32(&env, LP_ASSET_ID), &sac),
            Err(Ok(PoolError::BadAmount)),
            "legacy LP note-class tag is not a fungible reserve asset",
        );
        assert_eq!(
            client.try_register_asset(&u64_to_be32(&env, LP_TAG_BASE), &sac),
            Err(Ok(PoolError::BadAmount)),
            "per-pair LP note-class namespace is not a fungible reserve asset",
        );
        let normal_asset = b32(&env, 51);
        client.register_asset(&normal_asset, &sac);
        assert_eq!(client.reserve_of(&normal_asset), sac);
    }

    // Freezing verifier slots must also close the upgrade path; otherwise an operator could freeze verifiers
    // and later upload wasm that reopens those slots.
    #[test]
    fn freeze_verifiers_also_freezes_upgrades() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        client.freeze_verifiers();
        assert_eq!(
            client.try_upgrade(&b32(&env, 99)),
            Err(Ok(PoolError::Frozen)),
            "verifier freeze must be a full verifier-surface freeze, including wasm upgrade",
        );
    }

    // add_lp_confidential_for / remove_lp_confidential_for against a NEVER-created pair fail closed
    // (LpAmmNotSet) — the per-pair map is the allowlist; an unknown pair can't route to a rogue AMM.
    #[test]
    fn per_pair_lp_unknown_pair_fails_closed() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let from = Address::generate(&env);
        let unknown = b32(&env, 99);
        let add = client.try_add_lp_confidential_for(&unknown, &from, &100, &100, &0, &b32(&env, 7), &b32(&env, 8), &Bytes::new(&env), &Bytes::new(&env));
        assert_eq!(add, Err(Ok(PoolError::LpAmmNotSet)), "add for an unknown pair fails closed (map IS the allowlist)");
        // The remove path checks anchor-root membership BEFORE resolving the AMM, so an unknown pair with a
        // bogus anchor fails closed at the ring gate (BadAnchorRoot) — still fails closed, just an earlier gate.
        let rem = client.try_remove_lp_confidential_for(&unknown, &from, &50, &b32(&env, 1), &b32(&env, 2), &0u64, &Bytes::new(&env));
        assert!(rem.is_err(), "remove for an unknown pair fails closed");
    }

    // set_lp_pair (the granular writer) is admin-only and also refuses clobber.
    #[test]
    fn set_lp_pair_admin_only_and_no_clobber() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let a = Address::generate(&env);
        let tag = client.set_lp_pair(&b32(&env, 30), &a, &a, &a, &5u64, &6u64);
        assert_eq!(tag, LP_TAG_BASE, "granular writer assigns from the same counter");
        let res = client.try_set_lp_pair(&b32(&env, 30), &a, &a, &a, &5u64, &6u64);
        assert_eq!(res, Err(Ok(PoolError::PairExists)), "set_lp_pair refuses to clobber");
    }

    // A NON-admin cannot call deposit_internal: require_admin authorizes the stored
    // Admin, so mocking auth for a different address leaves admin.require_auth
    // unsatisfied and the invocation is rejected (no successful Ok return).
    #[test]
    fn deposit_internal_rejects_non_admin() {
        let env = Env::default();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        // Mock auth ONLY for an unrelated (non-admin) address. deposit_internal
        // requires the *admin* to authorize, so this must NOT succeed.
        let stranger = Address::generate(&env);
        let args = deposit_args(&env, &stranger, 100i128);
        let res = client
            .mock_auths(&[MockAuth {
                address: &stranger,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "deposit_internal",
                    args: args.clone(),
                    sub_invokes: &[],
                },
            }])
            .try_deposit_internal(
                &stranger,
                &b32(&env, 9),
                &100i128,
                &b32(&env, 7),
                &b32(&env, 8),
                &Bytes::new(&env),
                &Bytes::new(&env),
            );
        // Authorization for the admin is absent -> the call is rejected, never Ok.
        assert!(
            res.is_err(),
            "non-admin deposit_internal must be rejected, got {:?}",
            res
        );
    }

    // The ADMIN can call deposit_internal with a NON-denomination amount: the
    // internal path skips require_denom entirely, so a non-denom amount is NOT
    // rejected with BadDenom — it reaches mint_deposit and stops at NoReserve
    // (no reserve wired), proving the denomination rule was waived.
    #[test]
    fn deposit_internal_admin_exempt_from_denom() {
        let env = Env::default();
        let (id, admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let amount = 7i128; // NOT in the denomination set {100}
        let args = deposit_args(&env, &admin, amount);
        let res = client
            .mock_auths(&[MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "deposit_internal",
                    args,
                    sub_invokes: &[],
                },
            }])
            .try_deposit_internal(
                &admin,
                &b32(&env, 9),
                &amount,
                &b32(&env, 7),
                &b32(&env, 8),
                &Bytes::new(&env),
                &Bytes::new(&env),
            );
        // Crucially NOT BadDenom: the internal path is denom-exempt. With no reserve
        // wired, mint_deposit fails at NoReserve, confirming it cleared the denom gate.
        assert_eq!(
            res,
            Err(Ok(PoolError::NoReserve)),
            "admin deposit_internal must be denom-EXEMPT (NoReserve, not BadDenom)"
        );
    }

    // #37: an ALLOWLISTED MM funder (NOT the admin) may mint a denom-EXEMPT note via
    // deposit_internal by self-authorizing + self-funding (owner = funder). It clears the
    // auth gate through the funder path (not require_admin) and lands on NoReserve downstream
    // — same as the admin path — proving the allowlist relaxation works without admin. A
    // non-allowlisted address still hits require_admin (covered by deposit_internal_rejects_non_admin).
    #[test]
    fn deposit_internal_allowlisted_funder_self_funds() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let funder = Address::generate(&env);
        client.add_mm_funder(&funder);
        assert!(client.mm_funders().contains(&funder), "funder is on the allowlist");

        let amount = 7i128; // non-denomination: the internal path is denom-EXEMPT
        let res = client.try_deposit_internal(
            &funder,
            &b32(&env, 9),
            &amount,
            &b32(&env, 7),
            &b32(&env, 8),
            &Bytes::new(&env),
            &Bytes::new(&env),
        );
        assert_eq!(
            res,
            Err(Ok(PoolError::NoReserve)),
            "allowlisted funder must clear the auth gate (NoReserve downstream, not NotAdmin)"
        );

        // After revocation the same funder is back to admin-only (no longer on the list).
        client.remove_mm_funder(&funder);
        assert!(!client.mm_funders().contains(&funder), "funder revoked from the allowlist");
    }

    // AUTH-01: mint_deposit rejects owner == the pool's own address. Without the guard this falls through
    // to the reserve lookup and returns NoReserve (exactly like the admin test above); the guard makes it
    // BadAmount FIRST — blocking the net-zero pool→pool self-transfer that would otherwise mint an
    // unbacked, drainable note against reserves other depositors funded.
    #[test]
    fn auth01_rejects_pool_self_mint() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let res = client.try_deposit_internal(
            &id, // owner == the pool itself
            &b32(&env, 9),
            &100i128,
            &b32(&env, 7),
            &b32(&env, 8),
            &Bytes::new(&env),
            &Bytes::new(&env),
        );
        assert_eq!(
            res,
            Err(Ok(PoolError::BadAmount)),
            "owner == pool must be rejected at mint_deposit (AUTH-01), before the NoReserve path"
        );
    }

    // P1 (TTL keeper): bump_ttl is permissionless on an initialized pool (no auth; pays rent only) and
    // fails closed before init. An ops cron calls this so the instance entry never archives when traffic
    // is quiet.
    #[test]
    fn bump_ttl_keeper_permissionless_and_gated() {
        let env = Env::default();
        // fails closed before init (no setup): NotInitialized
        let raw = env.register(ConfibatchPool, ());
        let c_raw = ConfibatchPoolClient::new(&env, &raw);
        assert_eq!(
            c_raw.try_bump_ttl(),
            Err(Ok(PoolError::NotInitialized)),
            "keeper must fail closed before init"
        );
        // permissionless on an initialized pool — note: NO mock_all_auths, proving no auth is required
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        assert_eq!(client.try_bump_ttl(), Ok(Ok(())), "keeper is permissionless once initialized");
    }

    // #5: the observe-only outstanding accumulator: deposits add, the boundary subtracts, a
    // settle moves the NET between asset buckets, and it saturates (never panics) so it can
    // never break a value-moving path.
    #[test]
    fn outstanding_accumulator_tracks_value() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            let ax = b32(&env, 4);
            let ay = b32(&env, 5);
            let get = |a: &BytesN<32>| -> i128 {
                env.storage().persistent().get(&DataKey::OutstandingNoteValue(a.clone())).unwrap_or(0)
            };
            outstanding_add(&env, &ax, 1000).unwrap(); // deposit
            outstanding_add(&env, &ax, 500).unwrap(); // deposit
            assert_eq!(get(&ax), 1500, "deposits accumulate");
            outstanding_add(&env, &ax, -300).unwrap(); // withdraw boundary
            assert_eq!(get(&ax), 1200, "boundary decrements");
            // settle: X net-sold (x2 1100 > rx 1000), Y net-bought (y2 909 < ry 1000).
            // settle_outstanding_move reads PairX/PairY itself, so set them first.
            env.storage().instance().set(&DataKey::PairX, &ax);
            env.storage().instance().set(&DataKey::PairY, &ay);
            settle_outstanding_move(&env, 1000, 1000, 1100, 909).unwrap();
            assert_eq!(get(&ax), 1100, "settle: X bucket down by net (1000-1100)");
            assert_eq!(get(&ay), 91, "settle: Y bucket up by net (1000-909)");
            // saturating: extreme deltas must not panic (observe-only safety).
            outstanding_add(&env, &ax, i128::MAX).unwrap();
            outstanding_add(&env, &ax, i128::MAX).unwrap();
            assert_eq!(get(&ax), i128::MAX, "saturates instead of overflowing");
        });
    }

    // The PUBLIC deposit path still ENFORCES the denomination rule: an authorized
    // owner depositing a non-denomination amount is rejected with BadDenom, before
    // any reserve/verifier work (contrast with the internal path above).
    #[test]
    fn public_deposit_rejects_non_denom() {
        let env = Env::default();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let owner = Address::generate(&env);
        let amount = 7i128; // NOT in the denomination set {100}
        let args = deposit_args(&env, &owner, amount);
        let res = client
            .mock_auths(&[MockAuth {
                address: &owner,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "deposit",
                    args,
                    sub_invokes: &[],
                },
            }])
            .try_deposit(
                &owner,
                &b32(&env, 9),
                &amount,
                &b32(&env, 7),
                &b32(&env, 8),
                &Bytes::new(&env),
                &Bytes::new(&env),
            );
        assert_eq!(
            res,
            Err(Ok(PoolError::BadDenom)),
            "public deposit must reject a non-denomination amount with BadDenom"
        );
    }

    // #46④: the WITHDRAW-WITH-CHANGE public payout is denom-gated too (lib.rs:511), at
    // parity with deposit/withdraw — a non-denomination amount_out is rejected with
    // BadDenom before any proof work, so the change path can't be used to smuggle an
    // arbitrary-amount (fingerprinting) public exit. (The change note carries the
    // non-denom remainder in-circuit; only the cleartext payout must be a denomination.)
    #[test]
    fn withdraw_with_change_rejects_non_denom() {
        let env = Env::default();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let to = Address::generate(&env);
        let amount_out = 7i128; // NOT in the denomination set {100}
        // No require_auth precedes the denom gate (withdraw is proof-gated, relayer-submitted),
        // so this resolves at require_denom with no mocked auth.
        let res = client.try_withdraw_with_change(
            &to,
            &b32(&env, 9),     // asset_id
            &amount_out,
            &0i128,            // fee
            &b32(&env, 2),     // anchor_root
            &b32(&env, 3),     // nf
            &0u64,             // current_index
            &b32(&env, 7),     // new_root
            &b32(&env, 8),     // change_cm
            &Bytes::new(&env), // proof
            &Bytes::new(&env), // change_ct
        );
        assert_eq!(
            res,
            Err(Ok(PoolError::BadDenom)),
            "withdraw_with_change must reject a non-denomination payout with BadDenom"
        );
    }

    // Sanity: with the denom rule active, a VALID denomination (100) on the public
    // path clears the denom gate and lands on the SAME downstream failure
    // (NoReserve) as the denom-exempt internal path — i.e. the only difference
    // between the two paths is the denomination gate, nothing else.
    #[test]
    fn public_deposit_valid_denom_clears_gate() {
        let env = Env::default();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);

        let owner = Address::generate(&env);
        let amount = 100i128; // IS in the denomination set {100}
        let args = deposit_args(&env, &owner, amount);
        let res = client
            .mock_auths(&[MockAuth {
                address: &owner,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "deposit",
                    args,
                    sub_invokes: &[],
                },
            }])
            .try_deposit(
                &owner,
                &b32(&env, 9),
                &amount,
                &b32(&env, 7),
                &b32(&env, 8),
                &Bytes::new(&env),
                &Bytes::new(&env),
            );
        assert_eq!(
            res,
            Err(Ok(PoolError::NoReserve)),
            "a valid denomination must clear the denom gate (NoReserve downstream)"
        );
    }

    // Phase 4 — add_liquidity_confidential preconditions (the early gates that fire BEFORE the
    // AMM routing / proof verify, so they need no verifier or live AMM). The happy path (auth +
    // mini_amm pull via authorize_as_current_contract + minted-binding) is validated by the live
    // testnet e2e, where the real verifier + real SAC auth enforcement actually run.
    #[test]
    fn add_liquidity_confidential_rejects_zero_amount() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let from = Address::generate(&env);
        // amount_a = 0 -> BadAmount, before any storage read / token transfer / verify.
        let res = client.try_add_liquidity_confidential(
            &from,
            &0i128,
            &50i128,
            &b32(&env, 8),  // lp_cm
            &b32(&env, 7),  // new_root
            &Bytes::new(&env),
            &Bytes::new(&env),
        );
        assert_eq!(res, Err(Ok(PoolError::BadAmount)), "zero contribution must be rejected");
    }

    #[test]
    fn add_liquidity_confidential_requires_lp_amm() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env); // setup never wires the LP AMM
        let client = ConfibatchPoolClient::new(&env, &id);
        let from = Address::generate(&env);
        // Valid amounts, but set_lp_amm was never called -> fail closed (LpAmmNotSet), never
        // route a contribution to an unconfigured/attacker AMM.
        let res = client.try_add_liquidity_confidential(
            &from,
            &50i128,
            &50i128,
            &b32(&env, 8),
            &b32(&env, 7),
            &Bytes::new(&env),
            &Bytes::new(&env),
        );
        assert_eq!(res, Err(Ok(PoolError::LpAmmNotSet)), "must fail closed without a wired LP AMM");
    }

    // Phase 4 — remove_liquidity_confidential early gates (before the ring/verify/AMM path). The happy path
    // (LP-note spend via the WithdrawVerifier + mini_amm.remove_liquidity payout) is validated by the live e2e.
    #[test]
    fn remove_liquidity_confidential_rejects_zero_shares() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let recipient = Address::generate(&env);
        let res = client.try_remove_liquidity_confidential(&recipient, &0i128, &b32(&env, 1), &b32(&env, 9), &0u64, &Bytes::new(&env));
        assert_eq!(res, Err(Ok(PoolError::BadAmount)), "zero shares must be rejected");
    }

    #[test]
    fn remove_liquidity_confidential_rejects_unknown_anchor() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env); // fresh pool: the root ring is empty
        let client = ConfibatchPoolClient::new(&env, &id);
        let recipient = Address::generate(&env);
        // valid shares but an anchor root that isn't in the ring -> reject before spending/paying out.
        let res = client.try_remove_liquidity_confidential(&recipient, &50i128, &b32(&env, 9), &b32(&env, 8), &0u64, &Bytes::new(&env));
        assert_eq!(res, Err(Ok(PoolError::BadAnchorRoot)), "an anchor root not in the ring must be rejected");
    }

    #[test]
    fn remove_partial_shielded_rejects_zero_shares() {
        let env = Env::default();
        env.mock_all_auths();
        let (id, _admin) = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let e = Bytes::new(&env);
        let res = client.try_remove_partial_shielded(&b32(&env, 1), &b32(&env, 9), &0i128, &0u64, &b32(&env, 2), &b32(&env, 3), &b32(&env, 4), &b32(&env, 5), &b32(&env, 6), &b32(&env, 7), &e, &e, &e, &e, &e, &e);
        assert_eq!(res, Err(Ok(PoolError::BadAmount)), "zero remove_shares must be rejected");
    }
}

// route_net_pair / settle auto-route reserve-staleness race (item:
// e2e-route-reserve-staleness-race). settle_batch_vn proves the keyless clearing
// against `(rx, ry) = current_reserves()` (lib.rs:989), then — AFTER the commit —
// calls do_route_pair (lib.rs:1054/1057) which re-reads the pair's LIVE reserves
// inside do_route_pair_checked (lib.rs:1147-1148) and routes the net with NO
// min-out: the ONLY slippage guard is the internal `- 0.5% - 1` under-ask. The
// admin route_net entrypoint (lib.rs:592) DOES take a `min_out`; the auto-route /
// route_net_pair path does NOT. So if the pair's reserves drift between the
// proven snapshot and the route (a sandwich/front-run in the same ledger window),
// the routed output silently lands below what the proof priced — there is no
// tolerance band to reject it.
//
// This drives the real do_route_pair_checked + current_reserves against a minimal
// Soroswap-shaped mock pair (token_0 / get_reserves / swap(a0,a1,to)) plus real
// SAC tokens, with no live chain / verifier. It proves:
//   (a) current_reserves and do_route_pair_checked both read the pair's LIVE
//       reserves (so they drift together post-commit), and
//   (b) draining the output reserve between the proven read and the route makes
//       the routed output drop FAR below the proven price, with nothing in the
//       routed path to floor it — the staleness race is unguarded.
#[cfg(test)]
mod route_reserve_staleness_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    // Minimal Soroswap-compatible pair: exposes exactly the three methods the pool
    // invokes (token_0 / get_reserves / swap). Reserves live in storage so a test
    // can mutate them mid-flight to simulate live drift between the proof and the
    // route. swap() pays the requested output token amount out to `to` from the
    // pair's own balance (push model: the input was already transferred in).
    #[contracttype]
    enum PairKey {
        Token0,
        Token1,
        R0,
        R1,
        Bonus,
    }

    #[contract]
    pub struct MockPair;

    #[contractimpl]
    impl MockPair {
        pub fn setup(env: Env, token_0: Address, token_1: Address, r0: i128, r1: i128) {
            env.storage().instance().set(&PairKey::Token0, &token_0);
            env.storage().instance().set(&PairKey::Token1, &token_1);
            env.storage().instance().set(&PairKey::R0, &r0);
            env.storage().instance().set(&PairKey::R1, &r1);
            env.storage().instance().set(&PairKey::Bonus, &0i128);
        }
        // Mutate reserves directly — the "live drift" a front-runner would cause.
        pub fn set_reserves(env: Env, r0: i128, r1: i128) {
            env.storage().instance().set(&PairKey::R0, &r0);
            env.storage().instance().set(&PairKey::R1, &r1);
        }
        pub fn set_bonus(env: Env, bonus: i128) {
            env.storage().instance().set(&PairKey::Bonus, &bonus);
        }
        pub fn token_0(env: Env) -> Address {
            env.storage().instance().get(&PairKey::Token0).unwrap()
        }
        pub fn get_reserves(env: Env) -> (i128, i128) {
            (
                env.storage().instance().get(&PairKey::R0).unwrap(),
                env.storage().instance().get(&PairKey::R1).unwrap(),
            )
        }
        // a0/a1 are the requested outputs; pay whichever is > 0 to `to`. (The pool
        // computes amount_out off-chain and asks the pair for exactly it.)
        pub fn swap(env: Env, amount_0_out: i128, amount_1_out: i128, to: Address) {
            let t0: Address = env.storage().instance().get(&PairKey::Token0).unwrap();
            let t1: Address = env.storage().instance().get(&PairKey::Token1).unwrap();
            let here = env.current_contract_address();
            let bonus: i128 = env.storage().instance().get(&PairKey::Bonus).unwrap_or(0);
            if amount_0_out > 0 {
                token::TokenClient::new(&env, &t0).transfer(&here, &to, &(amount_0_out + bonus));
            }
            if amount_1_out > 0 {
                token::TokenClient::new(&env, &t1).transfer(&here, &to, &(amount_1_out + bonus));
            }
        }
    }

    // Replicate the pool's own routed-output math (do_route_pair_checked) so the
    // test asserts on the EXACT figure the contract would route for given reserves
    // — this is the "what the proof priced vs what live routing pays" comparison.
    fn routed_out(rin: i128, rout: i128, amount_in: i128) -> i128 {
        // Mirror of routed_out_checked: canonical UniswapV2 0.3%-fee output UNDER-ASKED by ~0.5%+1
        // (the K-check safety margin for real Soroswap pairs — see routed_out_checked).
        let fee_in = amount_in * 997;
        let raw = (rout * fee_in) / (rin * 1000 + fee_in);
        raw - raw / 200 - 1
    }

    // #64-B: the settle auto-route now carries a slippage floor derived from the PROVEN
    // reserve snapshot. The SAME drift that used to execute unguarded now REVERTS with
    // SlippageExceeded when the floor is applied — and with floor 0 (no protection) it still
    // executes, proving the floor is exactly what rejects the shortfall.
    #[test]
    fn auto_route_slippage_floor_rejects_drift() {
        let env = Env::default();
        env.mock_all_auths();

        let pool_id = env.register(ConfibatchPool, ());
        let pair_id = env.register(MockPair, ());

        // Two SAC tokens: token_in (X) is pushed to the pair by the route; token_out
        // (Y) is paid back to the pool by the pair's swap.
        let admin = Address::generate(&env);
        let sac_x = env.register_stellar_asset_contract_v2(admin.clone());
        let sac_y = env.register_stellar_asset_contract_v2(admin.clone());
        let tok_x = sac_x.address();
        let tok_y = sac_y.address();
        let xadmin = soroban_sdk::token::StellarAssetClient::new(&env, &tok_x);
        let yadmin = soroban_sdk::token::StellarAssetClient::new(&env, &tok_y);

        // token_0 of the pair is X; the pool's RouteTokenX must agree so the X/Y
        // orientation in current_reserves + do_route_pair_checked lines up.
        let proven_rx: i128 = 1_000_000_000; // X reserve at proof time
        let proven_ry: i128 = 1_000_000_000; // Y reserve at proof time
        let pair_client = MockPairClient::new(&env, &pair_id);
        pair_client.setup(&tok_x, &tok_y, &proven_rx, &proven_ry);

        // Fund the pair with Y (to pay swap output) and the pool with X (to push in).
        let net_in: i128 = 10_000_000; // the batch's net X imbalance to route
        yadmin.mint(&pair_id, &proven_ry); // pair holds its Y reserve for payout
        xadmin.mint(&pool_id, &net_in); // pool holds the net X to push

        // Configure the pool's route exactly as set_route would.
        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::RoutePair, &pair_id);
            env.storage().instance().set(&DataKey::RouteTokenX, &tok_x);
            env.storage().instance().set(&DataKey::RouteTokenY, &tok_y);
        });

        // current_reserves reads the pair's LIVE reserves in the pool's X/Y orientation —
        // the snapshot the clearing proof is bound to (proven = live at proof time).
        let (rx, ry) = env.as_contract(&pool_id, || current_reserves(&env));
        assert_eq!((rx, ry), (proven_rx, proven_ry), "proven snapshot = live reserves");
        let proven_out = routed_out(rx, ry, net_in); // what the proof priced the net at
        let floor = proven_out - proven_out / 100; // 1% band (matches set_route_slip_bps default 100)

        // DRIFT: a front-runner halves the Y (output) reserve between the proven read and
        // the route. The proof is bound to the stale (rx, ry); the floor catches the gap.
        let drift_ry: i128 = proven_ry / 2;
        pair_client.set_reserves(&proven_rx, &drift_ry);

        // (a) WITH the proven floor: the drifted route is REJECTED with SlippageExceeded and
        // NO tokens move (the floor is checked before the transfer/swap).
        let rejected = env.as_contract(&pool_id, || {
            do_route_pair_checked(&env, &pair_id, &tok_x, net_in, floor)
        });
        assert_eq!(
            rejected,
            Err(PoolError::SlippageExceeded),
            "drifted route below the proven floor must revert with SlippageExceeded"
        );
        assert_eq!(
            token::TokenClient::new(&env, &tok_x).balance(&pool_id),
            net_in,
            "rejected route must not move tokens — pool keeps its X"
        );

        // (b) WITH floor 0 (no protection): the SAME drifted route still executes at the
        // worse live price — confirming the floor, not anything else, is what reverts (a).
        let live_out = env.as_contract(&pool_id, || {
            do_route_pair_checked(&env, &pair_id, &tok_x, net_in, 0).unwrap()
        });
        assert_eq!(live_out, routed_out(proven_rx, drift_ry, net_in), "routes against LIVE (drifted) reserves");
        assert!(live_out < floor, "live drifted output {} is below the proven floor {}", live_out, floor);
        assert_eq!(
            token::TokenClient::new(&env, &tok_y).balance(&pool_id),
            live_out,
            "unprotected route (floor 0) still settles at the worse price"
        );
    }

    // #64-B: the slippage-bps admin setter defaults to 100 (1%) when unset, persists a set
    // value, and caps at 1000 (10%) — a larger band is rejected with BadAmount.
    #[test]
    fn set_route_slip_bps_caps_and_defaults() {
        let env = Env::default();
        env.mock_all_auths();
        let pool_id = env.register(ConfibatchPool, ());
        let admin = Address::generate(&env);
        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::Admin, &admin);
        });
        let client = ConfibatchPoolClient::new(&env, &pool_id);
        assert_eq!(client.get_route_slip_bps(), 100, "unset slippage bps defaults to 100 (1%)");
        client.set_route_slip_bps(&250);
        assert_eq!(client.get_route_slip_bps(), 250, "setter persists the value");
        assert_eq!(
            client.try_set_route_slip_bps(&1001),
            Err(Ok(PoolError::BadAmount)),
            "slippage bps > 1000 (10%) must be rejected"
        );
        client.set_route_slip_bps(&1000);
        assert_eq!(client.get_route_slip_bps(), 1000, "1000 bps (10%) is the accepted cap");
    }

    // Counterpart: the admin route_net path DOES carry a min_out, so the SAME drift
    // is rejectable there. We assert the floor's presence by feeding do_route_pair_checked
    // (the shared math) and showing the proven min-out is NOT met post-drift — i.e.
    // a tolerance band, if applied to the routed path, would have caught it.
    #[test]
    fn proven_min_out_would_reject_drifted_route() {
        // proof priced the net against these reserves:
        let (rx, ry, net_in) = (1_000_000_000i128, 1_000_000_000i128, 10_000_000i128);
        let proven_out = routed_out(rx, ry, net_in);
        // a reasonable min-out (proven minus a 1% tolerance band) the routed path lacks:
        let min_out = proven_out - proven_out / 100;
        // after the same drain-half drift the live output falls below that floor:
        let live_out = routed_out(rx, ry / 2, net_in);
        assert!(
            live_out < min_out,
            "drifted route {} should violate a proven min-out floor {}",
            live_out,
            min_out
        );
    }

    // ReserveX/Y is VESTIGIAL accounting, not custody. This locks in the invariant
    // the live pool relies on: with a RoutePair configured (the production config),
    // drift in the stored ReserveX/ReserveY slot CANNOT reach pricing. The pricing
    // read `current_reserves()` (lib.rs) — what settle_batch / settle_batch_v2 /
    // settle_batch_vn bind the clearing proof to — returns the LIVE route-pair
    // reserves and ignores the stored slot; the public `reserves()` view merely
    // echoes that slot for display. We drift the slot to the EXACT figure the live
    // appPool actually holds (ReserveX/Y = 22_734_049_385_528 / 4_948_678_070_866,
    // ≈ 2.27M / 494K at 7 decimals) — wildly decoupled from real custody — and show
    // it changes no priced outcome. The final step specs the latent hazard: the slot
    // becomes load-bearing ONLY in the no-route fallback.
    #[test]
    fn reserves_view_is_display_only_not_priced() {
        let env = Env::default();

        let pool_id = env.register(ConfibatchPool, ());
        let pair_id = env.register(MockPair, ());

        // No token transfers occur in this test (current_reserves only calls the
        // pair's token_0/get_reserves), so plain generated addresses suffice.
        let tok_x = Address::generate(&env);
        let tok_y = Address::generate(&env);

        // LIVE route-pair reserves = the real liquidity pricing must use.
        let live_rx: i128 = 1_000_000_000;
        let live_ry: i128 = 2_000_000_000;
        MockPairClient::new(&env, &pair_id).setup(&tok_x, &tok_y, &live_rx, &live_ry);

        // Configure the route exactly as set_route would (the live-pool config) AND
        // drift the stored slot to the live appPool's actual drifted values.
        let drift_x: i128 = 22_734_049_385_528;
        let drift_y: i128 = 4_948_678_070_866;
        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::RoutePair, &pair_id);
            env.storage().instance().set(&DataKey::RouteTokenX, &tok_x);
            env.storage().instance().set(&DataKey::RouteTokenY, &tok_y);
            env.storage().instance().set(&DataKey::ReserveX, &drift_x);
            env.storage().instance().set(&DataKey::ReserveY, &drift_y);
        });

        // (1) reserves() is DISPLAY-ONLY: it echoes the raw (drifted) slot verbatim.
        let pool_client = ConfibatchPoolClient::new(&env, &pool_id);
        assert_eq!(
            pool_client.reserves(),
            (drift_x, drift_y),
            "reserves() echoes the stored slot — a display getter, not custody/pricing"
        );

        // (2) current_reserves() is the PRICING read: with a RoutePair set it returns
        // the LIVE pair reserves and ignores the drifted slot entirely.
        let priced = env.as_contract(&pool_id, || current_reserves(&env));
        assert_eq!(
            priced,
            (live_rx, live_ry),
            "pricing uses LIVE route-pair reserves, NOT the drifted ReserveX/Y slot"
        );
        assert_ne!(
            priced,
            pool_client.reserves(),
            "display-slot drift must NOT reach pricing while a RoutePair is set"
        );

        // (3) SPEC of the latent hazard: the stored slot is load-bearing ONLY in the
        // no-route fallback. Drop the route and current_reserves() falls back to the
        // (drifted) slot — documenting why a no-route deployment must never trust it.
        env.as_contract(&pool_id, || {
            env.storage().instance().remove(&DataKey::RoutePair);
        });
        let fallback = env.as_contract(&pool_id, || current_reserves(&env));
        assert_eq!(
            fallback,
            (drift_x, drift_y),
            "no-route fallback reads the stored slot — only here is ReserveX/Y load-bearing"
        );
    }

    #[test]
    fn amount_blind_routed_batch_moves_and_records_atomically() {
        let env = Env::default();
        env.mock_all_auths();
        let pool_id = env.register(ConfibatchPool, ());
        let pair_id = env.register(MockPair, ());
        let admin = Address::generate(&env);
        let sac_x = env.register_stellar_asset_contract_v2(admin.clone());
        let sac_y = env.register_stellar_asset_contract_v2(admin.clone());
        let tok_x = sac_x.address();
        let tok_y = sac_y.address();
        let fr = |n: u8| {
            let mut value = [0u8; 32];
            value[31] = n;
            BytesN::from_array(&env, &value)
        };
        let tag_x = fr(2);
        let tag_y = fr(4);
        let empty_root = fr(1);
        let swap_root = fr(5);
        let reserves = 1_000_000_000i128;
        let sum_in = 10_000_000i128;
        let requested = routed_out(reserves, reserves, sum_in);
        let adapter_bonus = 123i128;
        let expected = requested + adapter_bonus;

        let pair_client = MockPairClient::new(&env, &pair_id);
        pair_client.setup(&tok_x, &tok_y, &reserves, &reserves);
        pair_client.set_bonus(&adapter_bonus);
        soroban_sdk::token::StellarAssetClient::new(&env, &tok_x).mint(&pool_id, &(sum_in * 2));
        soroban_sdk::token::StellarAssetClient::new(&env, &tok_y).mint(&pair_id, &reserves);
        env.as_contract(&pool_id, || {
            env.storage().instance().set(&DataKey::Admin, &admin);
            env.storage().instance().set(&DataKey::CmRoot, &empty_root);
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
            env.storage().instance().set(&DataKey::RoutePair, &pair_id);
            env.storage().instance().set(&DataKey::RouteTokenX, &tok_x);
            env.storage().instance().set(&DataKey::RouteTokenY, &tok_y);
            env.storage().persistent().set(&DataKey::Reserve(tag_x.clone()), &tok_x);
            env.storage().persistent().set(&DataKey::Reserve(tag_y.clone()), &tok_y);
        });
        let client = ConfibatchPoolClient::new(&env, &pool_id);
        let batch_ok = fr(7);
        let net = client.batch_execute_routed(
            &batch_ok, &tag_x, &tag_y, &sum_in, &(requested - 1), &swap_root, &2, &0, &tok_y,
        );
        assert_eq!(net, expected);
        assert_eq!(token::TokenClient::new(&env, &tok_y).balance(&pool_id), expected);
        env.as_contract(&pool_id, || {
            let bod: BatchOut = env.storage().persistent().get(&DataKey::BatchOut(batch_ok.clone())).unwrap();
            assert_eq!(bod.sum_in, sum_in);
            assert_eq!(bod.sum_out, expected);
        });

        // A floor above the live output reverts both the route and BatchOut.
        let batch_rejected = fr(8);
        let x_before = token::TokenClient::new(&env, &tok_x).balance(&pool_id);
        let rejected = client.try_batch_execute_routed(
            &batch_rejected, &tag_x, &tag_y, &sum_in, &(requested + 1), &swap_root, &2, &0, &tok_y,
        );
        assert_eq!(rejected, Err(Ok(PoolError::SlippageExceeded)));
        assert_eq!(token::TokenClient::new(&env, &tok_x).balance(&pool_id), x_before);
        env.as_contract(&pool_id, || {
            assert!(!env.storage().persistent().has(&DataKey::BatchOut(batch_rejected)));
        });
    }
}

// SPLIT entry (amount-blind Layer1a) — gate the pre-verify guards + the additive verifier setter. The
// deploy is GATED (needs the ceremony); these prove the entry's boundary checks (which run BEFORE any
// verifier work) and that the new setter can't be reached without the wired verifier. A full
// prove->verify->append path is covered off-chain by scripts/test_split.mjs (circuit soundness).
#[cfg(test)]
mod split_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn root(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }
    // minimal initialized pool (clears require_init); seed the recent-root ring with `anchor` if given.
    fn setup(env: &Env, anchor: Option<u8>) -> Address {
        let id = env.register(ConfibatchPool, ());
        let admin = Address::generate(env);
        env.as_contract(&id, || {
            env.storage().instance().set(&DataKey::Admin, &admin);
            env.storage().instance().set(&DataKey::CmRoot, &root(env, 1));
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
            let mut ring: Vec<BytesN<32>> = Vec::new(env);
            if let Some(a) = anchor {
                ring.push_back(root(env, a));
            }
            env.storage().instance().set(&DataKey::RootRing, &ring);
        });
        id
    }

    // anchor not in the recent-root ring -> BadAnchorRoot (before any proof work).
    #[test]
    fn split_rejects_bad_anchor() {
        let env = Env::default();
        let id = setup(&env, None); // empty ring
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_split(
            &root(&env, 9), &root(&env, 3), &9u64, &0u64,
            &root(&env, 20), &root(&env, 21), &root(&env, 22), &root(&env, 23),
            &Bytes::new(&env), &Bytes::new(&env), &Bytes::new(&env),
        );
        assert_eq!(r, Err(Ok(PoolError::BadAnchorRoot)));
    }

    // a nullifier already spent -> DoubleSpend (anchor IS in the ring, so it gets past ring_contains).
    #[test]
    fn split_rejects_double_spend() {
        let env = Env::default();
        let id = setup(&env, Some(5));
        env.as_contract(&id, || {
            mark_nullifier_spent(&env, &root(&env, 3));
        });
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_split(
            &root(&env, 5), &root(&env, 3), &9u64, &0u64,
            &root(&env, 20), &root(&env, 21), &root(&env, 22), &root(&env, 23),
            &Bytes::new(&env), &Bytes::new(&env), &Bytes::new(&env),
        );
        assert_eq!(r, Err(Ok(PoolError::DoubleSpend)));
    }

    // current_index beyond the on-chain frontier (NextIndex=0) -> BadAmount.
    #[test]
    fn split_rejects_stale_index() {
        let env = Env::default();
        let id = setup(&env, Some(5));
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_split(
            &root(&env, 5), &root(&env, 4), &9u64, &5u64,
            &root(&env, 20), &root(&env, 21), &root(&env, 22), &root(&env, 23),
            &Bytes::new(&env), &Bytes::new(&env), &Bytes::new(&env),
        );
        assert_eq!(r, Err(Ok(PoolError::BadAmount)));
    }

    // oversized note ciphertext -> CtTooLong (the very first guard, before canonical/ring).
    #[test]
    fn split_rejects_oversized_ct() {
        let env = Env::default();
        let id = setup(&env, Some(5));
        let client = ConfibatchPoolClient::new(&env, &id);
        let big = Bytes::from_slice(&env, &[0u8; (NOTE_CT_MAX as usize) + 1]);
        let r = client.try_split(
            &root(&env, 5), &root(&env, 4), &9u64, &0u64,
            &root(&env, 20), &root(&env, 21), &root(&env, 22), &root(&env, 23),
            &Bytes::new(&env), &big, &Bytes::new(&env),
        );
        assert_eq!(r, Err(Ok(PoolError::CtTooLong)));
    }
}

// SWAP_CLAIM over-subscription fix (3b) — the batch-scoped swap_root + claimed<=k guard. Gate the guard
// (runs before any verifier work): a batch at capacity refuses further claims. Full membership soundness
// (batch-subtree proof) is exercised off-chain by scripts/e2e_swap_decoupled.mjs. Deploy is GATED.
#[cfg(test)]
mod swap_claim_fix_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn root(env: &Env, n: u8) -> BytesN<32> {
        let mut a = [0u8; 32];
        a[31] = n;
        BytesN::from_array(env, &a)
    }
    fn setup(env: &Env) -> Address {
        let id = env.register(ConfibatchPool, ());
        env.as_contract(&id, || {
            // require_init needs Admin + CmRoot + NextIndex; swap_claim itself is not admin-gated.
            env.storage().instance().set(&DataKey::Admin, &Address::generate(env));
            env.storage().instance().set(&DataKey::CmRoot, &root(env, 1));
            env.storage().instance().set(&DataKey::NextIndex, &0u64);
            env.storage().persistent().set(&DataKey::Reserve(root(env, 2)), &Address::generate(env));
            env.storage().persistent().set(&DataKey::Reserve(root(env, 4)), &Address::generate(env));
        });
        id
    }

    // a batch already at capacity (claimed == k) refuses another claim with BatchFull, BEFORE any verify.
    #[test]
    fn swap_claim_rejects_oversubscription() {
        let env = Env::default();
        let id = setup(&env);
        let bid = root(&env, 7);
        env.as_contract(&id, || {
            let bod = BatchOut { asset_in: root(&env, 2), asset_out: root(&env, 4), sum_in: 10, sum_out: 10, swap_root: root(&env, 5) };
            env.storage().persistent().set(&DataKey::BatchOut(bid.clone()), &bod);
            env.storage().persistent().set(&DataKey::BatchCap(bid.clone()), &BatchCap { k: 1, claimed: 1 });
        });
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_swap_claim(&bid, &root(&env, 3), &root(&env, 8), &root(&env, 9), &Bytes::new(&env), &Bytes::new(&env));
        assert_eq!(r, Err(Ok(PoolError::BatchFull)));
    }

    // a batch with spare capacity (claimed < k) gets PAST the BatchFull guard (then fails later at the
    // unset verifier — proving the guard fired only at capacity, not spuriously).
    #[test]
    fn swap_claim_under_capacity_passes_guard() {
        let env = Env::default();
        let id = setup(&env);
        let bid = root(&env, 7);
        env.as_contract(&id, || {
            let bod = BatchOut { asset_in: root(&env, 2), asset_out: root(&env, 4), sum_in: 10, sum_out: 10, swap_root: root(&env, 5) };
            env.storage().persistent().set(&DataKey::BatchOut(bid.clone()), &bod);
            env.storage().persistent().set(&DataKey::BatchCap(bid.clone()), &BatchCap { k: 3, claimed: 0 });
        });
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_swap_claim(&bid, &root(&env, 3), &root(&env, 8), &root(&env, 9), &Bytes::new(&env), &Bytes::new(&env));
        assert!(r != Err(Ok(PoolError::BatchFull)), "under-capacity claim must not be rejected as BatchFull");
    }

    // a LEGACY unscoped batch (BatchOut present, NO BatchCap — as the deprecated batch_execute would leave it)
    // is REFUSED (NoBatch) — the old global-root over-claim path is closed by the additive fix.
    #[test]
    fn swap_claim_refuses_legacy_uncapped_batch() {
        let env = Env::default();
        let id = setup(&env);
        let bid = root(&env, 7);
        env.as_contract(&id, || {
            let bod = BatchOut { asset_in: root(&env, 2), asset_out: root(&env, 4), sum_in: 10, sum_out: 10, swap_root: root(&env, 5) }; // no BatchCap set
            env.storage().persistent().set(&DataKey::BatchOut(bid.clone()), &bod);
        });
        let client = ConfibatchPoolClient::new(&env, &id);
        let r = client.try_swap_claim(&bid, &root(&env, 3), &root(&env, 8), &root(&env, 9), &Bytes::new(&env), &Bytes::new(&env));
        assert_eq!(r, Err(Ok(PoolError::NoBatch)));
    }

    // A scoped batch id is single-use: overwriting BatchOut/BatchCap would reset capacity and reprice claims.
    #[test]
    fn batch_execute_scoped_refuses_batch_id_reuse() {
        let env = Env::default();
        env.mock_all_auths();
        let id = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let bid = root(&env, 7);
        let fee_asset = Address::generate(&env);

        client.batch_execute_scoped(&bid, &root(&env, 2), &root(&env, 4), &10, &10, &root(&env, 5), &1, &0, &fee_asset);
        let r = client.try_batch_execute_scoped(&bid, &root(&env, 2), &root(&env, 4), &10, &10, &root(&env, 6), &1, &0, &fee_asset);

        assert_eq!(r, Err(Ok(PoolError::PairExists)));
    }

    #[test]
    fn batch_execute_scoped_caps_venue_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let id = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let fee_asset = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.set_protocol_fee(&0, &treasury);

        let r = client.try_batch_execute_scoped(&root(&env, 7), &root(&env, 2), &root(&env, 4), &10, &10_000, &root(&env, 5), &1, &26, &fee_asset);

        assert_eq!(r, Err(Ok(PoolError::BadAmount)));
        assert_eq!(client.swap_fee_accrued(&fee_asset), 0);
    }

    #[test]
    fn batch_execute_scoped_rejects_unregistered_assets() {
        let env = Env::default();
        env.mock_all_auths();
        let id = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let fee_asset = Address::generate(&env);

        let r = client.try_batch_execute_scoped(
            &root(&env, 7),
            &root(&env, 9),
            &root(&env, 4),
            &10,
            &10,
            &root(&env, 5),
            &1,
            &0,
            &fee_asset,
        );

        assert_eq!(r, Err(Ok(PoolError::NoReserve)));
    }

    #[test]
    fn swap_commit_bound_rejects_unbound_or_unknown_route_assets_before_proof_work() {
        let env = Env::default();
        let id = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let empty = Bytes::new(&env);

        let same = client.try_swap_commit_bound(
            &root(&env, 1),
            &root(&env, 3),
            &root(&env, 5),
            &root(&env, 6),
            &root(&env, 7),
            &root(&env, 2),
            &root(&env, 2),
            &empty,
            &empty,
        );
        assert_eq!(same, Err(Ok(PoolError::BadAmount)));

        let unknown = client.try_swap_commit_bound(
            &root(&env, 1),
            &root(&env, 3),
            &root(&env, 5),
            &root(&env, 6),
            &root(&env, 7),
            &root(&env, 9),
            &root(&env, 4),
            &empty,
            &empty,
        );
        assert_eq!(unknown, Err(Ok(PoolError::NoReserve)));
    }

    #[test]
    fn batch_execute_scoped_stores_net_output_and_accrues_sweepable_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let id = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &id);
        let bid = root(&env, 7);
        let treasury = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let fee_asset = env.register_stellar_asset_contract_v2(token_admin.clone()).address();
        soroban_sdk::token::StellarAssetClient::new(&env, &fee_asset).mint(&id, &50);
        client.set_protocol_fee(&0, &treasury);
        env.as_contract(&id, || {
            env.storage().persistent().set(&DataKey::Reserve(root(&env, 4)), &fee_asset);
        });

        client.batch_execute_scoped(&bid, &root(&env, 2), &root(&env, 4), &10, &20_000, &root(&env, 5), &1, &5, &fee_asset);

        env.as_contract(&id, || {
            let bod: BatchOut = env.storage().persistent().get(&DataKey::BatchOut(bid.clone())).unwrap();
            assert_eq!(bod.sum_out, 19_990);
        });
        assert_eq!(client.swap_fee_accrued(&fee_asset), 10);

        let swept = client.sweep_fees(&fee_asset);
        assert_eq!(swept, 10);
        assert_eq!(client.swap_fee_accrued(&fee_asset), 0);
        assert_eq!(token::TokenClient::new(&env, &fee_asset).balance(&treasury), 10);
        assert_eq!(token::TokenClient::new(&env, &fee_asset).balance(&id), 40);
    }
}

// Mobile-v2 dual-proof boundary. These tests use independent recording
// verifier contracts so they exercise the cross-contract ABI exactly as the
// deployable pool does, without relying on generated proving artifacts.
#[cfg(test)]
mod mobile_v2_dual_proof_test {
    use super::*;
    use groth16_verifier::{Groth16Error, Proof};
    use soroban_sdk::testutils::{Address as _, Deployer as _, MockAuth, MockAuthInvoke};

    #[contracttype]
    enum RecorderKey {
        Accept,
        Inputs,
    }

    #[contract]
    struct RecordingVerifier;

    #[contractimpl]
    impl RecordingVerifier {
        pub fn set_accept(env: Env, accept: bool) {
            env.storage().instance().set(&RecorderKey::Accept, &accept);
        }

        pub fn verify(
            env: Env,
            _proof: Proof,
            public_inputs: Vec<BytesN<32>>,
        ) -> Result<bool, Groth16Error> {
            env.storage()
                .instance()
                .set(&RecorderKey::Inputs, &public_inputs);
            Ok(env
                .storage()
                .instance()
                .get(&RecorderKey::Accept)
                .unwrap_or(false))
        }

        pub fn inputs(env: Env) -> Vec<BytesN<32>> {
            env.storage()
                .instance()
                .get(&RecorderKey::Inputs)
                .unwrap_or(Vec::new(&env))
        }
    }

    struct Setup {
        pool: Address,
        commit: Address,
        claim: Address,
        append: Address,
        hasher: Address,
        executor: Address,
        admin: Address,
        old_root: BytesN<32>,
        asset_in: BytesN<32>,
        asset_out: BytesN<32>,
    }

    fn fe(env: &Env, n: u8) -> BytesN<32> {
        let mut value = [0u8; 32];
        value[31] = n;
        BytesN::from_array(env, &value)
    }

    fn proof(env: &Env) -> Bytes {
        Bytes::from_array(env, &[0u8; 384])
    }

    fn setup(env: &Env) -> Setup {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let old_root = fe(env, 1);
        let asset_in = fe(env, 10);
        let asset_out = fe(env, 11);
        let pool = env.register(ConfibatchPool, ());
        let commit = env.register(RecordingVerifier, ());
        let claim = env.register(RecordingVerifier, ());
        let append = env.register(RecordingVerifier, ());
        let hasher = env.register(mobile_v2_hasher::MobileV2Hasher, ());
        let executor = Address::from_str(
            env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        );
        RecordingVerifierClient::new(env, &commit).set_accept(&true);
        RecordingVerifierClient::new(env, &claim).set_accept(&true);
        RecordingVerifierClient::new(env, &append).set_accept(&true);

        let client = ConfibatchPoolClient::new(env, &pool);
        client.init(&admin, &old_root);
        client.set_swap_commit_v2_verifier(&commit);
        client.set_swap_claim_v2_verifier(&claim);
        client.set_append_v2_verifier(&append);
        client.activate_mobile_v2(&fe(env, 99), &hasher, &executor);
        env.as_contract(&pool, || {
            env.storage()
                .persistent()
                .set(&DataKey::Reserve(asset_in.clone()), &Address::generate(env));
            env.storage().persistent().set(
                &DataKey::Reserve(asset_out.clone()),
                &Address::generate(env),
            );
        });
        Setup {
            pool,
            commit,
            claim,
            append,
            hasher,
            executor,
            admin,
            old_root,
            asset_in,
            asset_out,
        }
    }

    #[test]
    fn activation_pins_profile_extends_helper_ttl_and_leaves_global_freezes_open() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let config = client.mobile_v2_config().unwrap();

        assert_eq!(config.protocol_version, 2);
        assert_eq!(config.writer_revision, 1);
        assert_eq!(config.batch_depth, MOBILE_V2_BATCH_DEPTH);
        assert_eq!(config.circuit_capacity, MOBILE_V2_BATCH_CAPACITY);
        assert_eq!(config.min_k, MOBILE_V2_MIN_K);
        assert_eq!(config.max_k, MOBILE_V2_MAX_K);
        assert_eq!(config.max_order_amount, MOBILE_V2_MAX_ORDER_AMOUNT);
        assert_eq!(config.batch_hash_id.to_array(), MOBILE_V2_BATCH_HASH_ID);
        assert_eq!(config.profile_hash, fe(&env, 99));
        assert_eq!(config.batch_hasher, s.hasher);
        assert_eq!(config.batch_executor, s.executor);
        assert_eq!(config.commit_verifier, s.commit);
        assert_eq!(config.claim_verifier, s.claim);
        assert_eq!(config.append_verifier, s.append);
        assert!(client.mobile_v2_active());
        assert!(env.deployer().get_contract_instance_ttl(&config.batch_hasher)
            >= NULLIFIER_TTL_BUMP - 1);
        assert!(env.deployer().get_contract_code_ttl(&config.batch_hasher)
            >= NULLIFIER_TTL_BUMP - 1);
        env.as_contract(&s.pool, || {
            assert!(!env.storage().instance().has(&DataKey::VerifiersFrozen));
            assert!(!env.storage().instance().has(&DataKey::UpgradeFrozen));
        });
        assert!(matches!(
            client.try_activate_mobile_v2(&fe(&env, 98), &s.hasher, &s.executor),
            Err(Ok(PoolError::WrongProtocol))
        ));
    }

    #[test]
    fn activation_requires_a_classic_threshold_account_executor() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let pool = env.register(ConfibatchPool, ());
        let commit = env.register(RecordingVerifier, ());
        let claim = env.register(RecordingVerifier, ());
        let append = env.register(RecordingVerifier, ());
        let hasher = env.register(mobile_v2_hasher::MobileV2Hasher, ());
        let contract_executor = Address::generate(&env);
        let account_executor = Address::from_str(
            &env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        );
        let client = ConfibatchPoolClient::new(&env, &pool);
        client.init(&admin, &fe(&env, 1));
        client.set_swap_commit_v2_verifier(&commit);
        client.set_swap_claim_v2_verifier(&claim);
        client.set_append_v2_verifier(&append);

        assert!(matches!(
            client.try_activate_mobile_v2(&fe(&env, 99), &hasher, &contract_executor),
            Err(Ok(PoolError::BadAmount))
        ));
        assert!(client.mobile_v2_config().is_none());
        client.activate_mobile_v2(&fe(&env, 99), &hasher, &account_executor);
        assert_eq!(
            client.mobile_v2_config().unwrap().batch_executor,
            account_executor
        );
    }

    #[test]
    fn canonical_writer_rejects_admin_only_authorization() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let executor = Address::from_str(
            &env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        );
        let pool = env.register(ConfibatchPool, ());
        let commit = env.register(RecordingVerifier, ());
        let claim = env.register(RecordingVerifier, ());
        let append = env.register(RecordingVerifier, ());
        let hasher = env.register(mobile_v2_hasher::MobileV2Hasher, ());
        let pair = Address::generate(&env);
        let client = ConfibatchPoolClient::new(&env, &pool);
        client.init(&admin, &fe(&env, 1));
        env.as_contract(&pool, || {
            env.storage().instance().set(&DataKey::SolvencyEnforced, &true);
            env.storage().instance().set(&DataKey::MobileV2Active, &true);
            env.storage()
                .instance()
                .set(&DataKey::SwapCommitBoundV2Verifier, &commit);
            env.storage()
                .instance()
                .set(&DataKey::SwapClaimV2Verifier, &claim);
            env.storage().instance().set(&DataKey::AppendV2Verifier, &append);
            env.storage().instance().set(
                &DataKey::MobileV2Config,
                &MobileV2Config {
                    protocol_version: 2,
                    writer_revision: 1,
                    batch_depth: MOBILE_V2_BATCH_DEPTH,
                    circuit_capacity: MOBILE_V2_BATCH_CAPACITY,
                    min_k: MOBILE_V2_MIN_K,
                    max_k: MOBILE_V2_MAX_K,
                    max_order_amount: MOBILE_V2_MAX_ORDER_AMOUNT,
                    batch_hash_id: BytesN::from_array(&env, &MOBILE_V2_BATCH_HASH_ID),
                    profile_hash: fe(&env, 99),
                    batch_hasher: hasher,
                    batch_executor: executor,
                    commit_verifier: commit,
                    claim_verifier: claim,
                    append_verifier: append,
                },
            );
        });
        let batch_id = fe(&env, 20);
        let asset_in = fe(&env, 10);
        let asset_out = fe(&env, 11);
        let scms = vec![&env, fe(&env, 2), fe(&env, 3)];
        let args = vec![
            &env,
            batch_id.clone().into_val(&env),
            asset_in.clone().into_val(&env),
            asset_out.clone().into_val(&env),
            pair.clone().into_val(&env),
            2i128.into_val(&env),
            1i128.into_val(&env),
            scms.clone().into_val(&env),
            0u32.into_val(&env),
        ];

        let result = client
            .mock_auths(&[MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &pool,
                    fn_name: "batch_execute_routed_v2",
                    args,
                    sub_invokes: &[],
                },
            }])
            .try_batch_execute_routed_v2(
                &batch_id,
                &asset_in,
                &asset_out,
                &pair,
                &2,
                &1,
                &scms,
                &0,
            );
        assert!(result.is_err());
        assert!(!client.batch_v2(&batch_id));
    }

    #[test]
    fn removing_the_activation_flag_fails_closed() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let batch_id = fe(&env, 60);
        let commit_nf = fe(&env, 61);
        let claim_nf = fe(&env, 62);
        assert!(client.mobile_v2_active());
        env.as_contract(&s.pool, || {
            env.storage().persistent().set(
                &DataKey::BatchV2(batch_id.clone()),
                &V2BatchRecord {
                    output: BatchOut {
                        asset_in: s.asset_in.clone(),
                        asset_out: s.asset_out.clone(),
                        sum_in: 1,
                        sum_out: 1,
                        swap_root: fe(&env, 63),
                    },
                    cap: BatchCap { k: 2, claimed: 0 },
                },
            );
            env.storage()
                .instance()
                .remove(&DataKey::MobileV2Active);
        });
        assert!(!client.mobile_v2_active());
        let raw = proof(&env);

        let commit = client.try_swap_commit_bound_v2(
            &s.old_root,
            &commit_nf,
            &fe(&env, 64),
            &fe(&env, 65),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 66),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(commit, Err(Ok(PoolError::WrongProtocol)));

        let claim = client.try_swap_claim_v2(
            &batch_id,
            &claim_nf,
            &fe(&env, 67),
            &fe(&env, 68),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(claim, Err(Ok(PoolError::WrongProtocol)));
        assert_eq!(client.root(), s.old_root);
        assert_eq!(client.next_index(), 0);
        assert!(!client.nullifier_spent(&commit_nf));
        assert!(!client.nullifier_spent(&claim_nf));
        assert!(RecordingVerifierClient::new(&env, &s.commit)
            .inputs()
            .is_empty());
        assert!(RecordingVerifierClient::new(&env, &s.claim)
            .inputs()
            .is_empty());
        assert!(RecordingVerifierClient::new(&env, &s.append)
            .inputs()
            .is_empty());
    }

    #[test]
    fn commit_binds_exact_semantic_and_current_append_abis() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let anchor = s.old_root.clone();
        let nf = fe(&env, 2);
        let scm = fe(&env, 3);
        let ct_hash = fe(&env, 4);
        let new_root = fe(&env, 5);
        let raw = proof(&env);

        client.swap_commit_bound_v2(
            &anchor,
            &nf,
            &scm,
            &ct_hash,
            &s.asset_in,
            &s.asset_out,
            &new_root,
            &raw,
            &raw,
            &Bytes::new(&env),
        );

        assert_eq!(
            RecordingVerifierClient::new(&env, &s.commit).inputs(),
            vec![
                &env,
                ct_hash.clone(),
                anchor,
                nf.clone(),
                scm.clone(),
                s.asset_in.clone(),
                s.asset_out.clone(),
            ]
        );
        assert_eq!(
            RecordingVerifierClient::new(&env, &s.append).inputs(),
            vec![
                &env,
                s.old_root,
                u64_to_be32(&env, 0),
                new_root.clone(),
                scm.clone()
            ]
        );
        assert_eq!(client.root(), new_root);
        assert_eq!(client.next_index(), 1);
        assert!(client.nullifier_spent(&nf));
        let receipt = client.bound_commit(&scm).unwrap();
        assert_eq!(receipt.ct_hash, ct_hash);
        assert_eq!(receipt.asset_in, s.asset_in);
        assert_eq!(receipt.asset_out, s.asset_out);
        assert!(client.bound_commit_v2(&scm));
    }

    #[test]
    fn legacy_bound_commit_never_writes_the_v2_receipt_marker() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        client.set_swap_commit_bound_verifier(&s.commit);
        let scm = fe(&env, 70);
        client.swap_commit_bound(
            &s.old_root,
            &fe(&env, 71),
            &scm,
            &fe(&env, 72),
            &fe(&env, 73),
            &s.asset_in,
            &s.asset_out,
            &proof(&env),
            &Bytes::new(&env),
        );
        assert!(client.bound_commit(&scm).is_some());
        assert!(!client.bound_commit_v2(&scm));
    }

    #[test]
    fn v2_receipt_marker_is_monotonic_and_blocks_cross_version_recommit() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        client.set_swap_commit_bound_verifier(&s.commit);
        let scm = fe(&env, 74);
        env.as_contract(&s.pool, || {
            env.storage()
                .persistent()
                .set(
                    &DataKey::BoundCommitV2(scm.clone()),
                    &V2CommitState::Available,
                );
        });
        let raw = proof(&env);
        assert_eq!(
            client.try_swap_commit_bound_v2(
                &s.old_root,
                &fe(&env, 75),
                &scm,
                &fe(&env, 76),
                &s.asset_in,
                &s.asset_out,
                &fe(&env, 77),
                &raw,
                &raw,
                &Bytes::new(&env),
            ),
            Err(Ok(PoolError::PairExists)),
        );
        assert_eq!(
            client.try_swap_commit_bound(
                &s.old_root,
                &fe(&env, 78),
                &scm,
                &fe(&env, 79),
                &fe(&env, 80),
                &s.asset_in,
                &s.asset_out,
                &raw,
                &Bytes::new(&env),
            ),
            Err(Ok(PoolError::PairExists)),
        );
        assert_eq!(client.root(), s.old_root);
        assert_eq!(client.next_index(), 0);
    }

    #[test]
    fn claim_uses_only_v2_batch_storage_and_binds_cm_out_to_append() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let batch_id = fe(&env, 20);
        let swap_root = fe(&env, 21);
        let nf_claim = fe(&env, 22);
        let cm_out = fe(&env, 23);
        let new_root = fe(&env, 24);
        let sum_in = 100i128;
        let sum_out = 175i128;
        env.as_contract(&s.pool, || {
            env.storage().persistent().set(
                &DataKey::BatchV2(batch_id.clone()),
                &V2BatchRecord {
                    output: BatchOut {
                        asset_in: s.asset_in.clone(),
                        asset_out: s.asset_out.clone(),
                        sum_in,
                        sum_out,
                        swap_root: swap_root.clone(),
                    },
                    cap: BatchCap { k: 2, claimed: 0 },
                },
            );
        });
        let raw = proof(&env);

        client.swap_claim_v2(
            &batch_id,
            &nf_claim,
            &cm_out,
            &new_root,
            &raw,
            &raw,
            &Bytes::new(&env),
        );

        assert_eq!(
            RecordingVerifierClient::new(&env, &s.claim).inputs(),
            vec![
                &env,
                batch_id.clone(),
                s.asset_in,
                s.asset_out,
                i128_to_be32(&env, sum_in),
                i128_to_be32(&env, sum_out),
                swap_root,
                nf_claim.clone(),
                cm_out.clone(),
            ]
        );
        assert_eq!(
            RecordingVerifierClient::new(&env, &s.append).inputs(),
            vec![
                &env,
                s.old_root,
                u64_to_be32(&env, 0),
                new_root.clone(),
                cm_out
            ]
        );
        assert_eq!(client.root(), new_root);
        assert_eq!(client.next_index(), 1);
        assert!(client.nullifier_spent(&nf_claim));
        assert_eq!(client.mobile_v2_batch(&batch_id).unwrap().cap.claimed, 1);
    }

    #[test]
    fn legacy_claim_rejects_a_self_contained_v2_batch_record() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let batch_id = fe(&env, 25);
        env.as_contract(&s.pool, || {
            env.storage().persistent().set(
                &DataKey::BatchV2(batch_id.clone()),
                &V2BatchRecord {
                    output: BatchOut {
                        asset_in: s.asset_in.clone(),
                        asset_out: s.asset_out.clone(),
                        sum_in: 2,
                        sum_out: 2,
                        swap_root: fe(&env, 26),
                    },
                    cap: BatchCap { k: 2, claimed: 0 },
                },
            );
        });
        let raw = proof(&env);

        assert_eq!(
            client.try_swap_claim(
                &batch_id,
                &fe(&env, 27),
                &fe(&env, 28),
                &fe(&env, 29),
                &raw,
                &Bytes::new(&env),
            ),
            Err(Ok(PoolError::WrongProtocol))
        );
    }

    #[test]
    fn either_failed_proof_leaves_commit_state_unchanged() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let nf = fe(&env, 30);
        let scm = fe(&env, 31);
        let raw = proof(&env);
        RecordingVerifierClient::new(&env, &s.append).set_accept(&false);
        let result = client.try_swap_commit_bound_v2(
            &s.old_root,
            &nf,
            &scm,
            &fe(&env, 32),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 33),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::InvalidProof)));
        assert_eq!(client.root(), s.old_root);
        assert_eq!(client.next_index(), 0);
        assert!(!client.nullifier_spent(&nf));
        assert!(client.bound_commit(&scm).is_none());
        assert!(!client.bound_commit_v2(&scm));

        RecordingVerifierClient::new(&env, &s.append).set_accept(&true);
        RecordingVerifierClient::new(&env, &s.commit).set_accept(&false);
        let result = client.try_swap_commit_bound_v2(
            &s.old_root,
            &nf,
            &scm,
            &fe(&env, 32),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 33),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::InvalidProof)));
        assert_eq!(client.root(), s.old_root);
        assert_eq!(client.next_index(), 0);
        assert!(!client.nullifier_spent(&nf));
        assert!(client.bound_commit(&scm).is_none());
        assert!(!client.bound_commit_v2(&scm));
    }

    #[test]
    fn either_failed_proof_leaves_claim_state_unchanged() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let batch_id = fe(&env, 34);
        let nf_claim = fe(&env, 35);
        let cm_out = fe(&env, 36);
        env.as_contract(&s.pool, || {
            env.storage().persistent().set(
                &DataKey::BatchV2(batch_id.clone()),
                &V2BatchRecord {
                    output: BatchOut {
                        asset_in: s.asset_in.clone(),
                        asset_out: s.asset_out.clone(),
                        sum_in: 1,
                        sum_out: 1,
                        swap_root: fe(&env, 37),
                    },
                    cap: BatchCap { k: 2, claimed: 0 },
                },
            );
        });
        let raw = proof(&env);
        let assert_unchanged = || {
            assert_eq!(client.root(), s.old_root);
            assert_eq!(client.next_index(), 0);
            assert!(!client.nullifier_spent(&nf_claim));
            assert_eq!(client.mobile_v2_batch(&batch_id).unwrap().cap.claimed, 0);
        };

        RecordingVerifierClient::new(&env, &s.append).set_accept(&false);
        let result = client.try_swap_claim_v2(
            &batch_id,
            &nf_claim,
            &cm_out,
            &fe(&env, 38),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::InvalidProof)));
        assert_unchanged();

        RecordingVerifierClient::new(&env, &s.append).set_accept(&true);
        RecordingVerifierClient::new(&env, &s.claim).set_accept(&false);
        let result = client.try_swap_claim_v2(
            &batch_id,
            &nf_claim,
            &cm_out,
            &fe(&env, 38),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::InvalidProof)));
        assert_unchanged();
    }

    #[test]
    fn zero_leaves_and_full_tree_reject_before_proofs() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let raw = proof(&env);

        let result = client.try_swap_commit_bound_v2(
            &s.old_root,
            &fe(&env, 39),
            &fe(&env, 0),
            &fe(&env, 40),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 41),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::BadAmount)));

        let result = client.try_swap_claim_v2(
            &fe(&env, 42),
            &fe(&env, 43),
            &fe(&env, 0),
            &fe(&env, 44),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::BadAmount)));

        env.as_contract(&s.pool, || {
            env.storage()
                .instance()
                .set(&DataKey::NextIndex, &TREE_CAPACITY);
        });
        let result = client.try_swap_commit_bound_v2(
            &s.old_root,
            &fe(&env, 45),
            &fe(&env, 46),
            &fe(&env, 47),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 48),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::TreeFull)));
        assert!(RecordingVerifierClient::new(&env, &s.commit)
            .inputs()
            .is_empty());
        assert!(RecordingVerifierClient::new(&env, &s.claim)
            .inputs()
            .is_empty());
        assert!(RecordingVerifierClient::new(&env, &s.append)
            .inputs()
            .is_empty());
    }

    #[test]
    fn claim_rejects_unversioned_batch_and_non_u64_totals_before_proofs() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let batch_id = fe(&env, 40);
        env.as_contract(&s.pool, || {
            env.storage().persistent().set(
                &DataKey::BatchOut(batch_id.clone()),
                &BatchOut {
                    asset_in: s.asset_in.clone(),
                    asset_out: s.asset_out.clone(),
                    sum_in: 1,
                    sum_out: 1,
                    swap_root: fe(&env, 41),
                },
            );
            env.storage().persistent().set(
                &DataKey::BatchCap(batch_id.clone()),
                &BatchCap { k: 1, claimed: 0 },
            );
        });
        let raw = proof(&env);
        let result = client.try_swap_claim_v2(
            &batch_id,
            &fe(&env, 42),
            &fe(&env, 43),
            &fe(&env, 44),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::WrongProtocol)));

        assert_eq!(validate_mobile_v2_totals(0, 1), Err(PoolError::BadAmount));
        assert_eq!(validate_mobile_v2_totals(1, 0), Err(PoolError::BadAmount));
        assert_eq!(
            validate_mobile_v2_totals((u64::MAX as i128) + 1, 1),
            Err(PoolError::BadAmount)
        );
        assert_eq!(
            validate_mobile_v2_totals(u64::MAX as i128, u64::MAX as i128),
            Ok(())
        );

        env.as_contract(&s.pool, || {
            env.storage()
                .persistent()
                .set(
                    &DataKey::BatchV2(batch_id.clone()),
                    &V2BatchRecord {
                        output: BatchOut {
                            asset_in: s.asset_in.clone(),
                            asset_out: s.asset_out.clone(),
                            sum_in: 1,
                            sum_out: 1,
                            swap_root: fe(&env, 41),
                        },
                        cap: BatchCap { k: 2, claimed: 0 },
                    },
                );
            env.storage()
                .instance()
                .remove(&DataKey::SolvencyEnforced);
        });
        let result = client.try_swap_claim_v2(
            &batch_id,
            &fe(&env, 49),
            &fe(&env, 50),
            &fe(&env, 51),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::WrongProtocol)));
        let result = client.try_swap_commit_bound_v2(
            &s.old_root,
            &fe(&env, 45),
            &fe(&env, 46),
            &fe(&env, 47),
            &s.asset_in,
            &s.asset_out,
            &fe(&env, 48),
            &raw,
            &raw,
            &Bytes::new(&env),
        );
        assert_eq!(result, Err(Ok(PoolError::WrongProtocol)));
    }

    #[test]
    fn v2_verifier_slots_are_additive_and_freeze_with_v1() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        env.as_contract(&s.pool, || {
            assert_eq!(
                env.storage()
                    .instance()
                    .get::<_, Address>(&DataKey::SwapCommitBoundV2Verifier),
                Some(s.commit)
            );
            assert_eq!(
                env.storage()
                    .instance()
                    .get::<_, Address>(&DataKey::SwapClaimV2Verifier),
                Some(s.claim)
            );
            assert_eq!(
                env.storage()
                    .instance()
                    .get::<_, Address>(&DataKey::AppendV2Verifier),
                Some(s.append)
            );
            assert!(!env
                .storage()
                .instance()
                .has(&DataKey::SwapCommitBoundVerifier));
            assert!(!env.storage().instance().has(&DataKey::SwapClaimVerifier));
        });
        client.freeze_verifiers();
        let replacement = env.register(RecordingVerifier, ());
        assert_eq!(
            client.try_set_append_v2_verifier(&replacement),
            Err(Ok(PoolError::Frozen))
        );
        let _ = s.admin;
    }

    #[test]
    fn active_v2_verifier_identity_is_locked_without_freezing_pool_upgrades() {
        let env = Env::default();
        let s = setup(&env);
        let client = ConfibatchPoolClient::new(&env, &s.pool);
        let replacement = env.register(RecordingVerifier, ());

        assert_eq!(
            client.try_set_swap_commit_v2_verifier(&replacement),
            Err(Ok(PoolError::Frozen))
        );
        assert_eq!(
            client.try_set_swap_claim_v2_verifier(&replacement),
            Err(Ok(PoolError::Frozen))
        );
        assert_eq!(
            client.try_set_append_v2_verifier(&replacement),
            Err(Ok(PoolError::Frozen))
        );

        // This is a version-scoped verifier lock, not the irreversible global
        // production freeze. Development Wasm upgrades and inactive verifier
        // generations remain governed by their existing controls.
        client.set_swap_commit_bound_verifier(&replacement);
        env.as_contract(&s.pool, || {
            assert!(!env.storage().instance().has(&DataKey::VerifiersFrozen));
            assert!(!env.storage().instance().has(&DataKey::UpgradeFrozen));
            assert_eq!(
                env.storage()
                    .instance()
                    .get::<_, Address>(&DataKey::SwapCommitBoundVerifier),
                Some(replacement)
            );
        });
    }
}

#[cfg(test)]
mod typed_event_wire_test {
    use super::*;
    use soroban_sdk::testutils::Events as _;

    #[test]
    fn typed_events_preserve_indexer_topics_and_data_shapes() {
        let env = Env::default();
        let id = env.register(ConfibatchPool, ());
        let cm = BytesN::from_array(&env, &[1u8; 32]);
        let nf = BytesN::from_array(&env, &[2u8; 32]);
        let hash = BytesN::from_array(&env, &[3u8; 32]);
        let asset_in = BytesN::from_array(&env, &[4u8; 32]);
        let asset_out = BytesN::from_array(&env, &[5u8; 32]);
        let ct = Bytes::from_slice(&env, &[6u8; 4]);

        env.as_contract(&id, || {
            emit_nullifier_spent(&env, &nf);
            emit_transfer(&env, &cm, 7, &nf, &ct);
            emit_bound_swap_commit(&env, &cm, 8, &ct, &hash, &asset_in, &asset_out);
            emit_bound_swap_commit_v2(&env, &cm, 9, &ct, &hash, &asset_in, &asset_out);
        });

        assert_eq!(
            env.events().all(),
            vec![
                &env,
                (
                    id.clone(),
                    (soroban_sdk::symbol_short!("nfspent"),).into_val(&env),
                    nf.clone().into_val(&env),
                ),
                (
                    id.clone(),
                    (soroban_sdk::symbol_short!("transfer"),).into_val(&env),
                    (cm.clone(), 7u64, nf, ct.clone()).into_val(&env),
                ),
                (
                    id.clone(),
                    (soroban_sdk::symbol_short!("swapcm"),).into_val(&env),
                    (
                        cm.clone(),
                        8u64,
                        ct.clone(),
                        hash.clone(),
                        asset_in.clone(),
                        asset_out.clone(),
                    ).into_val(&env),
                ),
                (
                    id,
                    (soroban_sdk::symbol_short!("swapcmv2"),).into_val(&env),
                    (cm, 9u64, ct, hash, asset_in, asset_out).into_val(&env),
                ),
            ]
        );
    }
}

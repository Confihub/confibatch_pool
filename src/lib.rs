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

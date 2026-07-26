use super::*;
use soroban_sdk::testutils::Address as _;

const ROUTE_RESERVE: i128 = 1_000_000_000;
const SUM_IN: i128 = 10_000_000;

#[contracttype]
enum PairKey {
    Token0,
    Token1,
    Reserve0,
    Reserve1,
    PayoutAdjust,
}

/// Minimal Soroswap-shaped pair used to exercise the writer's real routed path.
/// `PayoutAdjust` lets a test make the adapter return less than the requested
/// amount without reverting, so the post-call custody-delta check and Soroban
/// rollback are tested rather than only the pre-call quote floor.
#[contract]
pub struct MobileV2MockPair;

#[contractimpl]
impl MobileV2MockPair {
    pub fn setup(env: Env, token_0: Address, token_1: Address, reserve_0: i128, reserve_1: i128) {
        env.storage().instance().set(&PairKey::Token0, &token_0);
        env.storage().instance().set(&PairKey::Token1, &token_1);
        env.storage().instance().set(&PairKey::Reserve0, &reserve_0);
        env.storage().instance().set(&PairKey::Reserve1, &reserve_1);
        env.storage().instance().set(&PairKey::PayoutAdjust, &0i128);
    }

    pub fn set_payout_adjust(env: Env, adjustment: i128) {
        env.storage()
            .instance()
            .set(&PairKey::PayoutAdjust, &adjustment);
    }

    pub fn token_0(env: Env) -> Address {
        env.storage().instance().get(&PairKey::Token0).unwrap()
    }

    pub fn get_reserves(env: Env) -> (i128, i128) {
        (
            env.storage().instance().get(&PairKey::Reserve0).unwrap(),
            env.storage().instance().get(&PairKey::Reserve1).unwrap(),
        )
    }

    pub fn swap(env: Env, amount_0_out: i128, amount_1_out: i128, to: Address) {
        let token_0: Address = env.storage().instance().get(&PairKey::Token0).unwrap();
        let token_1: Address = env.storage().instance().get(&PairKey::Token1).unwrap();
        let adjustment: i128 = env
            .storage()
            .instance()
            .get(&PairKey::PayoutAdjust)
            .unwrap_or(0);
        let here = env.current_contract_address();
        if amount_0_out > 0 {
            token::TokenClient::new(&env, &token_0).transfer(
                &here,
                &to,
                &(amount_0_out + adjustment),
            );
        }
        if amount_1_out > 0 {
            token::TokenClient::new(&env, &token_1).transfer(
                &here,
                &to,
                &(amount_1_out + adjustment),
            );
        }
    }
}

#[contract]
pub struct MobileV2DummyVerifier;

#[contractimpl]
impl MobileV2DummyVerifier {
    pub fn ping() -> bool {
        true
    }
}

struct Setup {
    pool: Address,
    pair: Address,
    token_x: Address,
    token_y: Address,
    asset_in: BytesN<32>,
    asset_out: BytesN<32>,
    expected_out: i128,
}

fn fe(env: &Env, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    BytesN::from_array(env, &bytes)
}

fn sequential_scms(env: &Env, start: u8, count: u8) -> Vec<BytesN<32>> {
    let mut result = Vec::new(env);
    let mut value = start;
    while value < start + count {
        result.push_back(fe(env, value));
        value += 1;
    }
    result
}

fn setup(env: &Env, active: bool) -> Setup {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let pool = env.register(ConfibatchPool, ());
    let pair = env.register(MobileV2MockPair, ());
    let token_x = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_y = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let asset_in = fe(env, 10);
    let asset_out = fe(env, 11);
    let expected_out = routed_out_checked(ROUTE_RESERVE, ROUTE_RESERVE, SUM_IN).unwrap();

    MobileV2MockPairClient::new(env, &pair).setup(
        &token_x,
        &token_y,
        &ROUTE_RESERVE,
        &ROUTE_RESERVE,
    );
    soroban_sdk::token::StellarAssetClient::new(env, &token_x).mint(&pool, &(SUM_IN * 2));
    soroban_sdk::token::StellarAssetClient::new(env, &token_y).mint(&pair, &ROUTE_RESERVE);

    let client = ConfibatchPoolClient::new(env, &pool);
    client.init(&admin, &fe(env, 50));
    client.set_route(&pair, &token_x, &token_y);
    env.as_contract(&pool, || {
        env.storage()
            .persistent()
            .set(&DataKey::Reserve(asset_in.clone()), &token_x);
        env.storage()
            .persistent()
            .set(&DataKey::Reserve(asset_out.clone()), &token_y);
        // Keep an additional batch's worth of liability/custody so a successful
        // execution remains solvent and reuse tests can make a second attempt.
        env.storage().persistent().set(
            &DataKey::OutstandingNoteValue(asset_in.clone()),
            &(SUM_IN * 2),
        );
    });

    let commit = env.register(MobileV2DummyVerifier, ());
    let claim = env.register(MobileV2DummyVerifier, ());
    let append = env.register(MobileV2DummyVerifier, ());
    let hasher = env.register(mobile_v2_hasher::MobileV2Hasher, ());
    let executor = Address::from_str(
        env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    client.set_swap_commit_v2_verifier(&commit);
    client.set_swap_claim_v2_verifier(&claim);
    client.set_append_v2_verifier(&append);
    if active {
        client.activate_mobile_v2(&fe(env, 99), &hasher, &executor);
    }

    Setup {
        pool,
        pair,
        token_x,
        token_y,
        asset_in,
        asset_out,
        expected_out,
    }
}

fn seed_receipt(
    env: &Env,
    setup: &Setup,
    scm: &BytesN<32>,
    asset_in: &BytesN<32>,
    asset_out: &BytesN<32>,
    with_v2_marker: bool,
) {
    env.as_contract(&setup.pool, || {
        env.storage().persistent().set(
            &DataKey::BoundCommit(scm.clone()),
            &BoundCommit {
                ct_hash: fe(env, 90),
                asset_in: asset_in.clone(),
                asset_out: asset_out.clone(),
            },
        );
        if with_v2_marker {
            env.storage().persistent().set(
                &DataKey::BoundCommitV2(scm.clone()),
                &V2CommitState::Available,
            );
        }
    });
}

fn seed_valid_receipts(env: &Env, setup: &Setup, scms: &Vec<BytesN<32>>) {
    for scm in scms.iter() {
        seed_receipt(env, setup, &scm, &setup.asset_in, &setup.asset_out, true);
    }
}

#[test]
fn writer_success_derives_golden_root_assigns_members_and_records_output() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    let batch_id = fe(&env, 20);

    let net = client.batch_execute_routed_v2(
        &batch_id,
        &s.asset_in,
        &s.asset_out,
        &s.pair,
        &SUM_IN,
        &(s.expected_out - 1),
        &scms,
        &0,
    );
    assert_eq!(net, s.expected_out);
    assert!(client.batch_v2(&batch_id));

    let first = client.v2_member_use(&scms.get_unchecked(0)).unwrap();
    let second = client.v2_member_use(&scms.get_unchecked(1)).unwrap();
    assert_eq!(first.batch_id, batch_id);
    assert_eq!(first.position, 0);
    assert_eq!(second.batch_id, batch_id);
    assert_eq!(second.position, 1);

    let record = client.mobile_v2_batch(&batch_id).unwrap();
    let bod = record.output;
    let cap = record.cap;
    env.as_contract(&s.pool, || {
        let golden_root = BytesN::from_array(
            &env,
            &[
                0x40, 0xb9, 0x2b, 0xbb, 0x89, 0x4e, 0x2d, 0x2d, 0x99, 0x93, 0x27, 0x22, 0x37, 0xff,
                0x3e, 0xfb, 0xdd, 0xd7, 0x49, 0xb7, 0xc8, 0x26, 0x2c, 0x6b, 0x19, 0x20, 0x56, 0xf2,
                0x6d, 0x9c, 0xcd, 0xee,
            ],
        );
        assert_eq!(bod.asset_in, s.asset_in);
        assert_eq!(bod.asset_out, s.asset_out);
        assert_eq!(bod.sum_in, SUM_IN);
        assert_eq!(bod.sum_out, s.expected_out);
        assert_eq!(bod.swap_root, golden_root);
        assert_eq!(cap.k, 2);
        assert_eq!(cap.claimed, 0);
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::BatchOut(batch_id.clone())));
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::BatchCap(batch_id.clone())));
        assert_eq!(
            env.storage()
                .persistent()
                .get::<_, i128>(&DataKey::OutstandingNoteValue(s.asset_in.clone())),
            Some(SUM_IN)
        );
        assert_eq!(
            env.storage()
                .persistent()
                .get::<_, i128>(&DataKey::OutstandingNoteValue(s.asset_out.clone())),
            Some(s.expected_out)
        );
        assert!(!env.storage().instance().has(&DataKey::V2BatchExecutionLock));
    });
    assert_eq!(
        token::TokenClient::new(&env, &s.token_x).balance(&s.pool),
        SUM_IN
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_y).balance(&s.pool),
        s.expected_out
    );
}

#[test]
fn writer_fee_path_records_net_output_and_accrues_exact_fee() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let treasury = Address::generate(&env);
    client.set_protocol_fee(&0, &treasury);

    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    let batch_id = fe(&env, 20);
    let fee_bps = 25u32;
    let fee = venue_swap_fee_on(s.expected_out, fee_bps).unwrap();
    let expected_net = s.expected_out - fee;

    let net = client.batch_execute_routed_v2(
        &batch_id,
        &s.asset_in,
        &s.asset_out,
        &s.pair,
        &SUM_IN,
        &(s.expected_out - 1),
        &scms,
        &fee_bps,
    );

    assert_eq!(net, expected_net);
    assert_eq!(client.swap_fee_accrued(&s.token_y), fee);
    assert_eq!(
        client.mobile_v2_batch(&batch_id).unwrap().output.sum_out,
        expected_net
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_y).balance(&s.pool),
        s.expected_out
    );
    env.as_contract(&s.pool, || {
        assert_eq!(
            env.storage()
                .persistent()
                .get::<_, i128>(&DataKey::OutstandingNoteValue(s.asset_out.clone())),
            Some(expected_net)
        );
    });
}

#[test]
fn writer_is_fail_closed_until_exact_mobile_v2_activation() {
    let env = Env::default();
    let s = setup(&env, false);
    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    let result = ConfibatchPoolClient::new(&env, &s.pool).try_batch_execute_routed_v2(
        &fe(&env, 20),
        &s.asset_in,
        &s.asset_out,
        &s.pair,
        &SUM_IN,
        &(s.expected_out - 1),
        &scms,
        &0,
    );
    assert_eq!(result, Err(Ok(PoolError::WrongProtocol)));
}

#[test]
fn writer_rejects_zero_duplicate_and_zero_batch_identifiers() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);

    let zero_member = vec![&env, fe(&env, 0), fe(&env, 2)];
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 20),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &zero_member,
            &0,
        ),
        Err(Ok(PoolError::BadAmount))
    );

    let duplicate = vec![&env, fe(&env, 1), fe(&env, 1)];
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 21),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &duplicate,
            &0,
        ),
        Err(Ok(PoolError::DoubleSpend))
    );

    let valid = sequential_scms(&env, 1, 2);
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 0),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &valid,
            &0,
        ),
        Err(Ok(PoolError::BadAmount))
    );
}

#[test]
fn writer_requires_both_v2_marker_and_route_bound_receipt() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);

    let no_marker = sequential_scms(&env, 1, 2);
    seed_receipt(
        &env,
        &s,
        &no_marker.get_unchecked(0),
        &s.asset_in,
        &s.asset_out,
        false,
    );
    seed_receipt(
        &env,
        &s,
        &no_marker.get_unchecked(1),
        &s.asset_in,
        &s.asset_out,
        true,
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 20),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &no_marker,
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );

    let no_receipt = sequential_scms(&env, 3, 2);
    env.as_contract(&s.pool, || {
        env.storage().persistent().set(
            &DataKey::BoundCommitV2(no_receipt.get_unchecked(0)),
            &V2CommitState::Available,
        );
    });
    seed_receipt(
        &env,
        &s,
        &no_receipt.get_unchecked(1),
        &s.asset_in,
        &s.asset_out,
        true,
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 21),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &no_receipt,
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );

    let wrong_receipt_route = sequential_scms(&env, 5, 2);
    seed_receipt(
        &env,
        &s,
        &wrong_receipt_route.get_unchecked(0),
        &s.asset_in,
        &fe(&env, 12),
        true,
    );
    seed_receipt(
        &env,
        &s,
        &wrong_receipt_route.get_unchecked(1),
        &s.asset_in,
        &s.asset_out,
        true,
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 22),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &wrong_receipt_route,
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );
}

#[test]
fn writer_rejects_route_configuration_that_does_not_match_registered_assets() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    let unrelated_route_token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    client.set_route(&s.pair, &s.token_x, &unrelated_route_token);

    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 20),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &scms,
            &0,
        ),
        Err(Ok(PoolError::NoReserve))
    );
}

#[test]
fn writer_binds_the_exact_expected_route_pair_argument() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    let batch_id = fe(&env, 20);
    let different_pair = Address::generate(&env);

    assert_eq!(
        client.try_batch_execute_routed_v2(
            &batch_id,
            &s.asset_in,
            &s.asset_out,
            &different_pair,
            &SUM_IN,
            &1,
            &scms,
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );
    assert!(client.v2_member_use(&scms.get_unchecked(0)).is_none());
    assert!(client.v2_member_use(&scms.get_unchecked(1)).is_none());
    assert!(!client.batch_v2(&batch_id));
}

#[test]
fn writer_rejects_batch_and_commitment_reuse() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let used = sequential_scms(&env, 1, 2);
    let unused = sequential_scms(&env, 3, 2);
    seed_valid_receipts(&env, &s, &used);
    seed_valid_receipts(&env, &s, &unused);
    let batch_id = fe(&env, 20);
    client.batch_execute_routed_v2(
        &batch_id,
        &s.asset_in,
        &s.asset_out,
        &s.pair,
        &SUM_IN,
        &(s.expected_out - 1),
        &used,
        &0,
    );

    assert_eq!(
        client.try_batch_execute_routed_v2(
            &batch_id,
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &unused,
            &0,
        ),
        Err(Ok(PoolError::PairExists))
    );
    let new_batch = fe(&env, 21);
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &new_batch,
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &used,
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );
    assert!(!client.batch_v2(&new_batch));
    assert_eq!(
        client
            .v2_member_use(&used.get_unchecked(0))
            .unwrap()
            .batch_id,
        batch_id
    );
}

#[test]
fn writer_enforces_batch_size_and_sum_bounds_before_routing() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);

    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 20),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &sequential_scms(&env, 1, 1),
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 21),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &1,
            &sequential_scms(&env, 1, 6),
            &0,
        ),
        Err(Ok(PoolError::WrongProtocol))
    );

    let two = sequential_scms(&env, 1, 2);
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 22),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &1,
            &1,
            &two,
            &0,
        ),
        Err(Ok(PoolError::BadAmount))
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 23),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &((MOBILE_V2_MAX_ORDER_AMOUNT as i128 * 2) + 1),
            &1,
            &two,
            &0,
        ),
        Err(Ok(PoolError::BadAmount))
    );
    assert_eq!(
        client.try_batch_execute_routed_v2(
            &fe(&env, 24),
            &s.asset_in,
            &s.asset_out,
            &s.pair,
            &SUM_IN,
            &0,
            &two,
            &0,
        ),
        Err(Ok(PoolError::BadAmount))
    );

    assert_eq!(
        token::TokenClient::new(&env, &s.token_x).balance(&s.pool),
        SUM_IN * 2
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_y).balance(&s.pool),
        0
    );
}

#[test]
fn post_route_slippage_rolls_back_tokens_assignments_and_batch_state() {
    let env = Env::default();
    let s = setup(&env, true);
    let client = ConfibatchPoolClient::new(&env, &s.pool);
    let scms = sequential_scms(&env, 1, 2);
    seed_valid_receipts(&env, &s, &scms);
    MobileV2MockPairClient::new(&env, &s.pair).set_payout_adjust(&-10);
    let batch_id = fe(&env, 20);
    let pool_x_before = token::TokenClient::new(&env, &s.token_x).balance(&s.pool);
    let pair_x_before = token::TokenClient::new(&env, &s.token_x).balance(&s.pair);
    let pool_y_before = token::TokenClient::new(&env, &s.token_y).balance(&s.pool);
    let pair_y_before = token::TokenClient::new(&env, &s.token_y).balance(&s.pair);

    let result = client.try_batch_execute_routed_v2(
        &batch_id,
        &s.asset_in,
        &s.asset_out,
        &s.pair,
        &SUM_IN,
        &(s.expected_out - 1),
        &scms,
        &0,
    );
    assert_eq!(result, Err(Ok(PoolError::SlippageExceeded)));

    assert_eq!(
        token::TokenClient::new(&env, &s.token_x).balance(&s.pool),
        pool_x_before
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_x).balance(&s.pair),
        pair_x_before
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_y).balance(&s.pool),
        pool_y_before
    );
    assert_eq!(
        token::TokenClient::new(&env, &s.token_y).balance(&s.pair),
        pair_y_before
    );
    assert!(client.v2_member_use(&scms.get_unchecked(0)).is_none());
    assert!(client.v2_member_use(&scms.get_unchecked(1)).is_none());
    assert!(!client.batch_v2(&batch_id));
    env.as_contract(&s.pool, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::BatchOut(batch_id.clone())));
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::BatchCap(batch_id.clone())));
        assert!(!env.storage().instance().has(&DataKey::V2BatchExecutionLock));
        assert_eq!(
            env.storage()
                .persistent()
                .get::<_, i128>(&DataKey::OutstandingNoteValue(s.asset_in.clone())),
            Some(SUM_IN * 2)
        );
        assert_eq!(
            env.storage()
                .persistent()
                .get::<_, i128>(&DataKey::OutstandingNoteValue(s.asset_out.clone())),
            None
        );
    });
}

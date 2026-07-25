# confibatch_pool

`confibatch_pool` is the central Soroban contract for the ConfiBatch/confi.cash
shielded note pool, confidential batch swaps, withdrawals, and confidential LP
positions.

This standalone repository contains the latest contract implementation:

- on-chain contract version `12`;
- canonical mobile-v2 batch writer;
- fixed depth-3 batch roots with `2 <= k <= 5`;
- frontier-independent mobile-v2 semantic proofs plus separate append proofs;
- exact per-asset solvency accounting for fresh pools;
- batch-scoped claim capacity and single-use member receipts;
- guarded routed execution, fee accounting, confidential LP flows, TTL keepers,
  and one-way freeze controls.

It targets Soroban SDK `25.3.2`, Rust `1.91`, and Apache-2.0.

> Status: security-sensitive testnet/candidate code. It is not a claim of a
> completed audit or production readiness. Circuits, ceremonies, verifier keys,
> relayers, committee policy, deployment configuration, and operational controls
> are part of the security boundary.

## System role

```text
wallet/prover
  │ deposit, transfer, commit, claim, withdraw proofs
  ▼
confibatch_pool
  ├── verifies proofs through one Groth16 contract per circuit
  ├── stores the note root, recent-root ring, and nullifier set
  ├── holds registered Stellar Asset Contract reserves
  ├── routes only aggregate batch imbalance to an allowlisted pair
  ├── stores batch records and claim capacity
  └── represents LP positions as shielded notes
           │
           ├── route_adapter ──► mini_amm / external pair
           └── mini_amm for confidential LP accounting
```

The pool never stores user balances by address. Value is represented by
asset-tagged UTXO-style notes:

```text
NoteCommit(asset_id, amount, pk_d, rho, r)
```

The commitment tree and note openings are maintained off-chain. The contract
accepts a new root only after a Groth16 proof binds the current root/frontier,
the authorized leaf or spend, and the claimed new root.

## Core privacy and accounting model

### Commitment tree

- Fixed capacity: `2^16 = 65,536` leaves.
- The contract stores the current root and next free index.
- A 32-root recent-root ring allows spends against recent anchors.
- Public inputs must be canonical BLS12-381 scalar-field encodings.
- Encrypted note payloads are opaque to the contract and capped at 256 bytes.
- The contract does not reproduce the global tree's circomlib Poseidon hash.
  Append proofs authorize each root transition.

### Nullifiers

Every spend inserts a canonical 32-byte nullifier into persistent storage.
Existing nullifiers are rejected before proof/state commit. Spent-nullifier
entries receive long-lived TTL and can be renewed in bounded, permissionless
batches.

### Solvency

Fresh pools set `SolvencyEnforced = true` at initialization. For every registered
asset, the contract tracks outstanding shielded-note value and checks it against
the pool's live Stellar Asset Contract balance after value transitions.

The asset mapping is bijective on fresh pools:

```text
asset_id ──► SAC address
SAC address ──► asset_id
```

An asset cannot be silently repointed and one SAC cannot back two shielded asset
tags. Legacy upgraded pools without the fresh-pool flag are observe-only and
must not be described as having exact reconstructed liabilities.

### Denominations and boundary privacy

The admin may configure standard public deposit/withdraw denominations. Public
`deposit`, `withdraw`, and the public payout of `withdraw_with_change` enforce
that set. An empty denomination list disables the rule.

Arbitrary internal value can remain private through `split`,
`withdraw_with_change`, confidential LP change, and other proof-constrained
note transitions.

## Mobile-v2 batch flow

Version 12's preferred batch path is:

```text
swap_commit_bound_v2
        │ 2–5 accepted, unused route-bound SCM receipts
        ▼
batch_execute_routed_v2
        │ exact ordered members + aggregate route + atomic assignment
        ▼
swap_claim_v2
```

### 1. Commit

`swap_commit_bound_v2` verifies two independent statements before writing state:

- a frontier-independent semantic proof authorizing the note spend and binding
  `ct_hash`, anchor, nullifier, swap commitment, and route tags; and
- a relay-generated append proof binding
  `[oldRoot, startIndex, newRoot, scm]`.

The resulting receipt stores:

```text
BoundCommit { ct_hash, asset_in, asset_out }
BoundCommitV2::Available
```

The nullifier is spent and the `scm` leaf is appended only if both proofs pass.

### 2. Execute

`batch_execute_routed_v2` requires:

- admin authorization;
- authorization by the profile-pinned threshold executor account;
- an active exact mobile-v2 profile;
- a fresh solvency-enforced pool;
- a canonical nonzero batch ID;
- exactly 2 to 5 distinct, canonical, nonzero ordered SCMs;
- every receipt to be unused and bound to the selected route;
- the exact configured route pair;
- valid totals, per-order maximum, fee, and minimum output; and
- an unused batch ID.

The pinned helper computes a depth-3 Poseidon root over the ordered SCMs. Member
receipts move atomically from `Available` to
`Assigned { batch_id, position }`. The route, custody-delta measurement,
liability transition, batch record, fee accrual, assignments, and events all
share one Soroban invocation and roll back together on failure.

The circuit capacity is eight, but product policy intentionally permits only
`2 <= k <= 5`. `k = 1` is not mobile-v2 because the public aggregate would reveal
the member's exact input.

### 3. Claim

`swap_claim_v2` loads the complete `V2BatchRecord` from contract-derived state,
verifies:

- the frontier-independent claim statement; and
- a fresh append proof for `cm_out`.

It rejects replayed claim nullifiers and enforces `claimed < k`. The record
stores output data, participant capacity, claim count, and v2 protocol identity
together so selective archival restoration cannot separate claim accounting
from the batch marker.

### Mobile-v2 trust boundary

The threshold executor authorizes the aggregate. It must independently:

- match each ordered ciphertext to its on-chain `ct_hash`;
- recompute the aggregate;
- approve the exact `sum_in`, `min_out`, route pair, fee, batch ID, and member
  order; and
- authorize the exact Soroban invocation.

The current design does not prove that the committee's aggregate is honest or
bind every user's individual price limit on-chain. A dishonest threshold quorum
can authorize an incorrect aggregate or harmful price. Do not describe this
path as fully trustless.

## Legacy and compatibility paths

The contract retains older entrypoints for recovery and compatibility:

- `swap_commit`, `swap_commit_bound`, `batch_execute_scoped`, and `swap_claim`;
- `settle_batch`, `settle_batch_v2`, and `settle_batch_vn`;
- legacy single-pair confidential LP methods.

`batch_execute` is deliberately deprecated and always returns `BadAmount`.
Its original signature remains to preserve the deployed ABI. Claims reject
legacy unscoped batches that lack a batch capacity record.

Mobile-v2 batches cannot be claimed through the legacy `swap_claim` path, and
legacy batches cannot be claimed through `swap_claim_v2`.

## Contract interface

### Initialization, governance, and verifier wiring

| Function | Authorization | Description |
| --- | --- | --- |
| `__constructor(admin, empty_root)` | deployment | Atomically initializes a fresh pool. |
| `init(admin, empty_root)` | first call only | Legacy initialization path. |
| `set_*_verifier(v)` | admin | Sets the named verifier after validating that `v` is a contract. |
| `activate_mobile_v2(profile_hash, batch_hasher, batch_executor)` | admin | One-way activation of the exact v2 profile after all three v2 verifier slots are set. |
| `freeze_verifiers()` | admin, irreversible | Permanently freezes verifier changes and upgrades. |
| `freeze_upgrade()` | admin, irreversible | Permanently freezes Wasm upgrades. |
| `upgrade(new_wasm_hash)` | admin | Updates current Wasm unless upgrades are frozen; emits `upgrade`. |

Verifier setters exist for:

- deposit, transfer, withdraw, withdraw-with-change, and split;
- batch, order-spend, clearing, and N-buyer clearing;
- legacy swap commit, amount-bound swap commit, and swap claim; and
- mobile-v2 commit, mobile-v2 claim, and append.

`activate_mobile_v2` pins protocol version 2, writer revision 1, batch depth 3,
capacity 8, policy range 2–5, maximum order amount, hash identity, profile hash,
immutable helper, threshold executor, and three verifier identities. Activation
is separate from the global freeze controls.

### Asset, route, fee, and privacy configuration

| Function | Authorization | Description |
| --- | --- | --- |
| `register_asset(asset_id, sac)` | admin | Registers a canonical fungible asset tag and its reserve SAC with conflict checks. |
| `set_denominations(denoms)` | admin | Sets public deposit/withdraw denominations; empty disables the gate. |
| `set_pair(asset_x, asset_y)` | admin | Sets the legacy batch-pair asset tags. |
| `set_reserves(x, y)` | admin | Writes legacy display/PoC reserve accounting without moving tokens. |
| `seed_liquidity(amount_x, amount_y)` | admin | Pulls real registered pair tokens and increases legacy reserve accounting. |
| `set_route(pair, token_x, token_y)` | admin | Allowlists the routed pair/adapter and token ordering. |
| `set_route_slip_bps(bps)` | admin | Sets auto-route drift tolerance, capped at 1,000 bps; default is 100 bps. |
| `set_protocol_fee(bps, treasury)` | admin | Sets withdrawal fee and treasury, capped at 100 bps. |
| `sweep_fees(fee_asset)` | admin | Transfers accrued venue fees to the configured treasury after solvency checks. |
| `set_min_dwell(n)` | admin | Requires swap anchors to trail the current frontier by at least `n` appends; `n < 32`. |
| `add_mm_funder(funder)` | admin | Adds an independent, self-funding denomination-exempt deposit actor. |
| `remove_mm_funder(funder)` | admin | Removes an MM funder. |

The legacy `reserves()` value is display-only. It is not real custody, not a
solvency source, and not load-bearing for routed pricing. Read actual pool
custody from each registered SAC's `balance(pool_address)`.

### Shielded note operations

| Function | Authorization | Effect |
| --- | --- | --- |
| `deposit(...)` | owner | Pulls a standard-denomination reserve amount and appends one proof-bound note. |
| `deposit_internal(...)` | admin or allowlisted self-funding MM | Denomination-exempt proof-bound deposit. |
| `transfer(...)` | proof authority; relayer-safe | Spends one note and appends one hidden-value output note. |
| `split(...)` | proof authority; relayer-safe | Spends one note and appends two hidden-value notes. |
| `withdraw(...)` | proof authority; relayer-safe | Spends a note and pays a standard denomination to a proof-bound recipient, less protocol fee. |
| `withdraw_with_change(...)` | proof authority; relayer-safe | Pays a standard denomination, sends the exact policy fee, and appends private change. |

The pool derives `recipient_tag` as SHA-256 of the recipient's XDR with the top
byte masked into the scalar field. This binds relayed withdrawals to the
intended recipient.

### Decoupled swap operations

| Function | Status | Description |
| --- | --- | --- |
| `swap_commit(...)` | legacy | Spends a note and appends an unbound swap commitment. |
| `swap_commit_bound(...)` | v1 amount-bound | Also binds ciphertext hash and registered route tags. |
| `swap_commit_bound_v2(...)` | preferred v2 | Separates semantic and current-frontier append proofs and records a v2 receipt. |
| `batch_execute(...)` | disabled | ABI-preserved function that always rejects. |
| `batch_execute_scoped(...)` | legacy admin path | Records a batch-scoped root, participant cap, totals, and optional venue fee. |
| `batch_execute_routed(...)` | legacy routed path | Routes the aggregate and records the exact output custody delta atomically. |
| `batch_execute_routed_v2(...)` | preferred v2 | Derives ordered root/membership, routes, assigns receipts, and writes one v2 record atomically. |
| `swap_claim(...)` | legacy | Claims from a scoped non-v2 batch. |
| `swap_claim_v2(...)` | preferred v2 | Claims from a canonical v2 batch using semantic and append proofs. |

Venue fee is capped at 25 bps. The batch record stores net output after that
fee; accrued fees remain in pool custody until swept.

### Settlement and routing

| Function | Authorization | Description |
| --- | --- | --- |
| `route_net(amm, token_in, amount_in, min_out)` | admin | Legacy manual push route through the configured AMM only. |
| `route_net_pair(pair, token_in, amount_in)` | admin | Manual low-level pair route with checked constant-product math. |
| `settle_batch(...)` | proof | Legacy aggregate proof for one buy and one sell. |
| `settle_batch_v2(...)` | proofs | Two owner order-spend proofs plus one cross-bound keyless clearing proof. |
| `settle_batch_vn(...)` | proofs | N buyer proofs, one MM sell proof, and one N-buyer clearing proof. |

The automatic route compares live venue output with a floor derived from the
proof-bound reserve snapshot. Bad reserves, dust inconsistencies, or excessive
drift fail closed and roll back the settlement.

### Confidential LP operations

| Function | Description |
| --- | --- |
| `set_lp_amm(amm, token_a, token_b)` | Admin-wires the legacy AMM and tokens. |
| `set_lp_amm_tags(tag_a, tag_b)` | Admin-wires underlying shielded asset tags. |
| `set_lp_pair(...)` | Creates one pair config and assigns a unique LP note-class tag. |
| `create_pair(...)` | Registers both assets and creates the LP pair in one admin call. |
| `add_liquidity_confidential(...)` | Adds public liquidity and mints a private LP-position note without a minimum-share floor. |
| `add_liquidity_confidential_min(...)` | Adds liquidity with a positive minimum-share floor. |
| `add_lp_confidential_for(...)` | Per-pair add using that pair's unique LP note class. |
| `remove_liquidity_confidential(...)` | Legacy full LP-note removal to a public recipient. |
| `remove_lp_confidential_for(...)` | Per-pair full removal. |
| `remove_lp_confidential_for_min(...)` | Per-pair removal with positive per-leg output floors. |
| `remove_liquidity_partial(...)` | Public partial removal plus a private LP change note. |
| `remove_liquidity_shielded(...)` | Full removal into two shielded underlying-asset notes. |
| `remove_partial_shielded(...)` | Private LP change plus two shielded underlying outputs. |

The public AMM sees the pool contract as the sole LP of record. End-user
positions are owner-bound shielded notes. Per-pair note-class tags are unique,
preventing a note created for one AMM from removing liquidity from another.
Contributions and public withdrawals remain visible at the token boundary.

### Views

| Function | Returns |
| --- | --- |
| `version()` | `12` |
| `root()` / `next_index()` | Current commitment root/frontier |
| `recipient_tag(recipient)` | Contract-derived proof recipient tag |
| `denominations()` | Public denomination policy |
| `get_min_dwell()` / `get_route_slip_bps()` | Privacy/routing policy |
| `protocol_fee_bps()` / `swap_fee_accrued(asset)` | Fee configuration/accounting |
| `mm_funders()` | Independent MM allowlist |
| `nullifier_spent(nf)` | Whether a nullifier exists |
| `solvency_enforced()` | Whether exact fresh-pool liability checks are active |
| `reserve_of(asset_id)` | Registered reserve SAC |
| `route_config()` | `(pair, token_x, token_y)` |
| `bound_commit(scm)` | v1/v2 route and ciphertext receipt |
| `bound_commit_v2(scm)` | Whether v2 state exists for an SCM |
| `v2_member_use(scm)` | Assigned batch ID/position, if used |
| `mobile_v2_batch(batch_id)` | Complete v2 output/capacity record |
| `mobile_v2_config()` / `mobile_v2_active()` | Pinned profile and activation |
| `lp_pair(pair_id)` / `lp_pairs()` | Per-pair AMM, tokens, underlying tags, unique LP note tag, and pair enumeration |
| `outstanding_of(asset_id)` | Exact/observed liability; admin-authenticated because it is a value oracle |
| `reserves()` | Legacy display-only X/Y accounting |

### TTL keepers

| Function | Authorization | Limit |
| --- | --- | --- |
| `bump_ttl()` | none | Renews pool instance/code and configured batch hasher. |
| `bump_nullifier_ttl(nullifiers)` | none | Maximum 64 nullifiers per call. |
| `bump_pair_ttl(pair_ids)` | none | Maximum 64 persistent LP pair entries per call. |

Operational automation must call these before archival. A spent-nullifier
archive/restore policy is security-critical: losing the authoritative spent set
can enable replay.

## Proof public-input contracts

Every verifier instance must use a key for the exact listed order. All numeric
values are canonical 32-byte big-endian field elements.

| Operation | Public inputs |
| --- | --- |
| deposit | `[asset_id, amount, oldRoot, startIndex, newRoot, cm]` |
| transfer | `[anchorRoot, nf, oldRoot, startIndex, newRoot, cmOut]` |
| split | `[anchorRoot, nf, asset_id, currentIndex, oldRoot, startIndex, midRoot, newRoot, cmHi, cmLo]` |
| swap commit v1 | `[anchorRoot, nf, oldRoot, startIndex, newRoot, scm]` |
| bound swap commit v1 | `[ctHash, anchorRoot, nf, oldRoot, startIndex, newRoot, scm, assetIn, assetOut]` |
| bound swap commit v2 semantic | `[ctHash, anchorRoot, nf, scm, assetIn, assetOut]` |
| append v2 | `[oldRoot, startIndex, newRoot, leaf]` |
| swap claim v1 | `[batchId, assetIn, assetOut, sumIn, sumOut, swapRoot, nfClaim, oldRoot, startIndex, newRoot, cmOut]` |
| swap claim v2 semantic | `[batchId, assetIn, assetOut, sumIn, sumOut, swapRoot, nfClaim, cmOut]` |
| withdraw | `[anchorRoot, nf, asset_id, amount, recipientTag, currentIndex]` |
| withdraw with change | `[anchorRoot, nf, asset_id, amountOut, fee, recipientTag, currentIndex, oldRoot, startIndex, newRoot, changeCm]` |
| LP add | Deposit layout with pair-specific LP note tag and exact minted shares |
| LP remove | Withdraw layout with pair-specific LP note tag and exact shares |

Settlement layouts are documented next to their entrypoints in `src/lib.rs`
because their vector lengths vary with batch shape.

Proof bytes use the verifier repository's 384-byte format:

```text
G1 a (96) || G2 b (192) || G1 c (96)
```

## Events

| Topic | Event | Key data |
| --- | --- | --- |
| `nfspent` | `NullifierSpentEvent` | nullifier |
| `deposit` | `DepositEvent` | commitment, index, encrypted note |
| `transfer` | `TransferEvent` | commitment, index, nullifier, encrypted note |
| `withdraw` | `WithdrawEvent` | nullifier, public amount, protocol fee |
| `settle` | `SettleEvent` | nullifiers, output commitments, first index, ciphertexts |
| `swapcm` | `SwapCommitEvent` / `BoundSwapCommitEvent` | commitment and optional ciphertext/route binding |
| `swapcmv2` | `BoundSwapCommitV2Event` | v2 commitment, binding, route |
| `swapclaim` | `SwapClaimEvent` | output commitment, index, claim nullifier |
| `lpadd` | `LpAddEvent` | LP commitment, index, encrypted note |
| `lpremove` | `LpRemoveEvent` | nullifier and public returned token amounts |
| `paircreat` | `PairCreatedEvent` | pair ID and unique LP note tag |
| `batchexec` | `BatchExecutedEvent` | batch route, net totals, root, participants, fee |
| `batchexecv2` | `BatchExecutedV2Event` | batch ID and exact ordered SCM list |
| `vfreeze` | `VerifiersFrozenEvent` | irreversible verifier/upgrade freeze |
| `ufreeze` | `UpgradeFrozenEvent` | irreversible upgrade freeze |
| `upgrade` | `UpgradeEvent` | new Wasm hash |

Encrypted-note event data is public ciphertext. Indexers must preserve event
order and leaf indices exactly.

## Errors

| Code | Name | Meaning |
| ---: | --- | --- |
| 1 | `AlreadyInitialized` | Pool initialization already occurred. |
| 2 | `NotInitialized` | Required base state is missing. |
| 3 | `NotAdmin` | Admin state/authorization requirement failed. |
| 4 | `BadAmount` | Amount, index, total, fee, or other numeric shape is invalid. |
| 5 | `NoReserve` | Asset, pair, token, or route reserve configuration is missing. |
| 6 | `NonCanonical` | A 32-byte field input is not canonical. |
| 7 | `MalformedProof` | Proof bytes cannot be decoded. |
| 8 | `InvalidProof` | Groth16 verification returned false. |
| 9 | `BadAnchorRoot` | Anchor is outside the recent-root ring or a guarded route is wrong. |
| 10 | `DoubleSpend` | Nullifier/commitment member is duplicated or already spent. |
| 11 | `NoVerifier` | Required verifier or allowed route is absent. |
| 12 | `CtTooLong` | Encrypted note payload exceeds 256 bytes. |
| 13 | `Frozen` | A verifier or upgrade mutation is permanently disabled. |
| 14 | `BadDenom` | Public amount is not an allowed denomination. |
| 15 | `DwellNotMet` | Swap anchor has not aged by the configured append count. |
| 16 | `SlippageExceeded` | AMM/LP output is below the required floor. |
| 17 | `NoBatch` | Scoped legacy batch data/capacity is unavailable. |
| 18 | `LpAmmNotSet` | Required legacy or per-pair LP configuration is absent. |
| 19 | `BatchFull` | Participant/claim capacity is exceeded. |
| 20 | `PairExists` | A pair, batch ID, or commitment receipt would be overwritten. |
| 21 | `ReserveConflict` | Asset/SAC mapping conflicts with an existing registration. |
| 22 | `Insolvent` | Live token custody is below tracked shielded liabilities. |
| 23 | `LiabilityUnderflow` | A transition attempts to consume more liability than exists. |
| 24 | `TreeFull` | The 65,536-leaf global tree has no remaining capacity. |
| 25 | `WrongProtocol` | V1/v2 boundary, activation profile, executor, member state, or writer invariant is wrong. |

Soroban authorization failures and downstream token/AMM/verifier contract errors
may also abort an invocation.

## Storage layout and compatibility

`storage-layout.json` is the reviewable source of truth for `DataKey` order and
key payload types. Existing enum entries must never be reordered or deleted;
new keys are appended to preserve their XDR discriminants.

State is split between:

- instance configuration and live tree/frontier state;
- persistent reserve mappings and reverse mappings;
- long-lived spent nullifiers;
- bound commit receipts and member assignment;
- batch output/capacity records;
- per-asset liabilities and accrued fees; and
- per-pair confidential LP configuration.

Any upgrade must compare:

1. old and new contract specifications;
2. `DataKey` order and payload types;
3. public contract type layouts;
4. runtime readback of admin, root, frontier, asset mappings, verifiers, freeze
   flags, solvency flag, routes, fees, and v2 profile; and
5. expected `version()` before and after.

Never replace a live pool for a routine upgrade: doing so orphans existing
notes, roots, nullifiers, and liabilities. Use a reviewed guarded in-place
upgrade or a separately designed migration.

## Build

The standalone pool imports verifier ABI types and proof decoding from an exact
reviewed commit of the separate `Confihub/groth16_verifier` repository. The
dependency is commit-pinned rather than following a mutable branch.

Prerequisites:

- Rust `1.91` with the `wasm32v1-none` target;
- Stellar CLI compatible with Soroban SDK 25;
- Git access to the public verifier dependency; and
- sufficient memory for the Soroban release build.

```bash
rustup target add wasm32v1-none
stellar contract build
```

The optimized pool Wasm is produced under:

```text
target/wasm32v1-none/release/confibatch_pool.wasm
```

The fixed mobile-v2 batch hasher is included under `mobile_v2_hasher`.
Build its deployable Wasm separately when provisioning mobile-v2:

```bash
cargo build \
  --manifest-path mobile_v2_hasher/Cargo.toml \
  --target wasm32v1-none \
  --release
```

The helper exposes:

```text
version() -> 1
hash_id() -> SHA-256("confi.cash/mobile-v2/batch-root/poseidon-bls12381-t3-v1")
root(ordered_scms) -> depth-3 Poseidon root
```

The pool validates the helper's contract identity, version, and hash ID during
one-way v2 activation.

## Deployment and wiring order

1. Build release Wasm from the guarded default verifier configuration.
2. Deploy one `groth16_verifier` instance per circuit and immediately initialize
   each with its exact key.
3. Deploy the mobile-v2 batch-hash helper and verify `version()` and `hash_id()`.
4. Deploy `confibatch_pool` with the intended admin and canonical empty depth-16
   root.
5. Read back `version() == 12`, `solvency_enforced() == true`, root, and index 0.
6. Register each asset tag/SAC mapping and confirm the reverse-mapping conflict
   protections through expected reads.
7. Configure denominations, protocol fee/treasury, dwell, and slippage.
8. Deploy/configure the AMM or external pair and guarded route adapter, then call
   `set_route`.
9. Wire every verifier into its exact setter and execute known positive and
   negative proof vectors.
10. Configure the classic threshold executor account and independently verify
    signer/threshold policy.
11. Compute and review the semantic profile hash.
12. Call `activate_mobile_v2` once with the exact profile, helper, and executor.
13. Read back `mobile_v2_config()` and compare every field to the release
    manifest.
14. Run a small end-to-end deposit, 2–5-member commit/execute/claim, transfer,
    and withdrawal rehearsal while recording all transaction hashes.
15. Start TTL, solvency, fee, event-indexing, and archival monitoring.

Do not call `freeze_verifiers` or `freeze_upgrade` as a routine deployment step.
Both are irreversible governance actions and require a separately reviewed
production promotion decision.

Exact Stellar CLI arguments depend on the installed version. Inspect the built
specification before deployment:

```bash
stellar contract info interface \
  --wasm target/wasm32v1-none/release/confibatch_pool.wasm
```

## Security checklist

- Verify circuit/R1CS/proving-key/verifying-key/ceremony hashes.
- Confirm the verifier source exposes only the real pairing path.
- Confirm every verifier address and public-input order.
- Confirm the constructor's empty root and field canonicality.
- Confirm asset/SAC uniqueness and real custody.
- Confirm denomination, fee treasury, dwell, route, and slippage policies.
- Confirm route adapter recipient is the pool and the pool allowlists that exact
  adapter/pair.
- Confirm mobile-v2 profile/helper/executor identities from independent live
  readbacks.
- Validate wrong-root, stale-root, replayed-nullifier, duplicate-member,
  reordered-member, wrong-route, wrong-fee, changed-total, underpayment,
  over-capacity, and archive/restore failure cases before production.
- Retain at least 20% execution-resource margin using release Wasm and real
  verifier calls.
- Monitor nullifier and batch-record TTL; rehearse restoration procedures without
  weakening replay protection.
- Record Wasm hashes, contract IDs, network passphrase, configuration, ceremony
  references, deployment/wiring/activation hashes, and signed release manifest.
- Obtain external review of contracts, circuits, relayer, committee policy,
  frontend proof construction, indexer, and operations before production.

## Repository contents

```text
src/lib.rs                         Main contract and helpers
src/mobile_v2_batch.rs             Canonical ordered-SCM validation/helper call
mobile_v2_hasher/                  Pinned immutable Poseidon helper source
storage-layout.json                Ordered storage-key compatibility manifest
Cargo.toml                         Standalone Soroban build configuration
Cargo.lock                         Reproducible dependency lock
```

## Security and license

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
The source is licensed under the [Apache License 2.0](LICENSE).

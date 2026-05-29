# Bridge Withdrawals

Status: Active
Owner: Nockchain Maintainers
Last Reviewed: 2026-03-13
Canonical/Legacy: Canonical bridge withdrawal protocol and implementation spec

## Scope

This document specifies the implementation work required to enable bridge withdrawals (Base -> Nockchain) across:

1. Rust bridge crate (`open/crates/bridge`)
2. Hoon bridge kernel (`open/hoon/apps/bridge/bridge.hoon`, plus `base.hoon`, `nock.hoon`, `types.hoon`)

This spec focuses on:

1. What is currently unimplemented
2. What must be changed
3. What the withdrawal coordination model must be
4. How to validate correctness

## Current Implementation Status

### Kernel status (Hoon)

1. Nock-side withdrawal tx detection is now wired (no intentional hard-stop):
   - `open/hoon/apps/bridge/nock.hoon`
   - arm: `++ process-nock-txs`
   - branch: `is-bridge-withdrawal-tx`
   - current behavior: detects packed `%bridge-w` note-data, parses withdrawal metadata, and builds `withdrawal-settlement` entries (non-matching/malformed outputs are skipped, not fatal)

2. Nock-side settlement processing no longer intentionally rejects withdrawals:
   - `open/hoon/apps/bridge/nock.hoon`
   - arm: `++ nockchain-process-withdrawal-settlements`
   - current behavior: reconciles settlements against tracked withdrawals, emits hold when referenced `as_of` base hash is unknown, stops on irreconcilable counterpart issues, and clears matched unsettled entries

3. Base-side withdrawal proposal arm is now implemented:
   - `open/hoon/apps/bridge/base.hoon`
   - arm: `++ base-propose-withdrawals`
   - current behavior: returns `(list nock-withdrawal-request)` and is emitted as `%create-withdrawal-txs`

4. Withdrawal data/effect surface was updated:
   - `open/hoon/apps/bridge/types.hoon`
   - `withdrawal` now uses `dest=nock-lock-root` and no fee field
   - `withdrawal-settlement` now includes `base-batch-end` (including hashable encoding) and no `nock-tx-fee`
   - effects now include `%create-withdrawal-txs` and the confirmed-only
     `%withdrawal-terminal` alongside the existing deposit / stop surface
   - `%create-withdrawal-tx` exists as the dedicated poke/cause for asking the
     bridge app tx-builder to construct a withdrawal proposal from explicit
     inputs / withdrawal data
   - `%sign-tx` exists as the dedicated poke/cause for asking Rust-side
     withdrawal coordination to sign the transaction inside a
     `withdrawal-proposal`
   - current behavior: still stubbed as a guarded no-op; the intended
     implementation remains milestone 2, but specifically as a split builder
     seam before live submission is enabled

### Runtime status (Rust)

1. Core runtime and loops are deposit-centric:
   - `open/crates/bridge/src/main.rs`
   - `open/crates/bridge/src/runtime.rs`
   - active loops: signing cursor + posting loop for Base deposit submissions

2. Rust effect surface now decodes the milestone 1 withdrawal kernels effects:
   - `open/crates/bridge/src/types.rs`
   - withdrawal-related variant: `BridgeEffectVariant::CreateWithdrawalTxs(Vec<NockWithdrawalRequestKernelData>)`
   - terminal variant: `BridgeEffectVariant::WithdrawalTerminal(WithdrawalTerminalEffect)`

3. Legacy runtime local effect queue was removed:
   - `open/crates/bridge/src/runtime.rs`
   - `BridgeRuntime::process_effect` and `send_effect` no longer exist
   - effect consumption is now driver-specific (e.g., stop/deposit drivers)

4. Live effect handling remains deposit-only, with an explicit withdrawal
   guard:
   - `open/crates/bridge/src/deposit_log.rs`
   - `create_commit_nock_deposits_driver` consumes only `CommitNockDeposits`
   - `open/crates/bridge/src/withdrawal_guard.rs`
   - `open/crates/bridge/src/main.rs` registers a milestone-1 guard driver that
     logs and ignores `%create-withdrawal-txs` and `%withdrawal-terminal`

5. Ingress and proposal cache are deposit-specific:
   - `open/crates/bridge/proto/bridge_ingress.proto`
   - `open/crates/bridge/src/ingress.rs`
   - `open/crates/bridge/src/proposal_cache.rs`
   - all keyed by `DepositId` and Ethereum signature flow

5. Withdrawal proposal validation and tracking belong to Rust, but are not
   fully implemented yet:
   - there is no kernel proposal-validation cause in the intended design
   - Rust must own proposal-envelope validation against withdrawal identity,
     snapshot/selected-note inputs, epoch legality, replay/equivocation rules,
     and durable per-withdrawal proposal tracking
6. Base burn events are observed, but settlement execution path is missing:
   - `open/crates/bridge/src/ethereum.rs`
   - `process_nock_log` decodes `BurnForWithdrawal`
   - generated local `Withdrawal` currently has `dest: None`
   - TODO: base-side kernel processing must enforce the withdrawal minimum so burns at or below the configured minimum do not materialize into withdrawal state

7. Withdrawal-specific coordination state is partially implemented:
   - a durable sequencer-owned record of prepared / peer-canonical /
     authorized / submitted / confirmed withdrawals exists in Rust
   - append-only withdrawal lifecycle storage and local input-note reservation
     projections now exist
   - the ingress-side withdrawal proposal transport remains in the main bridge
     process, while the separate sequencer gRPC surface is now hosted by the
     dedicated `bridge-sequencer` binary
   - the Rust submission/release driver layer exists; sequencer-side
     submission and confirmed-settlement recording now live in the separate
     sequencer binary, while terminal release stays in the main bridge process
   - confirmed Nock blocks now drive bridge-owned note snapshot refresh in the
     main bridge process plus sequencer-side `tx_confirmed` recording in the
     separate sequencer binary
   - `%create-withdrawal-tx` and `%sign-tx` are now real kernel execution
     seams rather than stubs

### Contracts and dependencies

1. Contracts support burn-side initiation:
   - `open/crates/bridge/contracts/Nock.sol`: `burn(amount, lockRoot)` emits `BurnForWithdrawal`
   - `open/crates/bridge/contracts/MessageInbox.sol`: `notifyBurn` + `withdrawalsEnabled` gate

2. No immediate `Cargo.toml` dependency gap identified for baseline implementation:
   - `open/crates/bridge/Cargo.toml`
   - nockapp gRPC client dependencies already present

## Target Withdrawal Flow

1. User burns wrapped NOCK on Base (`Nock.sol::burn`), event emitted with `lockRoot`.
2. Rust Base observer ingests burn, emits `%base-blocks` cause to kernel.
3. Kernel stores unsettled withdrawals keyed by `(as_of base hash, base_event_id)`.
   Base-side kernel processing must enforce the withdrawal minimum first; only burns strictly above the configured minimum become withdrawals. We are targetting a minimum of 10,000 NOCKS.
4. Kernel emits `%create-withdrawal-txs` with `nock-withdrawal-request` payloads describing withdrawal intent.
5. Runtime treats each `nock-withdrawal-request` as a single-withdrawal coordination unit. `base-batch-end` remains part of withdrawal metadata, but settlement coordination is per-withdrawal rather than multi-withdrawal batching.
6. For a given withdrawal id `(as_of, base_event_id)`, a deterministic epoch
   leader selects a pinned balance snapshot `{height, block_id}` and an
   explicit selected input-note set.
7. The leader pokes `%create-withdrawal-tx` with the withdrawal id, epoch,
   pinned snapshot metadata, withdrawal metadata, and selected input note
   names.
8. The kernel bridge tx-builder emits `%withdrawal-proposal-built`, carrying
   the full `withdrawal-proposal`, including the exact wallet `transaction`
   and its unique `name`.
9. Rust persists and broadcasts that proposal envelope to peers.
10. Peers validate the proposal against kernel state and local bridge-owned note
    / tx-builder state, durably persist the exact envelope, and commit to at
    most one proposal hash for that `(withdrawal_id, epoch)`.
11. Once a threshold of peers has committed to the same exact proposal hash,
    that proposal becomes the peer-canonical candidate for that withdrawal and
    epoch.
12. Peer canonicalization alone is not enough to make a withdrawal submit-ready.
    The sequencer gRPC service durably records the canonical candidate as the
    only authorized next action for that withdrawal id.
13. Only the sequencer gRPC service may finalize and submit a withdrawal tx.
    The sequencer service maintains the authoritative submitted / in-flight
    withdrawal set and must not authorize the same withdrawal twice.
14. If the scheduled assembler is offline and no proposal becomes canonical
    before the assembly timeout, the next epoch leader may assemble a new
    candidate tx for the same withdrawal id.
15. The sequencer durably records the authorization / submission /
    confirmation lifecycle and owns the global in-flight gate for withdrawals.
    Only one withdrawal may be
    sequencer-authorized / submitted / unconfirmed at a time.
16. If the sequencer is unavailable, withdrawals pause. There is no automatic
    submission failover.
17. Authoritative progress is chain-observable, not gossip-observable. The
    bridge should distinguish:
    - diagnostic accepted state via `tx-accepted`
    - confirmed inclusion via observed settlement in a confirmed block
    A local "submitted" event is advisory only; sequencer authorization is the
    required precondition for submission, not a consensus fact on its own.
18. The sequencer service and Rust Nock watcher observe confirmed settlement in
    block txs. The sequencer durably records confirmation for the authorized
    withdrawal before clearing its authoritative in-flight record.
19. Kernel reconciles settlement with counterpart withdrawal on the confirmed
    Nock block stream, clears unsettled state, and emits a terminal withdrawal
    effect for confirmed outcomes.
20. Rust and the sequencer consume that terminal withdrawal effect, release the
    matching local reservations, and confirm that the withdrawal has been
    removed from the sequencer's submitted / in-flight set.
21. If settlement references an unknown `as_of` base hash, hold logic blocks
    advancement until that base hash is ingested. If `as_of` is known but
    counterpart data is inconsistent/missing, processing stops.

## Coordination Model

1. The coordination unit is one withdrawal, keyed by `(as_of, base_event_id)`. Once admitted, a withdrawal remains live until confirmed. Withdrawal settlement is not coordinated as a multi-withdrawal batch.
2. There is one failover stage:
   - assembly failover: if no proposal reaches canonicalization in the current epoch, the next epoch leader may assemble a new tx
3. A proposal becomes peer-canonical only after a threshold of bridge nodes has:
   - validated the same exact proposal hash
   - durably persisted the proposal envelope locally
   - committed to that proposal for the given `(withdrawal_id, epoch)`
4. Peer canonicalization is not enough to create a submit-ready withdrawal. A withdrawal may only advance past peer-canonical state when the sequencer durably authorizes it.
5. "Submitted" is not a consensus fact. It is a sequencer-owned local event recorded only after sequencer authorization. The protocol must not require all nodes to agree on whether a submit RPC was attempted.
6. Proposal assembly, peer canonicalization, submission, timeout, and supersession tracking live in runtime attempt machinery. They are not kernel withdrawal states.
7. There is one sequencer gRPC service for withdrawals. That sequencer service
   owns the authoritative submitted / in-flight withdrawal set and the durable
   confirmation record for authorized withdrawals.
8. Only one withdrawal may be sequencer-authorized / submitted / unconfirmed at a time.
9. If the sequencer is unavailable, withdrawals stop. There is no automatic submission failover.
10. Because there is no chain-enforced withdrawal nullifier today, peer threshold agreement alone is not a sufficient duplicate-withdrawal safety mechanism. The sequencer is part of the authorization boundary for withdrawals.

## Bridge-Owned Note Snapshot

1. The withdrawal pipeline does not depend on the standalone `nockchain-wallet` application.
2. The bridge runtime uses the Rust note selector and bridge-owned tx-builder flow, with bridge-owned note state fetched from the private nockchain API.
3. The bridge maintains a confirmed note snapshot for the bridge-controlled spend authority / note pool.
4. This confirmed snapshot should refresh whenever the bridge observes a newly confirmed nockchain block.
5. In practice, snapshot freshness is bounded by:
   - nockchain block production cadence
   - configured nockchain confirmation depth
   - nock watcher poll interval
6. A cached confirmed snapshot may be reused across multiple withdrawal assemblies, provided the planner always subtracts currently reserved input notes before selecting new inputs.
7. The runtime may also trigger an on-demand snapshot refresh before assembly if its cached confirmed snapshot is stale.

## Reservation Lifecycle

1. Input note reservations are per-node and must be persisted durably.
2. A proposal that is assembled locally but not yet canonical creates a provisional reservation on the assembling node only.
3. A proposal that becomes peer-canonical creates a canonical reservation on every node that accepts and persists that canonical proposal.
4. Provisional reservations prevent the assembling node from reusing selected inputs after restart while canonicalization is still pending.
5. Canonical reservations prevent all honest nodes from reusing inputs belonging to a sequencer-authorized in-flight withdrawal tx.
6. If a proposal does not become canonical, the rollback plan is:
   - mark the proposal attempt terminal
   - release its provisional reservations
   - clear the assembly/canonicalization lock
   - advance to the next epoch for the same withdrawal
7. If a sequencer-authorized tx fails to confirm, the withdrawal remains live. Recovery and replacement-attempt policy belongs to the sequencer-owned runtime attempt machinery for that same still-unconfirmed withdrawal.
8. Reservations are released or updated only when:
   - the kernel emits a terminal withdrawal effect after confirmed settlement reconciliation
   - the proposal attempt is rejected, expired, or superseded before canonicalization
   - sequencer-controlled local runtime recovery transfers or replaces canonical reservations for the same still-unconfirmed withdrawal without creating a kernel withdrawal outcome
9. A local submit RPC attempt is not enough to release or modify reservations.
10. The kernel should not emit raw note names for release. It should emit withdrawal identity plus confirmed-settlement information, and Rust should resolve that to the locally reserved note set on each node.

## Persistence and Tables

### Source of Truth

1. The source of truth is append-only.
2. Reserved input notes must be recorded in the append-only log, not only in mutable current-state tables.
3. Mutable tables are projections for fast lookup and operational convenience only.
4. On startup, the bridge rebuilds current attempt state and the current reserved-input set from the append-only log, then reconciles against observed chain state.
5. For withdrawals, the sequencer also owns an authoritative durable projection
   of which withdrawal ids are peer-canonical, authorized, submitted,
   confirmed, and still in-flight.

### Tables

1. `withdrawal_submission_events`
   - append-only event header table
   - one row per lifecycle event
   - minimum columns:
     - `event_id`
     - `created_at`
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `epoch`
     - `proposal_hash`
     - `transaction_name`
     - `event_type`
     - `transaction_jam` nullable
     - `snapshot_height` nullable
     - `snapshot_block_id` nullable
2. `withdrawal_submission_event_inputs`
   - append-only child table
   - one row per input note referenced by an event
   - minimum columns:
     - `event_id`
     - `note_name_first`
     - `note_name_last`
3. `withdrawal_attempts`
   - mutable/materialized table
   - one row per attempt, approximately keyed by `(withdrawal_id, epoch, proposal_hash)`
   - minimum columns:
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `epoch`
     - `proposal_hash`
     - `transaction_name`
     - `state`
     - `reservation_kind`
     - `transaction_jam`
     - `snapshot_height`
     - `snapshot_block_id`
     - `last_seen_accepted_at` nullable
     - `confirmed_height` nullable
     - `confirmed_block_id` nullable
     - `superseded_by_epoch` nullable
     - `created_at`
     - `updated_at`
4. `current_reserved_inputs`
   - mutable/materialized table
   - pure current live exclusion set used by the planner
   - one row per note that is reserved right now
   - minimum columns:
     - `note_name_first`
     - `note_name_last`
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `epoch`
     - `proposal_hash`
     - `reservation_kind`
     - `created_at`
5. `withdrawal_terminal_summaries`
   - optional future compaction/checkpoint table
   - one row per terminal withdrawal kept after detailed events are compacted
   - minimum columns:
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `final_state`
     - `final_tx_id` nullable
     - `winning_epoch` nullable
     - `winning_proposal_hash` nullable
     - `confirmed_height` nullable
     - `confirmed_block_id` nullable
     - `terminal_at`
     - `covered_through_event_id`
6. `sequenced_withdrawals`
   - authoritative mutable table owned by the sequencer
   - one row per withdrawal admitted to sequencer control
   - minimum columns:
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `current_epoch`
     - `peer_canonical_proposal_hash` nullable
     - `authorized_proposal_hash` nullable
     - `authorized_transaction_name` nullable
     - `state`
     - `created_at`
     - `updated_at`
7. `staged_withdrawal_requests`
   - mutable staging table owned by the local withdrawal assembly service
   - one row per kernel-emitted withdrawal request admitted to local planning
   - minimum columns:
     - `withdrawal_id_as_of`
     - `withdrawal_id_base_event_id`
     - `recipient`
     - `amount`
     - `base_batch_end`
     - `state`
     - `active_epoch` nullable
     - `created_at`
     - `updated_at`

### Event Types

1. Expected event types include:
   - `proposal_prepared`
   - `proposal_canonicalized`
   - `proposal_authorized`
   - `proposal_rejected`
   - `proposal_expired`
   - `proposal_superseded`
   - `tx_submitted`
   - `tx_seen_accepted`
   - `tx_confirmed`
   - `reservation_released`

### Append Log Schematics

1. Request staging:
   - upsert one `staged_withdrawal_requests` row for each
     `%create-withdrawal-txs` request
   - mark the chosen request as holding the local assembly lock before note
     selection / `%create-withdrawal-tx`
2. Local assembly attempt:
   - append `proposal_prepared`
   - append one `withdrawal_submission_event_inputs` row per selected input note
   - update or insert one `withdrawal_attempts` row
   - insert the selected notes into `current_reserved_inputs` as provisional reservations
   - update the matching `staged_withdrawal_requests` row to
     `proposal_prepared`
3. Canonicalization:
   - append `proposal_canonicalized`
   - append one `withdrawal_submission_event_inputs` row per canonical reserved note
   - update or insert one `withdrawal_attempts` row with canonical state
    - ensure the selected notes exist in `current_reserved_inputs` as canonical reservations
   - on the sequencer, update `sequenced_withdrawals` with the peer-canonical candidate
4. Sequencer authorization:
   - append `proposal_authorized`
   - update the sequencer-owned `sequenced_withdrawals` row with the only authorized proposal hash / transaction name for that withdrawal
   - do not authorize a second proposal for the same withdrawal while any authorized or submitted state remains live
5. Local rollback before canonicalization:
   - append `proposal_rejected`, `proposal_expired`, or `proposal_superseded`
   - append `reservation_released`
   - append one `withdrawal_submission_event_inputs` row per released note
   - update the matching `withdrawal_attempts` row to a terminal or superseded state
   - remove the released notes from `current_reserved_inputs`
6. Submission:
   - append `tx_submitted`
   - on the sequencer, transition `sequenced_withdrawals.state` to submitted / in-flight
   - update the matching `withdrawal_attempts` row
   - do not release reservations
7. Chain-observed progress:
   - append `tx_seen_accepted` as observed for diagnostics
   - update the matching `withdrawal_attempts` row
   - do not release reservations
8. Confirmed observation:
   - when confirmed settlement is observed for an authorized withdrawal,
     append `tx_confirmed`
   - update the matching `withdrawal_attempts` row to confirmed
   - do not release reservations yet
   - do not clear the sequencer-owned in-flight row yet
9. Terminal release:
   - after the kernel emits a terminal withdrawal effect for confirmed
     settlement, append `reservation_released`
   - append one `withdrawal_submission_event_inputs` row per released note
   - on the sequencer, remove or terminalize the `sequenced_withdrawals` row
   - remove the released notes from `current_reserved_inputs`

### Modification Rules

1. `withdrawal_attempts` must never be edited on its own.
2. `withdrawal_attempts` may only be inserted or updated in the same transaction that appends a new row to `withdrawal_submission_events`.
3. `current_reserved_inputs` must never be edited on its own during normal runtime.
4. `current_reserved_inputs` may only be inserted into or deleted from in the same transaction that appends the corresponding reservation event rows.
5. The only exception is startup rebuild, where mutable tables may be reconstructed by replaying the append-only log.
6. `current_reserved_inputs` is a pure "currently blocking note names" table.
7. `current_reserved_inputs` must not be treated as a history or audit table.
8. History, audit, restart recovery, and reservation provenance must come from the append-only event tables.

### Reservation Queries, Deletion, and Truncation

1. The planner should treat the live spendable set as:
   `spendable_notes = confirmed_snapshot - current_reserved_inputs`
2. When a note stops blocking planning, it should be removed from `current_reserved_inputs`.
3. Removing a note from `current_reserved_inputs` does not delete its reservation history.
4. Reservation history remains in the append-only event log forever unless it is safely compacted.
5. Safe truncation requires a terminal summary / checkpoint for a withdrawal before detailed event rows are deleted.
6. Detailed event rows must not be truncated for any withdrawal that:
   - is not terminal
   - still owns live reservations
   - may still be resubmitted
   - has not been checkpointed into a terminal summary
7. A practical future compaction path is:
   - write a compact terminal summary row for a finished withdrawal
   - confirm that no reservations or live attempts remain
   - archive or delete the detailed hot-path event rows for that withdrawal
   - optionally run SQLite `VACUUM`
8. Correctness is more important than aggressive truncation. It is acceptable to keep the full append-only withdrawal history and defer compaction.

## Required Changes

### A) Kernel changes (Hoon)

1. Keep withdrawal proposal handling out of the kernel.
   - do not introduce a kernel withdrawal proposal-validation cause
   - do not persist `withdrawal-proposals` in kernel state
   - do not validate proposal identity, epoch legality, replay, or
     equivocation in the kernel
   - do not validate proposal envelope fields against tracked withdrawal
     metadata in the kernel
   - the kernel should remain withdrawal-level only: qualifying burns create
     live/unconfirmed withdrawals, and confirmed settlements clear them
2. Harden Base-side proposal generation in `++ base-propose-withdrawals` (already emitting `nock-withdrawal-request`) with queue semantics suitable for single-flight assembly/canonicalization.
3. Harden withdrawal parsing path in `++ process-nock-txs` (already creating `withdrawal-settlement`) and close remaining schema/validation gaps.
4. Finalize `++ nockchain-process-withdrawal-settlements` behavior in `open/hoon/apps/bridge/nock.hoon`:
   - reconcile settlement against tracked unsettled withdrawals
   - apply hold/stop semantics for out-of-order or inconsistent settlement
   - tolerate sequencer retries of the same authorized tx without treating them as a second withdrawal
5. Add a dedicated create-withdrawal-tx poke/cause for bridge-side tx building.
   - this remains milestone 2 work, but it is a split builder seam rather than
     part of live submission enablement
   - widen the poke/cause so it includes `epoch` and pinned
     `withdrawal-snapshot` in addition to explicit withdrawal metadata plus
     selected inputs
   - it should let Rust ask the bridge app tx-builder to build one full
     `withdrawal-proposal`, not just a raw tx
   - successful construction should come back out via
     `%withdrawal-proposal-built`, carrying that full proposal
   - it should remain separate from `%create-withdrawal-txs`, which is the
     kernel effect describing withdrawal intent from Base burns
6. Add a dedicated `%sign-tx` poke/cause for transaction signing.
   - input should be the full `withdrawal-proposal`
   - Rust uses it after proposal construction / authorization, not as part of
     kernel withdrawal-state transitions
   - signing remains distinct from tx construction and from confirmed terminal
     effects
7. Extend the kernel effect surface with a terminal withdrawal outcome effect:
   - emit on confirmed settlement reconciliation from the confirmed Nock block stream
   - payload should identify the confirmed withdrawal and any confirmed-settlement data needed by Rust
   - payload must not include local note names
8. Normalize and finalize withdrawal metadata encoding:
   - new packed key path: `%bridge-w`
   - includes `base-block-hash`, `beid`, `base-batch-end`, `lock-root`
9. Finalize amount semantics in kernel models (`amount-burned` vs `settled-amount`) now that dedicated withdrawal fee fields were removed from molds.

### B) Rust bridge crate changes

1. Add withdrawal proposal transport and validation:
   - new ingress RPC and message types for nockchain tx proposal broadcast
   - proposal envelope must include withdrawal id, epoch, pinned snapshot metadata, selected input note names, and the built `transaction`
   - decode and route directly to Rust withdrawal coordination logic rather
     than via a kernel cause
   - validate the proposal envelope in Rust by checking:
     - whether the withdrawal exists
     - whether the proposal matches the tracked withdrawal
     - same-epoch replay vs equivocation
     - contiguous epoch legality
   - also validate pinned snapshot, selected notes, and transaction identity
     as part of the Rust-owned proposal envelope checks
2. Add the split withdrawal tx-builder seam:
   - Rust selects candidate inputs and pinned snapshot metadata, then pokes the
     widened `%create-withdrawal-tx`
   - decode `%withdrawal-proposal-built`, carrying the constructed full
     `withdrawal-proposal`
   - keep this builder seam implementable before durable submission is enabled
3. Add the signing seam:
   - Rust pokes `%sign-tx` with the full `withdrawal-proposal`
   - successful signing should come back out via `%withdrawal-tx-signed`,
     carrying the proposal envelope with signed transaction data
   - signing is driven from Rust-side coordination and remains separate from
     kernel withdrawal-state transitions
4. Add the withdrawal sequencing service:
   - implement the durable sequencing service core and schema first
   - append-only local log of proposal/canonicalization/submission/confirmation lifecycle
   - sequencer-owned authoritative tracking of peer-canonical / authorized /
     submitted withdrawals
   - sequencer-owned confirmation watcher that records confirmed withdrawals
     and clears the in-flight set
   - reserve input notes by note `Name` before submit
   - drive local tx-status reconciliation using `tx-accepted` as a diagnostic
     mempool/accepted signal and confirmed settlement observations as the
     release signal
   - consume the kernel's terminal withdrawal effect to release local canonical
     reservations by withdrawal id
   - make the sequencer the only submission authority for withdrawals
   - add the separate sequencer gRPC wrapper / RPC surface in the later
     proposal transport step
5. Add withdrawal execution driver:
   - consume `BridgeEffectVariant::CreateWithdrawalTxs`
   - allow at most one withdrawal in assembly/canonicalization at a time for the bridge-controlled spend authority / note pool
   - make the sequencer gRPC service the only component that finalizes and submits an authorized raw tx using nockapp public nockchain gRPC client (`wallet_send_transaction`)
   - include separate assembly timeout and sequencer submission timeout behavior
   - if the sequencer is unavailable, stop withdrawal progress rather than failing over to peer submission
6. Add proposal broadcast/signature workflow keyed off per-withdrawal epochs rather than deposit ids or withdrawal batches, with sequencer authorization required before a peer-canonical candidate becomes submit-ready.
7. Extend runtime/main wiring:
   - register new IO drivers in `open/crates/bridge/src/main.rs`
8. Extend bridge note snapshot handling:
   - use a normalized bridge-note balance snapshot for private-node sync as well as public sync
   - refresh the confirmed bridge-note snapshot whenever a newly confirmed nockchain block is observed
   - support on-demand refresh before assembly when the cached snapshot is stale
   - compute `spendable_notes = confirmed_snapshot - current_reserved_inputs`
   - prevent reuse of notes that belong to prepared/submitted but unconfirmed canonical txs
9. Add durable withdrawal storage schema and rebuild logic:
   - implement append-only event tables for withdrawal lifecycle and reserved inputs
   - implement mutable projection tables for attempts and current reserved inputs
   - rebuild projections from the append-only log on startup
   - reserve/release inputs transactionally with the corresponding event append
10. Optional but recommended:
   - enrich `process_nock_log` output in `open/crates/bridge/src/ethereum.rs` to propagate destination/lock-root mapping into runtime observability structures, or explicitly document that kernel state is canonical and Rust-side `dest` remains advisory-only.

### C) Type/protocol updates

1. `open/crates/bridge/proto/bridge_ingress.proto`
   - add withdrawal proposal request/response
   - proposal payload must be a full withdrawal proposal envelope, not just a bare transaction body
   - include withdrawal id, epoch, proposal hash / transaction name, pinned snapshot metadata, selected input note names, and typed payload
   - add sequencer service RPCs for authorize / submit / status / confirmed-record updates
2. `open/crates/bridge/src/types.rs`
   - keep `NockWithdrawalRequestKernelData` as the kernel-emitted withdrawal intent payload
   - add `%withdrawal-proposal-built`, carrying a full `withdrawal-proposal`
   - add `%withdrawal-tx-signed`, carrying a full signed `withdrawal-proposal`
   - add a separate withdrawal proposal envelope type for peer coordination
   - add a terminal withdrawal effect variant carrying withdrawal identity plus confirmed-settlement information
   - ensure serialized field order matches Hoon `nock-withdrawal-request` (`base_event_id`, `recipient`, `amount`, `base_batch_end`, `as_of`)
3. `open/hoon/apps/bridge/types.hoon`
   - keep withdrawal molds aligned with new shapes (`nock-lock-root`, `base-batch-end`, no dedicated withdrawal fee field)
   - widen `%create-withdrawal-tx` so bridge-side tx building includes
     `epoch` and pinned `withdrawal-snapshot`, not just withdrawal metadata and
     selected inputs
   - add a `%withdrawal-proposal-built` effect mold carrying a full
     `withdrawal-proposal`
   - add a `%withdrawal-tx-signed` effect mold carrying a full signed
     `withdrawal-proposal`
   - add a terminal withdrawal effect mold carrying withdrawal identity plus confirmed-settlement information
   - do not add a withdrawal proposal-validation cause to the kernel molds

## Invariants and Validation Rules

1. Withdrawal identity must be deterministic and replay-safe:
   - key by counterpart `(as_of, base_event_id)` with canonical encoding
   - this identity is the coordination key for proposal epochs as well as settlement reconciliation
2. Canonicalization identity must be deterministic:
   - proposal hash is computed over the exact proposal envelope / exact typed `transaction`
   - transaction identity inside that envelope comes from `transaction.name`, not a separate `tx_id`
   - honest peers must commit to at most one proposal hash per `(withdrawal_id, epoch)`
3. Settlement must match counterpart withdrawal on:
   - destination lock root / recipient
   - amount semantics (pre-fee vs post-fee exactly defined)
4. Authoritative protocol facts are chain-visible, not submit-attempt-visible:
   - peer-canonicalization is not sufficient for submission
   - sequencer authorization is required before a withdrawal may be submitted
   - `tx-accepted` is a diagnostic signal that the tx reached node-accepted /
     mempool-visible state, not that it was included in a block
   - confirmed settlement in a block is the confirmation signal for inclusion
   - the kernel's terminal withdrawal effect is the trigger for releasing
     canonical local reservations
   - local "submitted" events never make a tx canonical
   - the sequencer owns the authoritative submitted / in-flight withdrawal set
   - the sequencer durably records confirmation for authorized withdrawals
5. Input notes reserved by a canonical or in-flight tx must not be reused:
   - reserve by note `Name`
   - local spendable set is `confirmed normalized snapshot - locally reserved inputs`
   - reservations are only released on confirmed success or by local runtime attempt rollback/replacement rules that do not change withdrawal state
6. There is no automatic submission failover:
   - after sequencer authorization, only the sequencer may submit or retry the same tx
   - if the sequencer is unavailable, withdrawals pause
7. Unknown counterpart policy:
   - if `as_of` base hash is unknown: set hold and wait for counterpart chain progress
   - if `as_of` is known but counterpart event/state is missing: stop
8. Any irreconcilable mismatch is a stop condition.
9. No silent divergence:
   - kernel withdrawal-state failures remain explicitly one of ignore, hold, or stop
   - Rust proposal-validation failures must be durably recorded and surfaced,
     not hidden as kernel state transitions
10. At most one withdrawal may hold the assembly/canonicalization lock at a time for the bridge-controlled spend authority / note pool.
11. At most one withdrawal may be sequencer-authorized / submitted / unconfirmed at a time.

## Testing Plan

### Kernel tests

1. Burn event enters `unsettled-withdrawals`.
2. Valid settlement clears corresponding unsettled entry and emits the terminal withdrawal effect.
3. Settlement-before-counterpart sets hold and later resolves.
4. Settlement with known `as_of` but missing counterpart triggers stop.
5. Settlement mismatch triggers stop.
6. Duplicate/replay settlement does not corrupt state.

### Rust tests

1. Ingress decodes withdrawal proposal and hands it directly to Rust
   withdrawal coordination logic.
2. Rust proposal validation rejects unknown withdrawals, mismatched withdrawal
   metadata, illegal epochs, replay with mismatched envelope, and same-epoch
   equivocation.
3. Rust proposal broadcast driver emits full withdrawal proposal envelopes to peers correctly.
4. Canonicalization is reached only when threshold peers persist and commit to the same proposal hash.
5. Nock tx submission driver handles:
   - success ack
   - retryable errors
   - non-retryable errors
6. Only the sequencer may authorize and submit a peer-canonical withdrawal candidate.
7. Input notes used by prepared/submitted canonical txs are filtered from later planning snapshots.
8. Canonical reservations are released on confirmed settlement via the kernel terminal withdrawal effect, not via a withdrawal-level abandon/fail outcome.
9. Sequencer confirmation tracking records confirmed withdrawals and clears the authoritative in-flight set without double-recording the same withdrawal.
10. Sequencer restart preserves the authoritative in-flight withdrawal set and confirmed-withdrawal record, and does not re-authorize the same withdrawal twice.
11. Sequencer loss pauses withdrawal progress rather than failing over submission to peers.
12. End-to-end wiring test:
   - kernel emits `%create-withdrawal-txs`
   - peers converge on one canonical candidate
   - sequencer authorizes and submits that candidate
   - sequencer records confirmation for that authorized withdrawal
   - kernel later emits the terminal withdrawal effect and Rust releases the matching local reservations
   - no panic/regression in existing deposit path

### Multi-node integration

1. 5-node single-withdrawal proposal and threshold signature convergence with sequencer authorization.
2. Scheduled assembler offline before proposal timeout; next epoch leader assembles a new candidate tx.
3. After peer canonicalization, only the sequencer authorizes and submits the candidate tx.
4. Sequencer restart mid-flight preserves reservations, the in-flight withdrawal set, and the confirmed-withdrawal record, then resumes safely.
5. Sequencer unavailability pauses withdrawal progress rather than failing over submission to peers.
6. Conflicting later proposal for an already authorized withdrawal is treated as an invariant violation / stop.
7. Simulated out-of-order Base/Nock arrival with hold release.

## Open Decisions (Must Resolve Before Full Implementation)

1. Peer identity and signature domain for withdrawal tx proposals:
   - `nock-pubkey`, `nock-pkh`, or node id
2. Withdrawal authorization encoding:
   - the final withdrawal authorization path must require sequencer participation
   - peer threshold agreement alone must not produce a submit-ready withdrawal
3. Fee model:
   - exact formula for withdrawal fee deduction and where it is applied
4. Hold metadata requirements:
   - whether base block height must be embedded in tx metadata for deterministic unblock behavior
5. Whether single-flight policy should remain permanent, or only the current intended design

## Phased Delivery Plan

1. Phase 1: Kernel correctness skeleton
   - implement non-crashing withdrawal parse + settlement reconcile logic
   - implement hold/stop behavior
   - keep transport disabled behind clear guard if needed
2. Phase 2: Rust transport and execution
   - ingress proposal broadcast + separate sequencer-owned gRPC withdrawal service
   - single-flight assembly/canonicalization workflow
   - assemble, persist, authorize, submit, and record confirmation for one sequencer-owned withdrawal at a time
3. Phase 3: Multi-node convergence and failover hardening
   - assembly failover, sequencer restart recovery, reservation release
4. Phase 4: Production hardening
   - metrics, alerts, operational docs, replay abuse tests

## Acceptance Criteria

1. No `TODO`/hard-stop paths remain for withdrawal causes/effects in kernel.
2. Bridge nodes can process Base burns into canonicalized, submitted, and finalized per-withdrawal Nock settlements.
3. If the scheduled assembler is offline before canonicalization, the next epoch leader can assemble a replacement candidate without ambiguity.
4. If a tx becomes peer-canonical, only the sequencer may authorize and submit it.
5. Out-of-order chain arrival is handled via deterministic hold behavior.
6. Submitted-but-unconfirmed withdrawal inputs are not reused for later withdrawal planning.
7. Existing deposit pipeline remains unchanged and green.
8. Integration tests cover nominal, sequencer-stop, restart, and note-reservation scenarios.

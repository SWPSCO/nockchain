Golden JAM fixtures for `nockchain-types`.

Status: Active  
Owner: Nockchain Maintainers  
Last Reviewed: 2026-02-20  
Canonical/Legacy: Legacy (crate-level test fixture reference; canonical docs spine starts at [`START_HERE.md`](../../../START_HERE.md))

## Layout

- `jams/v0/`: v0 fixtures (`balance.jam`, `early-balance.jam`, `note.jam`, `raw-tx.jam`, `timelock.jam`)
- `jams/v1/`: v1 fixtures (`note.jam`, `raw-tx.jam`)

## Where These Fixtures Are Used

- `tests/balance_from_peek_v0.rs` and `tests/balance_from_peek_v1.rs` decode `jams/v0/early-balance.jam`, validate expected fields, and assert noun roundtrips.
- `tests/raw_tx_from_jam_v0.rs` and `tests/raw_tx_from_jam_v1.rs` decode `raw-tx.jam` / `note.jam` fixtures and assert structural invariants + noun roundtrips.
- `src/tx_engine/v0/note.rs` unit tests load `jams/v0/{balance,note,timelock}.jam`.

## Updating Fixtures

There is currently no in-tree `dump_balance_peek` example binary in this repo.  
To refresh coverage:

1. Capture new jam blobs with your external tooling/workflow.
2. Place files in the versioned `jams/v0` or `jams/v1` directory.
3. Update assertions in the matching tests when fixture structure changes.

These tests use fixed `include_bytes!` paths, so fixture files must exist at compile time.

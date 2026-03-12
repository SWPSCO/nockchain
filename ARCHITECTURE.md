# ARCHITECTURE

Status: Active
Owner: Nockchain Maintainers
Last Reviewed: 2026-02-19
Canonical/Legacy: Canonical (system boundaries and invariants; implementation detail lives in satellite docs)

This page defines architecture boundaries for the nockchain repository.
If an implementation detail conflicts with a boundary or invariant below, the boundary wins.

## System Boundaries

| Boundary                       | Owns                                                                      | Does Not Own                                     | Canonical Satellites                                                                                                                                       |
| ------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol and consensus rules   | Transaction validity, consensus transitions, upgrade gates                | Runbook steps, deployment policy                 | [`PROTOCOL.md`](./PROTOCOL.md), [`changelog/protocol/SPECIFICATION.md`](./changelog/protocol/SPECIFICATION.md)                                             |
| Node runtime and networking    | Kernel execution, peer communication, chain sync                          | Redefining protocol rules                        | [`README.md`](./README.md), [`crates/nockapp/README.md`](./crates/nockapp/README.md)                                                                       |
| Wallet and public API surfaces | Key management, transaction construction, public/private service exposure | Consensus authority                              | [`crates/nockchain-wallet/README.md`](./crates/nockchain-wallet/README.md), [`crates/nockchain-api/README.md`](./crates/nockchain-api/README.md)           |
| Bridge subsystem               | Cross-chain contracts, bridge runtime behavior, bridge operational policy | Base protocol authority for non-bridge consensus | [`crates/bridge/docs/architecture.md`](./crates/bridge/docs/architecture.md), [`crates/bridge/docs/node-runbook.md`](./crates/bridge/docs/node-runbook.md) |
| Tooling and packaging          | Build toolchain, compiler/bootstrap workflows, packaging/install channels | Protocol semantics                               | [`crates/hoonc/README.md`](./crates/hoonc/README.md), [`crates/nockup/README.md`](./crates/nockup/README.md)                                               |

## Global Invariants

1. Protocol-first authority: consensus behavior is normative only when documented in `PROTOCOL.md` and indexed upgrade specs.
2. Deterministic rule interpretation: node implementations must resolve the same consensus inputs to the same outputs.
3. Version-gated change control: consensus-affecting behavior must be introduced by a versioned protocol upgrade spec.
4. Separation of concerns: workflow and crate docs explain how to operate code, they do not redefine protocol or architecture authority.

## Evolving Areas (Non-Canonical Summary)

- Runtime/interface satellites promoted in this revision:
  - [`crates/nockapp/README.md`](./crates/nockapp/README.md)
  - [`crates/nockchain-api/README.md`](./crates/nockchain-api/README.md)
  - [`crates/nockchain-wallet/README.md`](./crates/nockchain-wallet/README.md)
  Treat these as Tier 1 scoped canonical guidance for their subsystem interfaces.
- Remaining crate docs remain contextual unless promoted by the spine.
- Bridge operational processes may change faster than core protocol docs, use bridge runbooks for current operations.

## Related Spine Docs

- [`START_HERE.md`](./START_HERE.md)
- [`WORKFLOWS.md`](./WORKFLOWS.md)
- [`DECISIONS/README.md`](./DECISIONS/README.md)

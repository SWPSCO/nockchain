# ADR 0002: Protocol-First Canonicalization

Status: accepted
Date: 2026-02-18
Owners: Nockchain Maintainers
Supersedes: none
Superseded by: none
Related:
- [START_HERE](../START_HERE.md)
- [PROTOCOL](../PROTOCOL.md)
- [ARCHITECTURE](../ARCHITECTURE.md)
- [WORKFLOWS](../WORKFLOWS.md)
- [DECISIONS index](./README.md)

## Context

Consensus-critical behavior was historically described across multiple documentation layers. When protocol semantics appear in quickstarts, workflow docs, or crate docs without a single authority path, divergence risk increases for operators and implementers.

## Decision

Adopt protocol-first canonicalization:

- Normative consensus behavior is authoritative only when defined by `PROTOCOL.md` and the indexed upgrade specs under `changelog/protocol/`.
- Consensus-affecting changes must be version-gated through upgrade specs and reflected in the `PROTOCOL.md` index in the same change.
- Workflow, runbook, and crate docs may explain operations, but they do not redefine protocol semantics.

## Alternatives Considered

1. Treat implementation code as the only authority and de-emphasize protocol docs. Rejected because operators and reviewers need human-readable normative specifications.
2. Let crate-local docs define protocol details near implementation. Rejected because authority becomes fragmented and conflicts are harder to detect.
3. Allow several top-level docs to co-own protocol semantics. Rejected because conflict resolution becomes ambiguous during upgrades.

## Consequences

- Positive: one canonical route for protocol interpretation, reducing consensus drift risk.
- Tradeoff: stricter documentation process for consensus changes, including index maintenance overhead.
- Tradeoff: ad hoc hotfix guidance outside the protocol index is non-normative and cannot stand alone.
- Ongoing obligation: maintain upgrade status/lifecycle metadata in `PROTOCOL.md`.

## Rollout

1. Route all protocol change reviews through `PROTOCOL.md` and indexed specs first.
2. Require consensus PRs to update relevant upgrade spec files and the protocol index together.
3. Treat non-indexed protocol notes as informative only until promoted.
4. Supersede this ADR if governance moves to a different protocol authority model.

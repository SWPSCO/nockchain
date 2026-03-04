# ADR 0001: Doc Spine And Authority

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

Repository documentation grew across many top-level and crate-local files, with different levels of authority and occasional conflicts. Contributors and agents needed a deterministic trust model for which docs are normative versus contextual.

## Decision

Establish a canonical Tier 0 documentation spine and explicit conflict policy:

- Tier 0 canonical spine: `START_HERE.md`, `PROTOCOL.md`, `ARCHITECTURE.md`, `WORKFLOWS.md`, and `DECISIONS/README.md`.
- Conflict rule: Tier 0 overrides Tier 1, Tier 1 overrides Tier 2.
- Isolation rule: crate READMEs are not protocol or architecture authority unless promoted by the spine.
- Maintenance rule: promotions/demotions and trust-contract changes update the spine docs in the same change.

## Alternatives Considered

1. Keep `README.md` as default authority and treat other docs as ad hoc references. Rejected because quickstart guidance and normative governance are different concerns and drift over time.
2. Add canonical metadata to every repository doc immediately. Rejected for high migration and review overhead relative to current needs.
3. Rely on reviewer judgment without formal tiers. Rejected because it is inconsistent across contributors and scales poorly for asynchronous work.

## Consequences

- Positive: deterministic read order and authority boundaries for humans and agents.
- Tradeoff: editors must update multiple spine files when authority boundaries change.
- Tradeoff: some existing docs are demoted to contextual or historical status, which may require explicit escalation for promotion.
- Ongoing obligation: keep Tier 0 links valid and keep this ADR index current.

## Rollout

1. Publish and maintain the trust contract in `START_HERE.md`.
2. Keep reciprocal links intact across Tier 0 spine docs and the ADR index.
3. Require authority-boundary changes to include spine updates in the same patch.
4. If the trust model changes materially, supersede this ADR with a new decision.

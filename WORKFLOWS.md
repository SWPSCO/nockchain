# WORKFLOWS

Status: Active
Owner: Nockchain Maintainers
Last Reviewed: 2026-02-19
Canonical/Legacy: Canonical (workflow routing index; detailed procedures live in satellite runbooks)

Use this page to choose the correct operational path.
Each journey below has one canonical landing doc.

## Routing Table By Job

| Job                       | Canonical Landing Doc                                                        | Scope                                           |
| ------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------- |
| Bootstrap a local node    | [`README.md`](./README.md)                                                   | Initial setup and first run                     |
| Operate a node day-to-day | [`README.md`](./README.md)                                                   | Routine run/monitor cycles                      |
| Track protocol upgrades   | [`PROTOCOL.md`](./PROTOCOL.md)                                               | Upgrade status, activation windows, spec links  |
| Operate a bridge node     | [`crates/bridge/docs/node-runbook.md`](./crates/bridge/docs/node-runbook.md) | Provisioning and steady-state bridge operations |
| Incident and debug triage | [`README.md`](./README.md)                                                   | First-response diagnostics and escalation       |

## Golden Paths

### 1. Bootstrap Node

Set up dependencies, configure environment, and run node/miner scripts.
Canonical landing doc: [`README.md`](./README.md)

### 2. Operate Node

Use the standard runtime commands, logs, and wallet checks for daily operation.
Canonical landing doc: [`README.md`](./README.md)

### 3. Protocol Upgrade Awareness

Check upgrade status, activation height/target, and read the authoritative upgrade spec before rollout.
Canonical landing doc: [`PROTOCOL.md`](./PROTOCOL.md)

### 4. Bridge Operations

*NOTE: only relevant to bridge operators!*
Run provisioning, runtime, and governance-aware bridge operations from the bridge runbook family.
Canonical landing doc: [`crates/bridge/docs/node-runbook.md`](./crates/bridge/docs/node-runbook.md)

### 5. Incident And Debug

Start with core diagnostics, then branch to bridge-specific runbooks if the incident is cross-chain or signer-related.
Canonical landing doc: [`README.md`](./README.md)

## Bridge-Specific Satellites

- Quickstart: [`crates/bridge/QUICKSTART.md`](./crates/bridge/QUICKSTART.md)
- Operator setup: [`crates/bridge/OPERATOR-SETUP.md`](./crates/bridge/OPERATOR-SETUP.md)
- Governance: [`crates/bridge/docs/governance.md`](./crates/bridge/docs/governance.md)

## Promoted Tier 1 Satellites

- Runtime interface guidance: [`crates/nockapp/README.md`](./crates/nockapp/README.md)
- Public API runtime/deployment guidance: [`crates/nockchain-api/README.md`](./crates/nockchain-api/README.md)
- Wallet CLI behavior and operations: [`crates/nockchain-wallet/README.md`](./crates/nockchain-wallet/README.md)

## Related Spine Docs

- [`START_HERE.md`](./START_HERE.md)
- [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- [`DECISIONS/README.md`](./DECISIONS/README.md)

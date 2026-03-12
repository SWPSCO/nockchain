# DOC_INVENTORY

Status: Active
Owner: Nockchain Maintainers
Last Reviewed: 2026-02-20
Canonical/Legacy: Legacy (audit coverage tracker for `**/*.md`; authority remains with Tier-0 docs)

Docs-only audit pass tracker.

- Source command: `find open -type f -name '*.md' | sort`
- Status markers: `pending`, `in-review`, `done`
- Total tracked markdown files: `70`

## Coverage Summary

| Slice                                                 | Files  | pending | in-review | done   |
| ----------------------------------------------------- | ------ | ------- | --------- | ------ |
| Tier-0 canonical spine                                | 5      | 0       | 0         | 5      |
| Protocol stack rule specs (`changelog/protocol`) | 13     | 0       | 0         | 13     |
| Tier-1 canonical satellites                           | 4      | 0       | 0         | 4      |
| Decision records and template                         | 3      | 0       | 0         | 3      |
| Bridge subsystem                                      | 12     | 0       | 0         | 12     |
| NockVM subsystem                                      | 23     | 0       | 0         | 23     |
| Nockup and templates                                  | 6      | 0       | 0         | 6      |
| Other crate docs under `crates`                  | 3      | 0       | 0         | 3      |
| Audit meta                                            | 1      | 0       | 0         | 1      |
| **Total**                                             | **70** | **0**   | **0**     | **70** |

## Tier-0 Canonical Spine

| Status | File                       |
| ------ | -------------------------- |
| done   | `START_HERE.md`       |
| done   | `PROTOCOL.md`         |
| done   | `ARCHITECTURE.md`     |
| done   | `WORKFLOWS.md`        |
| done   | `DECISIONS/README.md` |

## Protocol Stack Rule Specs (`changelog/protocol`)

| Status | File                                                            |
| ------ | --------------------------------------------------------------- |
| done   | `changelog/protocol/SPECIFICATION.md`                      |
| done   | `changelog/protocol/001-legacy-checkpoint-144.md`          |
| done   | `changelog/protocol/002-legacy-checkpoints-genesis-720.md` |
| done   | `changelog/protocol/003-legacy-checkpoint-2448.md`         |
| done   | `changelog/protocol/004-legacy-sign-output-source.md`      |
| done   | `changelog/protocol/005-legacy-checkpoint-4032.md`         |
| done   | `changelog/protocol/006-legacy-proof-v1-6750.md`           |
| done   | `changelog/protocol/007-legacy-proof-v2-12000.md`          |
| done   | `changelog/protocol/008-legacy-checkpoint-16128.md`        |
| done   | `changelog/protocol/009-legacy-segwit-cutover-initial.md`  |
| done   | `changelog/protocol/010-legacy-v1-phase-39000.md`          |
| done   | `changelog/protocol/011-legacy-lmp-axis-hotfix.md`         |
| done   | `changelog/protocol/012-bythos.md`                         |

## Tier-1 Canonical Satellites

| Status | File                                     |
| ------ | ---------------------------------------- |
| done   | `README.md`                         |
| done   | `crates/nockapp/README.md`          |
| done   | `crates/nockchain-api/README.md`    |
| done   | `crates/nockchain-wallet/README.md` |

## Decision Records And Template

| Status | File                                                     |
| ------ | -------------------------------------------------------- |
| done   | `DECISIONS/0001-doc-spine-and-authority.md`         |
| done   | `DECISIONS/0002-protocol-first-canonicalization.md` |
| done   | `DECISIONS/TEMPLATE.md`                             |

## Bridge Subsystem

| Status | File                                                                         |
| ------ | ---------------------------------------------------------------------------- |
| done   | `crates/bridge/README.md`                                               |
| done   | `crates/bridge/QUICKSTART.md`                                           |
| done   | `crates/bridge/OPERATOR-SETUP.md`                                       |
| done   | `crates/bridge/docs/README.md`                                          |
| done   | `crates/bridge/docs/architecture.md`                                    |
| done   | `crates/bridge/docs/governance.md`                                      |
| done   | `crates/bridge/docs/node-runbook.md`                                    |
| done   | `crates/bridge/docs/signatures.md`                                      |
| done   | `crates/bridge/contracts/DEPLOYMENT.md`                                 |
| done   | `crates/bridge/contracts/UPGRADE_GUIDE.md`                              |
| done   | `crates/bridge/contracts/environments/base-sepolia-testnet-accounts.md` |
| done   | `crates/bridge/scripts/environments/README.md`                          |

## NockVM Subsystem

| Status | File                                                            |
| ------ | --------------------------------------------------------------- |
| done   | `crates/nockvm/README.md`                                  |
| done   | `crates/nockvm/DEVELOPERS.md`                              |
| done   | `crates/nockvm/docs/b-trees.md`                            |
| done   | `crates/nockvm/docs/codegen-bootstrap.md`                  |
| done   | `crates/nockvm/docs/heap.md`                               |
| done   | `crates/nockvm/docs/llvm.md`                               |
| done   | `crates/nockvm/docs/moving-memory.md`                      |
| done   | `crates/nockvm/docs/persistence.md`                        |
| done   | `crates/nockvm/docs/pills.md`                              |
| done   | `crates/nockvm/docs/stack.md`                              |
| done   | `crates/nockvm/docs/storyboard.md`                         |
| done   | `crates/nockvm/docs/subject-knowledge.md`                  |
| done   | `crates/nockvm/docs/status/20230419.md`                    |
| done   | `crates/nockvm/docs/proposal/hypotheses.md`                |
| done   | `crates/nockvm/docs/proposal/milestones.md`                |
| done   | `crates/nockvm/docs/proposal/notes-~2021.9.23.md`          |
| done   | `crates/nockvm/docs/proposal/notes-~2021.9.24.md`          |
| done   | `crates/nockvm/docs/proposal/noun-representation.md`       |
| done   | `crates/nockvm/docs/proposal/proposal-nock-performance.md` |
| done   | `crates/nockvm/rust/ibig/CHANGELOG.md`                     |
| done   | `crates/nockvm/rust/ibig/README.md`                        |
| done   | `crates/nockvm/rust/murmur3/README.md`                     |
| done   | `crates/nockvm/rust/nockvm/updates/9-20-2023.md`           |

## Nockup And Templates

| Status | File                                                 |
| ------ | ---------------------------------------------------- |
| done   | `crates/nockup/README.md`                       |
| done   | `crates/nockup/templates/basic/README.md`       |
| done   | `crates/nockup/templates/grpc/README.md`        |
| done   | `crates/nockup/templates/http-server/README.md` |
| done   | `crates/nockup/templates/http-static/README.md` |
| done   | `crates/nockup/templates/repl/README.md`        |

## Other Crate Docs Under `crates`

| Status | File                                           |
| ------ | ---------------------------------------------- |
| done   | `crates/hoonc/README.md`                  |
| done   | `crates/nockchain-explorer-tui/README.md` |
| done   | `crates/nockchain-types/jams/README.md`   |

## Audit Meta

| Status | File                    |
| ------ | ----------------------- |
| done   | `DOC_INVENTORY.md` |

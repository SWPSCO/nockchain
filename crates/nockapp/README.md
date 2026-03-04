# NockApp

Status: Active
Owner: Nockchain Maintainers
Last Reviewed: 2026-02-19
Canonical/Legacy: Canonical (Tier 1 scoped authority for NockApp runtime interface and developer usage; protocol authority remains in [`PROTOCOL.md`](../../PROTOCOL.md))

***DEVELOPER ALPHA***

<img align="right" src="https://zorp.io/img/nockapp.png" height="150px" alt="NockApp">

NockApps are pure-functional state machines with automatic persistence and modular IO.

The NockApp framework is built around two core crates, `nockapp` and `nockvm`:
1. `nockapp` provides a minimal Rust interface to a Nock kernel.
2. [`nockvm`](https://github.com/zorp-corp/nockvm) is a modern Nock runtime that achieves durable execution.

## Canonical Scope

This document is Tier 1 canonical for:
- `nockapp` runtime interface expectations (`Kernel`, `poke`, `peek`, effect handling).
- Developer/operator usage guidance for this crate's runtime behavior.
- Logging/runtime configuration knobs exposed by this crate.

This document is NOT canonical for:
- protocol/consensus rules (use [`PROTOCOL.md`](../../PROTOCOL.md)).
- cross-crate architecture boundaries (use [`ARCHITECTURE.md`](../../ARCHITECTURE.md)).

## Failure Modes And Limits

- This crate is alpha-grade and interface details may evolve quickly.
- Examples may lag implementation unless updated in the same PR as interface changes.
- This doc cannot resolve protocol disputes; if runtime behavior appears to conflict with protocol semantics, protocol sources win.

## Verification Contract

When runtime-interface behavior changes in `nockapp`, update this doc in the same change.

Minimum validation:
- `make -C open docs-check`
- `cargo check -p nockapp`

<br>

## Get Started

To test compiling a Nock kernel using the `hoonc` command-line Hoon compiler, run the following commands from the repository root:

```
make install-hoonc
hoonc hoon/apps/dumbnet/outer.hoon hoon
```

For large builds, the rust stack might overflow. To get around this, increase the stack size by setting: `RUST_MIN_STACK=838860`.

## Building NockApps

The `nockapp` library is the primary framework for building NockApps. It provides a simple interface to a `Kernel`: a Nock core which can make state transitions with effects (via the `poke()` method) and allow inspection of its state via the `peek()` method.

For compiling Hoon to Nock, we're also including a pre-release of `hoonc`: a NockApp for the Hoon compiler. `hoonc` can compile Hoon to Nock as a batch-mode command-line process, without the need to spin up an interactive Urbit ship. It is intended both for developer workflows and for CI. `hoonc` is also our first example NockApp. More are coming!

## Logging Configuration

### Basic Usage

```bash
# nockapp is a library crate, configure logging on the binary that embeds it
RUST_LOG=info <nockapp-based-binary> <args>

# Use minimal log format
MINIMAL_LOG_FORMAT=true <nockapp-based-binary> <args>
```

### TLDR

Use `MINIMAL_LOG_FORMAT=true` for compact logging format

### Minimal Log Format Features

The minimal log format (`MINIMAL_LOG_FORMAT=true`) provides:
- Single-letter colored log levels (T, D, I, W, E)
- Simplified timestamps in HH:MM:SS format
- Abbreviated module paths (e.g., 'nockapp::kernel::boot' becomes '[cr] kernel::boot')
- Special handling for slogger messages (colored by log level)

### Environment Variables

The following environment variables can be used to configure logging:

```bash
# Set log level
RUST_LOG="nockapp::kernel=trace" <nockapp-based-binary> <args>

# Enable minimal log format
MINIMAL_LOG_FORMAT=true <nockapp-based-binary> <args>

# Combine environment variables
RUST_LOG="nockapp::kernel=trace" MINIMAL_LOG_FORMAT=true <nockapp-based-binary> <args>
```

# bridge runtime quickstart

This README is for bridge operators only. If you are not sure whether you are
a bridge operator, you are probably not.

## prerequisites
- Rust toolchain via `rustup` (uses the workspace `rust-toolchain.toml`).
- Foundry via official foundryup:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  ~/.foundry/bin/foundryup
  ```
- Config: copy `bridge-conf.example.toml` to
  `~/.nockapp/bridge/bridge-conf.toml` (or pass `--config-path`).

## quick run setup (from repo root)
From the repository root, install/update contract dependencies and build the
bridge runtime binary:

```bash
make assets/bridge.jam
make -C crates/bridge/contracts install  # installs or updates foundry and downloads contract dependencies
cargo build --profile release --bin bridge
```

## cross-compile for x86_64 linux

From the `open/` repository root:

```bash
make install-cargo-zigbuild
make zig-build-bridge
```

Default target is `x86_64-unknown-linux-gnu.2.39`.
Set `ZIGBUILD_TARGET` to a value compatible with your deployment host's glibc
version, for example:

```bash
make zig-build-bridge ZIGBUILD_TARGET=x86_64-unknown-linux-gnu.2.39
```

Output binary:

```bash
target/x86_64-unknown-linux-gnu/release/bridge
```

## nockchain bridge tui (operators only)
The TUI client can be launched from your local machine (for example, your
laptop or operator workstation); it does not need to run on the bridge node.
Your local machine must be connected to Tailscale so it can reach the bridge
node ingress gRPC endpoint.

From the `open/` repository root, build the TUI:

```bash
make build-nockchain-bridge-tui
```

Run the TUI:

```bash
# Uses default server 127.0.0.1:8001
./target/release/nockchain-bridge-tui

# Connect to a bridge node over Tailscale
./target/release/nockchain-bridge-tui --server <tailscale-ip>:8001
```

## running the node
```bash
./bridge  -c bridge_config_path
```
- `--start` will unfreeze stopped nodes
- `--new` wipes the on-disk kernel state; omit it for restarts.

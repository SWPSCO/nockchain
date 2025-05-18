# Set env variables
export RUST_BACKTRACE := full
export RUST_LOG := info,nockchain=debug,nockchain_libp2p_io=info,libp2p=info,libp2p_quic=info
export MINIMAL_LOG_FORMAT := true
export MINING_PUBKEY := EHmKL2U3vXfS5GYAY5aVnGdukfDWwvkQPCZXnjvZVShsSQi3UAuA4tQQpVwGJMzc9FfpTY8pLDkqhBGfWutiF4prrCktUH9oAWJxkXQBzAavKDc95NR3DjmYwnnw8GuugnK


.PHONY: build
build: build-hoon-all build-rust
	$(call show_env_vars)

## Build all rust
.PHONY: build-rust
build-rust:
	cargo build --release

## Run all tests
.PHONY: test
test:
	cargo test --release

.PHONY: install-hoonc
install-hoonc: nuke-hoonc-data ## Install hoonc from this repo
	$(call show_env_vars)
	cargo install --locked --force --path crates/hoonc --bin hoonc

.PHONY: update-hoonc
update-hoonc:
	$(call show_env_vars)
	cargo install --locked --path crates/hoonc --bin hoonc

.PHONY: install-nockchain
install-nockchain: build-hoon-all
	$(call show_env_vars)
	cargo install --locked --force --path crates/nockchain --bin nockchain

.PHONY: update-nockchain
update-nockchain: build-hoon-all
	$(call show_env_vars)
	cargo install --locked --path crates/nockchain --bin nockchain


.PHONY: install-nockchain-wallet
install-nockchain-wallet: build-hoon-all
	$(call show_env_vars)
	cargo install --locked --force --path crates/nockchain-wallet --bin nockchain-wallet

.PHONY: update-nockchain-wallet
update-nockchain-wallet: build-hoon-all
	$(call show_env_vars)
	cargo install --locked --path crates/nockchain-wallet --bin nockchain-wallet

.PHONY: ensure-dirs
ensure-dirs:
	mkdir -p hoon
	mkdir -p assets

.PHONY: build-trivial
build-trivial: ensure-dirs
	$(call show_env_vars)
	echo '%trivial' > hoon/trivial.hoon
	hoonc --arbitrary hoon/trivial.hoon

HOON_TARGETS=assets/dumb.jam assets/wal.jam

.PHONY: nuke-hoonc-data
nuke-hoonc-data:
	rm -rf .data.hoonc
	rm -rf ~/.nockapp/hoonc

.PHONY: nuke-assets
nuke-assets:
	rm -f assets/*.jam

.PHONY: build-hoon-all
build-hoon-all: nuke-assets update-hoonc ensure-dirs build-trivial $(HOON_TARGETS)
	$(call show_env_vars)

.PHONY: build-hoon
build-hoon: ensure-dirs update-hoonc $(HOON_TARGETS)
	$(call show_env_vars)

.PHONY: build-wallet
build-wallet: ensure-dirs update-hoonc assets/wal.jam
	$(call show_env_vars)

.PHONY: run-nockchain-leader
run-nockchain-leader:  # Run nockchain mode in leader mode
	$(call show_env_vars)
	mkdir -p test-leader && cd test-leader && rm -f nockchain.sock && RUST_BACKTRACE=1 cargo run --release --bin nockchain -- --fakenet --genesis-leader --npc-socket nockchain.sock --mining-pubkey $(MINING_PUBKEY) --bind /ip4/0.0.0.0/udp/3005/quic-v1 --peer /ip4/127.0.0.1/udp/3006/quic-v1 --new-peer-id --no-default-peers

.PHONY: run-nockchain-follower
run-nockchain-follower:  # Run nockchain mode in follower mode
	$(call show_env_vars)
	mkdir -p test-follower && cd test-follower && rm -f nockchain.sock && RUST_BACKTRACE=1 cargo run --release --bin nockchain -- --fakenet --genesis-watcher --npc-socket nockchain.sock --mining-pubkey $(MINING_PUBKEY) --bind /ip4/0.0.0.0/udp/3006/quic-v1 --peer /ip4/127.0.0.1/udp/3005/quic-v1 --new-peer-id --no-default-peers


HOON_SRCS := $(find hoon -type file -name '*.hoon')

## Build dumb.jam with hoonc
assets/dumb.jam: update-hoonc hoon/apps/dumbnet/outer.hoon $(HOON_SRCS)
	$(call show_env_vars)
	RUST_LOG=trace hoonc hoon/apps/dumbnet/outer.hoon hoon
	mv out.jam assets/dumb.jam

## Build wal.jam with hoonc
assets/wal.jam: update-hoonc hoon/apps/wallet/wallet.hoon $(HOON_SRCS)
	$(call show_env_vars)
	RUST_LOG=trace hoonc hoon/apps/wallet/wallet.hoon hoon
	mv out.jam assets/wal.jam

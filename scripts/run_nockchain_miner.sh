#!/bin/bash
source .env
export RUST_LOG
export MINIMAL_LOG_FORMAT
export MINING_PUBKEY
nockchain --mining-pubkey ${MINING_PUBKEY} --mine


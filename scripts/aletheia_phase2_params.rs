#!/usr/bin/env -S rust-script
//! Fetch the three Aletheia phase 2 cutover parameters from a Nockchain
//! public gRPC node and emit them in a form ready to paste into Hoon.
//!
//! - asert-anchor-digest      = base58 digest of mainnet block 65,499
//! - asert-anchor-min-timestamp = median-of-11 timestamp across blocks 65,489..=65,499
//! - asert-activation-digest  = base58 digest of mainnet block 65,500
//!
//! Hash <-> base58 conversion follows `Hash::to_base58` in
//! `open/crates/nockchain-types/src/tx_engine/common/mod.rs:149`: belts are
//! interpreted as a base-p number with p = 2^64 - 2^32 + 1 (the Mersenne
//! prime used as the field modulus), and the resulting bigint is encoded
//! big-endian then base58 (Bitcoin alphabet).
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! bs58 = "0.5"
//! num-bigint = "0.4"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```

use std::process::Command;

use anyhow::{Context, Result, bail};
use num_bigint::BigUint;
use serde::Deserialize;

const ANCHOR_HEIGHT: u64 = 65_499;
const ACTIVATION_HEIGHT: u64 = 65_500;
const MIN_PAST_BLOCKS: u64 = 11;
const ENDPOINT: &str = "23.252.122.122:5556";
const METHOD: &str = "nockchain.public.v2.NockchainBlockService/GetBlockDetails";

// Mersenne field prime: 2^64 - 2^32 + 1
const PRIME: u64 = 0xffffffff00000001;

#[derive(Debug, Deserialize)]
struct BeltValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct WireHash {
    belt1: BeltValue,
    belt2: BeltValue,
    belt3: BeltValue,
    belt4: BeltValue,
    belt5: BeltValue,
}

#[derive(Debug, Deserialize)]
struct WireDetails {
    #[serde(rename = "blockId")]
    block_id: WireHash,
    height: String,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct WireEnvelope {
    details: Option<WireDetails>,
    error: Option<serde_json::Value>,
}

fn fetch_block(height: u64) -> Result<WireDetails> {
    let payload = format!("{{\"height\":{height}}}");
    let out = Command::new("grpcurl")
        .args([
            "-plaintext",
            "-max-time",
            "30",
            "-d",
            &payload,
            ENDPOINT,
            METHOD,
        ])
        .output()
        .with_context(|| format!("invoking grpcurl for height {height}"))?;
    if !out.status.success() {
        bail!(
            "grpcurl failed for height {height}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let env: WireEnvelope = serde_json::from_slice(&out.stdout)
        .with_context(|| format!("parsing GetBlockDetails JSON for height {height}"))?;
    if let Some(err) = env.error {
        bail!("server error at height {height}: {err}");
    }
    let details = env
        .details
        .with_context(|| format!("no details field for height {height}"))?;
    let observed_height: u64 = details.height.parse()?;
    if observed_height != height {
        bail!("requested height {height} but server returned {observed_height}");
    }
    Ok(details)
}

fn belts_to_b58(h: &WireHash) -> Result<String> {
    let belts = [&h.belt1, &h.belt2, &h.belt3, &h.belt4, &h.belt5];
    let prime = BigUint::from(PRIME);
    let mut value = BigUint::from(0u8);
    let mut power = BigUint::from(1u8);
    for b in belts {
        let limb: u64 = b
            .value
            .parse()
            .with_context(|| format!("parsing belt value {:?}", b.value))?;
        value += BigUint::from(limb) * &power;
        power *= &prime;
    }
    Ok(bs58::encode(value.to_bytes_be()).into_string())
}

fn main() -> Result<()> {
    let lo = ANCHOR_HEIGHT - (MIN_PAST_BLOCKS - 1);
    let hi = ANCHOR_HEIGHT;
    eprintln!("Fetching blocks {lo}..={hi} for median-of-11");

    let mut timestamps: Vec<u64> = Vec::with_capacity(MIN_PAST_BLOCKS as usize);
    let mut anchor_details: Option<WireDetails> = None;
    for h in lo..=hi {
        let d = fetch_block(h)?;
        let ts: u64 = d
            .timestamp
            .parse()
            .with_context(|| format!("parsing timestamp at height {h}"))?;
        eprintln!("  height={h} timestamp={ts}");
        timestamps.push(ts);
        if h == ANCHOR_HEIGHT {
            anchor_details = Some(d);
        }
    }
    let anchor = anchor_details.expect("anchor fetched in loop above");

    eprintln!("Fetching activation block {ACTIVATION_HEIGHT}");
    let activation = fetch_block(ACTIVATION_HEIGHT)?;

    // Median of 11: sort, take the middle (index 5, 0-indexed).
    timestamps.sort_unstable();
    let median = timestamps[(MIN_PAST_BLOCKS as usize) / 2];

    let anchor_b58 = belts_to_b58(&anchor.block_id)?;
    let activation_b58 = belts_to_b58(&activation.block_id)?;

    println!();
    println!("=== Aletheia phase 2 parameters ===");
    println!("asert-anchor-digest       = '{}'", anchor_b58);
    println!("asert-anchor-min-timestamp = {}", median);
    println!("asert-activation-digest   = '{}'", activation_b58);
    println!();
    println!("Hoon snippets:");
    println!(
        "  [%65.499 (from-b58:hash:t '{}')]",
        anchor_b58
    );
    println!(
        "  [%65.500 (from-b58:hash:t '{}')]",
        activation_b58
    );
    println!(
        "  asert-anchor-min-timestamp={}",
        format_with_dots(median)
    );

    Ok(())
}

fn format_with_dots(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(*b as char);
    }
    out
}

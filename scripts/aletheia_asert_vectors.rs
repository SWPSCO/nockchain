#!/usr/bin/env -S rust-script
//! Fetch mainnet block timestamps and targets for a post-activation
//! range and emit them as Hoon-syntax test vectors. The output is a
//! `(list [height=@ parent-min-ts=@ target=@])` plus an
//! `++ anchor-min-timestamp` pin and an `++ anchor-target` pin —
//! ready to paste into a test that imports `lib/asert` and pins
//! `compute-target:asert` against observed mainnet outputs.
//!
//! For each post-activation block N, `parent-min-ts` is the
//! median-of-11 of timestamps from blocks (N-11)..=(N-1). This is
//! exactly the value `min-timestamps[parent.digest]` would hold on a
//! node that just accepted block N-1.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const ANCHOR_HEIGHT: u64 = 65_499;
const ACTIVATION_HEIGHT: u64 = 65_500;
const FIRST_TEST: u64 = ACTIVATION_HEIGHT;
const LAST_TEST: u64 = 65_520;
const LOOKBACK: u64 = 11;
const ENDPOINT: &str = "23.252.122.122:5556";
const METHOD: &str = "nockchain.public.v2.NockchainBlockService/GetBlockDetails";

#[derive(Debug, Deserialize)]
struct WireTarget {
    display: String,
}

#[derive(Debug, Deserialize)]
struct WireDetails {
    height: String,
    timestamp: String,
    target: WireTarget,
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
    env.details
        .with_context(|| format!("no details field for height {height}"))
}

fn format_dots(n: u128) -> String {
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

fn format_dots_str(s: &str) -> String {
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

fn main() -> Result<()> {
    // Need timestamps from (FIRST_TEST - LOOKBACK)..=LAST_TEST inclusive,
    // plus targets for FIRST_TEST..=LAST_TEST.
    let lo_ts = FIRST_TEST - LOOKBACK;
    eprintln!("Fetching heights {lo_ts}..={LAST_TEST}");
    let mut blocks: Vec<(u64, u64, String)> = Vec::new();
    for h in lo_ts..=LAST_TEST {
        let d = fetch_block(h)?;
        let observed_height: u64 = d.height.parse()?;
        if observed_height != h {
            bail!("height mismatch: requested {h}, got {observed_height}");
        }
        let ts: u64 = d.timestamp.parse()?;
        blocks.push((h, ts, d.target.display.clone()));
        eprintln!("  height={h} ts={ts} target_digits={}", d.target.display.len());
    }

    // Compute parent-min-ts (median-of-11 of timestamps[N-11..=N-1])
    // for each block N in FIRST_TEST..=LAST_TEST.
    println!();
    println!("::  Mainnet ASERT cross-check vectors. Each entry is");
    println!("::  [height=@ parent-min-ts=@ observed-target=@], where");
    println!("::  parent-min-ts is the median-of-11 of timestamps for");
    println!("::  blocks (height-11)..=(height-1) — exactly what");
    println!("::  min-timestamps[parent.digest] holds on a node that");
    println!("::  just accepted block (height-1).");
    println!("++  asert-vectors");
    println!("  ^-  (list [height=@ parent-min-ts=@ observed-target=@])");
    println!("  :~");
    for &(h, _ts, ref target) in &blocks {
        if h < FIRST_TEST {
            continue;
        }
        // window is blocks[(h - lo_ts - LOOKBACK)..(h - lo_ts)]
        let end_idx = (h - lo_ts) as usize;
        let start_idx = end_idx - LOOKBACK as usize;
        let mut window: Vec<u64> = blocks[start_idx..end_idx].iter().map(|b| b.1).collect();
        window.sort_unstable();
        let median = window[(LOOKBACK as usize) / 2];

        println!(
            "    [height={} parent-min-ts={} observed-target={}]",
            format_dots(h as u128),
            format_dots(median as u128),
            format_dots_str(target),
        );
    }
    println!("  ==");
    println!();
    println!("::  Anchor pins (block 65,499 = asert-anchor-height).");
    println!(
        "++  anchor-min-timestamp  {}",
        format_dots(9_223_372_093_639_027_842u128)
    );
    println!("++  anchor-target-atom    ^~((bex 291))");
    println!("++  asert-anchor-height   {}", format_dots(ANCHOR_HEIGHT as u128));

    Ok(())
}

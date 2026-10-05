# Urbit Hoon 135

Hatcher parses Hoon 135; Honk compiles it through the native compiler. Select
source roots explicitly in `honk.toml`, including mixed repositories:

```toml
[[project]]
root = "hoon"
dialect = "nockchain"
prelude = "hoon/common/hoon.hoon"

[[project]]
root = "desks/mydesk"
dialect = "urbit"
prelude = "urbit/pkg/arvo/sys/hoon.hoon"
system = "urbit/pkg/arvo/sys"
```

Paths are relative to the configuration file. Honk discovers the nearest
`honk.toml` above the entry, or accepts `--config PATH`. Nested roots select
the most specific project. Explicit command-line paths must agree with it.

```sh
cargo run --release -p honk -- --output app.jam desks/mydesk/app/example.hoon
```

The Urbit prelude must report Kelvin 135. `system` adds arvo, lull, and zuse;
omit it for a kernel-only subject. Desk imports support Clay's typed headers:

- `/+`, `/-`, and `/=` compile libraries, structures, and named source files.
- `/~` checks each immediate Hoon member against its mold in the importing
  subject and returns a typed map. Members compile against the base prelude.
- `/%` builds a typed mark interface with an inline or inherited gradient.
- `/$` builds a conversion gate, preferring source `grow` over target `grab`.
- `/*` converts raw MIME bytes to the stored mark, then to the requested mark.
  Binary lengths include trailing zero bytes; extensions do not select built-in
  decoders.

As in Clay, `/?` is parsed and ignored; the configured prelude determines the
compiler version.
The default output is the evaluated noun. `--dynock` emits `[%noun trap]`;
`--dynock-typed` uses the inferred type. The trap returns a formula closed
over the resolved subject. Urbit builds do not accept batch
manifests, `--arbitrary`, or `--sut-jam`.

## Incremental compilation

Pass `--cache-dir PATH` to reuse native mint products through Honk's
content-addressed cache. Each key includes the complete resolved subject type,
parsed expression, compiler fingerprint, jet registrations, and typechecking
setting. Imported core bodies are part of the subject type. Source and
dependency changes therefore invalidate affected products without relying on
file timestamps. `--new` bypasses reads and repopulates the cache.

The cache stores inferred types and Nock formulas. Each build evaluates its
prelude and dependencies to establish the runtime's jet registrations. It does
not persist compiler memo tables or a live evaluator. Completed dependencies
are compacted together so equal imported subgraphs share storage.
Cache packs hydrate directly into the noun slab, preserving their shared nodes.

## Validation

```sh
python3 tools/urbit135/verify.py --build-evaluator
bazel test //crates/hatcher:parser135_test //crates/honk:urbit135_parity_test
cargo test --release -p hatcher -p honk
```

Run the reference generator before building Honk or running the parity tests,
locally or in CI. It builds pinned Vere with Zig 0.15.2, verifies Hoon 135
self-compilation, and
writes ignored JAMs under `crates/honk/test-assets/urbit135/reference` and
the embedded lazy-import resolver at `crates/honk/assets/laze-135.jam`.
It verifies their SHA-256 hashes against the committed manifest. Native tests
compare these JAMs byte for byte with parser and compiler output, source spots,
system libraries, and evaluated results, and check rejection cases.
The Clay fixture compares its complete imported subject, including mark-core
types and conversion gates, against `tools/urbit135/clay.hoon` evaluated in Vere.
`--artifacts PATH` selects the Vere build and bootstrap cache directory.

`HONK_DUMP_URBIT_ARTIFACTS=PATH` exports each source's resolved subject vase
and `[type formula]` product for independent comparisons. Desk artifacts retain
the source's relative path. Match the logical source path and debug setting in
the reference parser; the CLI enables source-spot hints by default.

For a compiler build without the test references, run `just laze-135-asset`
or `python3 tools/urbit135/verify.py --build-evaluator --factory-only`.
`--urbit PATH` uses an existing evaluator built from the pinned revision and
patch instead of building one. Both modes generate the resolver and check its
source and output hashes before writing it; no existing JAM is required.

`--update` updates the committed hash manifest during full reference generation.
Native compilation and the independent reference generator verify the resolver
against its Hoon source. All Hoon 135 JAMs are generated artifacts and stay
untracked.

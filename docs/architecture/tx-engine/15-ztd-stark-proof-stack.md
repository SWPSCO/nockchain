# The ZTD STARK Proof Stack (ztd three through eight)

## Overview

Nockchain's transaction engine sits atop a complete STARK (Scalable Transparent ARgument of Knowledge) proof system, implemented across eight Hoon libraries (`ztd/one.hoon` through `ztd/eight.hoon`). This stack provides:
- The hash function (Tip5) used for all tx-engine commitments
- The Merkle tree primitives used for lock proofs
- The proof-of-work mechanism (proving correct execution of Nock programs)

The tx-engine accesses the full stack via `zeke.hoon` (a 1-line re-export of `ztd/eight.hoon`), which transitively imports the entire hierarchy.

## Import Hierarchy

```
ztd/one.hoon (~1390 lines)
  Belt, Felt, Melt, Bpoly, Fpoly, Mary, Base field arithmetic
    │
    ▼
ztd/two.hoon (~1716 lines)
  Extension field, Polynomial arithmetic, NTT/FFT, Interpolation
    │
    ▼
ztd/three.hoon (~2091 lines)
  Tip5 hash, Merkle trees, Proof types, u32 arithmetic, Bignum, Cheetah curve
    │
    ▼
ztd/four.hoon (~258 lines)
  Proof stream, Fiat-Shamir, Constraint utilities
    │
    ▼
ztd/five.hoon (~1026 lines)
  FRI polynomial commitment scheme
    │
    ▼
ztd/six.hoon (~309 lines)
  Table/jute interface for execution traces
    │
    ▼
ztd/seven.hoon (~963 lines)
  STARK constraint organization, Quotient computation
    │
    ▼
ztd/eight.hoon (~1034 lines)
  STARK prover engine, Proof-of-work integration
    │
    ▼
zeke.hoon (1 line)
  Re-exports ztd/eight → imported by zoon.hoon and tx-engine
```

Total: ~8,787 lines of Hoon implementing a complete STARK proof system from field arithmetic through proof generation.

## ztd/three.hoon: Cryptographic Primitives

Covered in detail in files 11 (Tip5) and 13 (Merkle trees). Key components:

| Component | Purpose | Used by tx-engine? |
|---|---|---|
| Tip5 hash | Sponge hash over Goldilocks | Yes — all commitments |
| Merkle trees (merk) | Binary hash trees with proofs | Yes — lock proofs, block commitments |
| Hashable | Tagged commitment trees | Yes — transaction IDs, lock hashes |
| Tog (PRNG) | Deterministic randomness from sponge | Indirectly — via STARK proofs |
| u32 arithmetic | 32-bit operations for S-box | Yes — Tip5 internals |
| Bignum (chunk/merge) | Multi-word integers | Yes — Cheetah scalar operations |
| Cheetah curve types | Elliptic curve point operations | Yes — Schnorr signatures |

## ztd/four.hoon: Proof Stream and Fiat-Shamir

~258 lines providing the interactive-to-non-interactive transformation for STARK proofs.

### Proof Stream

The proof stream is the central abstraction for building non-interactive proofs via the Fiat-Shamir heuristic:

```hoon
++  proof-stream
  |_  [objects=(list proof-data) read-index=@ sponge=tip5-state]
```

| Arm | Purpose |
|---|---|
| `push` | Append a proof object to the stream |
| `pull` | Read the next proof object from the stream |
| `prover-fiat-shamir` | Generate verifier challenges from prover's transcript |
| `verifier-fiat-shamir` | Regenerate challenges from received proof objects |

The Fiat-Shamir transform converts an interactive proof protocol (where the verifier sends random challenges) into a non-interactive one (where challenges are derived by hashing the transcript). The `sponge` field is a Tip5 sponge state that absorbs proof objects and squeezes out challenges.

### Proof Data Types

```hoon
+$  proof-data
  $%  [%tip5-digest noun-digest:tip5]
      [%merk-proof merk-proof:merkle]
      [%merk-data merk-data:merkle]
      [%codeword-data codeword-data]
      [%fp-codeword-data fp-codeword-data]
      [%deep-point deep-point]
      [%fp-deep-point fp-deep-point]
  ==
```

Each variant carries a different type of proof artifact — hash digests, Merkle proofs, polynomial evaluation data, and deep composition points.

### Constraint Utilities

```hoon
+$  mp-pelt  [a=belt b=belt c=belt]  :: Triple belt for constraint evaluation
++  mpadd-pelt  :: Add two pelts
++  mpmul-pelt  :: Multiply two pelts
++  mpsub-pelt  :: Subtract two pelts
```

The `mp-pelt` type represents constraint polynomial evaluations as triples, used for efficient batch evaluation of STARK AIR constraints.

## ztd/five.hoon: FRI Commitment Scheme

~1026 lines implementing the **Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI)** — the polynomial commitment scheme at the heart of STARKs.

### FRI Configuration

```hoon
+$  fri-input
  $:  offset=belt
      omega=belt           :: Root of unity for evaluation domain
      domain-length=@      :: Size of evaluation domain
      expansion-factor=@   :: LDE blow-up factor
      num-spot-checks=@    :: Number of random queries
      folding-degree=@     :: Degree reduction per FRI round
  ==
```

### FRI Engine

```hoon
++  fri-door
  |_  fri-input
  ++  prove   :: Generate FRI proof
  ++  verify  :: Verify FRI proof
```

FRI proves that a committed polynomial has degree at most `d` by:
1. Committing to polynomial evaluations via Merkle trees
2. Iteratively folding the polynomial (reducing degree by `folding-degree` per round)
3. Providing spot-check openings with Merkle proofs at random positions
4. The verifier checks that folding was done correctly at the queried positions

The Merkle trees used for FRI commitments are the same `merk-heap` type from ztd/three, using Tip5 for all hash operations.

## ztd/six.hoon: Table/Jute Interface

~309 lines defining the interface between execution traces and STARK constraints.

### Jute (Junction Table) Types

```hoon
+$  jute-data   :: Data for a single junction table column
+$  jute-funcs  :: Functions for a junction table column
+$  row         :: Single row of execution trace
+$  matrix      :: Multiple rows
+$  table       :: Named execution trace table
+$  table-mary  :: Table stored as mary (strided array)
```

A "jute" (junction table entry) represents a single column in the execution trace — the record of a Nock program's computation step-by-step. Each column captures one aspect of the computation (program counter, stack pointer, memory contents, etc.).

The STARK proof demonstrates that the execution trace satisfies all transition constraints (each step follows from the previous according to the Nock evaluation rules) and boundary constraints (the input/output match the claimed values).

## ztd/seven.hoon: STARK Core

~963 lines implementing the core STARK constraint machinery.

### Constraint Degrees

```hoon
+$  constraint-degrees
  $:  boundary=(list @)
      row=(list @)
      transition=(list @)
      terminal=(list @)
      extra=(list @)
  ==
```

Constraint types:
- **Boundary**: Fix values at specific rows (e.g., initial state, final output)
- **Row**: Must hold at every row independently
- **Transition**: Relate consecutive rows (e.g., `state[i+1] = f(state[i])`)
- **Terminal**: Fix values at the last row
- **Extra**: Additional constraints for cross-table lookups

### STARK Configuration

```hoon
+$  stark-config
+$  stark-input
```

Configuration includes: the number of trace columns, constraint degrees, FRI parameters, and the evaluation domain specification.

### Quotient Computation

```hoon
++  quot  :: Quotient polynomial computation
```

The quotient polynomial is the key object in STARK proofs. Given:
- An execution trace polynomial `T(x)`
- A set of constraint polynomials `C_i(T(x))`
- A zerofier polynomial `Z(x)` that vanishes on the trace domain

The quotient `Q(x) = C(T(x)) / Z(x)` exists as a polynomial (i.e., the division is exact) if and only if the constraints are satisfied. The STARK proof commits to `Q(x)` and uses FRI to prove its degree is bounded.

## ztd/eight.hoon: STARK Prover Engine

~1034 lines implementing the full STARK prover, including proof-of-work integration.

### STARK Engine

```hoon
++  stark-engine
++  stark-engine-jet-hook
```

The prover follows this pipeline:

1. **Trace generation**: Execute the Nock program, recording the execution trace
2. **Low-Degree Extension (LDE)**: Extend trace polynomials to a larger evaluation domain
3. **Constraint evaluation**: Evaluate all constraint polynomials over the extended domain
4. **Quotient computation**: Divide constraint evaluations by the zerofier
5. **Composition**: Combine quotient columns using random challenges (Fiat-Shamir)
6. **Deep composition**: Evaluate at a random out-of-domain point
7. **FRI**: Prove the composed polynomial has the expected degree
8. **Serialize**: Package all commitments and openings into a proof stream

### Proof-of-Work Integration

```hoon
++  puzzle-nock  :: Generate a proof-of-work puzzle
++  powork       :: Verify proof-of-work
++  gen-tree     :: Generate the execution tree for proof
++  fock         :: Proof caching mechanism
```

Nockchain's proof-of-work is unique: instead of finding a hash preimage (like Bitcoin), miners must generate a valid STARK proof that a given Nock computation was executed correctly. This means:

- The "puzzle" is a Nock program to execute
- The "solution" is a STARK proof of correct execution
- Verification is efficient (polylogarithmic in computation size)
- Mining requires actually performing computation, not just hashing

The `fock` arm provides proof caching — previously generated proofs can be stored and reused, avoiding redundant work for repeated computations.

## Connection to the Transaction Engine

The tx-engine does not directly use the STARK prover for transaction validation. Instead, the connection is:

### Direct Usage

| ZTD Component | Tx-Engine Usage |
|---|---|
| ztd/one (Belt, Melt) | Field arithmetic for all hash/signature operations |
| ztd/two (Shape, Felt) | Note-data size limits, Cheetah field operations |
| ztd/three (Tip5) | Transaction IDs, lock roots, Merkle proofs, z-map ordering |
| ztd/three (Merkle) | Lock Merkle proofs, block commitments |

### Indirect Usage

| ZTD Component | Role |
|---|---|
| ztd/four–eight (STARK prover) | Proof-of-work for block mining |

The STARK stack generates the proofs that secure the blockchain itself. When a miner produces a block, they must include a STARK proof that the block's Nock computation was executed correctly. The tx-engine's validated transactions are *inputs* to this computation.

### The Import Chain

```
tx-engine-1.hoon
  └─ imports zoon.hoon (z-map/z-set for all collections)
       └─ imports zeke.hoon
            └─ re-exports ztd/eight.hoon
                 └─ transitively imports one through seven
```

This means the tx-engine has access to the *entire* ZTD stack through its dependency chain. While it primarily uses ztd/one through ztd/three for field arithmetic, hashing, and Merkle trees, the full stack is available.

## Also: zose.hoon — Vendored Crypto Utilities

`hoon/common/zose.hoon` (~3684 lines) is a vendored copy of Urbit's `zuse` crypto library, providing:

| Component | Purpose |
|---|---|
| `base58` | Base58 encoding/decoding (Bitcoin-style) |
| `fu` | Modular arithmetic (generic prime field operations) |
| `curt` | Curve25519 scalar multiplication |
| `ga` | GF polynomial arithmetic (Galois fields) |

These utilities support non-consensus cryptographic operations like key derivation and Ed25519 signatures.

## Comparison with Other Blockchain Proof Systems

| Aspect | Bitcoin | Ethereum | Nockchain |
|---|---|---|---|
| Proof of work | SHA-256d hashcash | Ethash (deprecated) → PoS | STARK proof of Nock execution |
| Verification | Check hash < target | N/A (PoS) | Verify STARK proof |
| ZK proofs | None (native) | L2 rollups (external) | Native STARK prover (ztd stack) |
| Hash function | SHA-256 (binary) | Keccak-256 (binary) | Tip5 (algebraic, ZK-friendly) |
| Signature scheme | ECDSA/Schnorr over secp256k1 | ECDSA over secp256k1 | Schnorr over Cheetah (STARK-friendly) |
| Field arithmetic | None (no algebraic structure) | None (no algebraic structure) | Goldilocks field (ztd/one–two) |

The distinguishing feature of Nockchain's architecture is the **deep integration** between the proof system and the transaction engine. They share the same field (Goldilocks), the same hash function (Tip5), and the same data structures (z-maps, Merkle trees). This co-design means that verifying transactions *inside* a STARK proof is efficient — no impedance mismatch between the consensus layer's cryptographic primitives and the proof system's arithmetic.

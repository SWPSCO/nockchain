# Merkle Trees and Commitment Schemes

## Overview

Nockchain uses Tip5-based Merkle trees for two distinct purposes: (1) **lock trees** — Taproot-style MAST structures that define spending conditions, and (2) **hashable commitment trees** — deterministic hash commitments over structured data (transactions, proofs, blocks). Both share the same underlying Merkle primitives from `hoon/common/ztd/three.hoon`.

## Merkle Tree Types

The authoritative Hoon types from `ztd/three.hoon`:

### merk: Tagged Merkle Tree

```hoon
++  merk
  |$  [node]
  $~  [%leaf *noun-digest:tip5 ~]
  $%  [%leaf h=noun-digest:tip5 ~]
      [%tree h=noun-digest:tip5 t=(pair (merk node) (merk node))]
  ==
```

A `merk` is a tagged union:
- `[%leaf h ~]`: a leaf node containing only a hash digest
- `[%tree h [left right]]`: an internal node containing a hash and two children

Every node carries its hash `h`, which is either the hash of the leaf data or `hash-ten-cell(h.left, h.right)` for internal nodes.

### merk-proof: Inclusion Proof

```hoon
+$  merk-proof  [root=noun-digest:tip5 path=(list noun-digest:tip5)]
```

A Merkle proof consists of:
- **root**: the expected root hash (must match the committed root)
- **path**: sibling hashes from the leaf up to the root, one per level

### merk-heap: Flat Array Representation

```hoon
+$  merk-heap  [h=noun-digest:tip5 m=mary]
```

A heap-layout Merkle tree stored as a flat `mary` (fixed-stride array). The root hash `h` is stored separately. This representation is used for FRI polynomial commitment Merkle trees where random-access to sibling nodes is needed.

### mee: Untagged Binary Tree

```hoon
++  mee
  |$  [node]
  $~  [%leaf *node]
  $%  [%leaf n=node]
      [%tree l=(mee node) r=(mee node)]
  ==
```

A simpler binary tree without hash annotations, used as an intermediate structure during tree construction (`list-to-balanced-tree`).

## Tree Construction

### list-to-balanced-tree

Converts a flat `mary` (array) into a balanced binary `mee` tree:

```hoon
++  list-to-balanced-tree
  |=  lis=mary
  ^-  [h=@ t=(mee mary)]
  :-  (xeb len.array.lis)  :: height = ceil(log2(len))
  |-
  ?>  !=(0 len.array.lis)
  =/  len  len.array.lis
  ?:  =(1 len)  [%leaf ...]
  ?:  =(2 len)  [%tree [%leaf left] [%leaf right]]
  :: Split: left gets ceil(len/2), right gets floor(len/2)
  [%tree $(lis left-half) $(lis right-half)]
```

For odd-length lists, the left subtree gets one extra element, producing a left-heavy balanced tree.

### build-merk

Converts a `mary` into a full `merk` with hash annotations:

```hoon
++  build-merk
  |=  m=mary
  ^-  (pair @ (merk mary))
  =/  [h=@ n=(mee mary)]  (list-to-balanced-tree m)
  :-  h
  |-
  ?:  ?=([%leaf *] n)
    [%leaf (hash-hashable:tip5 (hashable-mary:tip5 n.n)) ~]
  =/  l=(merk mary)  $(n l.n)
  =/  r=(merk mary)  $(n r.n)
  [%tree (hash-ten-cell:tip5 h.l h.r) l r]
```

1. Build a balanced binary tree from the input array
2. Hash each leaf via `hash-hashable:tip5`
3. Hash each internal node as `hash-ten-cell(left.hash, right.hash)`
4. Return the tree height and annotated Merkle tree

### build-merk-heap

Builds a heap-layout Merkle tree (flat array) for efficient random-access proof generation:

```hoon
++  build-merk-heap
  |=  m=mary
  ^-  [depth=@ heap=merk-heap]
```

The heap layout stores all nodes in a contiguous array where index 0 is the root, and children of index `i` are at `2i+1` and `2i+2`. This layout is used by the FRI polynomial commitment scheme for efficient Merkle proof construction during STARK proof generation.

## Proof Generation

### prove-hashable-by-index

Generates an inclusion proof for a specific leaf in a hashable tree:

```hoon
++  prove-hashable-by-index
  |=  [h=hashable:tip5 idx=@]
  ^-  [axis=@ proof=merk-proof]
```

The algorithm:
1. Count leaves in the left and right subtrees
2. Recurse into the subtree containing the target index
3. At each level, record the sibling's hash in the proof path
4. Convert the leaf position to a Nock axis using `peg`
5. Return both the axis (for the lock Merkle proof) and the proof path

### build-merk-proof

Generates a proof from a heap-layout Merkle tree:

```hoon
++  build-merk-proof
  |=  [merk=merk-heap axis=@]
  ^-  merk-proof
  :-  h.merk   :: root hash
  |-            :: walk from leaf to root collecting siblings
  ?:  =(0 axis)  ~
  =/  parent   (div (dec axis) 2)
  =/  sibling  ?:((mod axis 2) (add axis 1) (sub axis 1))
  [(snag-as-digest:tip5 m.merk sibling) $(axis parent)]
```

Starting from the leaf's heap index, it walks up to the root, collecting the sibling hash at each level. The axis-to-heap-index conversion uses `(dec axis)`.

### verify-merk-proof

Verifies a Merkle inclusion proof:

```hoon
++  verify-merk-proof
  |=  [leaf=noun-digest:tip5 axis=@ merk-proof]
  ^-  ?
  ?:  =(1 axis)  &(=(root leaf) ?=(~ path))
  ?:  =(2 axis)  &(=(root (hash-ten-cell:tip5 leaf sib)) ?=(~ t.path))
  ?:  =(3 axis)  &(=(root (hash-ten-cell:tip5 sib leaf)) ?=(~ t.path))
  :: General case: reconstruct hashes from leaf to root
  ?:  =((mod axis 2) 0)
    $(axis (div axis 2), leaf (hash-ten-cell:tip5 leaf sib), path t.path)
  $(axis (div (dec axis) 2), leaf (hash-ten-cell:tip5 sib leaf), path t.path)
```

The axis determines sibling ordering at each level:
- **Even axis** (left child): hash as `(leaf, sibling)`
- **Odd axis** (right child): hash as `(sibling, leaf)`

This uses Nock's binary tree addressing where left children have even axes and right children have odd axes.

### index-to-axis

Maps a leaf index (0-based) to a Nock tree axis:

```hoon
++  index-to-axis
  |=  [h=@ i=@]
  ^-  axis
  =/  min  (bex (dec h))  :: 2^(height-1)
  (add min i)
```

In a balanced tree of height `h`, the leftmost leaf has axis `2^(h-1)` and leaf `i` has axis `2^(h-1) + i`.

## Hashable Commitment Construction

The `hashable` type is the central abstraction for computing deterministic hash commitments over structured data.

### The Hashable Type

From `ztd/three.hoon`:

```hoon
+$  hashable
  $%  [%leaf p=@]               :: raw value
      [%hash p=noun-digest]     :: pre-computed hash
      [%list p=(list hashable)] :: list of hashables
  ==
```

A `hashable` is a tagged tree:
- `leaf+value`: a raw atom to be hashed
- `hash+digest`: an already-computed 5-element Tip5 digest (avoids re-hashing)
- `list+[...]`: a list of sub-hashables, converted to a balanced binary tree for hashing

### hash-hashable: The Universal Commitment Function

`hash-hashable:tip5` traverses a hashable tree, producing a single 5-element Tip5 digest:

- **leaf**: hash the atom via `hash-varlen`
- **hash**: return the pre-computed digest directly
- **list**: convert to a balanced binary tree, hash leaves, then hash pairs up to the root via `hash-ten-cell`

This provides a **compositional** hashing interface: complex data structures define their `++hashable` arms that construct hashable trees, and `hash-hashable` traverses them uniformly.

### Transaction Engine Hashable Arms

Each tx-engine type defines a `++hashable` arm that builds its commitment structure:

**Lock Merkle Proof (Full format, post-Bythos):**

```hoon
:*  leaf+version.form
    hash+(hash:spend-condition spend-condition.form)
    leaf+axis.form
    (hashable-merk-proof merk-proof.form)
==
```

This commits to: the proof format version, the spend condition hash, the axis (which branch), and the Merkle path.

**Lock Merkle Proof (Stub format, pre-Bythos):**

```hoon
:+  hash+(hash:spend-condition spend-condition.form)
    hash+(from-b58:^hash '6mhCSwJQDvbkbiPAUNjetJtVoo1VLtEhmEYoU4hmdGd6ep1F6ayaV4A')
  (hashable-merk-proof merk-proof.form)
```

The stub format replaces the axis with a **hardcoded hash** — a static placeholder. This means the witness hash does not commit to which branch is being executed, a weakness fixed by the full format in Bythos.

**Spend Condition:**

The spend condition hashable includes all lock primitives in the condition list, each contributing their parameters as leaves and hashes.

**Transaction (Spends):**

The transaction ID is computed as `hash-hashable` of the entire spends structure — the map of all inputs being consumed.

## Usage in the Transaction Engine

### Lock Tree (MAST)

The lock tree is the primary use of Merkle trees in the tx-engine:

1. **Construction**: A lock is built as a Merkle tree of spend conditions. Each leaf is a `SpendCondition` (a list of lock primitives). The root hash becomes `Name.first` — the first component of the UTXO identifier.

2. **Proof**: When spending, the `LockMerkleProof` reveals one leaf (the spend condition being exercised) plus the sibling hashes from leaf to root.

3. **Verification**: The validator hashes the revealed spend condition, combines with siblings using the axis to determine ordering, and checks the result equals `Name.first`.

### Transaction IDs

The `TxId` (alias for `Hash`) is computed as `hash-hashable` of the transaction's spends structure, providing a unique, deterministic identifier for each transaction.

### Note Names

A Note's `Name` is `[first=Hash, last=Hash, null=0]` where:
- `first` = hash of the lock tree root (the spending conditions)
- `last` = hash of the source (parent transaction or coinbase)

Both components use Tip5 hashing via the hashable commitment machinery.

### Block Commitments

Pages (blocks) commit to their contents via Merkle roots over the included transactions, using the same `build-merk` infrastructure.

### FRI Polynomial Commitments

The STARK proof system uses `build-merk-heap` to commit to polynomial evaluations. The heap layout enables efficient Merkle proof construction for the spot-check queries in the FRI protocol.

## Comparison with Other Blockchain Merkle Trees

| Aspect | Bitcoin | Bitcoin Taproot | Nockchain |
|---|---|---|---|
| Hash function | SHA-256d | SHA-256 (tagged) | Tip5 |
| Transaction Merkle | Binary tree of txids | Same | Hashable tree of spends |
| Script tree | N/A | MAST of TapScript leaves | Lock tree of SpendConditions |
| Proof structure | txid + siblings | Control block + script + path | Axis + spend condition + path |
| UTXO commitment | None (pre-UtreexO) | None | Implicit in z-map root hash |
| ZK-friendly | No (SHA-256 is expensive in circuits) | No | Yes (Tip5 is native field arithmetic) |

### Nockchain's Merkle Innovation

Nockchain combines two Merkle patterns:

1. **Explicit Merkle trees** (lock trees, FRI commitments): traditional hash trees with sibling proofs, matching Taproot's MAST model

2. **Implicit Merkle structure** (z-map/z-set): the Tip5-ordered treap data structures (zoon) function as hash-committed collections without a separate Merkle tree — the z-map root hash already commits to the entire set's contents and structure

This means the UTXO set itself is a Merkle-like commitment — comparing two UTXO sets reduces to comparing their z-map root hashes. Bitcoin requires a separate accumulator (like Utreexo) to achieve similar properties.

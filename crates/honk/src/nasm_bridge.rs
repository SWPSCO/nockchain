//! Direct conversion of space-resident nockvm nouns into hash-consed nockasm
//! nouns.
//!
//! The converter walks the slab noun once, with no jam/cue round trip, and
//! interns every distinct subtree. Equal subtrees in the output are
//! pointer-equal, which keeps `nockasm::lift_bundle`'s structural memo on its
//! O(1) `ptr_eq` fast path.
//!
//! The intern tables key parents by their children's intern ids, so structural
//! equality of parents reduces to id-pair equality (children are canonical
//! before any parent is built). No whole subtree is compared or hashed; every
//! node costs O(1) map work.

use nockapp::noun::slab::NounSlab;
use nockvm::noun::{Atom, Noun, NounSpace, D, DIRECT_MAX, T};

use crate::errors::{CompilerError, Result};
use crate::native::identity::{AtomValue, CellKey, NounIdentity};
use crate::native::ut::types::FastHashMap;

/// Identity within one bridge's canonical noun arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct NasmNounId(u32);

#[derive(Default)]
pub struct SlabToNockasm {
    /// Canonical noun per intern id. The maps below store bare ids, so each
    /// canonical noun is held once, here, and the maps carry no `Rc` refcounts.
    canon: Vec<nockasm::Noun>,
    /// Raw slab noun bits (allocation offset + tag, or direct-atom value) to
    /// intern id. Slab nouns are immutable, so a raw value always denotes the
    /// same noun within one space.
    slab_memo: FastHashMap<NounIdentity, NasmNounId>,
    small_atoms: FastHashMap<AtomValue, NasmNounId>,
    big_atoms: std::collections::HashMap<
        Box<[u8]>,
        NasmNounId,
        std::hash::BuildHasherDefault<crate::native::ut::types::FastHasher>,
    >,
    cells: FastHashMap<CellKey<NasmNounId>, NasmNounId>,
}

enum Task {
    Visit(Noun),
    Build { raw: NounIdentity },
}

impl SlabToNockasm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert one root. Interning state persists across calls, so roots
    /// converted through one instance share their common subtrees.
    pub fn convert(&mut self, root: Noun, space: &NounSpace) -> Result<nockasm::Noun> {
        let mut tasks = vec![Task::Visit(root)];
        let mut values: Vec<NasmNounId> = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Visit(noun) => {
                    let raw = NounIdentity::of(noun);
                    if let Some(&hit) = self.slab_memo.get(&raw) {
                        values.push(hit);
                        continue;
                    }
                    let handle = noun.in_space(space);
                    if let Ok(atom) = handle.as_atom() {
                        let id = match atom.as_u64() {
                            Ok(value) => self.small_atom(value)?,
                            Err(_) => self.wide_atom(atom.as_ne_bytes())?,
                        };
                        self.slab_memo.insert(raw, id);
                        values.push(id);
                        continue;
                    }
                    let cell = handle.as_cell().map_err(|err| {
                        CompilerError::Decode(format!("nasm bridge noun not cell: {err:?}"))
                    })?;
                    let (head, tail) = cell.head_tail();
                    tasks.push(Task::Build { raw });
                    tasks.push(Task::Visit(tail.noun()));
                    tasks.push(Task::Visit(head.noun()));
                }
                Task::Build { raw } => {
                    let tail_id = values
                        .pop()
                        .expect("nasm bridge build frame missing tail value");
                    let head_id = values
                        .pop()
                        .expect("nasm bridge build frame missing head value");
                    let id = match self.cells.get(&CellKey {
                        head: head_id,
                        tail: tail_id,
                    }) {
                        Some(&id) => id,
                        None => {
                            let cell = nockasm::Noun::cell(
                                self.canon[head_id.0 as usize].clone(),
                                self.canon[tail_id.0 as usize].clone(),
                            );
                            let id = self.intern(cell)?;
                            self.cells.insert(
                                CellKey {
                                    head: head_id,
                                    tail: tail_id,
                                },
                                id,
                            );
                            id
                        }
                    };
                    self.slab_memo.insert(raw, id);
                    values.push(id);
                }
            }
        }
        let id = values
            .pop()
            .expect("nasm bridge traversal must produce a root value");
        debug_assert!(values.is_empty());
        Ok(self.canon[id.0 as usize].clone())
    }

    fn intern(&mut self, noun: nockasm::Noun) -> Result<NasmNounId> {
        let id = u32::try_from(self.canon.len()).map_err(|_| {
            CompilerError::Decode("nasm bridge exceeded u32 distinct nouns".to_string())
        })?;
        self.canon.push(noun);
        Ok(NasmNounId(id))
    }

    fn small_atom(&mut self, value: u64) -> Result<NasmNounId> {
        if let Some(&id) = self.small_atoms.get(&AtomValue(value)) {
            return Ok(id);
        }
        let id = self.intern(nockasm::Noun::from(value))?;
        self.small_atoms.insert(AtomValue(value), id);
        Ok(id)
    }

    /// Intern an atom given as (possibly zero-padded) little-endian bytes.
    fn wide_atom(&mut self, bytes: &[u8]) -> Result<NasmNounId> {
        let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let significant = &bytes[..end];
        if significant.len() <= 8 {
            let mut buf = [0u8; 8];
            buf[..significant.len()].copy_from_slice(significant);
            return self.small_atom(u64::from_le_bytes(buf));
        }
        if let Some(&id) = self.big_atoms.get(significant) {
            return Ok(id);
        }
        let id = self.intern(nockasm::Noun::from(nockasm::Atom::from_le_bytes(
            significant,
        )))?;
        self.big_atoms.insert(significant.into(), id);
        Ok(id)
    }
}

/// Build slab nouns for `root` and everything reachable from it, reusing any
/// nodes hydrated by earlier reads of the same pack. Node ids are
/// topologically ordered by construction (`NasmBundle::from_bytes` rejects
/// forward references), so one forward pass hydrates children before parents.
/// Mirrors `nockasm`'s `lower_root_node` for every node kind but builds
/// directly into the slab, with no lower/jam/cue round trip.
///
/// `nodes` and `root` must belong to a validated bundle. `values` must have one
/// slot per node and contain only nouns hydrated from that bundle into `slab`.
pub fn hydrate_pack_root(
    slab: &mut NounSlab,
    nodes: &[nockasm::DagNode],
    root: nockasm::DagId,
    values: &mut [Option<Noun>],
) -> Noun {
    if let Some(value) = values[root.index()] {
        return value;
    }
    let mut reachable = vec![false; nodes.len()];
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        let index = id.index();
        // Already-hydrated nodes stop the walk: their children are hydrated too.
        if reachable[index] || values[index].is_some() {
            continue;
        }
        reachable[index] = true;
        push_pack_children(&nodes[index], &mut stack);
    }
    for index in 0..nodes.len() {
        if !reachable[index] || values[index].is_some() {
            continue;
        }
        values[index] = Some(build_pack_node(slab, &nodes[index], values));
    }
    values[root.index()].expect("pack root hydrates after its children")
}

fn push_pack_children(node: &nockasm::DagNode, output: &mut Vec<nockasm::DagId>) {
    use nockasm::{DagNode, DagOp};
    match node {
        DagNode::Atom(_) | DagNode::Op(DagOp::Slot(_)) => {}
        DagNode::Cell(a, b)
        | DagNode::Op(DagOp::Eval(a, b))
        | DagNode::Op(DagOp::Eq(a, b))
        | DagNode::Op(DagOp::Comp(a, b))
        | DagNode::Op(DagOp::Push(a, b))
        | DagNode::Op(DagOp::Hint(a, b))
        | DagNode::Op(DagOp::Scry(a, b))
        | DagNode::Op(DagOp::Edit(_, a, b)) => output.extend([*a, *b]),
        DagNode::Nock(a)
        | DagNode::Op(DagOp::Const(a))
        | DagNode::Op(DagOp::Isa(a))
        | DagNode::Op(DagOp::Inc(a))
        | DagNode::Op(DagOp::Call(_, a)) => output.push(*a),
        DagNode::Op(DagOp::If(a, b, c)) | DagNode::Op(DagOp::Hintd(a, b, c)) => {
            output.extend([*a, *b, *c]);
        }
    }
}

/// Builds one node into the slab. Children are hydrated first (topological
/// order), so the lookups cannot miss. The op arms reproduce nockasm's
/// `lower_op` noun shapes. Cache packs are written in `Noun` mode and should
/// hold only atoms and cells, but a pack is untrusted input, so every node kind
/// is lowered.
fn build_pack_node(slab: &mut NounSlab, node: &nockasm::DagNode, values: &[Option<Noun>]) -> Noun {
    use nockasm::{DagNode, DagOp};
    let get =
        |id: &nockasm::DagId| values[id.index()].expect("pack children hydrate before parents");
    match node {
        DagNode::Atom(atom) => nasm_atom_to_slab(slab, atom),
        DagNode::Cell(head, tail) => {
            let (head, tail) = (get(head), get(tail));
            T(slab, &[head, tail])
        }
        DagNode::Nock(raw) => get(raw),
        DagNode::Op(op) => match op {
            DagOp::Slot(axis) => {
                let axis = nasm_atom_to_slab(slab, axis);
                T(slab, &[D(0), axis])
            }
            DagOp::Const(value) => {
                let value = get(value);
                T(slab, &[D(1), value])
            }
            DagOp::Eval(subject, formula) => {
                let (subject, formula) = (get(subject), get(formula));
                T(slab, &[D(2), subject, formula])
            }
            DagOp::Isa(formula) => {
                let formula = get(formula);
                T(slab, &[D(3), formula])
            }
            DagOp::Inc(formula) => {
                let formula = get(formula);
                T(slab, &[D(4), formula])
            }
            DagOp::Eq(left, right) => {
                let (left, right) = (get(left), get(right));
                T(slab, &[D(5), left, right])
            }
            DagOp::If(condition, then_, else_) => {
                let (condition, then_, else_) = (get(condition), get(then_), get(else_));
                T(slab, &[D(6), condition, then_, else_])
            }
            DagOp::Comp(first, second) => {
                let (first, second) = (get(first), get(second));
                T(slab, &[D(7), first, second])
            }
            DagOp::Push(value, body) => {
                let (value, body) = (get(value), get(body));
                T(slab, &[D(8), value, body])
            }
            DagOp::Call(axis, formula) => {
                let formula = get(formula);
                let axis = nasm_atom_to_slab(slab, axis);
                T(slab, &[D(9), axis, formula])
            }
            DagOp::Edit(axis, value, formula) => {
                let (value, formula) = (get(value), get(formula));
                let axis = nasm_atom_to_slab(slab, axis);
                let target = T(slab, &[axis, value]);
                T(slab, &[D(10), target, formula])
            }
            DagOp::Hint(tag, formula) => {
                let (tag, formula) = (get(tag), get(formula));
                T(slab, &[D(11), tag, formula])
            }
            DagOp::Hintd(tag, clue, formula) => {
                let (tag, clue, formula) = (get(tag), get(clue), get(formula));
                let pair = T(slab, &[tag, clue]);
                T(slab, &[D(11), pair, formula])
            }
            DagOp::Scry(reference, path) => {
                let (reference, path) = (get(reference), get(path));
                T(slab, &[D(12), reference, path])
            }
        },
    }
}

fn nasm_atom_to_slab(slab: &mut NounSlab, atom: &nockasm::Atom) -> Noun {
    if let Some(value) = atom.as_u64() {
        if value <= DIRECT_MAX {
            return D(value);
        }
    }
    <Atom as nockvm::ext::AtomExt>::from_bytes(slab, &atom.to_le_bytes()).as_noun()
}

#[cfg(test)]
mod tests {
    use nockapp::noun::slab::NounSlab;
    use nockvm::ext::AtomExt;
    use nockvm::noun::{Atom, NounAllocator, D, T};

    use super::*;

    #[test]
    fn packs_hydrate_every_node_kind() {
        let mut slab: NounSlab = NounSlab::new();
        let big = Atom::new(&mut slab, DIRECT_MAX + 1).as_noun();
        let huge = Atom::from_bytes(&mut slab, &[0xabu8; 12]).as_noun();
        let memo = Atom::from_bytes(&mut slab, b"memo").as_noun();
        let spot = Atom::from_bytes(&mut slab, b"spot").as_noun();
        let mut f = |cells: &[Noun]| T(&mut slab, cells);
        let s1 = f(&[D(0), D(1)]);
        let s2 = f(&[D(0), D(2)]);
        let s3 = f(&[D(0), D(3)]);
        let k0 = f(&[D(1), D(0)]);
        let k1 = f(&[D(1), D(1)]);
        let konst = f(&[D(42), D(43)]);
        let edit = f(&[D(6), s3]);
        let clue_body = f(&[D(1), D(0)]);
        let clue = f(&[spot, clue_body]);
        let formulas = vec![
            s1,
            f(&[D(0), big]),
            f(&[D(1), konst]),
            f(&[D(1), huge]),
            f(&[D(2), s1, k0]),
            f(&[D(3), s1]),
            f(&[D(4), s1]),
            f(&[D(5), s2, s3]),
            f(&[D(6), s1, k0, k1]),
            f(&[D(7), s1, s2]),
            f(&[D(8), s1, s2]),
            f(&[D(9), D(2), s1]),
            f(&[D(10), edit, s2]),
            f(&[D(11), memo, s1]),
            f(&[D(11), clue, s1]),
            f(&[D(12), s1, s2]),
            f(&[s1, s2]),
            f(&[D(99), D(1)]),
        ];
        let space = slab.noun_space();
        let mut bridge = SlabToNockasm::new();
        let converted: Vec<nockasm::Noun> = formulas
            .iter()
            .map(|formula| bridge.convert(*formula, &space).expect("convert"))
            .collect();
        let names: Vec<String> = (0..converted.len()).map(|i| format!("f{i}")).collect();
        let inputs: Vec<nockasm::DagInput<'_>> = converted
            .iter()
            .zip(&names)
            .map(|(noun, name)| nockasm::DagInput {
                name,
                noun,
                mode: nockasm::DagMode::Formula,
            })
            .collect();
        let bundle = nockasm::lift_bundle(&inputs).expect("lift");
        let mut children = Vec::new();
        for node in bundle.nodes() {
            push_pack_children(node, &mut children);
        }
        assert!(!children.is_empty());

        let mut target: NounSlab = NounSlab::new();
        let mut values = vec![None; bundle.nodes().len()];
        for (root, formula) in bundle.roots().iter().zip(&formulas) {
            hydrate_pack_root(&mut target, bundle.nodes(), root.id(), &mut values);
            // A second hydration of the same root is a no-op.
            hydrate_pack_root(&mut target, bundle.nodes(), root.id(), &mut values);
            let hydrated = values[root.id().index()].expect("root value");
            target.set_root(hydrated);
            slab.set_root(*formula);
            assert_eq!(target.jam(), slab.jam(), "{}", root.name());
        }
        for (value, direct) in [(DIRECT_MAX, true), (DIRECT_MAX + 1, false)] {
            let atom = nockasm::Atom::from(value);
            let noun = nasm_atom_to_slab(&mut target, &atom);
            assert_eq!(noun.is_direct(), direct);
            assert_eq!(
                noun.in_space(&target.noun_space())
                    .as_atom()
                    .unwrap()
                    .as_u64()
                    .unwrap(),
                value
            );
        }
    }

    /// The direct converter must agree with a jam/cue round trip: equal nouns,
    /// equal jam bytes, and the same lifted bundle.
    #[test]
    fn direct_conversion_matches_jam_cue_bridge() {
        let mut slab: NounSlab = NounSlab::new();
        let big = Atom::from_bytes(&mut slab, &[0xab; 19]).as_noun();
        let shared = T(&mut slab, &[D(42), big, D(7)]);
        // Equal subtrees in distinct allocations, real pointer sharing, and
        // both small and wide atoms.
        let shared_copy = T(&mut slab, &[D(42), big, D(7)]);
        let root = T(&mut slab, &[shared, shared_copy, shared, D(0)]);
        slab.set_root(root);
        let space = slab.noun_space();

        let jammed = slab.jam();
        let via_jam = nockasm::cue(&jammed).expect("cue slab jam");

        let direct = SlabToNockasm::new()
            .convert(root, &space)
            .expect("direct conversion");

        assert_eq!(direct, via_jam);
        assert_eq!(nockasm::jam(&direct), nockasm::jam(&via_jam));

        let lift = |noun: &nockasm::Noun| {
            nockasm::lift_bundle(&[nockasm::DagInput {
                name: "root",
                noun,
                mode: nockasm::DagMode::Noun,
            }])
            .expect("lift")
            .to_bytes()
        };
        assert_eq!(lift(&direct), lift(&via_jam));
    }

    #[test]
    fn cross_root_sharing_is_preserved() {
        let mut slab: NounSlab = NounSlab::new();
        let shared = T(&mut slab, &[D(1), D(2)]);
        let left = T(&mut slab, &[shared, D(3)]);
        let right = T(&mut slab, &[D(4), shared]);
        let root = T(&mut slab, &[left, right]);
        slab.set_root(root);
        let space = slab.noun_space();

        let mut bridge = SlabToNockasm::new();
        let left = bridge.convert(left, &space).expect("left");
        let right = bridge.convert(right, &space).expect("right");
        let bundle = nockasm::lift_bundle(&[
            nockasm::DagInput {
                name: "left",
                noun: &left,
                mode: nockasm::DagMode::Noun,
            },
            nockasm::DagInput {
                name: "right",
                noun: &right,
                mode: nockasm::DagMode::Noun,
            },
        ])
        .expect("lift");
        // [1 2] must appear once: 1, 2, [1 2], 3, [[1 2] 3], 4, [4 [1 2]].
        assert_eq!(bundle.nodes().len(), 7);
    }
}

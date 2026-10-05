//! AST noun shapes adapted from Hatch, evaluated using Urbit's own noun/map semantics.
//! This module does not implement or import a Nock runtime.
#![allow(non_snake_case, unused_variables, dead_code)]
use std::collections::HashMap;

use num_bigint::BigUint;

use crate::ast::hoon::*;

#[derive(Clone, Copy)]
enum Noun {
    Small(u64),
    Expression(usize),
}
#[derive(Default)]
struct ExpressionArena {
    nodes: Vec<Expression>,
    error: Option<String>,
}
enum Expression {
    Atom(String),
    Cell(Vec<Noun>),
    Map(Vec<(Noun, Noun)>),
}
impl ExpressionArena {
    fn push(&mut self, value: Expression) -> Noun {
        let index = self.nodes.len();
        self.nodes.push(value);
        Noun::Expression(index)
    }
    fn builder(&self, noun: Noun, nouns: &mut Nouns, memo: &mut HashMap<usize, usize>) -> usize {
        let index = match noun {
            Noun::Small(value) => return nouns.atom(value.to_le_bytes().to_vec()),
            Noun::Expression(index) => index,
        };
        if let Some(id) = memo.get(&index) {
            return *id;
        }
        let id = match &self.nodes[index] {
            Expression::Atom(decimal) => nouns.atom(
                BigUint::parse_bytes(decimal.as_bytes(), 10)
                    .expect("decimal AST atom")
                    .to_bytes_le(),
            ),
            Expression::Cell(items) => {
                let mut reversed = items.iter().rev();
                let mut tail = self.builder(*reversed.next().expect("nonempty cell"), nouns, memo);
                for item in reversed {
                    let head = self.builder(*item, nouns, memo);
                    let pair = nouns.cell(head, tail);
                    let tag = nouns.atom(Vec::new());
                    tail = nouns.cell(tag, pair);
                }
                tail
            }
            Expression::Map(pairs) => {
                let mut tail = nouns.atom(Vec::new());
                for (key, value) in pairs.iter().rev() {
                    let key = self.builder(*key, nouns, memo);
                    let value = self.builder(*value, nouns, memo);
                    let pair = nouns.cell(key, value);
                    tail = nouns.cell(pair, tail);
                }
                let tag = nouns.atom(vec![1]);
                nouns.cell(tag, tail)
            }
        };
        memo.insert(index, id);
        id
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
enum DataNoun {
    Atom(Vec<u8>),
    Cell(usize, usize),
}
#[derive(Default)]
struct Nouns {
    nodes: Vec<DataNoun>,
    interned: HashMap<DataNoun, usize>,
}
impl Nouns {
    fn intern(&mut self, noun: DataNoun) -> usize {
        if let Some(id) = self.interned.get(&noun) {
            return *id;
        }
        let id = self.nodes.len();
        self.nodes.push(noun.clone());
        self.interned.insert(noun, id);
        id
    }
    fn atom(&mut self, mut bytes: Vec<u8>) -> usize {
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        self.intern(DataNoun::Atom(bytes))
    }
    fn cell(&mut self, head: usize, tail: usize) -> usize {
        self.intern(DataNoun::Cell(head, tail))
    }
    fn jam(&self, root: usize) -> Vec<u8> {
        let mut writer = Bits::default();
        let mut cache = HashMap::<usize, usize>::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            let noun = &self.nodes[id];
            if let Some(position) = cache.get(&id) {
                let use_reference = match noun {
                    DataNoun::Cell(..) => true,
                    DataNoun::Atom(bytes) => {
                        bit_length(bytes) > usize::BITS as usize - position.leading_zeros() as usize
                    }
                };
                if use_reference {
                    writer.bit(true);
                    writer.bit(true);
                    writer.atom(&position.to_le_bytes());
                    continue;
                }
            } else {
                cache.insert(id, writer.length);
            }
            match noun {
                DataNoun::Atom(bytes) => {
                    writer.bit(false);
                    writer.atom(bytes);
                }
                DataNoun::Cell(head, tail) => {
                    writer.bit(true);
                    writer.bit(false);
                    pending.push(*tail);
                    pending.push(*head);
                }
            }
        }
        writer.bytes
    }
}
fn bit_length(bytes: &[u8]) -> usize {
    match bytes.iter().rposition(|byte| *byte != 0) {
        None => 0,
        Some(last) => last * 8 + 8 - bytes[last].leading_zeros() as usize,
    }
}
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    length: usize,
}
impl Bits {
    fn bit(&mut self, value: bool) {
        if self.length % 8 == 0 {
            self.bytes.push(0);
        }
        if value {
            self.bytes[self.length / 8] |= 1 << (self.length % 8);
        }
        self.length += 1;
    }
    fn atom(&mut self, bytes: &[u8]) {
        let length = bit_length(bytes);
        if length == 0 {
            self.bit(true);
            return;
        }
        let width = usize::BITS as usize - length.leading_zeros() as usize;
        for _ in 0..width {
            self.bit(false);
        }
        self.bit(true);
        for bit in 0..width - 1 {
            self.bit(length & (1 << bit) != 0);
        }
        for bit in 0..length {
            self.bit(bytes[bit / 8] & (1 << (bit % 8)) != 0);
        }
    }
}

fn D(value: u64) -> Noun {
    Noun::Small(value)
}
fn T(slab: &mut ExpressionArena, values: &[Noun]) -> Noun {
    assert!(values.len() >= 2);
    slab.push(Expression::Cell(values.to_vec()))
}
macro_rules! tas {
    ($bytes:expr) => {{
        let mut value = 0u64;
        for (i, byte) in $bytes.iter().enumerate() {
            value |= (*byte as u64) << (8 * i);
        }
        value
    }};
}
/// Encode the complete AST as jammed builder data. Atoms stay atoms, cells
/// become `[0 head tail]`, and maps become `[1 pairs]`. Urbit reconstructs the
/// actual maps itself, so hashing and tree ordering remain its responsibility.
pub fn jammed_builder(hoon: &Hoon) -> Result<Vec<u8>, String> {
    let mut arena = ExpressionArena::default();
    let noun = hoon_to_noun(&mut arena, hoon);
    jam_builder(arena, noun)
}

/// Encode the complete Clay pile: ordered import groups and its debug AST.
pub fn jammed_file_builder(file: &crate::ford::File) -> Result<Vec<u8>, String> {
    use crate::ford::HeaderKind;
    let mut arena = ExpressionArena::default();
    let mut groups: [Vec<Noun>; 7] = std::array::from_fn(|_| Vec::new());
    for header in &file.headers {
        let (group, values) = match &header.kind {
            HeaderKind::Version { .. } => continue,
            HeaderKind::Structures { imports } | HeaderKind::Libraries { imports } => {
                let group = usize::from(matches!(&header.kind, HeaderKind::Libraries { .. }));
                for import in imports {
                    let face = match &import.face {
                        Some(face) => {
                            let face = term_to_noun(&mut arena, face);
                            T(&mut arena, &[D(0), face])
                        }
                        None => D(0),
                    };
                    let path = term_to_noun(&mut arena, &import.path);
                    groups[group].push(T(&mut arena, &[face, path]));
                }
                continue;
            }
            HeaderKind::Source { face, path } => (
                2,
                vec![term_to_noun(&mut arena, face), path_to_noun(&mut arena, path)],
            ),
            HeaderKind::Directory {
                face, mold, path, ..
            } => (
                3,
                vec![
                    term_to_noun(&mut arena, face),
                    spec_to_noun(&mut arena, mold),
                    path_to_noun(&mut arena, path),
                ],
            ),
            HeaderKind::Mark { face, mark } => (
                4,
                vec![term_to_noun(&mut arena, face), term_to_noun(&mut arena, mark)],
            ),
            HeaderKind::Conversion { face, from, to } => (
                5,
                vec![
                    term_to_noun(&mut arena, face),
                    term_to_noun(&mut arena, from),
                    term_to_noun(&mut arena, to),
                ],
            ),
            HeaderKind::File { face, mark, path } => (
                6,
                vec![
                    term_to_noun(&mut arena, face),
                    term_to_noun(&mut arena, mark),
                    path_to_noun(&mut arena, path),
                ],
            ),
        };
        groups[group].push(T(&mut arena, &values));
    }
    let mut fields = groups
        .into_iter()
        .map(|group| list_to_noun(&mut arena, group))
        .collect::<Vec<_>>();
    fields.push(hoon_to_noun(&mut arena, &file.body));
    let noun = T(&mut arena, &fields);
    jam_builder(arena, noun)
}

fn jam_builder(mut arena: ExpressionArena, noun: Noun) -> Result<Vec<u8>, String> {
    if let Some(error) = arena.error.take() {
        return Err(error);
    }
    let mut nouns = Nouns::default();
    let root = arena.builder(noun, &mut nouns, &mut HashMap::new());
    Ok(nouns.jam(root))
}

/// Encode a list of atom pairs for the evaluator's binary sample transport.
pub fn jam_atom_pairs(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut nouns = Nouns::default();
    let mut list = nouns.atom(Vec::new());
    for (left, right) in pairs.iter().rev() {
        let left = nouns.atom(left.to_vec());
        let right = nouns.atom(right.to_vec());
        let pair = nouns.cell(left, right);
        list = nouns.cell(pair, list);
    }
    nouns.jam(list)
}

fn list_to_noun(slab: &mut ExpressionArena, nouns: Vec<Noun>) -> Noun {
    if nouns.is_empty() {
        return D(0);
    }
    let mut items = nouns;
    items.push(D(0));
    slab.push(Expression::Cell(items))
}
fn map_to_noun(slab: &mut ExpressionArena, pairs: Vec<(Noun, Noun)>) -> Noun {
    slab.push(Expression::Map(pairs))
}
fn term_to_noun(slab: &mut ExpressionArena, value: &str) -> Noun {
    if value == "$" {
        return D(0);
    }
    slab.push(Expression::Atom(
        BigUint::from_bytes_le(value.as_bytes()).to_string(),
    ))
}
fn cord_to_noun(slab: &mut ExpressionArena, value: &str) -> Noun {
    slab.push(Expression::Atom(
        BigUint::from_bytes_le(value.as_bytes()).to_string(),
    ))
}
fn atom_to_noun(slab: &mut ExpressionArena, value: &ParsedAtom) -> Noun {
    let decimal = match value {
        ParsedAtom::Small(n) => n.to_string(),
        ParsedAtom::Big(n) => n.to_string(),
    };
    slab.push(Expression::Atom(decimal))
}
fn axis_to_noun(slab: &mut ExpressionArena, value: &Axis) -> Noun {
    slab.push(Expression::Atom(value.as_biguint().to_string()))
}
fn opt_to_noun<T, F>(slab: &mut ExpressionArena, opt: &Option<T>, f: F) -> Noun
where
    F: FnOnce(&T) -> Noun,
{
    match opt {
        None => D(0),
        Some(x) => {
            let value = f(x);
            T(slab, &[D(0), value])
        }
    }
}
fn hoon_to_noun(slab: &mut ExpressionArena, hoon: &Hoon) -> Noun {
    use Hoon::*;

    match hoon {
        Pair(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[p, q])
        }
        ZapZap => T(slab, &[D(tas!(b"zpzp")), D(0)]),
        Axis(a) => {
            let axis = axis_to_noun(slab, a);
            T(slab, &[D(0), axis])
        }
        Base(bt) => {
            let bt_noun = basetype_to_noun(slab, bt);
            T(slab, &[D(tas!(b"base")), bt_noun])
        }
        Bust(bt) => {
            let bt_noun = basetype_to_noun(slab, bt);
            T(slab, &[D(tas!(b"bust")), bt_noun])
        }
        Dbug(spot, h) => {
            let spot_noun = spot_to_noun(slab, spot);
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"dbug")), spot_noun, h_noun])
        }
        Eror(msg) => {
            let msg_noun = cord_to_noun(slab, msg);
            T(slab, &[D(tas!(b"eror")), msg_noun])
        }
        Hand(_, _) => {
            slab.error =
                Some("compiler-internal %hand nodes are outside the source parser oracle".into());
            D(0)
        }
        Note(note, h) => {
            let note_noun = note_to_noun(slab, note);
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"note")), note_noun, h_noun])
        }
        Fits(h, wing) => {
            let h_noun = hoon_to_noun(slab, h);
            let wing_noun = wing_to_noun(slab, wing);
            T(slab, &[D(tas!(b"fits")), h_noun, wing_noun])
        }
        Knit(woofs) => {
            let woofs_noun: Vec<_> = woofs.iter().map(|w| woof_to_noun(slab, w)).collect();
            let list = list_to_noun(slab, woofs_noun);
            T(slab, &[D(tas!(b"knit")), list])
        }
        Leaf(tag, atom) => {
            let tag_noun = term_to_noun(slab, tag);
            let atom_noun = atom_to_noun(slab, atom);
            T(slab, &[D(tas!(b"leaf")), tag_noun, atom_noun])
        }
        Limb(name) => {
            let name_noun = term_to_noun(slab, name);
            T(slab, &[D(tas!(b"limb")), name_noun])
        }
        Lost(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"lost")), h_noun])
        }
        Rock(au, expr) => {
            let au_noun = term_to_noun(slab, au);
            let expr_noun = noun_expr_to_noun(slab, expr);
            T(slab, &[D(tas!(b"rock")), au_noun, expr_noun])
        }
        Sand(au, expr) => {
            let au_noun = term_to_noun(slab, au);
            let expr_noun = noun_expr_to_noun(slab, expr);
            T(slab, &[D(tas!(b"sand")), au_noun, expr_noun])
        }
        Tell(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"tell")), list])
        }
        Tune(tune) => {
            let tune_noun = term_or_tune_to_noun(slab, tune);
            T(slab, &[D(tas!(b"tune")), tune_noun])
        }
        Wing(wing) => {
            let wing_noun = wing_to_noun(slab, wing);
            T(slab, &[D(tas!(b"wing")), wing_noun])
        }
        Yell(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"yell")), list])
        }
        Xray(manx) => {
            let manx_noun = manx_to_noun(slab, manx);
            T(slab, &[D(tas!(b"xray")), manx_noun])
        }
        BarBuc(tagnames, spec) => {
            let tags_noun: Vec<_> = tagnames.iter().map(|s| term_to_noun(slab, s)).collect();
            let list = list_to_noun(slab, tags_noun);
            let spec_noun = spec_to_noun(slab, spec);
            T(slab, &[D(tas!(b"brbc")), list, spec_noun])
        }
        BarCab(spec, alas, tomes) => {
            let spec_noun = spec_to_noun(slab, spec);
            let alas_noun = alas_to_noun(slab, alas);

            let mut tomes_pairs = Vec::new();
            for (k, tome) in tomes {
                let k_noun = term_to_noun(slab, k);
                let tome_noun = tome_to_noun(slab, tome);
                tomes_pairs.push((k_noun, tome_noun));
            }
            let tomes_noun = map_to_noun(slab, tomes_pairs);
            T(slab, &[D(tas!(b"brcb")), spec_noun, alas_noun, tomes_noun])
        }
        BarCol(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"brcl")), p, q])
        }
        BarCen(prefix, tomes) => {
            let prefix_noun = match prefix.as_ref() {
                None => D(0u64),
                Some(s) => {
                    let term_noun = term_to_noun(slab, s);
                    T(slab, &[D(0), term_noun])
                }
            };
            let mut tomes_pairs = Vec::new();
            for (k, tome) in tomes {
                let k_noun = term_to_noun(slab, k);
                let tome_noun = tome_to_noun(slab, tome);
                tomes_pairs.push((k_noun, tome_noun));
            }
            let tomes_noun = map_to_noun(slab, tomes_pairs);
            T(slab, &[D(tas!(b"brcn")), prefix_noun, tomes_noun])
        }
        BarDot(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brdt")), p])
        }
        BarKet(p, tomes) => {
            let p_noun = hoon_to_noun(slab, p);
            let mut tomes_pairs = Vec::new();
            for (k, tome) in tomes {
                let k_noun = term_to_noun(slab, k);
                let tome_noun = tome_to_noun(slab, tome);
                tomes_pairs.push((k_noun, tome_noun));
            }
            let tomes_noun = map_to_noun(slab, tomes_pairs);
            T(slab, &[D(tas!(b"brkt")), p_noun, tomes_noun])
        }
        BarHep(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brhp")), p])
        }
        BarSig(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brsg")), spec_noun, p_noun])
        }
        BarTar(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brtr")), spec_noun, p_noun])
        }
        BarTis(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brts")), spec_noun, p_noun])
        }
        BarPat(prefix, tomes) => {
            let prefix_noun = match prefix.as_ref() {
                None => D(0u64),
                Some(s) => {
                    let term_noun = term_to_noun(slab, s);
                    T(slab, &[D(0), term_noun])
                }
            };
            let mut tomes_pairs = Vec::new();
            for (k, tome) in tomes {
                let k_noun = term_to_noun(slab, k);
                let tome_noun = tome_to_noun(slab, tome);
                tomes_pairs.push((k_noun, tome_noun));
            }
            let tomes_noun = map_to_noun(slab, tomes_pairs);
            T(slab, &[D(tas!(b"brpt")), prefix_noun, tomes_noun])
        }
        BarWut(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"brwt")), p])
        }
        ColCab(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"clcb")), p, q])
        }
        ColKet(a, b, c, d) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            let d = hoon_to_noun(slab, d);
            T(slab, &[D(tas!(b"clkt")), a, b, c, d])
        }
        ColHep(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"clhp")), p, q])
        }
        ColLus(a, b, c) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"clls")), a, b, c])
        }
        ColSig(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"clsg")), list])
        }
        ColTar(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"cltr")), list])
        }
        CenCab(wing, pairs) => {
            let wing_noun = wing_to_noun(slab, wing);
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(w, h)| {
                    let w_noun = wing_to_noun(slab, w);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[w_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            T(slab, &[D(tas!(b"cncb")), wing_noun, list])
        }
        CenDot(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"cndt")), p, q])
        }
        CenHep(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"cnhp")), p, q])
        }
        CenCol(p, hoons) => {
            let p = hoon_to_noun(slab, p);
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"cncl")), p, list])
        }
        CenTar(wing, p, pairs) => {
            let wing_noun = wing_to_noun(slab, wing);
            let p_noun = hoon_to_noun(slab, p);
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(w, h)| {
                    let w_noun = wing_to_noun(slab, w);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[w_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            T(slab, &[D(tas!(b"cntr")), wing_noun, p_noun, list])
        }
        CenKet(a, b, c, d) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            let d = hoon_to_noun(slab, d);
            T(slab, &[D(tas!(b"cnkt")), a, b, c, d])
        }
        CenLus(a, b, c) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"cnls")), a, b, c])
        }
        CenSig(wing, p, hoons) => {
            let wing_noun = wing_to_noun(slab, wing);
            let p_noun = hoon_to_noun(slab, p);
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"cnsg")), wing_noun, p_noun, list])
        }
        CenTis(wing, pairs) => {
            let wing_noun = wing_to_noun(slab, wing);
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(w, h)| {
                    let w_noun = wing_to_noun(slab, w);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[w_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            T(slab, &[D(tas!(b"cnts")), wing_noun, list])
        }
        DotKet(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"dtkt")), spec_noun, p_noun])
        }
        DotLus(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"dtls")), p])
        }
        DotTar(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"dttr")), p, q])
        }
        DotTis(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"dtts")), p, q])
        }
        DotWut(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"dtwt")), p])
        }
        KetBar(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"ktbr")), p])
        }
        KetDot(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"ktdt")), p, q])
        }
        KetLus(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"ktls")), p, q])
        }
        KetHep(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"kthp")), spec_noun, p_noun])
        }
        KetPam(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"ktpm")), p])
        }
        KetSig(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"ktsg")), p])
        }
        KetTis(skin, p) => {
            let skin_noun = skin_to_noun(slab, skin);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"ktts")), skin_noun, p_noun])
        }
        KetWut(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"ktwt")), p])
        }
        KetTar(spec) => {
            let spec_noun = spec_to_noun(slab, spec);
            T(slab, &[D(tas!(b"kttr")), spec_noun])
        }
        KetCab(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"ktcb")), p, q])
        }
        KetCol(spec) => {
            let spec_noun = spec_to_noun(slab, spec);
            T(slab, &[D(tas!(b"ktcl")), spec_noun])
        }
        SigBar(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"sgbr")), p, q])
        }
        SigCab(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"sgcb")), p, q])
        }
        SigCen(chum, p, tyre, q) => {
            let chum_noun = chum_to_noun(slab, chum);
            let p_noun = hoon_to_noun(slab, p);
            let tyre_noun = tyre_to_noun(slab, tyre);
            let q_noun = hoon_to_noun(slab, q);
            T(
                slab,
                &[D(tas!(b"sgcn")), chum_noun, p_noun, tyre_noun, q_noun],
            )
        }
        SigFas(chum, p) => {
            let chum_noun = chum_to_noun(slab, chum);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"sgfs")), chum_noun, p_noun])
        }
        SigGal(term_or_pair, p) => {
            let term_noun = term_or_pair_to_noun(slab, term_or_pair);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"sggl")), term_noun, p_noun])
        }
        SigGar(term_or_pair, p) => {
            let term_noun = term_or_pair_to_noun(slab, term_or_pair);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"sggr")), term_noun, p_noun])
        }
        SigBuc(tag, p) => {
            let tag_noun = term_to_noun(slab, tag);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"sgbc")), tag_noun, p_noun])
        }
        SigLus(n, p) => {
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"sgls")), D(*n), p_noun])
        }
        SigPam(n, p, q) => {
            let p_noun = hoon_to_noun(slab, p);
            let q_noun = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"sgpm")), D(*n), p_noun, q_noun])
        }
        SigTis(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"sgts")), p, q])
        }
        SigWut(n, a, b, c) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"sgwt")), D(*n), a, b, c])
        }
        SigZap(p, q) => {
            let p = hoon_to_noun(slab, p);
            let q = hoon_to_noun(slab, q);
            T(slab, &[D(tas!(b"sgzp")), p, q])
        }
        MicTis(marl) => {
            let marl_noun = marl_to_noun(slab, marl);
            T(slab, &[D(tas!(b"mcts")), marl_noun])
        }
        MicCol(p, hoons) => {
            let p = hoon_to_noun(slab, p);
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"mccl")), p, list])
        }
        MicFas(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"mcfs")), p])
        }
        MicGal(spec, a, b, c) => {
            let spec_noun = spec_to_noun(slab, spec);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"mcgl")), spec_noun, a, b, c])
        }
        MicSig(p, hoons) => {
            let p = hoon_to_noun(slab, p);
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"mcsg")), p, list])
        }
        MicMic(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"mcmc")), spec_noun, p_noun])
        }
        TisBar(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"tsbr")), spec_noun, p_noun])
        }
        TisCol(pairs, p) => {
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(w, h)| {
                    let w_noun = wing_to_noun(slab, w);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[w_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"tscl")), list, p_noun])
        }
        TisFas(skin, a, b) => {
            let skin_noun = skin_to_noun(slab, skin);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsfs")), skin_noun, a, b])
        }
        TisMic(skin, a, b) => {
            let skin_noun = skin_to_noun(slab, skin);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsmc")), skin_noun, a, b])
        }
        TisDot(wing, a, b) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsdt")), wing_noun, a, b])
        }
        TisWut(wing, a, b, c) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"tswt")), wing_noun, a, b, c])
        }
        TisGal(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsgl")), a, b])
        }
        TisHep(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tshp")), a, b])
        }
        TisGar(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsgr")), a, b])
        }
        TisKet(skin, wing, a, b) => {
            let skin_noun = skin_to_noun(slab, skin);
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tskt")), skin_noun, wing_noun, a, b])
        }
        TisLus(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tsls")), a, b])
        }
        TisSig(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"tssg")), list])
        }
        TisTar((name, spec_opt), a, b) => {
            let name_noun = term_to_noun(slab, name);
            let spec_unit = match spec_opt.as_ref() {
                None => D(0u64),
                Some(spec) => {
                    let spec_noun = spec_to_noun(slab, spec);
                    T(slab, &[D(0), spec_noun])
                }
            };
            let name_spec = T(slab, &[name_noun, spec_unit]);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tstr")), name_spec, a, b])
        }
        TisCom(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"tscm")), a, b])
        }
        WutBar(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"wtbr")), list])
        }
        WutHep(wing, pairs) => {
            let wing_noun = wing_to_noun(slab, wing);
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(spec, h)| {
                    let spec_noun = spec_to_noun(slab, spec);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[spec_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            T(slab, &[D(tas!(b"wthp")), wing_noun, list])
        }
        WutCol(a, b, c) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"wtcl")), a, b, c])
        }
        WutDot(a, b, c) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            let c = hoon_to_noun(slab, c);
            T(slab, &[D(tas!(b"wtdt")), a, b, c])
        }
        WutKet(wing, a, b) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"wtkt")), wing_noun, a, b])
        }
        WutGal(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"wtgl")), a, b])
        }
        WutGar(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"wtgr")), a, b])
        }
        WutLus(wing, a, pairs) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let pairs_noun: Vec<_> = pairs
                .iter()
                .map(|(spec, h)| {
                    let spec_noun = spec_to_noun(slab, spec);
                    let h_noun = hoon_to_noun(slab, h);
                    T(slab, &[spec_noun, h_noun])
                })
                .collect();
            let list = list_to_noun(slab, pairs_noun);
            T(slab, &[D(tas!(b"wtls")), wing_noun, a, list])
        }
        WutPam(hoons) => {
            let hoons_noun: Vec<_> = hoons.iter().map(|h| hoon_to_noun(slab, h)).collect();
            let list = list_to_noun(slab, hoons_noun);
            T(slab, &[D(tas!(b"wtpm")), list])
        }
        WutPat(wing, a, b) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"wtpt")), wing_noun, a, b])
        }
        WutSig(wing, a, b) => {
            let wing_noun = wing_to_noun(slab, wing);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"wtsg")), wing_noun, a, b])
        }
        WutHax(skin, wing) => {
            let skin_noun = skin_to_noun(slab, skin);
            let wing_noun = wing_to_noun(slab, wing);
            T(slab, &[D(tas!(b"wthx")), skin_noun, wing_noun])
        }
        WutTis(spec, wing) => {
            let spec_noun = spec_to_noun(slab, spec);
            let wing_noun = wing_to_noun(slab, wing);
            T(slab, &[D(tas!(b"wtts")), spec_noun, wing_noun])
        }
        WutZap(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"wtzp")), p])
        }
        ZapCom(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"zpcm")), a, b])
        }
        ZapGar(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"zpgr")), p])
        }
        ZapGal(spec, p) => {
            let spec_noun = spec_to_noun(slab, spec);
            let p_noun = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"zpgl")), spec_noun, p_noun])
        }
        ZapMic(a, b) => {
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"zpmc")), a, b])
        }
        ZapTis(p) => {
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"zpts")), p])
        }
        ZapPat(wings, a, b) => {
            let wing_nouns: Vec<_> = wings.iter().map(|w| wing_to_noun(slab, w)).collect();
            let wings_noun = list_to_noun(slab, wing_nouns);
            let a = hoon_to_noun(slab, a);
            let b = hoon_to_noun(slab, b);
            T(slab, &[D(tas!(b"zppt")), wings_noun, a, b])
        }
        ZapWut(arg, p) => {
            let arg_noun = zpwt_arg_to_noun(slab, arg);
            let p = hoon_to_noun(slab, p);
            T(slab, &[D(tas!(b"zpwt")), arg_noun, p])
        }
    }
}

fn basetype_to_noun(slab: &mut ExpressionArena, bt: &BaseType) -> Noun {
    match bt {
        BaseType::NounExpr => D(tas!(b"noun")),
        BaseType::Cell => D(tas!(b"cell")),
        BaseType::Flag => D(tas!(b"flag")),
        BaseType::Null => D(tas!(b"null")),
        BaseType::Void => D(tas!(b"void")),
        BaseType::Atom(au) => {
            let at = term_to_noun(slab, au);
            T(slab, &[D(tas!(b"atom")), at])
        }
    }
}

fn noun_expr_to_noun(slab: &mut ExpressionArena, expr: &NounExpr) -> Noun {
    match expr {
        NounExpr::ParsedAtom(a) => atom_to_noun(slab, a),
        NounExpr::Cell(l, r) => {
            let l_noun = noun_expr_to_noun(slab, l);
            let r_noun = noun_expr_to_noun(slab, r);
            T(slab, &[l_noun, r_noun])
        }
    }
}

fn path_to_noun(slab: &mut ExpressionArena, path: &Path) -> Noun {
    let knots: Vec<_> = path.iter().map(|k| cord_to_noun(slab, k)).collect();
    list_to_noun(slab, knots)
}

fn spec_to_noun(slab: &mut ExpressionArena, spec: &Spec) -> Noun {
    use Spec::*;
    match spec {
        Base(bt) => {
            let bt_noun = basetype_to_noun(slab, bt);
            T(slab, &[D(tas!(b"base")), bt_noun])
        }
        Dbug(spot, s) => {
            let spot_noun = spot_to_noun(slab, spot);
            let s_noun = spec_to_noun(slab, s);
            T(slab, &[D(tas!(b"dbug")), spot_noun, s_noun])
        }
        Leaf(tag, atom) => {
            let tag_noun = term_to_noun(slab, tag);
            let atom_noun = atom_to_noun(slab, atom);
            T(slab, &[D(tas!(b"leaf")), tag_noun, atom_noun])
        }
        Like(wing, wings) => {
            let wing_noun = wing_to_noun(slab, wing);
            let wings_vec: Vec<_> = wings.iter().map(|w| wing_to_noun(slab, w)).collect();
            let wings_noun = list_to_noun(slab, wings_vec);
            T(slab, &[D(tas!(b"like")), wing_noun, wings_noun])
        }
        Loop(name) => {
            let name_noun = term_to_noun(slab, name);
            T(slab, &[D(tas!(b"loop")), name_noun])
        }
        Made((name, args), s) => {
            let name_noun = term_to_noun(slab, name);
            let args_vec: Vec<_> = args.iter().map(|a| term_to_noun(slab, a)).collect();
            let args_noun = list_to_noun(slab, args_vec);
            let s_noun = spec_to_noun(slab, s);
            let inner = T(slab, &[name_noun, args_noun]);
            T(slab, &[D(tas!(b"made")), inner, s_noun])
        }
        Make(hoon, specs) => {
            let hoon_noun = hoon_to_noun(slab, hoon);
            let specs_vec: Vec<_> = specs.iter().map(|s| spec_to_noun(slab, s)).collect();
            let specs_noun = list_to_noun(slab, specs_vec);
            T(slab, &[D(tas!(b"make")), hoon_noun, specs_noun])
        }
        Name(name, s) => {
            let name_noun = term_to_noun(slab, name);
            let s_noun = spec_to_noun(slab, s);
            T(slab, &[D(tas!(b"name")), name_noun, s_noun])
        }
        Over(wing, s) => {
            let wing_noun = wing_to_noun(slab, wing);
            let s_noun = spec_to_noun(slab, s);
            T(slab, &[D(tas!(b"over")), wing_noun, s_noun])
        }
        BucGar(a, b) => {
            let a_noun = spec_to_noun(slab, a);
            let b_noun = spec_to_noun(slab, b);
            T(slab, &[D(tas!(b"bcgr")), a_noun, b_noun])
        }
        BucBuc(a, map) => {
            let a_noun = spec_to_noun(slab, a);
            let entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (term_to_noun(slab, k), spec_to_noun(slab, v)))
                .collect();
            let map_noun = map_to_noun(slab, entries);
            T(slab, &[D(tas!(b"bcbc")), a_noun, map_noun])
        }
        BucBar(a, h) => {
            let a_noun = spec_to_noun(slab, a);
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"bcbr")), a_noun, h_noun])
        }
        BucCab(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"bccb")), h_noun])
        }
        BucCol(a, specs) => {
            let a_noun = spec_to_noun(slab, a);
            let specs_vec: Vec<_> = specs.iter().map(|s| spec_to_noun(slab, s)).collect();
            let specs_noun = list_to_noun(slab, specs_vec);
            T(slab, &[D(tas!(b"bccl")), a_noun, specs_noun])
        }
        BucCen(a, specs) => {
            let a_noun = spec_to_noun(slab, a);
            let specs_vec: Vec<_> = specs.iter().map(|s| spec_to_noun(slab, s)).collect();
            let specs_noun = list_to_noun(slab, specs_vec);
            T(slab, &[D(tas!(b"bccn")), a_noun, specs_noun])
        }
        BucDot(a, map) => {
            let a_noun = spec_to_noun(slab, a);
            let entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (term_to_noun(slab, k), spec_to_noun(slab, v)))
                .collect();
            let map_noun = map_to_noun(slab, entries);
            T(slab, &[D(tas!(b"bcdt")), a_noun, map_noun])
        }
        BucGal(a, b) => {
            let a_noun = spec_to_noun(slab, a);
            let b_noun = spec_to_noun(slab, b);
            T(slab, &[D(tas!(b"bcgl")), a_noun, b_noun])
        }
        BucHep(a, b) => {
            let a_noun = spec_to_noun(slab, a);
            let b_noun = spec_to_noun(slab, b);
            T(slab, &[D(tas!(b"bchp")), a_noun, b_noun])
        }
        BucKet(a, b) => {
            let a_noun = spec_to_noun(slab, a);
            let b_noun = spec_to_noun(slab, b);
            T(slab, &[D(tas!(b"bckt")), a_noun, b_noun])
        }
        BucLus(tag, s) => {
            let tag_noun = term_to_noun(slab, tag);
            let s_noun = spec_to_noun(slab, s);
            T(slab, &[D(tas!(b"bcls")), tag_noun, s_noun])
        }
        BucFas(a, map) => {
            let a_noun = spec_to_noun(slab, a);
            let entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (term_to_noun(slab, k), spec_to_noun(slab, v)))
                .collect();
            let map_noun = map_to_noun(slab, entries);
            T(slab, &[D(tas!(b"bcfs")), a_noun, map_noun])
        }
        BucMic(h) => {
            let inner = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"bcmc")), inner])
        }
        BucPam(a, h) => {
            let a_noun = spec_to_noun(slab, a);
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"bcpm")), a_noun, h_noun])
        }
        BucSig(h, a) => {
            let h_noun = hoon_to_noun(slab, h);
            let a_noun = spec_to_noun(slab, a);
            T(slab, &[D(tas!(b"bcsg")), h_noun, a_noun])
        }
        BucTic(a, map) => {
            let a_noun = spec_to_noun(slab, a);
            let entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (term_to_noun(slab, k), spec_to_noun(slab, v)))
                .collect();
            let map_noun = map_to_noun(slab, entries);
            T(slab, &[D(tas!(b"bctc")), a_noun, map_noun])
        }
        BucTis(skin, a) => {
            let skin_noun = skin_to_noun(slab, skin);
            let a_noun = spec_to_noun(slab, a);
            T(slab, &[D(tas!(b"bcts")), skin_noun, a_noun])
        }
        BucPat(a, b) => {
            let a_noun = spec_to_noun(slab, a);
            let b_noun = spec_to_noun(slab, b);
            T(slab, &[D(tas!(b"bcpt")), a_noun, b_noun])
        }
        BucWut(a, specs) => {
            let a_noun = spec_to_noun(slab, a);
            let specs_vec: Vec<_> = specs.iter().map(|s| spec_to_noun(slab, s)).collect();
            let specs_noun = list_to_noun(slab, specs_vec);
            T(slab, &[D(tas!(b"bcwt")), a_noun, specs_noun])
        }
        BucZap(a, map) => {
            let a_noun = spec_to_noun(slab, a);
            let entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (term_to_noun(slab, k), spec_to_noun(slab, v)))
                .collect();
            let map_noun = map_to_noun(slab, entries);
            T(slab, &[D(tas!(b"bczp")), a_noun, map_noun])
        }
    }
}

fn skin_to_noun(slab: &mut ExpressionArena, skin: &Skin) -> Noun {
    use Skin::*;
    match skin {
        Term(s) => term_to_noun(slab, s),
        Base(bt) => {
            let inner = basetype_to_noun(slab, bt);
            T(slab, &[D(tas!(b"base")), inner])
        }
        Cell(l, r) => {
            let l = skin_to_noun(slab, l);
            let r = skin_to_noun(slab, r);
            T(slab, &[D(tas!(b"cell")), l, r])
        }
        Dbug(spot, s) => {
            let spot_noun = spot_to_noun(slab, spot);
            let s_noun = skin_to_noun(slab, s);
            T(slab, &[D(tas!(b"dbug")), spot_noun, s_noun])
        }
        Leaf(tag, atom) => {
            let tag_noun = term_to_noun(slab, tag);
            let atom_noun = atom_to_noun(slab, atom);
            T(slab, &[D(tas!(b"leaf")), tag_noun, atom_noun])
        }
        Name(name, s) => {
            let name_noun = term_to_noun(slab, name);
            let s_noun = skin_to_noun(slab, s);
            T(slab, &[D(tas!(b"name")), name_noun, s_noun])
        }
        Over(wing, s) => {
            let wing_noun = wing_to_noun(slab, wing);
            let s_noun = skin_to_noun(slab, s);
            T(slab, &[D(tas!(b"over")), wing_noun, s_noun])
        }
        Spec(spec, s) => {
            let spec_noun = spec_to_noun(slab, spec);
            let s_noun = skin_to_noun(slab, s);
            T(slab, &[D(tas!(b"spec")), spec_noun, s_noun])
        }
        Wash(n) => T(slab, &[D(tas!(b"wash")), D(*n)]),
    }
}

fn wing_to_noun(slab: &mut ExpressionArena, wing: &WingType) -> Noun {
    let limbs: Vec<Noun> = wing.iter().map(|l| limb_to_noun(slab, l)).collect();

    list_to_noun(slab, limbs)
}

fn limb_to_noun(slab: &mut ExpressionArena, limb: &Limb) -> Noun {
    match limb {
        Limb::Term(s) => term_to_noun(slab, s),

        Limb::Axis(n) => {
            let axis = axis_to_noun(slab, n);
            T(slab, &[D(0), axis])
        }

        Limb::Parent(n, opt) => {
            let opt_noun = match opt {
                Some(s) => {
                    let s_noun = term_to_noun(slab, s);
                    T(slab, &[D(0), s_noun])
                }
                None => D(0),
            };

            T(slab, &[D(1), D(*n), opt_noun])
        }
    }
}

fn spot_to_noun(slab: &mut ExpressionArena, spot: &Spot) -> Noun {
    let path_noun = path_to_noun(slab, &spot.p);
    let pint_noun = pint_to_noun(slab, &spot.q);
    T(slab, &[path_noun, pint_noun])
}

fn pint_to_noun(slab: &mut ExpressionArena, pint: &Pint) -> Noun {
    let p = T(slab, &[D(pint.p.0), D(pint.p.1)]);
    let q = T(slab, &[D(pint.q.0), D(pint.q.1)]);
    T(slab, &[p, q])
}

fn note_to_noun(slab: &mut ExpressionArena, note: &Note) -> Noun {
    match note {
        Note::Know(s) => {
            let s_noun = term_to_noun(slab, s);
            T(slab, &[D(tas!(b"know")), s_noun])
        }

        Note::Made(s, opt_wings) => {
            let s_noun = term_to_noun(slab, s);

            let wings_noun = opt_wings.as_ref().map(|wings| {
                let wing_nouns: Vec<Noun> = wings.iter().map(|w| wing_to_noun(slab, w)).collect();

                list_to_noun(slab, wing_nouns)
            });

            let wings_noun = match wings_noun {
                None => D(0),
                Some(p) => T(slab, &[D(0), p]),
            };

            T(slab, &[D(tas!(b"made")), s_noun, wings_noun])
        }
    }
}

fn woof_to_noun(slab: &mut ExpressionArena, woof: &Woof) -> Noun {
    match woof {
        Woof::ParsedAtom(a) => {
            let val = atom_to_noun(slab, a);
            val
        }
        Woof::Hoon(h) => {
            let val = hoon_to_noun(slab, h);
            T(slab, &[D(0), val])
        }
    }
}

fn tome_to_noun(slab: &mut ExpressionArena, tome: &Tome) -> Noun {
    if tome.0.is_some() {
        slab.error = Some("documentation metadata is not part of a Hoon 135 tome".into());
    }
    let pairs = tome
        .1
        .iter()
        .map(|(key, value)| (term_to_noun(slab, key), hoon_to_noun(slab, value)))
        .collect();
    map_to_noun(slab, pairs)
}

fn alas_to_noun(slab: &mut ExpressionArena, alas: &Alas) -> Noun {
    let pairs: Vec<Noun> = alas
        .iter()
        .map(|(k, v)| {
            let k_noun = term_to_noun(slab, k);
            let v_noun = hoon_to_noun(slab, v);
            T(slab, &[k_noun, v_noun])
        })
        .collect();
    list_to_noun(slab, pairs)
}

fn tyre_to_noun(slab: &mut ExpressionArena, tyre: &Tyre) -> Noun {
    let pairs: Vec<Noun> = tyre
        .iter()
        .map(|(k, v)| {
            let k_noun = term_to_noun(slab, k);
            let v_noun = hoon_to_noun(slab, v);
            T(slab, &[k_noun, v_noun])
        })
        .collect();
    list_to_noun(slab, pairs)
}

fn chum_to_noun(slab: &mut ExpressionArena, chum: &Chum) -> Noun {
    match chum {
        Chum::Lef(s) => term_to_noun(slab, s),
        Chum::StdKel(s, a) => {
            let s_noun = term_to_noun(slab, s);
            let a_noun = atom_to_noun(slab, a);
            T(slab, &[s_noun, a_noun])
        }
        Chum::VenProKel(v, p, a) => {
            let v_noun = term_to_noun(slab, v);
            let p_noun = term_to_noun(slab, p);
            let a_noun = atom_to_noun(slab, a);
            T(slab, &[v_noun, p_noun, a_noun])
        }
        Chum::VenProVerKel(v, p, a1, a2) => {
            let v_noun = term_to_noun(slab, v);
            let p_noun = term_to_noun(slab, p);
            let a1_noun = atom_to_noun(slab, a1);
            let a2_noun = atom_to_noun(slab, a2);
            T(slab, &[v_noun, p_noun, a1_noun, a2_noun])
        }
    }
}

fn term_or_tune_to_noun(slab: &mut ExpressionArena, tot: &TermOrTune) -> Noun {
    match tot {
        TermOrTune::Term(s) => term_to_noun(slab, s),
        TermOrTune::Tune(tune) => tune_to_noun(slab, tune),
    }
}

fn tune_to_noun(slab: &mut ExpressionArena, (map, vec): &Tune) -> Noun {
    let map_pairs: Vec<_> = map
        .iter()
        .map(|(k, opt_v)| {
            let k_noun = term_to_noun(slab, k);
            let v_noun = match opt_v {
                None => D(0),
                Some(v) => {
                    let hoon_noun = hoon_to_noun(slab, v);
                    T(slab, &[D(0), hoon_noun])
                }
            };
            (k_noun, v_noun)
        })
        .collect();

    let map_noun = map_to_noun(slab, map_pairs);

    let vec_nouns: Vec<_> = vec.iter().map(|v| hoon_to_noun(slab, v)).collect();

    let vec_noun = list_to_noun(slab, vec_nouns);

    T(slab, &[map_noun, vec_noun])
}

fn term_or_pair_to_noun(slab: &mut ExpressionArena, top: &TermOrPair) -> Noun {
    match top {
        TermOrPair::Term(s) => term_to_noun(slab, s),
        TermOrPair::Pair(s, h) => {
            let s_noun = term_to_noun(slab, s);
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[s_noun, h_noun])
        }
    }
}

fn zpwt_arg_to_noun(slab: &mut ExpressionArena, arg: &ZpwtArg) -> Noun {
    match arg {
        ZpwtArg::ParsedAtom(s) => slab.push(Expression::Atom(s.clone())),
        ZpwtArg::Pair(s1, s2) => {
            let s1_noun = slab.push(Expression::Atom(s1.clone()));
            let s2_noun = slab.push(Expression::Atom(s2.clone()));
            T(slab, &[s1_noun, s2_noun])
        }
    }
}

fn mane_to_noun(slab: &mut ExpressionArena, mane: &Mane) -> Noun {
    match mane {
        Mane::Tag(s) => term_to_noun(slab, s),
        Mane::TagSpace(s1, s2) => {
            let s1_noun = term_to_noun(slab, s1);
            let s2_noun = term_to_noun(slab, s2);
            T(slab, &[s1_noun, s2_noun])
        }
    }
}

fn marx_to_noun(slab: &mut ExpressionArena, marx: &Marx) -> Noun {
    let n = mane_to_noun(slab, &marx.n);
    let a = mart_to_noun(slab, &marx.a);
    T(slab, &[n, a])
}

fn manx_to_noun(slab: &mut ExpressionArena, manx: &Manx) -> Noun {
    let g = marx_to_noun(slab, &manx.g);
    let c = marl_to_noun(slab, &manx.c);
    T(slab, &[g, c])
}

fn mart_to_noun(slab: &mut ExpressionArena, mart: &Mart) -> Noun {
    let cells: Vec<Noun> = mart
        .iter()
        .map(|(mane, beers)| {
            let mane_noun = mane_to_noun(slab, mane);

            let beer_nouns: Vec<Noun> = beers.iter().map(|b| beer_to_noun(slab, b)).collect();

            let beers_noun = list_to_noun(slab, beer_nouns);

            T(slab, &[mane_noun, beers_noun])
        })
        .collect();

    list_to_noun(slab, cells)
}

fn beer_to_noun(slab: &mut ExpressionArena, beer: &Beer) -> Noun {
    match beer {
        Beer::Char(atom) => atom_to_noun(slab, atom),
        Beer::Hoon(h) => {
            let hoon_noun = hoon_to_noun(slab, h);
            T(slab, &[D(0), hoon_noun])
        }
    }
}

fn marl_to_noun(slab: &mut ExpressionArena, marl: &Marl) -> Noun {
    let items: Vec<Noun> = marl.iter().map(|t| tuna_to_noun(slab, t)).collect();

    list_to_noun(slab, items)
}

fn tuna_to_noun(slab: &mut ExpressionArena, tuna: &Tuna) -> Noun {
    match tuna {
        Tuna::Manx(m) => manx_to_noun(slab, m),
        Tuna::TunaTail(tail) => tuna_tail_to_noun(slab, tail),
    }
}

fn tuna_tail_to_noun(slab: &mut ExpressionArena, tail: &TunaTail) -> Noun {
    match tail {
        TunaTail::Tape(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"tape")), h_noun])
        }
        TunaTail::Manx(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"manx")), h_noun])
        }
        TunaTail::Marl(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"marl")), h_noun])
        }
        TunaTail::Call(h) => {
            let h_noun = hoon_to_noun(slab, h);
            T(slab, &[D(tas!(b"call")), h_noun])
        }
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    #[test]
    fn jam_known_nouns_and_atom_boundaries() {
        let mut nouns = Nouns::default();
        let zero = nouns.atom(vec![]);
        let one = nouns.atom(vec![1]);
        assert_eq!(nouns.jam(zero), vec![2]);
        assert_eq!(nouns.jam(one), vec![12]);
        let cell = nouns.cell(zero, zero);
        assert_eq!(nouns.jam(cell), vec![41]);
        let cell = nouns.cell(one, one);
        assert_eq!(nouns.jam(cell), vec![0x31, 0x03]);
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0, 1]), 17);
        assert_eq!(bit_length(&[0xff; 64]), 512);
    }
}

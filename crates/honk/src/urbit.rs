//! Hoon 135 syntax adapted to Honk's compiler AST without narrowing atoms.

use std::collections::HashMap;
use std::hash::Hash;
use std::path::Path;
use std::sync::Arc;

use chumsky::Parser;
use hatch::ast::hoon as target;
use hatcher::ast::hoon as source;

use crate::errors::{CompilerError, CompilerErrorLocation, CompilerErrorMetadata, Result};

pub fn parse_file(
    path: &Path,
    bytes: &[u8],
    wer: Vec<String>,
    dbug: bool,
) -> Result<hatcher::ford::File> {
    hatcher::source::with_bytes(bytes, |text| {
        let lines = Arc::new(hatcher::utils::LineMap::new(text));
        hatcher::native_file_parser(wer, dbug, Arc::clone(&lines))
            .parse(text)
            .into_result()
            .map(|mut file| {
                let original = |span: &mut std::ops::Range<usize>| {
                    *span = hatcher::source::original_offset(text, span.start)
                        ..hatcher::source::original_offset(text, span.end);
                };
                for header in &mut file.headers {
                    original(&mut header.span);
                    if let hatcher::ford::HeaderKind::Directory { mold_span, .. } = &mut header.kind
                    {
                        original(mold_span);
                    }
                }
                file
            })
            .map_err(|errors| {
                let Some(error) = errors.first() else {
                    return CompilerError::Parse("Hoon 135 parser failed".into());
                };
                let span = error.span().into_range();
                let pint = lines.pint(span.clone());
                CompilerError::Parse(format!("Hoon 135 parser failed: {}", error.reason()))
                    .with_metadata(CompilerErrorMetadata::default().with_location(
                        CompilerErrorLocation {
                            file: Some(path.display().to_string()),
                            start_byte: Some(hatcher::source::original_offset(text, span.start)),
                            end_byte: Some(hatcher::source::original_offset(text, span.end)),
                            start_line: Some(pint.p.0),
                            start_col: Some(pint.p.1),
                            end_line: Some(pint.q.0),
                            end_col: Some(pint.q.1),
                        },
                    ))
            })
    })
}

pub fn into_compiler_ast(hoon: source::Hoon) -> target::Hoon {
    hoon.native()
}

trait Native {
    type Output;
    fn native(self) -> Self::Output;
}

impl Native for String {
    type Output = Self;
    fn native(self) -> Self {
        self
    }
}
impl Native for u64 {
    type Output = Self;
    fn native(self) -> Self {
        self
    }
}
impl Native for u128 {
    type Output = Self;
    fn native(self) -> Self {
        self
    }
}
impl Native for num_bigint::BigUint {
    type Output = Self;
    fn native(self) -> Self {
        self
    }
}
impl<T: Native> Native for Box<T> {
    type Output = Box<T::Output>;
    fn native(self) -> Self::Output {
        Box::new((*self).native())
    }
}
impl<T: Native> Native for Vec<T> {
    type Output = Vec<T::Output>;
    fn native(self) -> Self::Output {
        self.into_iter().map(Native::native).collect()
    }
}
impl<T: Native> Native for Option<T> {
    type Output = Option<T::Output>;
    fn native(self) -> Self::Output {
        self.map(Native::native)
    }
}
impl<K: Native, V: Native> Native for HashMap<K, V>
where
    K::Output: Eq + Hash,
{
    type Output = HashMap<K::Output, V::Output>;
    fn native(self) -> Self::Output {
        self.into_iter()
            .map(|(k, v)| (k.native(), v.native()))
            .collect()
    }
}
impl<A: Native, B: Native> Native for (A, B) {
    type Output = (A::Output, B::Output);
    fn native(self) -> Self::Output {
        (self.0.native(), self.1.native())
    }
}
impl Native for source::Axis {
    type Output = target::Axis;
    fn native(self) -> Self::Output {
        self.into_biguint().into()
    }
}

impl Native for source::NounExpr {
    type Output = target::NounExpr;
    fn native(self) -> Self::Output {
        match self {
            source::NounExpr::ParsedAtom(v0) => target::NounExpr::ParsedAtom(v0.native()),
            source::NounExpr::Cell(v0, v1) => target::NounExpr::Cell(v0.native(), v1.native()),
        }
    }
}

impl Native for source::ParsedAtom {
    type Output = target::ParsedAtom;
    fn native(self) -> Self::Output {
        match self {
            source::ParsedAtom::Small(v0) => target::ParsedAtom::Small(v0.native()),
            source::ParsedAtom::Big(v0) => target::ParsedAtom::Big(v0.native()),
        }
    }
}

impl Native for source::TermOrTune {
    type Output = target::TermOrTune;
    fn native(self) -> Self::Output {
        match self {
            source::TermOrTune::Term(v0) => target::TermOrTune::Term(v0.native()),
            source::TermOrTune::Tune(v0) => target::TermOrTune::Tune(v0.native()),
        }
    }
}

impl Native for source::Stencil {
    type Output = target::Stencil;
    fn native(self) -> Self::Output {
        match self {
            source::Stencil::Half { left, rite } => target::Stencil::Half {
                left: left.native(),
                rite: rite.native(),
            },
            source::Stencil::Full { blocks } => target::Stencil::Full {
                blocks: blocks.native(),
            },
            source::Stencil::Lazy { fragment, resolve } => target::Stencil::Lazy {
                fragment: fragment.native(),
                resolve: resolve.native(),
            },
        }
    }
}

impl Native for source::Beer {
    type Output = target::Beer;
    fn native(self) -> Self::Output {
        match self {
            source::Beer::Char(v0) => target::Beer::Atom(v0.native()),
            source::Beer::Hoon(v0) => target::Beer::Hoon(v0.native()),
        }
    }
}

impl Native for source::Woof {
    type Output = target::Woof;
    fn native(self) -> Self::Output {
        match self {
            source::Woof::ParsedAtom(v0) => target::Woof::ParsedAtom(v0.native()),
            source::Woof::Hoon(v0) => target::Woof::Hoon(v0.native()),
        }
    }
}

impl Native for source::Mane {
    type Output = target::Mane;
    fn native(self) -> Self::Output {
        match self {
            source::Mane::Tag(v0) => target::Mane::Tag(v0.native()),
            source::Mane::TagSpace(v0, v1) => target::Mane::TagSpace(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Manx {
    type Output = target::Manx;
    fn native(self) -> Self::Output {
        target::Manx {
            g: self.g.native(),
            c: self.c.native(),
        }
    }
}

impl Native for source::Marx {
    type Output = target::Marx;
    fn native(self) -> Self::Output {
        target::Marx {
            n: self.n.native(),
            a: self.a.native(),
        }
    }
}

impl Native for source::Mare {
    type Output = target::Mare;
    fn native(self) -> Self::Output {
        match self {
            source::Mare::Manx(v0) => target::Mare::Manx(v0.native()),
            source::Mare::Marl(v0) => target::Mare::Marl(v0.native()),
        }
    }
}

impl Native for source::Maru {
    type Output = target::Maru;
    fn native(self) -> Self::Output {
        match self {
            source::Maru::Tuna(v0) => target::Maru::Tuna(v0.native()),
            source::Maru::Marl(v0) => target::Maru::Marl(v0.native()),
        }
    }
}

impl Native for source::Tuna {
    type Output = target::Tuna;
    fn native(self) -> Self::Output {
        match self {
            source::Tuna::Manx(v0) => target::Tuna::Manx(v0.native()),
            source::Tuna::TunaTail(v0) => target::Tuna::TunaTail(v0.native()),
        }
    }
}

impl Native for source::TunaTail {
    type Output = target::TunaTail;
    fn native(self) -> Self::Output {
        match self {
            source::TunaTail::Tape(v0) => target::TunaTail::Tape(v0.native()),
            source::TunaTail::Manx(v0) => target::TunaTail::Manx(v0.native()),
            source::TunaTail::Marl(v0) => target::TunaTail::Marl(v0.native()),
            source::TunaTail::Call(v0) => target::TunaTail::Call(v0.native()),
        }
    }
}

impl Native for source::Chum {
    type Output = target::Chum;
    fn native(self) -> Self::Output {
        match self {
            source::Chum::Lef(v0) => target::Chum::Lef(v0.native()),
            source::Chum::StdKel(v0, v1) => target::Chum::StdKel(v0.native(), v1.native()),
            source::Chum::VenProKel(v0, v1, v2) => {
                target::Chum::VenProKel(v0.native(), v1.native(), v2.native())
            }
            source::Chum::VenProVerKel(v0, v1, v2, v3) => {
                target::Chum::VenProVerKel(v0.native(), v1.native(), v2.native(), v3.native())
            }
        }
    }
}

impl Native for source::Coin {
    type Output = target::Coin;
    fn native(self) -> Self::Output {
        match self {
            source::Coin::Dime(v0, v1) => target::Coin::Dime(v0.native(), v1.native()),
            source::Coin::Blob(v0) => target::Coin::Blob(v0.native()),
            source::Coin::Many(v0) => target::Coin::Many(v0.native()),
        }
    }
}

impl Native for source::Pint {
    type Output = target::Pint;
    fn native(self) -> Self::Output {
        target::Pint {
            p: self.p.native(),
            q: self.q.native(),
        }
    }
}

impl Native for source::Spot {
    type Output = target::Spot;
    fn native(self) -> Self::Output {
        target::Spot {
            p: self.p.native(),
            q: self.q.native(),
        }
    }
}

impl Native for source::Limb {
    type Output = target::Limb;
    fn native(self) -> Self::Output {
        match self {
            source::Limb::Term(v0) => target::Limb::Term(v0.native()),
            source::Limb::Axis(v0) => target::Limb::Axis(v0.native()),
            source::Limb::Parent(v0, v1) => target::Limb::Parent(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Spec {
    type Output = target::Spec;
    fn native(self) -> Self::Output {
        match self {
            source::Spec::Base(v0) => target::Spec::Base(v0.native()),
            source::Spec::Dbug(v0, v1) => target::Spec::Dbug(v0.native(), v1.native()),
            source::Spec::Leaf(v0, v1) => target::Spec::Leaf(v0.native(), v1.native()),
            source::Spec::Like(v0, v1) => target::Spec::Like(v0.native(), v1.native()),
            source::Spec::Loop(v0) => target::Spec::Loop(v0.native()),
            source::Spec::Made(v0, v1) => target::Spec::Made(v0.native(), v1.native()),
            source::Spec::Make(v0, v1) => target::Spec::Make(v0.native(), v1.native()),
            source::Spec::Name(v0, v1) => target::Spec::Name(v0.native(), v1.native()),
            source::Spec::Over(v0, v1) => target::Spec::Over(v0.native(), v1.native()),
            source::Spec::BucGar(v0, v1) => target::Spec::BucGar(v0.native(), v1.native()),
            source::Spec::BucBuc(v0, v1) => target::Spec::BucBuc(v0.native(), v1.native()),
            source::Spec::BucBar(v0, v1) => target::Spec::BucBar(v0.native(), v1.native()),
            source::Spec::BucCab(v0) => target::Spec::BucCab(v0.native()),
            source::Spec::BucCol(v0, v1) => target::Spec::BucCol(v0.native(), v1.native()),
            source::Spec::BucCen(v0, v1) => target::Spec::BucCen(v0.native(), v1.native()),
            source::Spec::BucDot(v0, v1) => target::Spec::BucDot(v0.native(), v1.native()),
            source::Spec::BucGal(v0, v1) => target::Spec::BucGal(v0.native(), v1.native()),
            source::Spec::BucHep(v0, v1) => target::Spec::BucHep(v0.native(), v1.native()),
            source::Spec::BucKet(v0, v1) => target::Spec::BucKet(v0.native(), v1.native()),
            source::Spec::BucLus(v0, v1) => target::Spec::BucLus(v0.native(), v1.native()),
            source::Spec::BucFas(v0, v1) => target::Spec::BucFas(v0.native(), v1.native()),
            source::Spec::BucMic(v0) => target::Spec::BucMic(v0.native()),
            source::Spec::BucPam(v0, v1) => target::Spec::BucPam(v0.native(), v1.native()),
            source::Spec::BucSig(v0, v1) => target::Spec::BucSig(v0.native(), v1.native()),
            source::Spec::BucTic(v0, v1) => target::Spec::BucTic(v0.native(), v1.native()),
            source::Spec::BucTis(v0, v1) => target::Spec::BucTis(v0.native(), v1.native()),
            source::Spec::BucPat(v0, v1) => target::Spec::BucPat(v0.native(), v1.native()),
            source::Spec::BucWut(v0, v1) => target::Spec::BucWut(v0.native(), v1.native()),
            source::Spec::BucZap(v0, v1) => target::Spec::BucZap(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Nock {
    type Output = target::Nock;
    fn native(self) -> Self::Output {
        match self {
            source::Nock::Pair(v0, v1) => target::Nock::Pair(v0.native(), v1.native()),
            source::Nock::Const(v0) => target::Nock::Const(v0.native()),
            source::Nock::Compose(v0, v1) => target::Nock::Compose(v0.native(), v1.native()),
            source::Nock::CellTest(v0) => target::Nock::CellTest(v0.native()),
            source::Nock::Increment(v0) => target::Nock::Increment(v0.native()),
            source::Nock::Equality(v0, v1) => target::Nock::Equality(v0.native(), v1.native()),
            source::Nock::IfThenElse(v0, v1, v2) => {
                target::Nock::IfThenElse(v0.native(), v1.native(), v2.native())
            }
            source::Nock::SerialCompose(v0, v1) => {
                target::Nock::SerialCompose(v0.native(), v1.native())
            }
            source::Nock::PushSubject(v0, v1) => {
                target::Nock::PushSubject(v0.native(), v1.native())
            }
            source::Nock::SelectArm(v0, v1) => target::Nock::SelectArm(v0.native(), v1.native()),
            source::Nock::Edit(v0, v1) => target::Nock::Edit(v0.native(), v1.native()),
            source::Nock::Hint(v0, v1) => target::Nock::Hint(v0.native(), v1.native()),
            source::Nock::GrabData(v0, v1) => target::Nock::GrabData(v0.native(), v1.native()),
            source::Nock::AxisSelect(v0) => target::Nock::AxisSelect(v0.native()),
        }
    }
}

impl Native for source::NockHint {
    type Output = target::NockHint;
    fn native(self) -> Self::Output {
        match self {
            source::NockHint::ParsedAtom(v0) => target::NockHint::ParsedAtom(v0.native()),
            source::NockHint::Pair(v0, v1) => target::NockHint::Pair(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Note {
    type Output = target::Note;
    fn native(self) -> Self::Output {
        match self {
            source::Note::Know(v0) => target::Note::Know(v0.native()),
            source::Note::Made(v0, v1) => target::Note::Made(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Coil {
    type Output = target::Coil;
    fn native(self) -> Self::Output {
        target::Coil {
            p: self.p.native(),
            q: self.q.native(),
            r: self.r.native(),
        }
    }
}

impl Native for source::Garb {
    type Output = target::Garb;
    fn native(self) -> Self::Output {
        target::Garb {
            name: self.name.native(),
            poly: self.poly.native(),
            vair: self.vair.native(),
        }
    }
}

impl Native for source::Poly {
    type Output = target::Poly;
    fn native(self) -> Self::Output {
        match self {
            source::Poly::Wet => target::Poly::Wet,
            source::Poly::Dry => target::Poly::Dry,
        }
    }
}

impl Native for source::Vair {
    type Output = target::Vair;
    fn native(self) -> Self::Output {
        match self {
            source::Vair::Gold => target::Vair::Gold,
            source::Vair::Iron => target::Vair::Iron,
            source::Vair::Lead => target::Vair::Lead,
            source::Vair::Zinc => target::Vair::Zinc,
        }
    }
}

impl Native for source::BaseType {
    type Output = target::BaseType;
    fn native(self) -> Self::Output {
        match self {
            source::BaseType::NounExpr => target::BaseType::NounExpr,
            source::BaseType::Cell => target::BaseType::Cell,
            source::BaseType::Flag => target::BaseType::Flag,
            source::BaseType::Null => target::BaseType::Null,
            source::BaseType::Void => target::BaseType::Void,
            source::BaseType::Atom(v0) => target::BaseType::Atom(v0.native()),
        }
    }
}

impl Native for source::Tiki {
    type Output = target::Tiki;
    fn native(self) -> Self::Output {
        match self {
            source::Tiki::Wing(v0) => target::Tiki::Wing(v0.native()),
            source::Tiki::Hoon(v0) => target::Tiki::Hoon(v0.native()),
        }
    }
}

impl Native for source::Skin {
    type Output = target::Skin;
    fn native(self) -> Self::Output {
        match self {
            source::Skin::Term(v0) => target::Skin::Term(v0.native()),
            source::Skin::Base(v0) => target::Skin::Base(v0.native()),
            source::Skin::Cell(v0, v1) => target::Skin::Cell(v0.native(), v1.native()),
            source::Skin::Dbug(v0, v1) => target::Skin::Dbug(v0.native(), v1.native()),
            source::Skin::Leaf(v0, v1) => target::Skin::Leaf(v0.native(), v1.native()),
            source::Skin::Name(v0, v1) => target::Skin::Name(v0.native(), v1.native()),
            source::Skin::Over(v0, v1) => target::Skin::Over(v0.native(), v1.native()),
            source::Skin::Spec(v0, v1) => target::Skin::Spec(v0.native(), v1.native()),
            source::Skin::Wash(v0) => target::Skin::Wash(v0.native()),
        }
    }
}

impl Native for source::Type {
    type Output = target::Type;
    fn native(self) -> Self::Output {
        match self {
            source::Type::NounExpr => target::Type::NounExpr,
            source::Type::Void => target::Type::Void,
            source::Type::ParsedAtom(v0, v1) => target::Type::ParsedAtom(v0.native(), v1.native()),
            source::Type::Cell(v0, v1) => target::Type::Cell(v0.native(), v1.native()),
            source::Type::Core(v0, v1) => target::Type::Core(v0.native(), v1.native()),
            source::Type::Face(v0, v1) => target::Type::Face(v0.native(), v1.native()),
            source::Type::Fork(v0) => target::Type::Fork(v0.native()),
            source::Type::Hint(v0, v1) => target::Type::Hint(v0.native(), v1.native()),
            source::Type::Hold(v0, v1) => target::Type::Hold(v0.native(), v1.native()),
        }
    }
}

impl Native for source::FaceType {
    type Output = target::FaceType;
    fn native(self) -> Self::Output {
        match self {
            source::FaceType::Term(v0) => target::FaceType::Term(v0.native()),
            source::FaceType::Tune(v0) => target::FaceType::Tune(v0.native()),
        }
    }
}

impl Native for source::ZpwtArg {
    type Output = target::ZpwtArg;
    fn native(self) -> Self::Output {
        match self {
            source::ZpwtArg::ParsedAtom(v0) => target::ZpwtArg::ParsedAtom(v0.native()),
            source::ZpwtArg::Pair(v0, v1) => target::ZpwtArg::Pair(v0.native(), v1.native()),
        }
    }
}

impl Native for source::TermOrPair {
    type Output = target::TermOrPair;
    fn native(self) -> Self::Output {
        match self {
            source::TermOrPair::Term(v0) => target::TermOrPair::Term(v0.native()),
            source::TermOrPair::Pair(v0, v1) => target::TermOrPair::Pair(v0.native(), v1.native()),
        }
    }
}

impl Native for source::Hoon {
    type Output = target::Hoon;
    fn native(self) -> Self::Output {
        match self {
            source::Hoon::Pair(v0, v1) => target::Hoon::Pair(v0.native(), v1.native()),
            source::Hoon::ZapZap => target::Hoon::ZapZap,
            source::Hoon::Axis(v0) => target::Hoon::Axis(v0.native()),
            source::Hoon::Base(v0) => target::Hoon::Base(v0.native()),
            source::Hoon::Bust(v0) => target::Hoon::Bust(v0.native()),
            source::Hoon::Dbug(v0, v1) => target::Hoon::Dbug(v0.native(), v1.native()),
            source::Hoon::Eror(v0) => target::Hoon::Eror(v0.native()),
            source::Hoon::Hand(v0, v1) => target::Hoon::Hand(v0.native(), v1.native()),
            source::Hoon::Note(v0, v1) => target::Hoon::Note(v0.native(), v1.native()),
            source::Hoon::Fits(v0, v1) => target::Hoon::Fits(v0.native(), v1.native()),
            source::Hoon::Knit(v0) => target::Hoon::Knit(v0.native()),
            source::Hoon::Leaf(v0, v1) => target::Hoon::Leaf(v0.native(), v1.native()),
            source::Hoon::Limb(v0) => target::Hoon::Limb(v0.native()),
            source::Hoon::Lost(v0) => target::Hoon::Lost(v0.native()),
            source::Hoon::Rock(v0, v1) => target::Hoon::Rock(v0.native(), v1.native()),
            source::Hoon::Sand(v0, v1) => target::Hoon::Sand(v0.native(), v1.native()),
            source::Hoon::Tell(v0) => target::Hoon::Tell(v0.native()),
            source::Hoon::Tune(v0) => target::Hoon::Tune(v0.native()),
            source::Hoon::Wing(v0) => target::Hoon::Wing(v0.native()),
            source::Hoon::Yell(v0) => target::Hoon::Yell(v0.native()),
            source::Hoon::Xray(v0) => target::Hoon::Xray(v0.native()),
            source::Hoon::BarBuc(v0, v1) => target::Hoon::BarBuc(v0.native(), v1.native()),
            source::Hoon::BarCab(v0, v1, v2) => {
                target::Hoon::BarCab(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::BarCol(v0, v1) => target::Hoon::BarCol(v0.native(), v1.native()),
            source::Hoon::BarCen(v0, v1) => target::Hoon::BarCen(v0.native(), v1.native()),
            source::Hoon::BarDot(v0) => target::Hoon::BarDot(v0.native()),
            source::Hoon::BarKet(v0, v1) => target::Hoon::BarKet(v0.native(), v1.native()),
            source::Hoon::BarHep(v0) => target::Hoon::BarHep(v0.native()),
            source::Hoon::BarSig(v0, v1) => target::Hoon::BarSig(v0.native(), v1.native()),
            source::Hoon::BarTar(v0, v1) => target::Hoon::BarTar(v0.native(), v1.native()),
            source::Hoon::BarTis(v0, v1) => target::Hoon::BarTis(v0.native(), v1.native()),
            source::Hoon::BarPat(v0, v1) => target::Hoon::BarPat(v0.native(), v1.native()),
            source::Hoon::BarWut(v0) => target::Hoon::BarWut(v0.native()),
            source::Hoon::ColCab(v0, v1) => target::Hoon::ColCab(v0.native(), v1.native()),
            source::Hoon::ColKet(v0, v1, v2, v3) => {
                target::Hoon::ColKet(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::ColHep(v0, v1) => target::Hoon::ColHep(v0.native(), v1.native()),
            source::Hoon::ColLus(v0, v1, v2) => {
                target::Hoon::ColLus(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::ColSig(v0) => target::Hoon::ColSig(v0.native()),
            source::Hoon::ColTar(v0) => target::Hoon::ColTar(v0.native()),
            source::Hoon::CenCab(v0, v1) => target::Hoon::CenCab(v0.native(), v1.native()),
            source::Hoon::CenDot(v0, v1) => target::Hoon::CenDot(v0.native(), v1.native()),
            source::Hoon::CenHep(v0, v1) => target::Hoon::CenHep(v0.native(), v1.native()),
            source::Hoon::CenCol(v0, v1) => target::Hoon::CenCol(v0.native(), v1.native()),
            source::Hoon::CenTar(v0, v1, v2) => {
                target::Hoon::CenTar(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::CenKet(v0, v1, v2, v3) => {
                target::Hoon::CenKet(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::CenLus(v0, v1, v2) => {
                target::Hoon::CenLus(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::CenSig(v0, v1, v2) => {
                target::Hoon::CenSig(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::CenTis(v0, v1) => target::Hoon::CenTis(v0.native(), v1.native()),
            source::Hoon::DotKet(v0, v1) => target::Hoon::DotKet(v0.native(), v1.native()),
            source::Hoon::DotLus(v0) => target::Hoon::DotLus(v0.native()),
            source::Hoon::DotTar(v0, v1) => target::Hoon::DotTar(v0.native(), v1.native()),
            source::Hoon::DotTis(v0, v1) => target::Hoon::DotTis(v0.native(), v1.native()),
            source::Hoon::DotWut(v0) => target::Hoon::DotWut(v0.native()),
            source::Hoon::KetBar(v0) => target::Hoon::KetBar(v0.native()),
            source::Hoon::KetCab(v0, v1) => target::Hoon::KetCab(v0.native(), v1.native()),
            source::Hoon::KetDot(v0, v1) => target::Hoon::KetDot(v0.native(), v1.native()),
            source::Hoon::KetLus(v0, v1) => target::Hoon::KetLus(v0.native(), v1.native()),
            source::Hoon::KetHep(v0, v1) => target::Hoon::KetHep(v0.native(), v1.native()),
            source::Hoon::KetPam(v0) => target::Hoon::KetPam(v0.native()),
            source::Hoon::KetSig(v0) => target::Hoon::KetSig(v0.native()),
            source::Hoon::KetTis(v0, v1) => target::Hoon::KetTis(v0.native(), v1.native()),
            source::Hoon::KetWut(v0) => target::Hoon::KetWut(v0.native()),
            source::Hoon::KetTar(v0) => target::Hoon::KetTar(v0.native()),
            source::Hoon::KetCol(v0) => target::Hoon::KetCol(v0.native()),
            source::Hoon::SigBar(v0, v1) => target::Hoon::SigBar(v0.native(), v1.native()),
            source::Hoon::SigCab(v0, v1) => target::Hoon::SigCab(v0.native(), v1.native()),
            source::Hoon::SigCen(v0, v1, v2, v3) => {
                target::Hoon::SigCen(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::SigFas(v0, v1) => target::Hoon::SigFas(v0.native(), v1.native()),
            source::Hoon::SigGal(v0, v1) => target::Hoon::SigGal(v0.native(), v1.native()),
            source::Hoon::SigGar(v0, v1) => target::Hoon::SigGar(v0.native(), v1.native()),
            source::Hoon::SigBuc(v0, v1) => target::Hoon::SigBuc(v0.native(), v1.native()),
            source::Hoon::SigLus(v0, v1) => target::Hoon::SigLus(v0.native(), v1.native()),
            source::Hoon::SigPam(v0, v1, v2) => {
                target::Hoon::SigPam(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::SigTis(v0, v1) => target::Hoon::SigTis(v0.native(), v1.native()),
            source::Hoon::SigWut(v0, v1, v2, v3) => {
                target::Hoon::SigWut(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::SigZap(v0, v1) => target::Hoon::SigZap(v0.native(), v1.native()),
            source::Hoon::MicTis(v0) => target::Hoon::MicTis(v0.native()),
            source::Hoon::MicCol(v0, v1) => target::Hoon::MicCol(v0.native(), v1.native()),
            source::Hoon::MicFas(v0) => target::Hoon::MicFas(v0.native()),
            source::Hoon::MicGal(v0, v1, v2, v3) => {
                target::Hoon::MicGal(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::MicSig(v0, v1) => target::Hoon::MicSig(v0.native(), v1.native()),
            source::Hoon::MicMic(v0, v1) => target::Hoon::MicMic(v0.native(), v1.native()),
            source::Hoon::TisBar(v0, v1) => target::Hoon::TisBar(v0.native(), v1.native()),
            source::Hoon::TisCol(v0, v1) => target::Hoon::TisCol(v0.native(), v1.native()),
            source::Hoon::TisFas(v0, v1, v2) => {
                target::Hoon::TisFas(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::TisMic(v0, v1, v2) => {
                target::Hoon::TisMic(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::TisDot(v0, v1, v2) => {
                target::Hoon::TisDot(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::TisWut(v0, v1, v2, v3) => {
                target::Hoon::TisWut(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::TisGal(v0, v1) => target::Hoon::TisGal(v0.native(), v1.native()),
            source::Hoon::TisHep(v0, v1) => target::Hoon::TisHep(v0.native(), v1.native()),
            source::Hoon::TisGar(v0, v1) => target::Hoon::TisGar(v0.native(), v1.native()),
            source::Hoon::TisKet(v0, v1, v2, v3) => {
                target::Hoon::TisKet(v0.native(), v1.native(), v2.native(), v3.native())
            }
            source::Hoon::TisLus(v0, v1) => target::Hoon::TisLus(v0.native(), v1.native()),
            source::Hoon::TisSig(v0) => target::Hoon::TisSig(v0.native()),
            source::Hoon::TisTar(v0, v1, v2) => {
                target::Hoon::TisTar(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::TisCom(v0, v1) => target::Hoon::TisCom(v0.native(), v1.native()),
            source::Hoon::WutBar(v0) => target::Hoon::WutBar(v0.native()),
            source::Hoon::WutHep(v0, v1) => target::Hoon::WutHep(v0.native(), v1.native()),
            source::Hoon::WutCol(v0, v1, v2) => {
                target::Hoon::WutCol(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutDot(v0, v1, v2) => {
                target::Hoon::WutDot(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutKet(v0, v1, v2) => {
                target::Hoon::WutKet(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutGal(v0, v1) => target::Hoon::WutGal(v0.native(), v1.native()),
            source::Hoon::WutGar(v0, v1) => target::Hoon::WutGar(v0.native(), v1.native()),
            source::Hoon::WutLus(v0, v1, v2) => {
                target::Hoon::WutLus(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutPam(v0) => target::Hoon::WutPam(v0.native()),
            source::Hoon::WutPat(v0, v1, v2) => {
                target::Hoon::WutPat(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutSig(v0, v1, v2) => {
                target::Hoon::WutSig(v0.native(), v1.native(), v2.native())
            }
            source::Hoon::WutHax(v0, v1) => target::Hoon::WutHax(v0.native(), v1.native()),
            source::Hoon::WutTis(v0, v1) => target::Hoon::WutTis(v0.native(), v1.native()),
            source::Hoon::WutZap(v0) => target::Hoon::WutZap(v0.native()),
            source::Hoon::ZapCom(v0, v1) => target::Hoon::ZapCom(v0.native(), v1.native()),
            source::Hoon::ZapGar(v0) => target::Hoon::ZapGar(v0.native()),
            source::Hoon::ZapGal(v0, v1) => target::Hoon::ZapGal(v0.native(), v1.native()),
            source::Hoon::ZapMic(v0, v1) => target::Hoon::ZapMic(v0.native(), v1.native()),
            source::Hoon::ZapTis(v0) => target::Hoon::ZapTis(v0.native()),
            source::Hoon::ZapPat(v0, v1, v2) => {
                // The compiler AST puts the branch for present wings first.
                target::Hoon::ZapPat(v0.native(), v2.native(), v1.native())
            }
            source::Hoon::ZapWut(v0, v1) => target::Hoon::ZapWut(v0.native(), v1.native()),
        }
    }
}

//! Clay file headers, in `++pile-rule` order.
use std::ops::Range;

use chumsky::prelude::*;

use crate::ast::hoon::{Hoon, ParsedAtom, Spec};
use crate::utils::{decimal_to_atom, gap, symbol, vul, Err, ParserExt};

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Import {
    pub face: Option<String>,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub enum HeaderKind {
    Version {
        version: ParsedAtom,
    },
    Structures {
        imports: Vec<Import>,
    },
    Libraries {
        imports: Vec<Import>,
    },
    Source {
        face: String,
        path: Vec<String>,
    },
    Directory {
        face: String,
        mold: Spec,
        mold_span: Range<usize>,
        path: Vec<String>,
    },
    Mark {
        face: String,
        mark: String,
    },
    Conversion {
        face: String,
        from: String,
        to: String,
    },
    File {
        face: String,
        mark: String,
        path: Vec<String>,
    },
}

impl HeaderKind {
    pub fn rune(&self) -> &'static str {
        match self {
            Self::Version { .. } => "/?",
            Self::Structures { .. } => "/-",
            Self::Libraries { .. } => "/+",
            Self::Source { .. } => "/=",
            Self::Directory { .. } => "/~",
            Self::Mark { .. } => "/%",
            Self::Conversion { .. } => "/$",
            Self::File { .. } => "/*",
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Header {
    /// The directive and its arguments, excluding the following gap.
    pub span: Range<usize>,
    pub kind: HeaderKind,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct File {
    pub headers: Vec<Header>,
    pub body: Hoon,
}

fn classic_whitespace<'src>() -> impl Parser<'src, &'src str, (), Err<'src>> {
    choice((vul(), one_of(" \n").ignored()))
        .repeated()
        .ignored()
}

fn version_number<'src>() -> impl Parser<'src, &'src str, ParsedAtom, Err<'src>> {
    let continuation = just('\\').then(gap().or_not()).then(just('/'));
    any()
        .filter(|c: &char| c.is_ascii_digit())
        .separated_by(continuation.or_not())
        .at_least(1)
        .collect::<String>()
        .map(decimal_to_atom)
}

fn import<'src>() -> impl Parser<'src, &'src str, Import, Err<'src>> {
    choice((
        just('*')
            .ignore_then(symbol())
            .map(|path| Import { face: None, path }),
        symbol()
            .then_ignore(just('='))
            .then(symbol())
            .map(|(face, path)| Import {
                face: Some(face),
                path,
            }),
        symbol().map(|path| Import {
            face: Some(path.clone()),
            path,
        }),
    ))
}

/// `++stap` keeps each `++urs:ab` segment as an undecoded `@ta` atom.
fn path<'src>() -> impl Parser<'src, &'src str, Vec<String>, Err<'src>> {
    let segment = any()
        .filter(|c: &char| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '~' | '_')
        })
        .repeated()
        .collect::<String>();
    just('/')
        .ignore_then(
            segment
                .separated_by(just('/'))
                .at_least(1)
                .collect::<Vec<_>>(),
        )
        .try_map(|parts, span| {
            if parts.len() == 1 && parts[0].is_empty() {
                Ok(vec![])
            } else if parts.last().is_some_and(|part| !part.is_empty()) {
                Ok(parts)
            } else {
                Err(Rich::custom(span, "Ford path has a trailing empty segment"))
            }
        })
}

fn directive<'src>(
    rune: &'static str,
    payload: impl Parser<'src, &'src str, HeaderKind, Err<'src>>,
) -> impl Parser<'src, &'src str, Header, Err<'src>> {
    just(rune)
        .ignore_then(gap())
        .ignore_then(payload)
        .map_with(|kind, extra| Header {
            kind,
            span: extra.span().into_range(),
        })
}

fn directive_group<'src>(
    rune: &'static str,
    payload: impl Parser<'src, &'src str, HeaderKind, Err<'src>>,
) -> impl Parser<'src, &'src str, Vec<Header>, Err<'src>> {
    directive(rune, payload)
        .separated_by(gap())
        .collect::<Vec<_>>()
        .then_ignore(gap())
        .or(empty().to(vec![]))
}

pub(crate) fn headers<'src>(
    mold: impl ParserExt<'src, Spec>,
) -> impl Parser<'src, &'src str, Vec<Header>, Err<'src>> {
    let imports = import()
        .separated_by(just(',').then(classic_whitespace()))
        .at_least(1)
        .collect::<Vec<_>>()
        .boxed();
    let version = directive(
        "/?",
        version_number().map(|version| HeaderKind::Version { version }),
    )
    .then_ignore(gap())
    .or_not();
    let structures = directive_group(
        "/-",
        imports
            .clone()
            .map(|imports| HeaderKind::Structures { imports }),
    );
    let libraries = directive_group(
        "/+",
        imports.map(|imports| HeaderKind::Libraries { imports }),
    );
    let sources = directive_group(
        "/=",
        symbol()
            .then_ignore(gap())
            .then(path())
            .map(|(face, path)| HeaderKind::Source { face, path }),
    );
    let directories = directive_group(
        "/~",
        symbol()
            .then_ignore(gap())
            .then(mold.map_with(|mold, extra| (mold, extra.span().into_range())))
            .then_ignore(gap())
            .then(path())
            .map(|((face, (mold, mold_span)), path)| HeaderKind::Directory {
                face,
                mold,
                mold_span,
                path,
            }),
    );
    let mark = just('%').ignore_then(symbol()).boxed();
    let marks = directive_group(
        "/%",
        symbol()
            .then_ignore(gap())
            .then(mark.clone())
            .map(|(face, mark)| HeaderKind::Mark { face, mark }),
    );
    let conversions = directive_group(
        "/$",
        symbol()
            .then_ignore(gap())
            .then(mark.clone())
            .then_ignore(gap())
            .then(mark.clone())
            .map(|((face, from), to)| HeaderKind::Conversion { face, from, to }),
    );
    let files = directive_group(
        "/*",
        symbol()
            .then_ignore(gap())
            .then(mark)
            .then_ignore(gap())
            .then(path())
            .map(|((face, mark), path)| HeaderKind::File { face, mark, path }),
    );
    gap()
        .or_not()
        .ignore_then(version)
        .then(structures)
        .then(libraries)
        .then(sources)
        .then(directories)
        .then(marks)
        .then(conversions)
        .then(files)
        .map(
            |(
                (
                    (((((version, structures), libraries), sources), directories), marks),
                    conversions,
                ),
                files,
            )| {
                version
                    .into_iter()
                    .chain(structures)
                    .chain(libraries)
                    .chain(sources)
                    .chain(directories)
                    .chain(marks)
                    .chain(conversions)
                    .chain(files)
                    .collect()
            },
        )
}

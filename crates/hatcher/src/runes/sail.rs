mod markdown;

use std::sync::Arc;

use chumsky::prelude::*;

use crate::ast::hoon::*;
use crate::utils::*;

fn mixed_case_symbol<'src>() -> impl Parser<'src, &'src str, String, Err<'src>> {
    any()
        .filter(|c: &char| c.is_ascii_alphabetic())
        .then(
            any()
                .filter(|c: &char| c.is_ascii_alphanumeric() || *c == '-')
                .repeated()
                .collect::<String>(),
        )
        .map(|(first, rest)| format!("{first}{rest}"))
}

fn mane_parser<'src>() -> impl Parser<'src, &'src str, Mane, Err<'src>> {
    mixed_case_symbol()
        .then(just('_').ignore_then(mixed_case_symbol()).or_not())
        .map(|(base, suffix)| match suffix {
            Some(ns) => Mane::TagSpace(base, ns),
            None => Mane::Tag(base),
        })
}

fn hoon_to_beers(hoon: Hoon) -> Vec<Beer> {
    match hoon {
        Hoon::Knit(woofs) => woofs
            .into_iter()
            .map(|woof| match woof {
                Woof::ParsedAtom(atom) => Beer::Char(atom),
                Woof::Hoon(hoon) => Beer::Hoon(hoon),
            })
            .collect(),
        other => vec![Beer::Hoon(other)],
    }
}

fn string_to_beers(value: String) -> Vec<Beer> {
    crate::source::source_bytes(&value)
        .into_iter()
        .map(|byte| Beer::Char(ParsedAtom::Small(byte.into())))
        .collect()
}

fn literal_node(chars: Vec<Beer>) -> Tuna {
    Tuna::Manx(Manx {
        g: Marx {
            n: Mane::Tag(String::new()),
            a: vec![(Mane::Tag(String::new()), chars)],
        },
        c: vec![],
    })
}

fn attr_pair<'src>(
    hoon_wide: impl ParserExt<'src, Hoon>,
) -> impl Parser<'src, &'src str, (Mane, Vec<Beer>), Err<'src>> {
    mane_parser()
        .then_ignore(just(' '))
        .then(hoon_wide)
        .map(|(name, value)| (name, hoon_to_beers(value)))
}

fn tag_head<'src>(
    hoon_wide: impl ParserExt<'src, Hoon>,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Marx, Err<'src>> {
    let id = just('#')
        .ignore_then(symbol())
        .map(|id| (Mane::Tag("id".into()), string_to_beers(id)));
    let classes = just('.')
        .ignore_then(symbol())
        .repeated()
        .at_least(1)
        .collect::<Vec<_>>()
        .map(|classes| {
            (
                Mane::Tag("class".into()),
                string_to_beers(classes.join(" ")),
            )
        });
    let link = choice((just('/').to("href"), just('@').to("src")))
        .then(soil(hoon_wide.clone(), linemap))
        .map(|(name, value)| (Mane::Tag(name.into()), hoon_to_beers(Hoon::Knit(value))));
    let attributes = attr_pair(hoon_wide)
        .separated_by(just(", "))
        .collect::<Vec<_>>()
        .delimited_by(just('('), just(')'));
    mane_parser()
        .then(id.or_not())
        .then(classes.or_not())
        .then(link.or_not())
        .then(attributes.or_not())
        .map(|((((name, id), classes), link), attributes)| Marx {
            n: name,
            a: id
                .into_iter()
                .chain(classes)
                .chain(link)
                .chain(attributes.into_iter().flatten())
                .collect(),
        })
}

fn braced_hoon<'src>(
    hoon_wide: impl ParserExt<'src, Hoon>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    hoon_wide
        .separated_by(just(' '))
        .at_least(1)
        .collect::<Vec<_>>()
        .delimited_by(just('{'), just('}'))
        .map(Hoon::ColTar)
}

#[derive(Clone, Copy)]
enum TunaMode {
    Tape,
    Manx,
    Marl,
    Call,
}

impl TunaMode {
    fn wrap(self, hoon: Hoon) -> Tuna {
        Tuna::TunaTail(match self {
            Self::Tape => TunaTail::Tape(hoon),
            Self::Manx => TunaTail::Manx(hoon),
            Self::Marl => TunaTail::Marl(hoon),
            Self::Call => TunaTail::Call(hoon),
        })
    }
}

fn tuna_mode<'src>() -> impl Parser<'src, &'src str, TunaMode, Err<'src>> {
    choice((
        just('-').to(TunaMode::Tape),
        just('+').to(TunaMode::Manx),
        just('*').to(TunaMode::Marl),
        just('%').to(TunaMode::Call),
    ))
}

#[derive(Clone)]
enum QuotePiece {
    Text(Vec<Beer>),
    Embed(Tuna),
}

fn collapse_chars(pieces: Vec<QuotePiece>, tall: bool) -> Marl {
    let mut nodes = Vec::new();
    let mut chars = Vec::new();
    for piece in pieces {
        match piece {
            QuotePiece::Text(mut text) => chars.append(&mut text),
            QuotePiece::Embed(node) => {
                if !chars.is_empty() {
                    nodes.push(literal_node(std::mem::take(&mut chars)));
                }
                nodes.push(node);
            }
        }
    }
    if tall {
        while matches!(chars.last(), Some(Beer::Char(ParsedAtom::Small(32)))) {
            chars.pop();
        }
        chars.push(Beer::Char(ParsedAtom::Small(10)));
    }
    if !chars.is_empty() {
        nodes.push(literal_node(chars));
    }
    nodes
}

fn flatten_top(top: Mare) -> Marl {
    match top {
        Mare::Manx(node) => vec![Tuna::Manx(node)],
        Mare::Marl(nodes) => nodes,
    }
}

fn indented_quote<'src>(
    piece: impl ParserExt<'src, QuotePiece>,
    lines: Arc<LineMap>,
    tall: bool,
) -> impl Parser<'src, &'src str, Marl, Err<'src>> {
    custom(
        move |input: &mut chumsky::input::InputRef<'src, '_, &'src str, Err<'src>>| {
            let start_cursor = input.cursor();
            let start = input.span_since(&start_cursor).start;
            let indent = lines.source_column(start).saturating_sub(1);
            input.parse(just("\"\"\"\n"))?;
            let body_cursor = input.cursor();
            let body_start = input.span_since(&body_cursor).start;
            let source = input.slice_from(&body_cursor..);
            let prefix = " ".repeat(indent as usize);
            let closing = format!("\n{prefix}\"\"\"");
            let Some(end) = source.find(&closing) else {
                return Err(Rich::custom(
                    SimpleSpan::from(start..start),
                    "unterminated Sail quotation",
                ));
            };
            let body_end = body_start + end;
            let mut pieces = vec![];
            lines.with_indented_block(body_start, body_end + 1, indent, || {
                let mut at_line_start = true;
                loop {
                    let cursor = input.cursor();
                    let at = input.span_since(&cursor).start;
                    if at == body_end {
                        break;
                    }
                    if at_line_start {
                        if input.peek() != Some('\n') {
                            for _ in 0..indent {
                                input.parse(just(' '))?;
                            }
                        }
                        at_line_start = false;
                        let cursor = input.cursor();
                        if input.span_since(&cursor).start == body_end {
                            break;
                        }
                    }
                    if input.peek() == Some('\n') {
                        input.next();
                        pieces.push(QuotePiece::Text(string_to_beers("\n".into())));
                        at_line_start = true;
                    } else {
                        pieces.push(input.parse(piece.clone())?);
                    }
                }
                Ok::<_, Rich<'src, char>>(())
            })?;
            for expected in closing.chars() {
                input.parse(just(expected))?;
            }
            Ok(collapse_chars(pieces, tall))
        },
    )
}

fn sail_parser<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    linemap: Arc<LineMap>,
    tall: bool,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    let mut wide_top = Recursive::declare();
    let mut wide_inner = Recursive::declare();
    let mut tall_top = Recursive::declare();
    let head = tag_head(hoon_wide.clone(), linemap.clone()).boxed();
    let bracketed = head
        .clone()
        .then(
            just(' ')
                .ignore_then(wide_inner.clone())
                .repeated()
                .collect::<Vec<Marl>>(),
        )
        .delimited_by(just('{'), just('}'))
        .map(|(g, children)| {
            Tuna::Manx(Manx {
                g,
                c: children.into_iter().flatten().collect(),
            })
        });
    let embed_tuna = choice((
        just(';').ignore_then(bracketed),
        tuna_mode()
            .then(braced_hoon(hoon_wide.clone()))
            .map(|(mode, h)| mode.wrap(h)),
        braced_hoon(hoon_wide.clone()).map(|h| TunaMode::Tape.wrap(h)),
    ))
    .boxed();
    let embed = embed_tuna.clone().map(QuotePiece::Embed).boxed();
    let escape = just('\\')
        .ignore_then(choice((
            one_of("-+*%;{\\\"").map(|ch| ch as u8),
            one_of("0123456789abcdef")
                .then(one_of("0123456789abcdef"))
                .map(|(a, b)| {
                    u8::from_str_radix(&format!("{a}{b}"), 16).expect("two parsed hex digits")
                }),
        )))
        .map(|byte| QuotePiece::Text(vec![Beer::Char(ParsedAtom::Small(byte.into()))]));
    let raw = any()
        .filter(|c: &char| *c >= ' ' && *c != '\u{7f}' && !matches!(*c, '\\' | '{' | '"'))
        .map(|ch| QuotePiece::Text(string_to_beers(ch.to_string())));
    let line_raw = any()
        .filter(|c: &char| *c >= ' ' && *c != '\u{7f}' && !matches!(*c, '\\' | '{'))
        .map(|ch| QuotePiece::Text(string_to_beers(ch.to_string())));
    let line_piece = choice((escape.clone(), embed.clone(), line_raw)).boxed();
    let wide_piece = choice((escape.clone(), embed.clone(), raw)).boxed();
    let line_innards = line_piece.clone().repeated().collect::<Vec<_>>().boxed();
    let quote_innards = wide_piece
        .clone()
        .repeated()
        .collect::<Vec<_>>()
        .map(|pieces| collapse_chars(pieces, false))
        .boxed();
    let quoted = choice((
        indented_quote(wide_piece, linemap.clone(), false),
        just("\"\"\"")
            .not()
            .ignore_then(quote_innards.clone().delimited_by(just('"'), just('"'))),
    ))
    .boxed();
    let tall_quoted = indented_quote(line_piece, linemap.clone(), true).boxed();
    let parens = wide_inner
        .clone()
        .separated_by(just(' '))
        .collect::<Vec<Marl>>()
        .delimited_by(just('('), just(')'))
        .map(|nodes| nodes.into_iter().flatten().collect::<Marl>())
        .boxed();
    let cord_nodes = cord(linemap.clone()).map(|atom| {
        let bytes = match atom {
            ParsedAtom::Small(atom) => {
                let mut bytes = atom.to_le_bytes().to_vec();
                while bytes.last() == Some(&0) {
                    bytes.pop();
                }
                bytes
            }
            ParsedAtom::Big(atom) => atom.to_bytes_le(),
        };
        vec![literal_node(
            bytes
                .into_iter()
                .map(|byte| Beer::Char(ParsedAtom::Small(byte.into())))
                .collect(),
        )]
    });
    let wrapped = choice((
        parens.clone(),
        cord_nodes,
        wide_top.clone().map(flatten_top),
    ))
    .boxed();
    let wide_tail = choice((
        just(':').ignore_then(wrapped.clone()),
        just(';').to(vec![]),
        empty().to(vec![]),
    ));
    wide_top.define(
        choice((
            quoted.clone().map(Mare::Marl),
            parens.map(Mare::Marl),
            head.clone()
                .then(wide_tail)
                .map(|(g, c)| Mare::Manx(Manx { g, c })),
        ))
        .boxed(),
    );
    wide_inner.define(
        choice((
            wide_top.clone().map(flatten_top),
            tuna_mode()
                .then(hoon_wide.clone())
                .map(|(mode, h)| vec![mode.wrap(h)]),
        ))
        .boxed(),
    );
    let markdown = markdown::parser(
        hoon_wide.clone(),
        embed_tuna,
        tall_top.clone(),
        linemap.clone(),
    )
    .boxed();
    let tall_children = gap()
        .ignore_then(
            choice((
                just(';').ignore_then(tall_top.clone()).map(flatten_top),
                markdown.clone(),
            ))
            .then_ignore(gap())
            .repeated()
            .collect::<Vec<_>>(),
        )
        .then_ignore(just("=="))
        .map(|nodes| nodes.into_iter().flatten().collect::<Marl>())
        .boxed();
    let tall_tail = choice((
        just(';').to(vec![]),
        just(':').ignore_then(wrapped),
        just(": ").ignore_then(
            line_innards
                .clone()
                .map(|pieces| collapse_chars(pieces, false)),
        ),
        tall_children.clone(),
    ))
    .boxed();
    let tall_attrs = gap()
        .then_ignore(just('='))
        .ignore_then(mane_parser())
        .then_ignore(gap())
        .then(hoon_wide.clone())
        .map(|(name, value)| (name, hoon_to_beers(value)))
        .repeated()
        .collect::<Vec<_>>();
    let tall_tag = head
        .then(tall_attrs)
        .then(tall_tail.clone())
        .map(|((mut g, mut attrs), c)| {
            g.a.append(&mut attrs);
            Mare::Manx(Manx { g, c })
        });
    let raw_script_line = just(';')
        .ignore_then(choice((
            just(' ').ignore_then(
                any()
                    .filter(|c: &char| *c >= ' ' && *c != '\u{7f}')
                    .repeated()
                    .collect::<String>(),
            ),
            empty().to("\n".into()),
        )))
        .map(|text| literal_node(string_to_beers(text)));
    let raw_script = choice((just("script"), just("style")))
        .then(
            attr_pair(hoon_wide.clone())
                .separated_by(just(", "))
                .collect::<Vec<_>>()
                .delimited_by(just('('), just(')'))
                .or_not(),
        )
        .then(
            gap()
                .ignore_then(
                    raw_script_line
                        .then_ignore(gap())
                        .repeated()
                        .at_least(1)
                        .collect::<Vec<_>>(),
                )
                .then_ignore(just("==")),
        )
        .map(|((name, attrs), c)| {
            Mare::Manx(Manx {
                g: Marx {
                    n: Mane::Tag(name.into()),
                    a: attrs.unwrap_or_default(),
                },
                c,
            })
        });
    tall_top.define(
        choice((
            raw_script,
            tall_tag,
            tall_quoted.map(Mare::Marl),
            just('=').ignore_then(tall_tail).map(Mare::Marl),
            just('>').then_ignore(gap()).ignore_then(markdown).map(|c| {
                Mare::Manx(Manx {
                    g: Marx {
                        n: Mane::Tag("div".into()),
                        a: vec![],
                    },
                    c,
                })
            }),
            tuna_mode()
                .then_ignore(gap())
                .then(hoon)
                .map(|(mode, h)| Mare::Marl(vec![mode.wrap(h)])),
            just(' ')
                .repeated()
                .at_least(1)
                .ignore_then(line_innards.map(|pieces| collapse_chars(pieces, true)))
                .map(Mare::Marl),
            just('\n')
                .ignored()
                .or(end())
                .rewind()
                .to(Mare::Marl(vec![literal_node(string_to_beers("\n".into()))])),
        ))
        .boxed(),
    );
    let top = if tall { tall_top } else { wide_top };
    top.map(|node| match node {
        Mare::Manx(node) => Hoon::Xray(node),
        Mare::Marl(nodes) => Hoon::MicTis(nodes),
    })
}

pub fn sail_tall<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    sail_parser(hoon, hoon_wide, linemap, true)
}

pub fn sail_wide<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    sail_parser(hoon, hoon_wide, linemap, false)
}

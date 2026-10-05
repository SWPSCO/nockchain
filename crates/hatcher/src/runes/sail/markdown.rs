//! Hoon 135 `++cram`: indentation-driven blocks and inline Sail markup.
use std::sync::Arc;

use chumsky::input::{Checkpoint, InputRef};
use chumsky::prelude::*;

use super::{flatten_top, literal_node};
use crate::ast::hoon::*;
use crate::source::{character_bytes, source_bytes};
use crate::utils::*;

type Input<'src, 'parse> = InputRef<'src, 'parse, &'src str, Err<'src>>;
type Saved<'src, 'parse> = Checkpoint<'src, 'parse, &'src str, ()>;
type Rule<'src, T> = Boxed<'src, 'src, &'src str, T, Err<'src>>;

#[derive(Clone)]
struct Rules<'src> {
    wide: Rule<'src, Hoon>,
    embed: Rule<'src, Tuna>,
    sail: Rule<'src, Mare>,
    constant: Rule<'src, ()>,
    lines: Arc<LineMap>,
}

pub(super) fn parser<'src>(
    wide: impl ParserExt<'src, Hoon>,
    embed: impl ParserExt<'src, Tuna>,
    sail: impl ParserExt<'src, Mare>,
    lines: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Marl, Err<'src>> {
    let constant = choice((
        number().ignored(),
        just('.').ignore_then(perd()).ignored(),
        just('~').ignore_then(twid().ignored().or(empty())),
        constant(lines.clone()).ignored(),
    ))
    .boxed();
    let rules = Rules {
        wide: wide.boxed(),
        embed: embed.boxed(),
        sail: sail.boxed(),
        constant,
        lines,
    };
    custom(move |input| parse_blocks(input, &rules))
}

fn offset(input: &mut Input<'_, '_>) -> usize {
    let cursor = input.cursor();
    input.span_since(&cursor).start
}
fn rest<'src>(input: &mut Input<'src, '_>) -> &'src str {
    let cursor = input.cursor();
    input.slice_from(&cursor..)
}
fn advance(input: &mut Input<'_, '_>, bytes: usize) {
    let target = offset(input) + bytes;
    while offset(input) < target {
        input.next();
    }
}
fn error<'src>(input: &mut Input<'src, '_>, message: &str) -> Rich<'src, char> {
    let at = offset(input);
    Rich::custom(SimpleSpan::from(at..at), message.to_owned())
}
fn bytes_node(bytes: Vec<u8>) -> Tuna {
    literal_node(
        bytes
            .into_iter()
            .map(|b| Beer::Char(ParsedAtom::Small(b.into())))
            .collect(),
    )
}
fn element(tag: &str, children: Marl) -> Tuna {
    Tuna::Manx(Manx {
        g: Marx {
            n: Mane::Tag(tag.into()),
            a: vec![],
        },
        c: children,
    })
}
fn attr(name: &str, bytes: Vec<u8>) -> (Mane, Vec<Beer>) {
    (
        Mane::Tag(name.into()),
        bytes
            .into_iter()
            .map(|b| Beer::Char(ParsedAtom::Small(b.into())))
            .collect(),
    )
}
fn skip_spaces(input: &mut Input<'_, '_>) {
    while input.peek() == Some(' ') {
        input.next();
    }
}
fn is_printable(c: char) -> bool {
    c >= ' ' && c != '\u{7f}'
}
fn whitespace(input: &mut Input<'_, '_>, end: usize) -> bool {
    let mut consumed = false;
    while offset(input) < end && matches!(input.peek(), Some(' ' | '\n')) {
        input.next();
        consumed = true;
    }
    consumed
}
fn try_rule<'src, T>(input: &mut Input<'src, '_>, parser: Rule<'src, T>, end: usize) -> Option<T> {
    let saved = input.save();
    match input.parse(parser) {
        Ok(value) if offset(input) <= end => Some(value),
        _ => {
            input.rewind(saved);
            None
        }
    }
}

#[derive(Clone)]
enum Inline {
    Text(Vec<u8>),
    Bold(Vec<Inline>),
    Italic(Vec<Inline>),
    Quote(Vec<Inline>),
    Code(Vec<u8>),
    Link(Vec<Inline>, Vec<u8>),
    Image(Vec<u8>, Vec<u8>),
    Embed(Tuna),
}

fn render_inline(items: Vec<Inline>) -> Marl {
    let mut nodes = vec![];
    let mut text = vec![];
    for item in items {
        if let Inline::Text(mut part) = item {
            text.append(&mut part);
            continue;
        }
        if !text.is_empty() {
            nodes.push(bytes_node(std::mem::take(&mut text)));
        }
        match item {
            Inline::Text(_) => unreachable!(),
            Inline::Bold(children) => nodes.push(element("b", render_inline(children))),
            Inline::Italic(children) => nodes.push(element("i", render_inline(children))),
            Inline::Quote(mut children) => {
                children.insert(0, Inline::Text("“".as_bytes().to_vec()));
                children.push(Inline::Text("”".as_bytes().to_vec()));
                nodes.extend(render_inline(children));
            }
            Inline::Code(bytes) => nodes.push(element("code", vec![bytes_node(bytes)])),
            Inline::Link(children, url) => nodes.push(Tuna::Manx(Manx {
                g: Marx {
                    n: Mane::Tag("a".into()),
                    a: vec![attr("href", url)],
                },
                c: render_inline(children),
            })),
            Inline::Image(alt, url) => {
                let mut attrs = vec![attr("src", url)];
                if !alt.is_empty() {
                    attrs.push(attr("alt", alt));
                }
                nodes.push(Tuna::Manx(Manx {
                    g: Marx {
                        n: Mane::Tag("img".into()),
                        a: attrs,
                    },
                    c: vec![],
                }));
            }
            Inline::Embed(node) => nodes.push(node),
        }
    }
    if !text.is_empty() {
        nodes.push(bytes_node(text));
    }
    nodes
}

// `cash` retains escapes and whitespace; `calf` removes escaped backticks.
fn fence_end(input: &mut Input<'_, '_>, fence: char, end: usize, code: bool) -> Option<usize> {
    let mut at = offset(input);
    let mut chars = rest(input).chars().peekable();
    while let Some(ch) = chars.next() {
        if at >= end {
            return None;
        }
        if ch == fence {
            return Some(at);
        }
        if ch == '\\' && chars.peek() == Some(&fence) {
            chars.next();
            at += ch.len_utf8() + fence.len_utf8();
            continue;
        }
        if !(is_printable(ch) || (!code && ch == '\n')) {
            return None;
        }
        at += ch.len_utf8();
    }
    None
}
fn raw_until(input: &mut Input<'_, '_>, end: usize) -> Vec<u8> {
    let start = offset(input);
    let text = rest(input)[..end - start].to_owned();
    advance(input, end - start);
    // Block reading removes spaces at the ends of physical lines.
    text.split_inclusive('\n')
        .flat_map(|line| {
            if let Some(line) = line.strip_suffix('\n') {
                [source_bytes(line.trim_end_matches(' ')), vec![b'\n']].concat()
            } else {
                source_bytes(line)
            }
        })
        .collect()
}
fn fenced_raw<'src>(
    input: &mut Input<'src, '_>,
    open: char,
    close: char,
    end: usize,
) -> Option<Vec<u8>> {
    if input.peek() != Some(open) {
        return None;
    }
    input.next();
    let at = fence_end(input, close, end, false)?;
    let bytes = raw_until(input, at);
    input.next();
    Some(bytes)
}

fn inline<'src>(
    input: &mut Input<'src, '_>,
    rules: &Rules<'src>,
    end: usize,
) -> Result<Vec<Inline>, Rich<'src, char>> {
    let mut result = vec![];
    while offset(input) < end {
        let saved = input.save();
        let begin = offset(input);
        let ch = input
            .peek()
            .ok_or_else(|| error(input, "unterminated Markdown paragraph"))?;
        if ch.is_ascii_alphabetic() {
            input.next();
            while offset(input) < end
                && input
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                input.next();
            }
            let cursor = input.cursor();
            result.push(Inline::Text(source_bytes(
                input.slice(saved.cursor()..&cursor),
            )));
            continue;
        }
        if ch == '\\' {
            input.next();
            let tail = rest(input);
            let spaces = tail.bytes().take_while(|b| *b == b' ').count();
            if tail.get(spaces..).is_some_and(|s| s.starts_with('\n')) {
                advance(input, spaces + 1);
                result.push(Inline::Embed(element("br", vec![])));
                continue;
            }
            if input.peek().is_some_and(|c| is_printable(c) && c != ' ') {
                let escaped = input.next().expect("escaped character follows backslash");
                result.push(Inline::Text(character_bytes(escaped)));
                continue;
            }
            input.rewind(saved.clone());
        }
        if matches!(ch, '*' | '_' | '"' | '`') {
            input.next();
            if let Some(close) = fence_end(input, ch, end, ch == '`') {
                let item = if ch == '`' {
                    let bytes = raw_until(input, close);
                    let mut unescaped = vec![];
                    let mut pos = 0;
                    while pos < bytes.len() {
                        if bytes[pos] == b'\\' && bytes.get(pos + 1) == Some(&b'`') {
                            pos += 1;
                        }
                        unescaped.push(bytes[pos]);
                        pos += 1;
                    }
                    Some(Inline::Code(unescaped))
                } else {
                    match inline(input, rules, close) {
                        Ok(children) => Some(match ch {
                            '*' => Inline::Bold(children),
                            '_' => Inline::Italic(children),
                            _ => Inline::Quote(children),
                        }),
                        Err(_) => None,
                    }
                };
                if let Some(item) = item {
                    input.next();
                    result.push(item);
                    continue;
                }
            }
            input.rewind(saved.clone());
        }
        if ch == '+' {
            let text = rest(input);
            let bytes = text.as_bytes();
            if matches!(bytes.get(1), Some(b'+' | b'$' | b'*'))
                && bytes.get(2).is_some_and(u8::is_ascii_lowercase)
            {
                let len = 3 + bytes[3..]
                    .iter()
                    .take_while(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b':')
                    })
                    .count();
                if begin + len <= end {
                    result.push(Inline::Code(bytes[..len].to_vec()));
                    advance(input, len);
                    continue;
                }
            }
        }
        if ch == '[' || (ch == '!' && rest(input).starts_with("![")) {
            let image = ch == '!';
            if image {
                input.next();
            }
            input.next();
            if let Some(close) = fence_end(input, ']', end, false) {
                let content = if image {
                    Ok(vec![Inline::Text(raw_until(input, close))])
                } else {
                    inline(input, rules, close)
                };
                if let Ok(content) = content {
                    input.next();
                    whitespace(input, end);
                    if let Some(url) = fenced_raw(input, '(', ')', end) {
                        let item = if image {
                            let alt = match content.into_iter().next() {
                                Some(Inline::Text(bytes)) => bytes,
                                _ => vec![],
                            };
                            Inline::Image(alt, url)
                        } else {
                            Inline::Link(content, url)
                        };
                        result.push(item);
                        continue;
                    }
                }
            }
            input.rewind(saved.clone());
        }
        let column = rules.lines.pint(begin..begin).p.1;
        if matches!(ch, ' ' | '\n') || column == 1 {
            let had_whitespace = whitespace(input, end);
            let code_start = input.cursor();
            let text = rest(input);
            let hashed = text.starts_with('#');
            let constant = matches!(text.as_bytes().first(), Some(b'-' | b'.' | b'~' | b'%'))
                || (text.starts_with('0')
                    && text.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic));
            let parsed = if hashed {
                input.next();
                try_rule(input, rules.wide.clone(), end).map(|_| ())
            } else if constant {
                try_rule(input, rules.constant.clone(), end)
            } else {
                None
            };
            if parsed.is_some() && offset(input) < end && matches!(input.peek(), Some(' ' | '\n')) {
                if had_whitespace {
                    result.push(Inline::Text(vec![b' ']));
                }
                let stop = input.cursor();
                let mut code = source_bytes(input.slice(&code_start..&stop));
                if hashed {
                    code.remove(0);
                }
                result.push(Inline::Code(code));
                continue;
            }
            input.rewind(saved.clone());
        }
        if matches!(ch, ' ' | '\n') {
            whitespace(input, end);
            result.push(Inline::Text(vec![b' ']));
            continue;
        }
        if let Some(node) = try_rule(input, rules.embed.clone(), end) {
            result.push(Inline::Embed(node));
            continue;
        }
        input.rewind(saved);
        if !is_printable(ch) {
            return Err(error(input, "invalid Markdown character"));
        }
        input.next();
        result.push(Inline::Text(character_bytes(ch)));
    }
    Ok(result)
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Down,
    Heading,
    Unordered,
    Ordered,
    Item,
    Verse,
    Quote,
}
struct Context {
    kind: Kind,
    children: Marl,
}
#[derive(Clone, Copy, PartialEq)]
enum Style {
    Blank,
    End,
    Rule,
    Fence,
    Expr,
    Heading,
    Unordered,
    Ordered,
    Quote,
    Text,
    Verse,
}
struct Look {
    column: u64,
    style: Style,
    stop_line: bool,
}
fn look_at(text: &str, offset: usize, outer: u64, rules: &Rules<'_>) -> Look {
    let spaces = text.bytes().take_while(|b| *b == b' ').count();
    let text = &text[spaces..];
    let column = rules.lines.pint(offset + spaces..offset + spaces).p.1;
    let mut style = if text.starts_with('\n') {
        Style::Blank
    } else if text.is_empty() || text.starts_with("==") {
        Style::End
    } else if text.starts_with("---") {
        Style::Rule
    } else if text.starts_with("```") {
        Style::Fence
    } else if text.starts_with(';') {
        Style::Expr
    } else if text.starts_with('#') && text.trim_start_matches('#').starts_with(' ') {
        Style::Heading
    } else if text.starts_with("- ") {
        Style::Unordered
    } else if text.starts_with("+ ") {
        Style::Ordered
    } else if text.starts_with("> ") {
        Style::Quote
    } else {
        Style::Text
    };
    let mut stop_line = text.starts_with("==");
    if style != Style::End && style != Style::Blank && outer > 0 && column < outer {
        style = Style::End;
        stop_line = true;
    }
    Look {
        column,
        style,
        stop_line,
    }
}
fn look(input: &mut Input<'_, '_>, outer: u64, rules: &Rules<'_>) -> Look {
    let at = offset(input);
    look_at(rest(input), at, outer, rules)
}
struct Paragraph<'src, 'parse> {
    start: Saved<'src, 'parse>,
    end: usize,
    lines: Vec<Vec<u8>>,
}
struct Blocks<'src, 'parse> {
    outer: u64,
    inner: u64,
    current: Context,
    stack: Vec<Context>,
    paragraph: Option<Paragraph<'src, 'parse>>,
}
impl Blocks<'_, '_> {
    fn push(&mut self, kind: Kind) {
        self.stack.push(std::mem::replace(
            &mut self.current,
            Context {
                kind,
                children: vec![],
            },
        ));
    }
    fn close(&mut self) {
        if let Some(parent) = self.stack.pop() {
            let current = std::mem::replace(&mut self.current, parent);
            let children = match current.kind {
                Kind::Down | Kind::Heading => current.children,
                kind => vec![element(
                    match kind {
                        Kind::Unordered => "ul",
                        Kind::Ordered => "ol",
                        Kind::Item => "li",
                        Kind::Verse => "div",
                        Kind::Quote => "blockquote",
                        _ => unreachable!(),
                    },
                    current.children,
                )],
            };
            self.current.children.extend(children);
        }
    }
    fn retreat<'src>(
        &mut self,
        input: &mut Input<'src, '_>,
        column: u64,
    ) -> Result<(), Rich<'src, char>> {
        while column < self.inner {
            let amount = match self.current.kind {
                Kind::Down | Kind::Item | Kind::Quote => 2,
                Kind::Verse => 8,
                _ => 0,
            };
            if amount > self.inner - column || self.stack.is_empty() {
                return Err(error(input, "invalid Markdown indentation retreat"));
            }
            self.close();
            self.inner -= amount;
        }
        Ok(())
    }
}
fn heading_id(nodes: &[Tuna]) -> Vec<u8> {
    fn text(nodes: &[Tuna], out: &mut Vec<u8>) {
        for node in nodes {
            if let Tuna::Manx(node) = node {
                if matches!(&node.g.n, Mane::Tag(tag) if tag.is_empty())
                    && node.g.a.len() == 1
                    && node.c.is_empty()
                {
                    for beer in &node.g.a[0].1 {
                        if let Beer::Char(atom) = beer {
                            if let Some(byte) = atom.to_u8() {
                                out.push(byte);
                            }
                        }
                    }
                } else {
                    text(&node.c, out);
                }
            }
        }
    }
    let mut bytes = vec![];
    text(nodes, &mut bytes);
    bytes
        .into_iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase()
            } else {
                b'-'
            }
        })
        .collect()
}
fn close_paragraph<'src, 'parse>(
    input: &mut Input<'src, 'parse>,
    rules: &Rules<'src>,
    state: &mut Blocks<'src, 'parse>,
) -> Result<(), Rich<'src, char>> {
    let Some(paragraph) = state.paragraph.take() else {
        return Ok(());
    };
    if paragraph.lines.is_empty() {
        return Ok(());
    }
    if state.current.kind == Kind::Verse {
        if !state.current.children.is_empty() {
            state.current.children.push(element("br", vec![]));
        }
        for mut line in paragraph.lines {
            line.push(b'\n');
            state
                .current
                .children
                .push(element("p", vec![bytes_node(line)]));
        }
        state.close();
        state.inner -= 8;
        return Ok(());
    }
    let after = input.save();
    input.rewind(paragraph.start.clone());
    let heading = state.current.kind == Kind::Heading;
    let mut hashes = 0;
    if heading {
        skip_spaces(input);
        while input.peek() == Some('#') {
            input.next();
            hashes += 1;
        }
        if !(1..=6).contains(&hashes) || !whitespace(input, paragraph.end) {
            return Err(error(input, "invalid Markdown heading"));
        }
    } else {
        whitespace(input, paragraph.end);
    }
    let paragraph_start = {
        let current = input.save();
        input.rewind(paragraph.start.clone());
        let start = offset(input);
        input.rewind(current);
        start
    };
    let parsed = rules
        .lines
        .with_reparsed_first_line(paragraph_start, || inline(input, rules, paragraph.end));
    input.rewind(after);
    let children = render_inline(parsed?);
    if heading {
        let id = heading_id(&children);
        state.current.children.push(Tuna::Manx(Manx {
            g: Marx {
                n: Mane::Tag(format!("h{hashes}")),
                a: vec![attr("id", id)],
            },
            c: children,
        }));
        state.close();
    } else if !children.is_empty() {
        state.current.children.push(element("p", children));
    }
    Ok(())
}
fn read_line<'src>(
    input: &mut Input<'src, '_>,
    rules: &Rules<'src>,
    inner: u64,
    outer: u64,
) -> Result<(Vec<u8>, usize, bool), Rich<'src, char>> {
    let mut bytes = vec![];
    loop {
        let at = offset(input);
        let ch = input
            .peek()
            .ok_or_else(|| error(input, "unterminated Markdown line"))?;
        if ch == '\n' {
            while bytes.last() == Some(&b' ') {
                bytes.pop();
            }
            let next = look_at(&rest(input)[1..], at + 1, outer, rules);
            if next.stop_line {
                return Ok((bytes, at + 1, true));
            }
            input.next();
            return Ok((bytes, at + 1, false));
        }
        let column = rules.lines.pint(at..at).p.1;
        if column < inner {
            if ch != ' ' {
                return Err(error(input, "expected Markdown indentation"));
            }
        } else {
            bytes.extend(character_bytes(ch));
        }
        input.next();
    }
}
fn read_leaf<'src>(
    input: &mut Input<'src, '_>,
    rules: &Rules<'src>,
    state: &mut Blocks<'src, '_>,
    style: Style,
) -> Result<(), Rich<'src, char>> {
    skip_spaces(input);
    match style {
        Style::Expr => {
            input.parse(just(';'))?;
            let value = input.parse(rules.sail.clone())?;
            input.parse(gap().rewind())?;
            state.current.children.extend(flatten_top(value));
        }
        Style::Rule => {
            input.parse(just('-').repeated().at_least(3).then_ignore(just('\n')))?;
            state.current.children.push(element("hr", vec![]));
        }
        Style::Fence => {
            input.parse(just("```\n"))?;
            let indent = " ".repeat(state.inner.saturating_sub(1) as usize);
            let closing = format!("{indent}```\n");
            let mut bytes = vec![];
            loop {
                let source = rest(input);
                if source.starts_with(&closing) {
                    advance(input, closing.len());
                    break;
                }
                let Some(end) = source.find('\n') else {
                    return Err(error(input, "unterminated Markdown code fence"));
                };
                let line = &source[..end];
                let content = if line.bytes().all(|b| b == b' ') {
                    ""
                } else {
                    line.strip_prefix(&indent)
                        .ok_or_else(|| error(input, "invalid code fence indentation"))?
                };
                if !content.chars().all(is_printable) {
                    return Err(error(input, "invalid code fence character"));
                }
                bytes.extend(source_bytes(content));
                bytes.push(b'\n');
                advance(input, end + 1);
            }
            state
                .current
                .children
                .push(element("pre", vec![bytes_node(bytes)]));
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn parse_blocks<'src, 'parse>(
    input: &mut Input<'src, 'parse>,
    rules: &Rules<'src>,
) -> Result<Marl, Rich<'src, char>> {
    let start = offset(input);
    let mut state = Blocks {
        outer: 0,
        inner: 0,
        current: Context {
            kind: Kind::Down,
            children: vec![],
        },
        stack: vec![],
        paragraph: None,
    };
    loop {
        let mut saw = look(input, state.outer, rules);
        if saw.style == Style::Blank {
            let (_, _, stop) = read_line(input, rules, state.inner, state.outer)?;
            if stop {
                break;
            }
            close_paragraph(input, rules, &mut state)?;
            continue;
        }
        if saw.style == Style::End {
            break;
        }
        if state.outer == 0 {
            state.outer = saw.column;
            state.inner = saw.column;
        }
        if state.paragraph.is_none()
            || (matches!(state.current.kind, Kind::Down | Kind::Item | Kind::Quote)
                && (saw.style != Style::Text || saw.column > state.inner))
        {
            close_paragraph(input, rules, &mut state)?;
            state.retreat(input, saw.column)?;
            match saw.column - state.inner {
                0 => (),
                8 => saw.style = Style::Verse,
                _ => return Err(error(input, "invalid Markdown indentation advance")),
            }
            state.inner = saw.column;
            if (state.current.kind == Kind::Unordered && saw.style != Style::Unordered)
                || (state.current.kind == Kind::Ordered && saw.style != Style::Ordered)
            {
                state.close();
            }
            match saw.style {
                Style::Rule | Style::Fence | Style::Expr => {
                    read_leaf(input, rules, &mut state, saw.style)?;
                    continue;
                }
                Style::Heading => state.push(Kind::Heading),
                Style::Verse => state.push(Kind::Verse),
                Style::Quote | Style::Unordered | Style::Ordered => {
                    let kind = match saw.style {
                        Style::Quote => Kind::Quote,
                        Style::Unordered => Kind::Unordered,
                        _ => Kind::Ordered,
                    };
                    if kind != Kind::Quote && state.current.kind != kind {
                        state.push(kind);
                    }
                    state.inner += 2;
                    while rules.lines.pint(offset(input)..offset(input)).p.1 < state.inner {
                        input.next();
                    }
                    state.push(if kind == Kind::Quote {
                        Kind::Quote
                    } else {
                        Kind::Item
                    });
                }
                Style::Text => (),
                _ => unreachable!(),
            }
            state.paragraph = Some(Paragraph {
                start: input.save(),
                end: offset(input),
                lines: vec![],
            });
            continue;
        }
        let has_lines = state
            .paragraph
            .as_ref()
            .is_some_and(|p| !p.lines.is_empty());
        if has_lines {
            let valid = match state.current.kind {
                Kind::Heading | Kind::Unordered | Kind::Ordered => false,
                Kind::Verse => saw.column >= state.inner,
                _ => saw.column == state.inner,
            };
            if !valid {
                return Err(error(input, "invalid Markdown block structure"));
            }
        }
        let (line, end, stop) = read_line(input, rules, state.inner, state.outer)?;
        let paragraph = state.paragraph.as_mut().expect("paragraph is initialized");
        paragraph.lines.push(line);
        paragraph.end = end;
        if stop {
            break;
        }
    }
    // ++cram resolves its final paragraph after the error check in ++main.
    // A final inline parse failure contributes no nodes.
    let end = input.save();
    let _ = close_paragraph(input, rules, &mut state);
    input.rewind(end);
    while !state.stack.is_empty() {
        state.close();
    }
    if offset(input) == start {
        return Err(error(input, "expected Markdown content"));
    }
    Ok(state.current.children)
}

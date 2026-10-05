#![allow(
    dead_code, redundant_semicolons, unreachable_patterns, unused_assignments, unused_doc_comments,
    unused_imports, unused_mut, unused_parens, unused_variables
)]
#![allow(
    clippy::assign_op_pattern, clippy::borrow_deref_ref, clippy::clone_on_copy,
    clippy::collapsible_else_if, clippy::collapsible_if, clippy::cmp_owned, clippy::empty_docs,
    clippy::get_first, clippy::if_same_then_else, clippy::implied_bounds_in_impls,
    clippy::into_iter_on_ref, clippy::io_other_error, clippy::iter_skip_next,
    clippy::let_and_return, clippy::manual_contains, clippy::manual_div_ceil,
    clippy::manual_is_ascii_check, clippy::manual_is_multiple_of, clippy::manual_map,
    clippy::manual_range_contains, clippy::manual_repeat_n, clippy::manual_saturating_arithmetic,
    clippy::match_like_matches_macro, clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args, clippy::needless_range_loop,
    clippy::needless_return, clippy::nonminimal_bool, clippy::only_used_in_recursion,
    clippy::op_ref, clippy::ptr_arg, clippy::redundant_closure, clippy::redundant_pattern_matching,
    clippy::result_unit_err, clippy::should_implement_trait, clippy::too_many_arguments,
    clippy::type_complexity, clippy::unnecessary_cast, clippy::unnecessary_map_or,
    clippy::unnecessary_to_owned, clippy::unnecessary_unwrap, clippy::useless_conversion,
    clippy::useless_format
)]

use std::sync::Arc;

use chumsky::prelude::*;

use crate::ast::hoon::*;
use crate::runes::*;
use crate::utils::*;

macro_rules! rune_branch_pair {
    ($token:expr, $tall:expr, $wide:expr) => {
        just($token).ignore_then(choice(($tall, $wide))).boxed()
    };
}

macro_rules! rune_branch {
    ($token:expr, $form:expr) => {
        just($token).ignore_then($form).boxed()
    };
}

fn spec_parser<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    spec: impl ParserExt<'src, Spec>,
    spec_wide: impl ParserExt<'src, Spec>,
) -> impl Parser<'src, &'src str, Spec, Err<'src>> + Clone {
    choice((
        rune_branch_pair!(
            "$",
            buc_spec_tall(hoon.clone(), spec.clone()),
            buc_spec_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        rune_branch_pair!(
            "%",
            cen_spec_tall(hoon.clone(), spec.clone()),
            cen_spec_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        spec_wide.clone(),
    ))
    .boxed()
}

fn spec_wide_parser<'src>(
    spec_wide: impl ParserExt<'src, Spec>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Spec, Err<'src>> + Clone {
    let parsers = vec![
        typed_path_spec().boxed(),
        just('%')
            .ignore_then(cen_spec_wide(hoon_wide.clone(), spec_wide.clone()))
            .boxed(),
        just('$')
            .ignore_then(buc_spec_wide(hoon_wide.clone(), spec_wide.clone()))
            .boxed(),
        buccab_spec_irregular(hoon_wide.clone()).boxed(), //  _p
        bucmic_spec_irregular(hoon_wide.clone()).boxed(), //  ,p0
        buctis_irregular(spec_wide.clone()).boxed(),      // foo=bar, =bar,  =foo=bar
        buccol_irregular(spec_wide.clone()).boxed(),      // [foo=bar foo=bar]
        reference_spec(spec_wide.clone()).boxed(),        // foo or foo:bar
        bucwut_irregular_spec(spec_wide.clone()).boxed(), // ?(foo bar)
        parenthesis_spec(hoon_wide.clone(), spec_wide.clone()).boxed(), // (foo bar)
        constant(linemap)
            .try_map(|coin, span| {
                //  %foo
                match coin {
                    Coin::Dime(p, q) => Ok(Spec::Leaf(p, q)),
                    _ => Err(Rich::custom(span, "invalid spec constant")),
                }
            })
            .boxed(),
        aura_spec().boxed(), //  @foo
        loop_spec().boxed(), //  /foo
        just('^').to(Spec::Base(BaseType::Cell)).boxed(),
        just('?').to(Spec::Base(BaseType::Flag)).boxed(),
        just('~').to(Spec::Base(BaseType::Null)).boxed(),
        just('*').to(Spec::Base(BaseType::NounExpr)).boxed(),
        just("!!").to(Spec::Base(BaseType::Void)).boxed(),
    ];

    choice(parsers).boxed()
}

#[derive(serde::Serialize, PartialEq, Debug, Clone)]
enum WideOp {
    KetTis(Hoon),
    TisGal(Hoon),
    Pair(Hoon),
    Modify(Vec<(WingType, Hoon)>),
}

fn hoon_wide_parser<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    spec_wide: impl ParserExt<'src, Spec>,
    hoon_wide_with_trace: impl ParserExt<'src, Hoon>,
    hoon_wide_no_trace: impl ParserExt<'src, Hoon>,
    wer: Path,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> + Clone {
    let regular = choice(vec![
        rune_branch!('|', bar_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!('=', tis_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!('?', wut_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!('%', cen_runes_wide(hoon_wide.clone())),
        rune_branch!(':', col_runes_wide(hoon_wide.clone())),
        rune_branch!('~', sig_runes_wide(hoon_wide.clone())),
        rune_branch!('$', buc_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!('^', ket_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!(
            '!',
            zap_runes_wide(
                hoon_wide.clone(),
                spec_wide.clone(),
                hoon_wide_with_trace,
                hoon_wide_no_trace
            )
        ),
        rune_branch!(';', mic_runes_wide(hoon_wide.clone(), spec_wide.clone())),
        rune_branch!('.', dot_runes_wide(hoon_wide.clone(), spec_wide.clone())),
    ]);
    let scat = choice(vec![
        just('=')
            .ignore_then(choice((
                dottis_irregular(hoon_wide.clone()),
                kettis_irregular(spec_wide.clone()).boxed(),
            )))
            .boxed(),
        just('?')
            .ignore_then(choice((
                bucwut_irregular(spec_wide.clone()).boxed(),
                empty().to(Hoon::Base(BaseType::Flag)).boxed(),
            )))
            .boxed(),
        just('%')
            .ignore_then(choice((
                just('|').to(Hoon::Rock(
                    "f".to_owned(),
                    NounExpr::ParsedAtom(ParsedAtom::Small(1)),
                )),
                just('&').to(Hoon::Rock(
                    "f".to_owned(),
                    NounExpr::ParsedAtom(ParsedAtom::Small(0)),
                )),
                nuck().map(|coin| jock(true, &coin)),
            )))
            .boxed(),
        just(':')
            .ignore_then(choice((
                miccol_irregular(hoon_wide.clone()).boxed(),
                just('/')
                    .ignore_then(hoon_wide.clone())
                    .map(|hoon| Hoon::MicFas(Box::new(hoon)))
                    .boxed(),
            )))
            .boxed(),
        just('~')
            .ignore_then(choice((
                censig_irregular(hoon_wide.clone()),
                twid().map(|coin| jock(false, &coin)),
            )))
            .boxed(),
        leaf_constant(linemap.clone()).boxed(),
        just('.')
            .ignore_then(perd().map(|coin| jock(false, &coin)))
            .boxed(),
        just('`')
            .ignore_then(choice((
                tic_aura(hoon_wide.clone()),
                kethep_noun_irregular(hoon_wide.clone()).boxed(),
                kethep_irregular(hoon_wide.clone(), spec_wide.clone()).boxed(),
                ketlus_irregular(hoon_wide.clone()),
                tic_cell_construction(hoon_wide.clone()).boxed(),
            )))
            .boxed(),
        function_call(hoon_wide.clone()).boxed(),
        ketcol_irregular(spec_wide.clone()).boxed(),
        aura_hoon().boxed(),
        buccab_irregular(hoon_wide.clone()).boxed(),
        constant_separator_hoon(hoon_wide.clone()).boxed(),
        list_syntax(hoon.clone(), hoon_wide.clone()).boxed(),
        kettar_irregular(spec_wide.clone()).boxed(),
        wutzap_irregular(hoon_wide.clone()).boxed(),
        wutbar_irregular(hoon_wide.clone()).boxed(),
        wutpam_irregular(hoon_wide.clone()).boxed(),
        increment(hoon_wide.clone()).boxed(),
        tell(hoon_wide.clone()).boxed(),
        yell_parser(hoon_wide.clone()).boxed(),
        number()
            .map(|(aura, atom)| Hoon::Sand(aura, NounExpr::ParsedAtom(atom)))
            .boxed(),
        prefixed_tape(hoon_wide.clone(), linemap.clone()).boxed(),
        wing().boxed(),
        just('^').to(Hoon::Base(BaseType::Cell)).boxed(),
        constant(linemap.clone())
            .map(|coin| jock(true, &coin))
            .boxed(),
        cord(linemap.clone())
            .map(|atom| Hoon::Sand("t".to_owned(), NounExpr::ParsedAtom(atom)))
            .boxed(),
        path(hoon_wide.clone(), wer, linemap.clone()).boxed(),
        typed_path(hoon_wide.clone(), linemap.clone()).boxed(),
        tape(hoon_wide.clone(), linemap.clone()).boxed(),
        just('~').to(Hoon::Bust(BaseType::Null)).boxed(),
        just('&')
            .to(Hoon::Sand(
                "f".to_owned(),
                NounExpr::ParsedAtom(ParsedAtom::Small(0)),
            ))
            .boxed(),
        just('|')
            .to(Hoon::Sand(
                "f".to_owned(),
                NounExpr::ParsedAtom(ParsedAtom::Small(1)),
            ))
            .boxed(),
        just('*').to(Hoon::Base(BaseType::NounExpr)).boxed(),
    ]);
    // ++long adds exactly one suffix to a ++scat production.
    let long = scat
        .then(
            choice((
                just('=').ignore_then(hoon_wide.clone()).map(WideOp::KetTis),
                just(':').ignore_then(hoon_wide.clone()).map(WideOp::TisGal),
                just('^').ignore_then(hoon_wide.clone()).map(WideOp::Pair),
                list_wing_hoon_wide(hoon_wide.clone())
                    .delimited_by(just('('), just(')'))
                    .map(WideOp::Modify),
            ))
            .or_not(),
        )
        .try_map(|(p, suffix), span| match suffix {
            Some(WideOp::KetTis(q)) => flay(p)
                .map(|skin| Hoon::KetTis(skin, Box::new(q)))
                .ok_or_else(|| Rich::custom(span, "invalid skin in p=q")),
            Some(WideOp::TisGal(_)) if p == Hoon::Base(BaseType::Flag) => Err(Rich::custom(
                span, "flag mold does not accept a colon suffix",
            )),
            Some(WideOp::TisGal(q)) => Ok(Hoon::TisGal(Box::new(p), Box::new(q))),
            Some(WideOp::Pair(q)) => Ok(Hoon::Pair(Box::new(p), Box::new(q))),
            Some(WideOp::Modify(pairs)) => reek(p)
                .map(|wing| Hoon::CenTis(wing, pairs))
                .ok_or_else(|| Rich::custom(span, "updates require a wing")),
            None => Ok(p),
        });
    choice((
        regular.boxed(),
        long.boxed(),
        just(';')
            .ignore_then(sail_wide(hoon, hoon_wide, linemap))
            .boxed(),
    ))
}

pub fn hoon_parser<'src>(
    hoon: impl ParserExt<'src, Hoon>,
    hoon_wide: impl ParserExt<'src, Hoon>,
    spec: impl ParserExt<'src, Spec>,
    spec_wide: impl ParserExt<'src, Spec>,
    hoon_with_trace: impl ParserExt<'src, Hoon>,
    hoon_no_trace: impl ParserExt<'src, Hoon>,
    hoon_wide_with_trace: impl ParserExt<'src, Hoon>,
    hoon_wide_no_trace: impl ParserExt<'src, Hoon>,
    wer: Path,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    let parsers = vec![
        rune_branch_pair!(
            '|',
            bar_runes_tall(hoon.clone(), spec.clone()),
            bar_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        rune_branch_pair!(
            '=',
            tis_runes_tall(hoon.clone(), spec.clone(), spec_wide.clone()),
            tis_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        just('?')
            .ignore_then(choice((
                wut_runes_tall(
                    hoon.clone(),
                    hoon_wide.clone(),
                    spec.clone(),
                    spec_wide.clone(),
                )
                .boxed(),
                wut_runes_wide(hoon_wide.clone(), spec_wide.clone()).boxed(),
            )))
            .boxed(),
        rune_branch_pair!(
            '%',
            cen_runes_tall(hoon.clone()),
            cen_runes_wide(hoon_wide.clone())
        ),
        rune_branch_pair!(
            ':',
            col_runes_tall(hoon.clone()),
            col_runes_wide(hoon_wide.clone())
        ),
        rune_branch_pair!(
            '~',
            sig_runes_tall(hoon.clone()),
            sig_runes_wide(hoon_wide.clone())
        ),
        rune_branch_pair!(
            '$',
            buc_runes_tall(hoon.clone(), spec.clone()),
            buc_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        rune_branch_pair!(
            '^',
            ket_runes_tall(hoon.clone(), spec.clone()),
            ket_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        rune_branch_pair!(
            '!',
            zap_runes_tall(
                hoon.clone(),
                spec.clone(),
                hoon_with_trace.clone(),
                hoon_no_trace.clone()
            ),
            zap_runes_wide(
                hoon_wide.clone(),
                spec_wide.clone(),
                hoon_wide_with_trace.clone(),
                hoon_wide_no_trace.clone()
            )
        ),
        rune_branch_pair!(
            ';',
            choice((
                sail_tall(hoon.clone(), hoon_wide.clone(), linemap.clone()),
                mic_runes_tall(hoon.clone(), spec.clone()),
            )),
            mic_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        rune_branch_pair!(
            '.',
            dot_runes_tall(hoon.clone(), spec.clone()),
            dot_runes_wide(hoon_wide.clone(), spec_wide.clone())
        ),
        hoon_wide.clone().and_is(just(';').not()).boxed(),
        noun_tall(hoon.clone()).boxed(),
    ];

    choice(parsers)
}

pub fn parser<'src>(
    wer: Path,
    bug: bool,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, Hoon, Err<'src>> {
    file_parser(wer, bug, linemap).map(|file| file.body)
}

pub fn file_parser<'src>(
    wer: Path,
    bug: bool,
    linemap: Arc<LineMap>,
) -> impl Parser<'src, &'src str, crate::ford::File, Err<'src>> {
    let mut hoon = Recursive::declare();
    let mut hoon_wide = Recursive::declare();
    let mut spec = Recursive::declare();
    let mut spec_wide = Recursive::declare();

    let mut hoon_no_trace = Recursive::declare();
    let mut hoon_wide_no_trace = Recursive::declare();
    let mut spec_no_trace = Recursive::declare();
    let mut spec_wide_no_trace = Recursive::declare();

    let spec_body = spec_parser(
        hoon.clone(),
        hoon_wide.clone(),
        spec.clone(),
        spec_wide.clone(),
    )
    .map_with(wrap_spec_with_trace(wer.clone(), linemap.clone()))
    .labelled("Spec")
    .boxed();

    spec.define(spec_body);

    let spec_wide_body = spec_wide_parser(spec_wide.clone(), hoon_wide.clone(), linemap.clone())
        .map_with(wrap_spec_with_trace(wer.clone(), linemap.clone()))
        .labelled("Spec Wide")
        .boxed();

    spec_wide.define(spec_wide_body);

    let hoon_wide_body = hoon_wide_parser(
        hoon.clone(),
        hoon_wide.clone(),
        spec_wide.clone(),
        hoon_wide.clone(),
        hoon_wide_no_trace.clone(),
        wer.clone(),
        linemap.clone(),
    )
    .map_with(wrap_hoon_with_trace(wer.clone(), linemap.clone()))
    .labelled("Hoon Wide")
    .boxed();

    hoon_wide.define(hoon_wide_body);

    let hoon_body = hoon_parser(
        hoon.clone(),
        hoon_wide.clone(),
        spec.clone(),
        spec_wide.clone(),
        hoon.clone(),
        hoon_no_trace.clone(),
        hoon_wide.clone(),
        hoon_wide_no_trace.clone(),
        wer.clone(),
        linemap.clone(),
    )
    .map_with(wrap_hoon_with_trace(wer.clone(), linemap.clone()))
    .labelled("Hoon")
    .boxed();

    hoon.define(hoon_body);

    let hoon_no_trace_body = hoon_parser(
        hoon_no_trace.clone(),
        hoon_wide_no_trace.clone(),
        spec_no_trace.clone(),
        spec_wide_no_trace.clone(),
        hoon.clone(),
        hoon_no_trace.clone(),
        hoon_wide.clone(),
        hoon_wide_no_trace.clone(),
        wer.clone(),
        linemap.clone(),
    )
    .labelled("Hoon")
    .boxed();

    hoon_no_trace.define(hoon_no_trace_body);

    let hoon_wide_no_trace_body = hoon_wide_parser(
        hoon_no_trace.clone(),
        hoon_wide_no_trace.clone(),
        spec_wide_no_trace.clone(),
        hoon_wide.clone(),
        hoon_wide_no_trace.clone(),
        wer.clone(),
        linemap.clone(),
    )
    .labelled("Hoon Wide")
    .boxed();

    hoon_wide_no_trace.define(hoon_wide_no_trace_body);

    let spec_body_no_trace = spec_parser(
        hoon_no_trace.clone(),
        hoon_wide_no_trace.clone(),
        spec_no_trace.clone(),
        spec_wide_no_trace.clone(),
    )
    .labelled("Spec")
    .boxed();

    spec_no_trace.define(spec_body_no_trace);

    let spec_wide_no_trace_body = spec_wide_parser(
        spec_wide_no_trace.clone(),
        hoon_wide_no_trace.clone(),
        linemap.clone(),
    )
    .labelled("Spec Wide")
    .boxed();

    spec_wide_no_trace.define(spec_wide_no_trace_body);

    let hoon = if bug { hoon } else { hoon_no_trace };

    let body = hoon
        .separated_by(gap())
        .at_least(1)
        .collect::<Vec<Hoon>>()
        .map(|hoons| Hoon::TisSig(hoons))
        .delimited_by(gap().or_not(), gap().or_not())
        .boxed();
    crate::ford::headers(spec_wide_no_trace)
        .then(body)
        .map(|(headers, body)| crate::ford::File { headers, body })
}

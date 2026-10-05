use std::collections::BTreeSet;
use std::sync::Arc;

use chumsky::Parser;
use hatcher::ast::hoon::Hoon;
use hatcher::utils::LineMap;
use serde::Deserialize;

fn parse(source: &[u8]) -> Hoon {
    hatcher::source::with_bytes(source, |text| {
        hatcher::native_file_parser(vec![], false, Arc::new(LineMap::new(text)))
            .parse(text)
            .into_result()
            .expect("Hoon 135 source")
            .body
    })
}

#[derive(Deserialize)]
struct Case {
    rune: String,
    role: String,
    tall: String,
    wide: Option<String>,
}

#[test]
fn every_kernel_rune_has_a_parsing_case() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let cases: Vec<Case> =
                serde_json::from_str(include_str!("fixtures/runes135.json")).expect("catalog");
            let kernel = include_str!("../../honk/test-assets/urbit135/kernel/hoon.hoon");
            let expression = kernel
                .split_once("    ++  expression\n")
                .expect("expression")
                .1
                .split_once("    ++  boog")
                .expect("boog")
                .0;
            let mut family = '?';
            let mut expected = BTreeSet::new();
            for line in expression.lines() {
                for (name, prefix) in [
                    ("bar", '|'),
                    ("buc", '$'),
                    ("cen", '%'),
                    ("col", ':'),
                    ("dot", '.'),
                    ("ket", '^'),
                    ("sig", '~'),
                    ("mic", ';'),
                    ("tis", '='),
                    ("wut", '?'),
                    ("zap", '!'),
                ] {
                    if line.trim() == format!(";~  pfix  {name}") {
                        family = prefix;
                    }
                }
                if let Some((_, branch)) = line.split_once("['") {
                    expected.insert(format!(
                        "{family}{}",
                        branch.chars().next().expect("suffix")
                    ));
                }
            }
            let actual: BTreeSet<_> = cases
                .iter()
                .filter(|case| case.role == "expression")
                .map(|case| case.rune.clone())
                .collect();
            assert_eq!(expected.len(), 113);
            assert_eq!(expected, actual);
            for case in cases {
                let _ = parse(case.tall.as_bytes());
                if let Some(wide) = case.wide {
                    let _ = parse(wide.as_bytes());
                }
            }
        })
        .expect("worker")
        .join()
        .expect("parser cases");
}

#[test]
fn bytes_atoms_and_axes_are_lossless() {
    let bytes: Vec<_> = (0..=255).collect();
    let mapped = hatcher::source::decode(&bytes);
    assert_eq!(hatcher::source::encode(&mapped).expect("octets"), bytes);
    for (original, (offset, _)) in mapped.char_indices().enumerate() {
        assert_eq!(hatcher::source::original_offset(&mapped, offset), original);
    }
    assert_eq!(parse(b"'\xff'"), parse(b"'\\ff'"));
    assert_ne!(parse(b"'\xff'"), parse("'ÿ'".as_bytes()));
    for source in ["0xffff.ffff.ffff.ffff.ffff", "+18446744073709551617"] {
        let _ = parse(source.as_bytes());
    }
}

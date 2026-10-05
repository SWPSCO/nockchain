//! Byte-for-byte comparisons against the independently reproduced Hoon 135 artifacts.

use std::path::{Path, PathBuf};

use hatch::ast::hoon::Dialect;
use honk::native::NativeCompiler;
use nockapp::noun::slab::NounSlab;
use nockapp::noun::NounAllocatorExt;
use nockvm::noun::{NounAllocator, D, T};

fn assets() -> PathBuf {
    option_env!("URBIT135_ASSETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("test-assets/urbit135"))
}

#[test]
fn clay_directories_marks_and_file_conversions_are_typed() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            use honk::urbit_workspace::{Builder, Output};
            let directory = tempfile::tempdir().expect("desk");
            let root = directory.path().canonicalize().expect("root");
            let fixtures = assets().join("desk");
            for entry in walkdir::WalkDir::new(&fixtures) {
                let entry = entry.expect("fixture");
                let destination = root.join(entry.path().strip_prefix(&fixtures).unwrap());
                if entry.file_type().is_dir() {
                    std::fs::create_dir_all(destination).expect("fixture directory");
                } else {
                    std::fs::copy(entry.path(), destination).expect("fixture file");
                }
            }
            let kernel = assets().join("kernel").canonicalize().expect("kernel");
            let project = honk::project::Project {
                root: root.clone(),
                dialect: Dialect::Urbit,
                prelude: kernel.join("hoon.hoon"),
                system: Some(kernel),
            };
            let cache = honk::build_cache::BuildCache::new(root.join("cache"), false);
            let mut builder = Builder::new(&project, false, true, Some(cache)).expect("system");
            eprintln!("Clay system prelude evaluated");
            let entry = root.join("entry.hoon");
            let output = builder.build(&entry, Output::Value).expect("Clay imports");
            eprintln!("Clay import values evaluated");
            let mut actual: NounSlab = NounSlab::new();
            let result = actual
                .cue_into(bytes::Bytes::from(output))
                .expect("Clay output");
            let (subject, values) =
                honk::native::noun::noun_pair(result, &actual.noun_space()).unwrap();
            actual.set_root(values);
            let mut expected: NounSlab = NounSlab::new();
            let fields: Vec<_> = [30, 0, 42, 43, 44, 42, 61, 71, 42, 141, 4, 5, 0]
                .into_iter()
                .map(D)
                .collect();
            let tuple = T(&mut expected, &fields);
            expected.set_root(tuple);
            assert_eq!(actual.jam(), expected.jam());
            actual.set_root(subject);
            let subject = actual.jam();
            let reference = std::fs::read(assets().join("reference/clay-subject.vase.jam"))
                .expect("Vere Clay subject");
            if subject.as_ref() != reference {
                let artifacts = directory.keep();
                std::fs::write(artifacts.join("native.vase.jam"), subject).unwrap();
                panic!(
                    "Clay subject differs from Vere; native artifact: {}",
                    artifacts.display()
                );
            }
            eprintln!("Clay imported subject matches Vere");
            assert!(builder.cache_stats().unwrap().hits > 0);

            std::fs::write(&entry, "/*  raw  %oct  /bytes/oct\nraw\n").unwrap();
            for bytes in [b"\xff\0".as_slice(), b"".as_slice()] {
                std::fs::write(root.join("bytes.oct"), bytes).unwrap();
                let output = builder.build(&entry, Output::Value).expect("binary file");
                let tuple = T(
                    &mut expected,
                    &[D(bytes.len() as u64), D(if bytes.is_empty() { 0 } else { 255 })],
                );
                expected.set_root(tuple);
                assert_eq!(output, expected.jam().as_ref());
            }

            for (source, error) in [
                ("/%  edit  %cycle-a\n0\n", "cyclic Urbit import"),
                (
                    "/$  convert  %missing  %nongate\n0\n", "grab must produce a gate",
                ),
                ("/$  convert  %unknown  %absent\n0\n", "no-cast-between"),
                ("/*  raw  %oct  /missing/oct\n0\n", "no desk file"),
            ] {
                std::fs::write(&entry, source).unwrap();
                let actual = builder
                    .build(&entry, Output::Value)
                    .expect_err("invalid import")
                    .to_string();
                assert!(actual.contains(error), "{source}: {actual}");
            }
            std::fs::write(root.join("numbers/b/hoon"), "[1 2]\n").unwrap();
            std::fs::write(&entry, "/~  numbers  @ud  /numbers\n0\n").unwrap();
            let error = builder
                .build(&entry, Output::Value)
                .expect_err("directory type mismatch")
                .to_string();
            assert!(error.contains("nest-fail"), "{error}");
            std::fs::write(root.join("numbers/b/hoon"), "20\n").unwrap();
            std::fs::write(
                &entry, "/~  numbers  @ud  /numbers\n(~(got by numbers) %b)\n",
            )
            .unwrap();
            expected.set_root(D(20));
            assert_eq!(
                builder
                    .build(&entry, Output::Value)
                    .expect("recovered directory"),
                expected.jam().as_ref()
            );
            std::fs::write(root.join("numbers/!$.hoon"), "33\n").unwrap();
            std::fs::write(
                &entry, "/~  numbers  @ud  /numbers\n(~(got by numbers) ;;(@ta 36))\n",
            )
            .unwrap();
            expected.set_root(D(33));
            assert_eq!(
                builder
                    .build(&entry, Output::Value)
                    .expect("literal directory key"),
                expected.jam().as_ref()
            );
            std::fs::write(root.join("numbers/!a.hoon"), "11\n").unwrap();
            let error = builder
                .build(&entry, Output::Value)
                .expect_err("ambiguous member")
                .to_string();
            assert!(error.contains("ambiguous"), "{error}");
        })
        .expect("Clay worker")
        .join()
        .expect("Clay imports");
}

#[test]
fn mint_cache_tracks_subjects_settings_and_repairs_corrupt_packs() {
    use honk::build_cache::BuildCache;
    use honk::urbit_workspace::{Builder, Output};

    let directory = tempfile::tempdir().expect("desk");
    let root = directory.path().canonicalize().expect("root");
    std::fs::create_dir(root.join("lib")).expect("libraries");
    let prelude = root.join("prelude.hoon");
    let prelude_source =
        |seed| format!(":+  0  0\n|%\n++  hoon-version  135\n++  seed  {seed}\n--\n");
    std::fs::write(&prelude, prelude_source(1)).expect("prelude");
    let helper = root.join("lib/helper.hoon");
    std::fs::write(&helper, "|%\n++  answer  42\n--\n").expect("helper");
    let entry = root.join("entry.hoon");
    std::fs::write(&entry, "/+  helper\nanswer:helper\n").expect("entry");
    let project = honk::project::Project {
        root: root.clone(),
        dialect: Dialect::Urbit,
        prelude,
        system: None,
    };
    let cache_dir = root.join("cache");
    let cache = |fresh| Some(BuildCache::new(cache_dir.clone(), fresh));
    let compile = |cache, dbug, vet| {
        let mut builder = Builder::new(&project, dbug, vet, cache).expect("builder");
        let result = builder.build(&entry, Output::Value);
        (result, builder.cache_stats())
    };
    let atom_jam = |value| {
        let mut slab: NounSlab = NounSlab::new();
        slab.set_root(D(value));
        slab.jam().to_vec()
    };

    let expected = compile(None, false, true).0.expect("uncached");
    assert_eq!(expected, atom_jam(42));
    let (cold, cold_stats) = compile(cache(false), false, true);
    assert_eq!(cold.expect("cold"), expected);
    let cold_stats = cold_stats.expect("cold stats");
    assert!(cold_stats.writes > 0);
    let (warm, warm_stats) = compile(cache(false), false, true);
    assert_eq!(warm.expect("warm"), expected);
    let warm_stats = warm_stats.expect("warm stats");
    assert_eq!(warm_stats.hits, cold_stats.writes);
    assert_eq!(warm_stats.misses, 0);
    let (fresh, fresh_stats) = compile(cache(true), false, true);
    assert_eq!(fresh.expect("fresh"), expected);
    assert_eq!(fresh_stats.expect("fresh stats").hits, 0);

    std::fs::write(&helper, "|%\n++  answer  43\n--\n").expect("changed dependency");
    let (changed, changed_stats) = compile(cache(false), false, true);
    assert_eq!(changed.expect("changed dependency"), atom_jam(43));
    assert!(changed_stats.expect("changed stats").misses >= 2);
    let debug_expected = compile(None, true, true).0.expect("uncached debug");
    assert_eq!(
        compile(cache(false), true, true).0.expect("cached debug"),
        debug_expected
    );

    std::fs::write(&entry, "^-  @ud\n[1 2]\n").expect("invalid cast");
    assert!(compile(cache(false), false, false).0.is_ok());
    assert!(compile(cache(false), false, true)
        .0
        .expect_err("checked compilation rejects an unchecked product")
        .to_string()
        .contains("mint-nice"));

    std::fs::write(&entry, "seed\n").expect("prelude-dependent entry");
    assert_eq!(
        compile(cache(false), false, true).0.expect("seed one"),
        atom_jam(1)
    );
    std::fs::write(&project.prelude, prelude_source(2)).expect("changed prelude");
    assert_eq!(
        compile(cache(false), false, true).0.expect("seed two"),
        atom_jam(2)
    );

    for shard in std::fs::read_dir(cache_dir.join("v1/packs")).expect("cache shards") {
        for pack in std::fs::read_dir(shard.expect("shard").path()).expect("cache packs") {
            std::fs::write(pack.expect("pack").path(), b"invalid").expect("damage pack");
        }
    }
    let (repaired, repaired_stats) = compile(cache(false), false, true);
    assert_eq!(repaired.expect("repaired"), atom_jam(2));
    assert!(repaired_stats.expect("repair stats").corrupt > 0);
    let (warm, warm_stats) = compile(cache(false), false, true);
    assert_eq!(warm.expect("warm repaired"), atom_jam(2));
    assert_eq!(warm_stats.expect("warm repair stats").misses, 0);

    std::fs::write(&project.prelude, prelude_source(2).replace("135", "134"))
        .expect("incompatible prelude");
    assert!(Builder::new(&project, false, true, None)
        .err()
        .expect("prelude version is checked")
        .to_string()
        .contains("must report hoon-version 135"));
}

#[test]
fn hoon_hoon_build_matches_vere_byte_for_byte() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let root = assets();
            // Compile the complete source under %noun, then compare the JAM
            // of both its inferred type and Nock formula to the Vere artifact.
            // Keep this independent of the manifest's list of smaller cases.
            check_parser_and_mint_case(&root, "kernel", &root.join("kernel/hoon.hoon"));
        })
        .expect("kernel parity worker")
        .join()
        .expect("hoon.hoon byte-for-byte parity");
}

#[test]
fn parser_and_mint_match_urbit() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(check_parser_and_mint)
        .expect("parity worker")
        .join()
        .expect("Hoon 135 parity");
}

fn check_parser_and_mint() {
    let root = assets();
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("reference/manifest.json")).expect("reference manifest"),
    )
    .expect("manifest JSON");
    let cases = manifest["cases"].as_object().expect("reference cases");
    for name in cases.keys().filter(|name| name.as_str() != "kernel") {
        check_parser_and_mint_case(
            &root,
            name,
            &root.join("cases").join(format!("{name}.hoon")),
        );
    }
}

fn check_parser_and_mint_case(root: &Path, name: &str, source: &Path) {
    let file = honk::urbit::parse_file(
        source,
        &std::fs::read(source).expect("source"),
        vec![],
        false,
    )
    .expect("Hoon 135 parse");
    assert!(file.headers.is_empty());
    let ast = honk::urbit::into_compiler_ast(file.body);
    let mut slab = NounSlab::new();
    let noun = hatch::utils::hoon_to_noun_for_dialect(Dialect::Urbit, &mut slab, &ast);
    slab.set_root(noun);
    assert!(
        slab.jam().as_ref()
            == std::fs::read(root.join(format!("reference/{name}.ast.jam")))
                .expect("AST reference"),
        "AST bytes differ from Vere: {name}"
    );
    let mut compiled = NativeCompiler::with_dialect(Dialect::Urbit)
        .compile_expr(&ast)
        .unwrap_or_else(|error| panic!("mint {name}: {error}"));
    let pair = T(&mut compiled.slab, &[compiled.ty.noun(), compiled.formula]);
    compiled.slab.set_root(pair);
    assert!(
        compiled.slab.jam().as_ref()
            == std::fs::read(root.join(format!("reference/{name}.mint.jam")))
                .expect("mint reference"),
        "compiled [type formula] bytes differ from Vere: {name}"
    );
}

#[test]
fn every_rune_form_matches_the_kernel_parser_with_original_spots() {
    let catalog: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../hatcher/tests/fixtures/runes135.json"))
            .expect("runes");
    let mut slab = NounSlab::new();
    let mut nouns = vec![];
    for case in catalog {
        for form in ["tall", "wide"] {
            let Some(source) = case[form].as_str() else {
                continue;
            };
            let file =
                honk::urbit::parse_file(Path::new("rune.hoon"), source.as_bytes(), vec![], false)
                    .expect("rune parse");
            let ast = honk::urbit::into_compiler_ast(file.body);
            nouns.push(hatch::utils::hoon_to_noun_for_dialect(
                Dialect::Urbit,
                &mut slab,
                &ast,
            ));
        }
    }
    let list = nouns
        .into_iter()
        .rev()
        .fold(D(0), |tail, head| T(&mut slab, &[head, tail]));
    slab.set_root(list);
    assert_eq!(
        slab.jam().as_ref(),
        std::fs::read(assets().join("reference/runes.ast.jam")).expect("rune reference")
    );
}

#[test]
fn rejects_the_reference_type_errors() {
    let root = assets();
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("reference/manifest.json")).expect("manifest"),
    )
    .expect("JSON");
    for name in manifest["rejections"]
        .as_object()
        .expect("rejection cases")
        .keys()
    {
        let path = root.join(format!("reject/{name}.hoon"));
        let file =
            honk::urbit::parse_file(&path, &std::fs::read(&path).expect("source"), vec![], false)
                .expect("valid syntax");
        let ast = honk::urbit::into_compiler_ast(file.body);
        assert!(
            NativeCompiler::with_dialect(Dialect::Urbit)
                .compile_expr(&ast)
                .is_err(),
            "accepted {name}"
        );
    }
}

#[test]
fn system_layers_and_evaluated_prelude_match_urbit() {
    let root = assets().canonicalize().expect("assets");
    let directory = tempfile::tempdir().expect("desk");
    let entry = directory.path().join("entry.hoon");
    std::fs::write(&entry, ".\n").expect("entry");
    let config = format!(
        "[[project]]\nroot = \".\"\ndialect = \"urbit\"\nprelude = {:?}\nsystem = {:?}\n",
        root.join("kernel/hoon.hoon"),
        root.join("kernel")
    );
    std::fs::write(directory.path().join("honk.toml"), config).expect("configuration");
    let binary = std::env::var_os("HONK_BINARY")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_honk").map(PathBuf::from))
        .expect("honk binary");
    let artifacts = directory.path().join("artifacts");
    let output = directory.path().join("build/value.jam");
    let result = std::process::Command::new(binary)
        .env("HONK_DUMP_URBIT_ARTIFACTS", &artifacts)
        .env("HONK_WORKER_STACK_BYTES", "67108864")
        .args(["--no-dbug", "--output"])
        .arg(&output)
        .arg(&entry)
        .output()
        .expect("honk");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for name in ["arvo", "lull", "zuse"] {
        assert_eq!(
            std::fs::read(artifacts.join(format!("{name}.mint.jam"))).expect("native layer"),
            std::fs::read(root.join(format!("reference/system-{name}.mint.jam")))
                .expect("reference layer"),
            "{name}"
        );
    }
    assert_eq!(
        std::fs::read(output).expect("native value"),
        std::fs::read(root.join("reference/system-zuse.value.jam")).expect("reference value")
    );
}

#[test]
fn desk_imports_use_typed_modules_and_reject_invalid_dependencies() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let directory = tempfile::tempdir().expect("desk");
            let root = directory.path().canonicalize().expect("root");
            std::fs::create_dir_all(root.join("lib/nested")).expect("libraries");
            std::fs::create_dir(root.join("sur")).expect("structures");
            std::fs::create_dir(root.join("mar")).expect("marks");
            for (path, source) in [
                ("lib/helper.hoon", "|%\n++  answer  42\n--\n"),
                ("lib/nested/tool.hoon", "|%\n++  answer  44\n--\n"),
                ("sur/item.hoon", "|%\n+$  seed  @ud\n--\n"),
                ("lib/cycle-a.hoon", "/+  cycle-b\n0\n"),
                ("lib/cycle-b.hoon", "/+  cycle-a\n0\n"),
                (
                    "mar/number.hoon",
                    "|_  value=@ud\n++  grow  |%  ++  text  (add value 1)  --\n--\n",
                ),
                (
                    "mar/text.hoon",
                    "|_  value=@ud\n++  grab  |%  ++  number  |=(a=@ud (add a 10))  --\n--\n",
                ),
                ("mar/broken.hoon", "|%\n++  grow  !!\n--\n"),
                (
                    "mar/receiver.hoon",
                    "|%\n++  grab  |%  ++  broken  |=(a=@ud (add a 10))  --\n--\n",
                ),
                (
                    "mar/atom.hoon", "|%\n++  grab  |%  ++  missing  7  --\n--\n",
                ),
            ] {
                std::fs::write(root.join(path), source).expect("module");
            }
            let project = honk::project::Project {
                root: root.clone(),
                dialect: Dialect::Urbit,
                prelude: assets()
                    .join("kernel/hoon.hoon")
                    .canonicalize()
                    .expect("kernel"),
                system: None,
            };
            let mut builder =
                honk::urbit_workspace::Builder::new(&project, false, true, None).expect("prelude");
            for name in ["lazy-resolver", "mink"] {
                let entry = root.join(format!("{name}.hoon"));
                std::fs::copy(assets().join(format!("environment/{name}.hoon")), &entry)
                    .expect("environment source");
                let value = builder
                    .build(&entry, honk::urbit_workspace::Output::Value)
                    .expect("environment value");
                assert!(
                    value
                        == std::fs::read(assets().join(format!("reference/{name}.value.jam")))
                            .expect("reference environment value"),
                    "{name} differs"
                );
            }
            // Vere's bytecode compiler rejects malformed bodies before
            // collecting hints. Check this trace against the Hoon evaluator
            // directly, bypassing jet dispatch by evaluating its battery.
            let traced = root.join("malformed-mink-trace.hoon");
            std::fs::write(
                &traced,
                r#"=/  formula  [%11 [%mean [%1 17]] 42]
=/  reply  |=([ref=* path=*] ``[ref path])
=/  core  .*(mink [%10 [6 [%1 [[0 formula] reply]]] %0 1])
=/  raw  .*(core [%7 [%0 1] .*(core [%0 2])])
?>  =([%2 [%mean 17] ~] raw)
=(raw (mink [0 formula] reply))
"#,
            )
            .expect("malformed formula trace source");
            assert_eq!(
                builder
                    .build(&traced, honk::urbit_workspace::Output::Value)
                    .expect("malformed formula trace"),
                vec![2], // jam of %.y
                "mink must retain the Hoon evaluator's malformed-formula trace"
            );
            let factory = root.join("laze.hoon");
            std::fs::write(&factory, include_bytes!("../assets/laze-135.hoon"))
                .expect("factory source");
            let factory_value = builder
                .build(&factory, honk::urbit_workspace::Output::Value)
                .expect("native resolver factory");
            assert!(
                factory_value == include_bytes!("../assets/laze-135.jam").as_slice(),
                "native resolver factory differs"
            );
            let entry = root.join("entry.hoon");
            // Each module retains its imported core across a compiler frame.
            for index in 0..20 {
                let source = if index == 0 {
                    "|%\n++  answer  0\n--\n".to_owned()
                } else {
                    format!(
                        "/+  previous=step-{}\n|%\n++  answer  +(answer:previous)\n--\n",
                        index - 1
                    )
                };
                std::fs::write(root.join(format!("lib/step-{index}.hoon")), source)
                    .expect("nested dependency");
            }
            std::fs::write(&entry, "/+  step-19\nanswer:step-19\n")
                .expect("nested dependency entry");
            let output = builder
                .build(&entry, honk::urbit_workspace::Output::Value)
                .expect("nested dependency result");
            let mut expected: NounSlab = NounSlab::new();
            expected.set_root(D(19));
            assert_eq!(output, expected.jam().as_ref());

            for (source, value) in [
                ("/?  135\n/+  util=helper\nanswer:util\n", 42),
                ("/?  310\n/+  util=helper\nanswer:util\n", 42),
                ("/+  *helper\nanswer\n", 42),
                ("/-  item\n(seed:item 7)\n", 7),
                ("/=  util  /lib/helper\nanswer:util\n", 42),
                ("/+  nested-tool\nanswer:nested-tool\n", 44),
                ("/$  convert  %number  %text\n(convert 41)\n", 42),
                ("/$  convert  %broken  %receiver\n(convert 41)\n", 51),
                ("/$  convert  %absent  %absent\n(convert 42)\n", 42),
                ("/$  convert  %absent  %noun\n(convert 42)\n", 42),
            ] {
                std::fs::write(&entry, source).expect("entry");
                let output = builder
                    .build(&entry, honk::urbit_workspace::Output::Value)
                    .unwrap_or_else(|error| panic!("{source}: {error}"));
                let mut expected: NounSlab = NounSlab::new();
                expected.set_root(D(value));
                assert_eq!(output, expected.jam().as_ref(), "{source}");
            }
            std::fs::write(
                root.join("lib/nested-tool.hoon"),
                "|%\n++  answer  45\n--\n",
            )
            .expect("literal path");
            std::fs::write(&entry, "/+  nested-tool\nanswer:nested-tool\n").expect("literal entry");
            let mut expected: NounSlab = NounSlab::new();
            expected.set_root(D(45));
            assert_eq!(
                builder
                    .build(&entry, honk::urbit_workspace::Output::Value)
                    .expect("literal takes precedence"),
                expected.jam().as_ref()
            );
            std::fs::write(&entry, "/+  nested-tool\n^-  @ud\nanswer:nested-tool\n")
                .expect("typed dynamic entry");
            for mode in [
                honk::urbit_workspace::Output::Dynock,
                honk::urbit_workspace::Output::DynockTyped,
            ] {
                let output = builder.build(&entry, mode).expect("dynamic output");
                let mut slab: NounSlab = NounSlab::new();
                let root = slab
                    .cue_into(bytes::Bytes::from(output))
                    .expect("dynamic JAM");
                let space = slab.noun_space();
                let pair = root.in_space(&space).as_cell().expect("type and trap");
                match mode {
                    honk::urbit_workspace::Output::Dynock => {
                        assert!(pair.head().as_atom().expect("noun type").eq_bytes(b"noun"))
                    }
                    _ => assert!(pair
                        .head()
                        .as_cell()
                        .expect("inferred type")
                        .head()
                        .as_atom()
                        .expect("type tag")
                        .eq_bytes(b"atom")),
                }
                let trap = pair.tail().as_cell().expect("constant trap");
                assert_eq!(
                    trap.tail()
                        .as_atom()
                        .expect("payload")
                        .as_u64()
                        .expect("zero"),
                    0
                );
                let battery = trap.head().as_cell().expect("battery");
                assert_eq!(
                    battery
                        .head()
                        .as_atom()
                        .expect("constant opcode")
                        .as_u64()
                        .expect("opcode"),
                    1
                );
                let formula = battery.tail().noun();
                let mut stack = nockvm::mem::NockStack::new(1 << 24, 0);
                let cold = nockvm::jets::cold::Cold::new(&mut stack);
                let mut context = nockapp::utils::create_context(
                    stack,
                    &[],
                    cold,
                    None,
                    vec![],
                    nockvm::jets::JetDispatchMode::Exact,
                );
                let formula = context.stack.copy_into(formula, &space);
                let value = nockvm::interpreter::interpret(&mut context, D(0), formula)
                    .expect("evaluate dynamic formula");
                assert_eq!(value.as_direct().expect("answer").data(), 45);
            }
            for (source, error) in [
                ("/+  cycle-a\n0\n", "cyclic Urbit import"),
                ("/+  missing\n0\n", "no desk source"),
                ("^-  @ud\n[1 2]\n", "mint-nice"),
                (
                    "/$  convert  %missing  %atom\n0\n", "grab must produce a gate",
                ),
                ("/$  convert  %absent  %other\n0\n", "no-cast-between"),
                ("/*  data  %txt  /missing\n0\n", "no desk file"),
            ] {
                std::fs::write(&entry, source).expect("entry");
                let actual = builder
                    .build(&entry, honk::urbit_workspace::Output::Value)
                    .expect_err("invalid dependency")
                    .to_string();
                assert!(actual.contains(error), "{source}: {actual}");

                // A failed invocation leaves the evaluated prelude usable.
                std::fs::write(&entry, "/+  util=helper\nanswer:util\n").expect("valid entry");
                let output = builder
                    .build(&entry, honk::urbit_workspace::Output::Value)
                    .expect("build after failure");
                let mut expected: NounSlab = NounSlab::new();
                expected.set_root(D(42));
                assert_eq!(output, expected.jam().as_ref());
            }
        })
        .expect("desk worker")
        .join()
        .expect("desk imports");
}

#[test]
fn raw_octets_keep_header_and_error_locations_in_source_bytes() {
    let bytes = b":: \xff comment\n/+  helper\n!:\n42\n";
    let file =
        honk::urbit::parse_file(Path::new("raw.hoon"), bytes, vec![], false).expect("raw file");
    assert_eq!(&bytes[file.headers[0].span.clone()], b"/+  helper");
    let malformed = b":: \xff\n[1 )";
    let error = honk::urbit::parse_file(Path::new("raw.hoon"), malformed, vec![], false)
        .expect_err("syntax");
    let honk::errors::CompilerError::Detailed { metadata, .. } = error else {
        panic!("located error")
    };
    let location = metadata.location.expect("location");
    let offset = location.start_byte.expect("byte offset");
    assert_eq!(malformed[offset], b')');
}

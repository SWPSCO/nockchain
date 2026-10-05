#!/usr/bin/env python3
"""Generate and verify Hoon 135 reference artifacts with pinned Vere and Urbit sources."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "crates/honk/test-assets/urbit135"
VERE = "40a69573e93e28cfca5028738722a9dafb57bd0e"
PATCH = Path(__file__).with_name("vere-eval.patch")
COMPILER = "|=  [subject=type source=@t]  (~(mint ut subject) %noun (ream source))"
PARSE = "(rash source (ifix [gay gay] (stag %tssg (most gap tall:vast))))"
MINT = "|=  source=@t\n(~(mint ut %noun) %noun (ream source))"
ADAPTER = f"""|=  source=@t
=/  kernel  (~(mint ut %noun) %noun (ream source))
=/  env=vase  [p.kernel .*(~ q.kernel)]
q:(~(mint ut p.env) %noun (ream '{COMPILER}'))
"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def capture(args, **kwargs):
    return run(args, stdout=subprocess.PIPE, text=True, **kwargs).stdout.strip()


def jam_atom(data):
    """Canonical JAM of a single input atom; no source text enters a program."""
    atom = int.from_bytes(data, "little")
    length = atom.bit_length()
    if length == 0:
        return b"\x02"
    width = length.bit_length()
    value = ((1 << (1 + width))
             | ((length - (1 << (width - 1))) << (width + 2))
             | (atom << (1 + 2 * width)))
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def jam_noun(noun):
    """Encode input tuples without references; Vere's cue accepts this JAM."""
    def bits(noun):
        if isinstance(noun, tuple):
            head, head_width = bits(noun[0])
            tail, tail_width = bits(noun[1])
            return 1 | (head << 2) | (tail << (2 + head_width)), 2 + head_width + tail_width
        data = jam_atom(noun)
        value = int.from_bytes(data, "little")
        return value, value.bit_length()
    value, width = bits(noun)
    return value.to_bytes((width + 7) // 8, "little")


def noun_list(items):
    result = b""
    for item in reversed(items):
        result = (item, result)
    return result


def evaluate(executable, program, *, sample=None, kernel=None, compiler=None):
    with tempfile.TemporaryDirectory(prefix="honk-urbit-eval-") as temporary:
        args = [executable, "eval", "-j", "-n"]
        if kernel is not None:
            args.extend(["--kernel-formula", kernel])
        if compiler is not None:
            args.extend(["--compiler-formula", compiler])
        if sample is not None:
            path = Path(temporary) / "sample.jam"
            path.write_bytes(jam_noun(sample))
            args.extend(["--sample", path])
        result = subprocess.run([str(arg) for arg in args], input=program.encode(),
                                capture_output=True, timeout=600)
        frame = result.stdout
        if (result.returncode or len(frame) < 6 or frame[0] != 0
                or int.from_bytes(frame[1:5], "little") != len(frame) - 5):
            raise RuntimeError("Vere evaluation failed: " + result.stderr.decode(errors="replace"))
        return frame[5:]


def build_evaluator(directory):
    if capture(["zig", "version"]) != "0.15.2":
        raise RuntimeError("Vere requires Zig 0.15.2")
    checkout = directory / "vere"
    if not checkout.exists():
        run(["git", "clone", "--filter=blob:none", "--no-checkout",
             "https://github.com/urbit/vere.git", checkout])
        run(["git", "checkout", "--detach", VERE], cwd=checkout)
        run(["git", "apply", PATCH], cwd=checkout)
    if capture(["git", "rev-parse", "HEAD"], cwd=checkout) != VERE:
        raise RuntimeError(f"{checkout} is not the pinned Vere revision")
    # A private index verifies the complete checkout against the pinned patch.
    with tempfile.TemporaryDirectory(prefix="honk-vere-index-") as temporary:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary) / "index")}
        run(["git", "read-tree", VERE], cwd=checkout, env=env)
        run(["git", "apply", "--cached", PATCH], cwd=checkout, env=env)
        run(["git", "diff", "--no-ext-diff", "--exit-code", "--"], cwd=checkout, env=env)
        if capture(["git", "ls-files", "--others", "--exclude-standard"], cwd=checkout, env=env):
            raise RuntimeError(f"{checkout} contains untracked source files")
    run(["zig", "build", "-Doptimize=ReleaseFast", "-j4"], cwd=checkout)
    arch = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[platform.machine()]
    system = {"Linux": "linux-musl", "Darwin": "macos-none"}[platform.system()]
    executable = directory / "urbit"
    shutil.copy2(checkout / "zig-out" / f"{arch}-{system}" / "urbit", executable)
    return executable


def prepare(executable, directory):
    source = ASSETS / "kernel/hoon.hoon"
    identity = json.loads((source.parent / "source.json").read_text())
    if identity["hoon_version"] != 135 or digest(source) != identity["sha256"]:
        raise RuntimeError("Hoon 135 kernel source does not match its identity")
    for name, expected in json.loads((source.parent / "prelude.json").read_text())["files"].items():
        if digest(source.parent / name) != expected["sha256"]:
            raise RuntimeError(f"{name} does not match its source identity")
    kernel = directory / "kernel.jam"
    compiler = directory / "compiler.jam"
    marker = directory / "identity.json"
    inputs = {"source": identity, "evaluator_sha256": digest(executable),
              "generator_sha256": digest(Path(__file__)), "patch_sha256": digest(PATCH)}
    if marker.exists() and kernel.exists() and compiler.exists():
        cached = json.loads(marker.read_text())
        expected = {**inputs, "kernel_sha256": digest(kernel), "compiler_sha256": digest(compiler)}
        if cached == expected:
            return kernel, compiler
    raw = source.read_bytes()
    bootstrap = directory / "bootstrap.jam"
    bootstrap.write_bytes(evaluate(executable, MINT, sample=raw))
    # The bootstrapped core runs Hoon 135's own mint to produce both artifacts.
    kernel.write_bytes(evaluate(executable, MINT, sample=raw, kernel=bootstrap))
    compiler.write_bytes(evaluate(executable, ADAPTER, sample=raw, kernel=bootstrap))
    version = evaluate(executable, "hoon-version", kernel=kernel, compiler=compiler)
    if version != jam_atom(bytes([135])):
        raise RuntimeError("reference compiler does not report Hoon 135")
    replay = evaluate(executable, MINT, sample=raw, kernel=kernel, compiler=compiler)
    if replay != kernel.read_bytes():
        raise RuntimeError("Hoon 135 self-compilation is not byte-identical")
    marker.write_text(json.dumps({**inputs, "kernel_sha256": digest(kernel),
                                 "compiler_sha256": digest(compiler)}, indent=2) + "\n")
    return kernel, compiler


def system_artifacts(executable, kernel, compiler):
    def execute(program, sample):
        return evaluate(executable, program, sample=sample, kernel=kernel, compiler=compiler)
    env = execute("""|=  artifact=@
=/  raw  (cue artifact)
=/  boot=vase  [;;(type -.raw) .*(~ +.raw)]
=/  projection  (~(mint ut p.boot) %noun (ream '+>'))
[p.projection .*(q.boot q.projection)]
""", kernel.read_bytes())
    outputs = {}
    for name in ["arvo", "part", "lull", "zuse"]:
        source = b"..part" if name == "part" else (ASSETS / f"kernel/{name}.hoon").read_bytes()
        path = b"" if name == "part" else noun_list([b"sys", name.encode(), b"hoon"])
        mint = execute("""|=  [env=@ source=@t path=path]
=/  env  ;;(vase (cue env))
=/  vaz  (vang | path)
(~(mint ut p.env) %noun (rash source (ifix [gay gay] (stag %tssg (most gap tall:vaz)))))
""", (env, (source, path)))
        outputs[f"system-{name}.mint.jam"] = mint
        env = execute("""|=  [env=@ artifact=@]
=/  env  ;;(vase (cue env))
=/  artifact  (cue artifact)
[-.artifact .*(q.env +.artifact)]
""", (env, mint))
        print(f"Hoon 135: system {name} compiled and evaluated", flush=True)
    outputs["system-zuse.value.jam"] = execute("|=  env=@\n+:(cue env)", env)
    return outputs


def kernel_expression(executable, kernel, compiler, source):
    return evaluate(executable, """|=  [artifact=@ source=@t]
=/  raw  (cue artifact)
=/  boot=vase  [;;(type -.raw) .*(~ +.raw)]
=/  projection  (~(mint ut p.boot) %noun (ream '+>'))
=/  env=vase  [p.projection .*(q.boot q.projection)]
=/  mint  (~(mint ut p.env) %noun (ream source))
.*(q.env q.mint)
""", sample=(kernel.read_bytes(), source), kernel=kernel, compiler=compiler)


def write_factory(source, factory, expected):
    identity = {"source_sha256": digest(source),
                "gate_sha256": hashlib.sha256(factory).hexdigest()}
    if expected is not None and identity != expected:
        raise RuntimeError("lazy resolver factory hashes differ from the committed manifest")
    source.with_suffix(".jam").write_bytes(factory)
    return identity


def clay_artifact(executable, kernel, compiler):
    """Assemble the desk fixture independently with Clay's Hoon vase operations."""
    desk = ASSETS / "desk"
    files = []
    for path in sorted(desk.rglob("*")):
        if not path.is_file():
            continue
        parts = list(path.relative_to(desk).parts)
        parts[-1:] = parts[-1].rsplit(".", 1)
        data = path.read_bytes()
        files.append((noun_list([part.encode() for part in parts]),
                      (len(data).to_bytes(8, "little"), data)))
    builder = Path(__file__).with_name("clay.hoon").read_text()
    program = """|=  [mint=@ value=@ files=(list [path [size=@ud data=@]])]
=/  build
""" + "\n".join("  " + line for line in builder.splitlines()) + """
.*  build
  :*  9  2  10
      :+  6  1
      :-  [-:(cue mint) (cue value)]
      (~(gas by *(map path [size=@ud data=@])) files)
      0  1
  ==
"""
    reference = ASSETS / "reference"
    # The independently generated type/value are already well-formed. Pass
    # them to the typed gate directly; molding repeats shared graph traversal.
    return evaluate(executable, program,
                    sample=((reference / "system-zuse.mint.jam").read_bytes(),
                            ((reference / "system-zuse.value.jam").read_bytes(), noun_list(files))),
                    kernel=kernel, compiler=compiler)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "target/urbit135-oracle")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--build-evaluator", action="store_true")
    group.add_argument("--urbit", type=Path)
    parser.add_argument("--update", action="store_true", help="update the reference hash manifest")
    parser.add_argument("--factory-only", action="store_true",
                        help="generate only the embedded resolver factory and verify its pinned hashes")
    args = parser.parse_args()
    if args.factory_only and args.update:
        parser.error("--factory-only cannot be combined with --update")
    directory = args.artifacts.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    executable = build_evaluator(directory) if args.build_evaluator else args.urbit.resolve()
    kernel, compiler = prepare(executable, directory)
    manifest_path = ASSETS / "reference/manifest.json"
    expected = None if args.update else json.loads(manifest_path.read_text())["lazy_factory"]
    factory_source = ROOT / "crates/honk/assets/laze-135.hoon"
    factory = kernel_expression(executable, kernel, compiler, factory_source.read_bytes())
    factory_identity = write_factory(factory_source, factory, expected)
    print(f"Hoon 135: resolver factory generated at {factory_source.with_suffix('.jam')}", flush=True)
    if args.factory_only:
        return
    reference = ASSETS / "reference"
    reference.mkdir(exist_ok=True)
    manifest = {"vere_revision": VERE, "patch_sha256": digest(PATCH), "cases": {}}
    catalog = ROOT / "crates/hatcher/tests/fixtures/runes135.json"
    sources = []
    for case in json.loads(catalog.read_text()):
        sources.append(case["tall"].encode())
        if case.get("wide") is not None:
            sources.append(case["wide"].encode())
    data = evaluate(executable, "|=  sources=(list @t)\n(turn sources |=(source=@t " + PARSE + "))",
                    sample=noun_list(sources), kernel=kernel, compiler=compiler)
    path = reference / "runes.ast.jam"
    path.write_bytes(data)
    manifest["runes"] = {"source_sha256": digest(catalog), "ast_sha256": hashlib.sha256(data).hexdigest(),
                         "forms": len(sources)}
    print(f"Hoon 135: {len(sources)} rune forms verified", flush=True)
    cases = [(p.stem, p) for p in sorted((ASSETS / "cases").glob("*.hoon"))]
    cases.append(("kernel", ASSETS / "kernel/hoon.hoon"))
    for name, source in cases:
        outputs = {}
        for mode, expression in [("ast", PARSE), ("mint", f"(~(mint ut %noun) %noun {PARSE})")]:
            data = evaluate(executable, "|=  source=@t\n" + expression,
                            sample=source.read_bytes(), kernel=kernel, compiler=compiler)
            path = reference / f"{name}.{mode}.jam"
            path.write_bytes(data)
            outputs[mode + "_sha256"] = hashlib.sha256(data).hexdigest()
        manifest["cases"][name] = {"source_sha256": digest(source), **outputs}
        print(f"Hoon 135: {name} AST and mint verified", flush=True)
    manifest["rejections"] = {}
    for source in sorted((ASSETS / "reject").glob("*.hoon")):
        program = "|=  source=@t\n=/  ast  " + PARSE + "\n" + \
            "=/  result  (mute:vi |.((~(mint ut %noun) %noun ast)))\n?=(%| -.result)"
        verdict = evaluate(executable, program, sample=source.read_bytes(), kernel=kernel, compiler=compiler)
        if verdict != jam_atom(b""):
            raise RuntimeError(f"reference accepts rejection case: {source}")
        manifest["rejections"][source.stem] = {"source_sha256": digest(source)}
        print(f"Hoon 135: {source.stem} rejection verified", flush=True)
    manifest["system"] = {}
    for name, data in system_artifacts(executable, kernel, compiler).items():
        path = reference / name
        path.write_bytes(data)
        manifest["system"][name] = hashlib.sha256(data).hexdigest()
    clay = clay_artifact(executable, kernel, compiler)
    (reference / "clay-subject.vase.jam").write_bytes(clay)
    manifest["clay"] = {
        "reference_sha256": digest(Path(__file__).with_name("clay.hoon")),
        "files": {str(path.relative_to(ASSETS / "desk")): digest(path)
                  for path in sorted((ASSETS / "desk").rglob("*")) if path.is_file()},
        "subject_sha256": hashlib.sha256(clay).hexdigest(),
    }
    manifest["environment"] = {}
    for source in sorted((ASSETS / "environment").glob("*.hoon")):
        data = kernel_expression(executable, kernel, compiler, source.read_bytes())
        path = reference / f"{source.stem}.value.jam"
        path.write_bytes(data)
        manifest["environment"][source.stem] = {"source_sha256": digest(source),
                                               "value_sha256": hashlib.sha256(data).hexdigest()}
    manifest["lazy_factory"] = factory_identity
    if args.update:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    elif json.loads(manifest_path.read_text()) != manifest:
        raise RuntimeError("generated reference hashes differ from the committed manifest")
    print(f"Hoon 135: reference hashes verified; artifacts in {reference}", flush=True)


if __name__ == "__main__":
    main()

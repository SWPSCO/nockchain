//! Emit the parser AST and checked `[type formula]` for differential tests.

use std::path::PathBuf;

use honk::native::{Dialect, NativeCompiler};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::T;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let input = PathBuf::from(args.next().ok_or("expected source path")?);
    let output = PathBuf::from(args.next().ok_or("expected output prefix")?);
    let source = std::fs::read(&input)?;
    let file = honk::urbit::parse_file(&input, &source, Vec::new(), false)?;
    if !file.headers.is_empty() {
        return Err("expression parity source has Clay headers".into());
    }
    let ast = honk::urbit::into_compiler_ast(file.body);
    let mut slab = NounSlab::new();
    let noun = hatch::utils::hoon_to_noun_for_dialect(Dialect::Urbit, &mut slab, &ast);
    slab.set_root(noun);
    std::fs::write(output.with_extension("ast.jam"), slab.jam())?;
    let mut compiler = NativeCompiler::with_dialect(Dialect::Urbit);
    let mut compiled = compiler.compile_expr(&ast)?;
    let pair = T(&mut compiled.slab, &[compiled.ty.noun(), compiled.formula]);
    compiled.slab.set_root(pair);
    std::fs::write(output.with_extension("mint.jam"), compiled.slab.jam())?;
    Ok(())
}

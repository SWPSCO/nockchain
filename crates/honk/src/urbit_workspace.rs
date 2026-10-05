//! Hoon 135 compilation with explicit preludes and Clay library subjects.

mod cache;
mod clay;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use clay::{Dependency, Import};
use hatch::ast::hoon::Hoon;
use hatcher::ford::HeaderKind;
use nockapp::noun::slab::NounSlab;
use nockapp::noun::{BrandedEvalExt, BrandedNounSpaceExt};
use nockapp::utils::{create_context, NOCK_STACK_SIZE_MEDIUM};
use nockvm::interpreter::Context;
use nockvm::jets::cold::{Cold, Nounable};
use nockvm::jets::JetDispatchMode;
use nockvm::mem::NockStack;
use nockvm::noun::{Noun, NounAllocator, D, T};

use crate::build_cache::{BuildCache, SessionStats};
use crate::errors::{CompilerError, Result};
use crate::native::hot135::HOT_STATE;
use crate::native::noun::{noun_pair, term_to_noun};
use crate::native::ut::{ty_noun, Ut};
use crate::native::Dialect;
use crate::project::Project;
use crate::urbit::{into_compiler_ast, parse_file};

#[derive(Clone, Copy)]
pub enum Output {
    Value,
    Dynock,
    DynockTyped,
}

#[derive(Clone, Copy)]
struct Subject {
    ty: Noun,
    value: Noun,
}

pub struct Builder {
    slab: NounSlab,
    context: Context,
    project: Project,
    base: Subject,
    cache: HashMap<Dependency, Subject>,
    visiting: HashSet<Dependency>,
    dbug: bool,
    vet: bool,
    build_cache: Option<BuildCache>,
}

impl Builder {
    pub fn new(
        project: &Project,
        dbug: bool,
        vet: bool,
        build_cache: Option<BuildCache>,
    ) -> Result<Self> {
        if project.dialect != Dialect::Urbit {
            return Err(CompilerError::Parse(
                "Hoon 135 requires an Urbit project".into(),
            ));
        }
        let mut slab = NounSlab::new();
        let base = Subject {
            ty: ty_noun(&mut slab),
            value: D(0),
        };
        let mut stack = NockStack::new(NOCK_STACK_SIZE_MEDIUM, 0);
        let cold = Cold::new(&mut stack);
        let context = create_context(stack, HOT_STATE, cold, None, vec![], JetDispatchMode::Exact);
        let mut builder = Self {
            slab,
            context,
            project: project.clone(),
            base,
            cache: HashMap::new(),
            visiting: HashSet::new(),
            dbug,
            vet,
            build_cache,
        };
        builder.base = builder.layer(&project.prelude, vec![], base)?;
        builder.compact()?;
        builder.base = builder.expression(b"+>", builder.base)?;
        builder.compact()?;
        let version = builder.expression(b"hoon-version", builder.base)?;
        if version.value.as_direct().map(|atom| atom.data()) != Ok(135) {
            return Err(CompilerError::Parse(
                "Urbit prelude must report hoon-version 135".into(),
            ));
        }
        if let Some(system) = &project.system {
            builder.base =
                builder.layer(&system.join("arvo.hoon"), system_path("arvo"), builder.base)?;
            builder.compact()?;
            builder.base = builder.expression(b"..part", builder.base)?;
            builder.compact()?;
            builder.base =
                builder.layer(&system.join("lull.hoon"), system_path("lull"), builder.base)?;
            builder.compact()?;
            builder.base =
                builder.layer(&system.join("zuse.hoon"), system_path("zuse"), builder.base)?;
        }
        builder.compact()?;
        Ok(builder)
    }

    pub fn cache_stats(&self) -> Option<SessionStats> {
        self.build_cache.as_ref().map(BuildCache::stats)
    }

    fn compact(&mut self) -> Result<()> {
        // Canonical JAM shares equal subgraphs across every retained subject,
        // including independent evaluator copies of the same imported core.
        let mut subjects = vec![&mut self.base];
        subjects.extend(self.cache.values_mut());
        let mut root = D(0);
        for subject in subjects.iter().rev() {
            let vase = T(&mut self.slab, &[subject.ty, subject.value]);
            root = T(&mut self.slab, &[vase, root]);
        }
        self.slab.set_root(root);
        let mut slab = NounSlab::new();
        let mut root = slab
            .cue_into(self.slab.jam())
            .map_err(|error| CompilerError::Noun(error.to_string()))?;
        let space = slab.noun_space();
        for subject in subjects {
            let (vase, next) = noun_pair(root, &space)?;
            let (ty, value) = noun_pair(vase, &space)?;
            *subject = Subject { ty, value };
            root = next;
        }
        self.slab = slab;
        Ok(())
    }

    /// Produce the evaluated noun or a dynamic formula in a constant trap.
    pub fn build(&mut self, entry: &Path, output: Output) -> Result<Vec<u8>> {
        self.cache.clear();
        self.compact()?;
        let entry = self.source_path(entry)?;
        let key = Dependency::Source(entry.clone());
        self.visiting.insert(key.clone());
        let result = self.compile_file(&entry);
        self.visiting.remove(&key);
        let (ty, formula, subject) = result?;
        let root = match output {
            Output::Value => self.evaluate(formula, subject.value)?,
            Output::Dynock | Output::DynockTyped => {
                let constant = T(&mut self.slab, &[D(1), subject.value]);
                let closed = T(&mut self.slab, &[D(7), constant, formula]);
                let header = match output {
                    Output::DynockTyped => ty,
                    _ => ty_noun(&mut self.slab),
                };
                let battery = T(&mut self.slab, &[D(1), closed]);
                let trap = T(&mut self.slab, &[battery, D(0)]);
                T(&mut self.slab, &[header, trap])
            }
        };
        self.slab.set_root(root);
        Ok(self.slab.jam().to_vec())
    }

    fn mint(&mut self, subject: Subject, expr: &Hoon) -> Result<(Noun, Noun)> {
        stacker::maybe_grow(32 * 1024, 64 * 1024 * 1024, || {
            let cold_jam = self.cold_jam();
            // Compiler temporaries live only for this invocation. Transfer the
            // product as one graph so its type and formula retain shared nodes.
            let mut slab = NounSlab::new();
            let subject = slab.copy_into(subject.ty, &self.slab.noun_space());
            let key = self
                .build_cache
                .as_ref()
                .map(|_| cache::key(&mut slab, subject, expr, self.vet, &cold_jam));
            let cached = match (&mut self.build_cache, key) {
                (Some(cache), Some(key)) => cache::read(cache, key, &mut slab)?,
                _ => None,
            };
            let product = if let Some(product) = cached {
                product
            } else {
                let goal = ty_noun(&mut slab);
                let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
                ut.load_musk_cold_state(&cold_jam, "evaluated Hoon 135 subject")?;
                ut.set_vet(self.vet);
                let (ty, formula) = ut.mint_noun(subject, goal, expr)?;
                let product = T(ut.slab, &[ty, formula]);
                drop(ut);
                if let (Some(cache), Some(key)) = (&mut self.build_cache, key) {
                    cache::write(cache, key, &slab, product)?;
                }
                product
            };
            let product = self.slab.copy_into(product, &slab.noun_space());
            noun_pair(product, &self.slab.noun_space())
        })
    }

    fn cold_jam(&mut self) -> bytes::Bytes {
        let cold = unsafe {
            self.context
                .with_stack_frame(0, |context| context.cold.into_noun(&mut context.stack))
        };
        let mut slab: NounSlab = NounSlab::new();
        slab.copy_into(cold, &self.context.stack.noun_space());
        slab.jam()
    }

    fn evaluate(&mut self, formula: Noun, subject: Noun) -> Result<Noun> {
        let space = self.slab.noun_space();
        let value = unsafe {
            self.context.with_stack_frame(0, |context| {
                let stack_space = context.stack.noun_space();
                stack_space.with_brand(|brand| {
                    let subject = brand.copy_in(&mut context.stack, subject, &space);
                    let formula = brand.copy_in(&mut context.stack, formula, &space);
                    brand
                        .interpret(context, subject, formula)
                        .map(|value| value.unbranded().noun())
                })
            })
        }
        .map_err(|error| CompilerError::Backend(format!("Hoon 135 evaluation: {error:?}")))?;
        Ok(self.slab.copy_into(value, &self.context.stack.noun_space()))
    }

    fn expression(&mut self, source: &[u8], subject: Subject) -> Result<Subject> {
        let file = parse_file(Path::new("<subject>"), source, vec![], false)?;
        self.expression_ast(&into_compiler_ast(file.body), subject)
    }

    fn expression_ast(&mut self, expr: &Hoon, subject: Subject) -> Result<Subject> {
        let (ty, formula) = self.mint(subject, expr)?;
        Ok(Subject {
            ty,
            value: self.evaluate(formula, subject.value)?,
        })
    }

    fn layer(&mut self, path: &Path, wer: Vec<String>, subject: Subject) -> Result<Subject> {
        tracing::info!(path = %path.display(), "compiling Hoon 135 system layer");
        let file = parse_file(path, &std::fs::read(path)?, wer, false)?;
        if !file.headers.is_empty() {
            return Err(CompilerError::Parse(format!(
                "{}: system layer has Clay headers",
                path.display()
            )));
        }
        let (ty, formula) = self.mint(subject, &into_compiler_ast(file.body))?;
        let stem = path
            .file_stem()
            .ok_or_else(|| CompilerError::Parse("system source has no file name".into()))?;
        self.dump_artifacts(Path::new(stem), subject, ty, formula)?;
        tracing::info!(path = %path.display(), "evaluating Hoon 135 system layer");
        Ok(Subject {
            ty,
            value: self.evaluate(formula, subject.value)?,
        })
    }

    fn dump_artifacts(
        &mut self,
        path: &Path,
        subject: Subject,
        ty: Noun,
        formula: Noun,
    ) -> Result<()> {
        if let Some(directory) = std::env::var_os("HONK_DUMP_URBIT_ARTIFACTS") {
            let path = PathBuf::from(directory).join(path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            for (kind, head, tail) in
                [("subject", subject.ty, subject.value), ("mint", ty, formula)]
            {
                let pair = T(&mut self.slab, &[head, tail]);
                self.slab.set_root(pair);
                std::fs::write(path.with_extension(format!("{kind}.jam")), self.slab.jam())?;
            }
        }
        Ok(())
    }

    fn source_path(&self, path: &Path) -> Result<PathBuf> {
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&self.project.root) {
            return Err(CompilerError::Parse(format!(
                "import escapes project root: {}",
                path.display()
            )));
        }
        Ok(canonical)
    }

    fn named_path(&self, directory: &str, name: &str) -> Result<PathBuf> {
        let path = crate::urbit_path::fit_path(&self.project.root, directory, name)
            .map_err(CompilerError::Parse)?;
        self.source_path(&path)
    }

    fn import_path(&self, parts: &[String]) -> Result<PathBuf> {
        let mut parts = parts.to_vec();
        parts.push("hoon".into());
        let path = crate::urbit_path::lookup_file(&self.project.root, &parts)
            .map_err(CompilerError::Parse)?
            .ok_or_else(|| {
                CompilerError::Parse(format!("no desk source matches /{}", parts.join("/")))
            })?;
        self.source_path(&path)
    }

    fn dependency(&mut self, key: Dependency) -> Result<Dependency> {
        if self.cache.contains_key(&key) {
            return Ok(key);
        }
        if !self.visiting.insert(key.clone()) {
            return Err(CompilerError::Parse(format!(
                "cyclic Urbit import: {key:?}"
            )));
        }
        let result = self.build_dependency(&key);
        self.visiting.remove(&key);
        let subject = result?;
        self.cache.insert(key.clone(), subject);
        self.compact()?;
        Ok(key)
    }

    fn push(&mut self, subject: Subject, imported: Subject, face: Option<&str>) -> Subject {
        let ty = if let Some(face) = face {
            let tag = term_to_noun(&mut self.slab, "face");
            let face = term_to_noun(&mut self.slab, face);
            T(&mut self.slab, &[tag, face, imported.ty])
        } else {
            imported.ty
        };
        let cell = term_to_noun(&mut self.slab, "cell");
        Subject {
            ty: T(&mut self.slab, &[cell, ty, subject.ty]),
            value: T(&mut self.slab, &[imported.value, subject.value]),
        }
    }

    fn compile_file(&mut self, path: &Path) -> Result<(Noun, Noun, Subject)> {
        let relative = path
            .strip_prefix(&self.project.root)
            .map_err(|error| CompilerError::Parse(error.to_string()))?
            .to_path_buf();
        let wer = crate::urbit_path::from_relative_path(&relative).map_err(CompilerError::Parse)?;
        let file = parse_file(path, &std::fs::read(path)?, wer, self.dbug)?;
        let mut resolved_imports = Vec::new();
        for header in file.headers {
            let rune = header.kind.rune();
            match header.kind {
                // Clay parses this annotation without constraining the prelude.
                HeaderKind::Version { .. } => {}
                HeaderKind::Libraries { imports } | HeaderKind::Structures { imports } => {
                    let directory = if rune == "/+" { "lib" } else { "sur" };
                    for import in imports {
                        let dependency = self.named_path(directory, &import.path)?;
                        let dependency = self.dependency(Dependency::Source(dependency))?;
                        resolved_imports.push((Import::Value(dependency), import.face));
                    }
                }
                HeaderKind::Source { face, path: parts } => {
                    let dependency = self.import_path(&parts)?;
                    let dependency = self.dependency(Dependency::Source(dependency))?;
                    resolved_imports.push((Import::Value(dependency), Some(face)));
                }
                HeaderKind::Conversion { face, from, to } => {
                    let dependency = self.dependency(Dependency::Conversion { from, to })?;
                    resolved_imports.push((Import::Value(dependency), Some(face)));
                }
                HeaderKind::Mark { face, mark } => {
                    let dependency = self.dependency(Dependency::Mark(mark))?;
                    resolved_imports.push((Import::Value(dependency), Some(face)));
                }
                HeaderKind::File { face, mark, path } => {
                    let stored = path
                        .last()
                        .ok_or_else(|| {
                            CompilerError::Parse(
                                "a file import needs its stored mark in the path".into(),
                            )
                        })?
                        .clone();
                    let file = crate::urbit_path::lookup_file(&self.project.root, &path)
                        .map_err(CompilerError::Parse)?
                        .ok_or_else(|| {
                            CompilerError::Parse(format!(
                                "no desk file matches /{}",
                                path.join("/")
                            ))
                        })?;
                    let path = self.source_path(&file)?;
                    let dependency = self.dependency(Dependency::File { path, stored, mark })?;
                    resolved_imports.push((Import::Value(dependency), Some(face)));
                }
                HeaderKind::Directory {
                    face, mold, path, ..
                } => {
                    let members = self.directory_members(&path)?;
                    resolved_imports.push((
                        Import::Directory {
                            mold,
                            members,
                            path,
                        },
                        Some(face),
                    ));
                }
            }
        }
        // Resolve the dependency graph before borrowing any subject nouns:
        // completing a dependency compacts all retained subjects.
        let mut subject = self.base;
        for (dependency, face) in resolved_imports {
            let imported = match dependency {
                Import::Value(key) => self.cache[&key],
                Import::Directory {
                    mold,
                    members,
                    path,
                } => self.directory(subject, mold, &members, &path)?,
            };
            subject = self.push(subject, imported, face.as_deref());
        }
        tracing::info!(path = %path.display(), "compiling Hoon 135 desk source");
        let (ty, formula) = self.mint(subject, &into_compiler_ast(file.body))?;
        self.dump_artifacts(&relative, subject, ty, formula)?;
        Ok((ty, formula, subject))
    }
}

fn system_path(name: &str) -> Vec<String> {
    vec!["sys".into(), name.into(), "hoon".into()]
}

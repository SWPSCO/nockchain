//! Clay's typed file and mark-conversion dependencies.

use std::collections::BTreeSet;
use std::path::PathBuf;

use hatch::ast::hoon::{NounExpr, TermOrPair};
use hatcher::ast::hoon::{BaseType, Hoon as SourceHoon, Limb, Spec};
use nockvm::ext::AtomExt;
use nockvm::noun::Atom;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Dependency {
    Source(PathBuf),
    Mark(String),
    Conversion {
        from: String,
        to: String,
    },
    File {
        path: PathBuf,
        stored: String,
        mark: String,
    },
}

pub(super) enum Import {
    Value(Dependency),
    Directory {
        mold: Spec,
        members: Vec<(String, Dependency)>,
        path: Vec<String>,
    },
}

impl Builder {
    pub(super) fn directory_members(
        &mut self,
        path: &[String],
    ) -> Result<Vec<(String, Dependency)>> {
        let mut names = BTreeSet::new();
        for directory in crate::urbit_path::matching_directories(&self.project.root, path)
            .map_err(CompilerError::Parse)?
        {
            self.source_path(&directory)?;
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let file = entry.path();
                let name = entry.file_name();
                if file.is_dir() {
                    let name = name.to_str().ok_or_else(|| {
                        CompilerError::Parse("directory name is not UTF-8".into())
                    })?;
                    names.insert(
                        crate::urbit_path::decode_component(name).map_err(CompilerError::Parse)?,
                    );
                } else if file.is_file() {
                    let parts = crate::urbit_path::from_relative_path(Path::new(&name))
                        .map_err(CompilerError::Parse)?;
                    if let [name, mark] = parts.as_slice() {
                        if mark == "hoon" {
                            names.insert(name.clone());
                        }
                    }
                }
            }
        }
        let mut members = Vec::new();
        for name in names {
            let mut parts = path.to_vec();
            parts.extend([name.clone(), "hoon".into()]);
            if let Some(file) = crate::urbit_path::lookup_file(&self.project.root, &parts)
                .map_err(CompilerError::Parse)?
            {
                let file = self.source_path(&file)?;
                let key = self.dependency(Dependency::Source(file))?;
                members.push((name, key));
            }
        }
        Ok(members)
    }

    pub(super) fn directory(
        &mut self,
        subject: Subject,
        mold: Spec,
        members: &[(String, Dependency)],
        path: &[String],
    ) -> Result<Subject> {
        let value = into_compiler_ast(SourceHoon::KetTar(Box::new(mold.clone())));
        let map = into_compiler_ast(SourceHoon::KetTar(Box::new(Spec::Make(
            SourceHoon::Wing(vec![Limb::Term("map".into())]),
            vec![Spec::Base(BaseType::Atom("ta".into())), mold],
        ))));
        let cold = self.cold_jam();
        let mut ut = Ut::new_for_dialect(&mut self.slab, Dialect::Urbit);
        ut.load_musk_cold_state(&cold, "evaluated Hoon 135 subject")?;
        let value_type = ut.play_noun(subject.ty, &value)?;
        let map_type = ut.play_noun(subject.ty, &map)?;
        for (name, key) in members {
            if !ut.nest_noun(value_type, self.cache[key].ty)? {
                return Err(CompilerError::Backend(format!(
                    "nest-fail: /{} {name}",
                    path.join("/")
                )));
            }
        }
        drop(ut);
        let mut value = D(0);
        for (name, key) in members {
            let name = if name.is_empty() {
                D(0)
            } else {
                Atom::from_bytes(&mut self.slab, name.as_bytes()).as_noun()
            };
            value =
                crate::native::ut::map_put_mug(&mut self.slab, value, name, self.cache[key].value)?;
        }
        Ok(Subject {
            ty: map_type,
            value,
        })
    }

    pub(super) fn build_dependency(&mut self, key: &Dependency) -> Result<Subject> {
        match key {
            Dependency::Source(path) => {
                let (ty, formula, subject) = self.compile_file(path)?;
                Ok(Subject {
                    ty,
                    value: self.evaluate(formula, subject.value)?,
                })
            }
            Dependency::Conversion { from, to } => self.conversion(from, to),
            Dependency::Mark(mark) => self.mark(mark),
            Dependency::File { path, stored, mark } => {
                let first = self.dependency(Dependency::Conversion {
                    from: "mime".into(),
                    to: stored.clone(),
                })?;
                let second = self.dependency(Dependency::Conversion {
                    from: stored.clone(),
                    to: mark.clone(),
                })?;
                let contents = std::fs::read(path)?;
                let bytes = if contents.is_empty() {
                    D(0)
                } else {
                    Atom::from_bytes(&mut self.slab, &contents).as_noun()
                };
                let length = Atom::new(&mut self.slab, contents.len() as u64).as_noun();
                let text = term_to_noun(&mut self.slab, "text");
                let plain = term_to_noun(&mut self.slab, "plain");
                let mime = T(&mut self.slab, &[text, plain, D(0)]);
                let value = T(&mut self.slab, &[mime, length, bytes]);
                let sample = Subject {
                    ty: ty_noun(&mut self.slab),
                    value,
                };
                let mold = self.expression(b"mime", self.base)?;
                let mime = self.slam(mold, sample)?;
                let stored = self.slam(self.cache[&first], mime)?;
                self.slam(self.cache[&second], stored)
            }
        }
    }

    fn mark_source(&mut self, name: &str) -> Result<Option<Dependency>> {
        crate::urbit_path::try_fit_path(&self.project.root, "mar", name)
            .map_err(CompilerError::Parse)?
            .map(|path| {
                let path = self.source_path(&path)?;
                self.dependency(Dependency::Source(path))
            })
            .transpose()
    }

    fn mark(&mut self, name: &str) -> Result<Subject> {
        let path = self.named_path("mar", name)?;
        let key = self.dependency(Dependency::Source(path))?;
        let gradient = self.expression(b"grad", self.cache[&key])?;
        let space = self.slab.noun_space();
        let Ok(parent) = gradient.value.in_space(&space).as_atom() else {
            let subject = self.push(self.base, self.cache[&key], Some("cor"));
            return self.expression(NAVE_INLINE.as_bytes(), subject);
        };
        let parent = parent
            .into_string()
            .map_err(|error| CompilerError::Decode(error.to_string()))?;
        let gradient = self.dependency(Dependency::Mark(parent.clone()))?;
        let forward = self.dependency(Dependency::Conversion {
            from: name.into(),
            to: parent.clone(),
        })?;
        let backward = self.dependency(Dependency::Conversion {
            from: parent,
            to: name.into(),
        })?;
        let nave = self.expression(b"nave:clay", self.base)?;
        // Clay's with-faces constructs this subject without a trailing prelude.
        let mut subject = self.face(self.cache[&gradient], "deg");
        for (face, value) in [
            ("tub", self.cache[&forward]),
            ("but", self.cache[&backward]),
            ("cor", self.cache[&key]),
            ("nave", nave),
        ] {
            subject = self.push(subject, value, Some(face));
        }
        self.expression(NAVE_INHERITED.as_bytes(), subject)
    }

    fn conversion(&mut self, from: &str, to: &str) -> Result<Subject> {
        if from == to {
            return self.expression(b"same", self.base);
        }
        if from == "mime" && to == "hoon" {
            return self.expression(b"|=(m=mime q.q.m)", self.base);
        }
        // Resolve both mark cores before borrowing their nouns: resolving a
        // dependency can compact the slab. Clay also builds both before choosing.
        let old = self.mark_source(from)?;
        let new = self.mark_source(to)?;
        if let Some(old) = old {
            let core = self.cache[&old];
            if self.has_conversion_arm(core, "grow", to)? {
                let core = self.face(core, "cor");
                // Clay constructs limb nodes here. Re-parsing a source wing
                // changes the arm AST retained in the resulting gate type.
                let body = Hoon::TisGal(
                    Box::new(Hoon::Limb(to.into())),
                    Box::new(fragment(b"~(grow cor v)")?),
                );
                let expr = Hoon::BarCol(
                    Box::new(fragment(b"v=+<.cor")?),
                    Box::new(Hoon::SigGar(spin("grow", from, to), Box::new(body))),
                );
                return self.expression_ast(&expr, core);
            }
        }
        if let Some(new) = new {
            let core = self.cache[&new];
            if self.has_conversion_arm(core, "grab", from)? {
                let body = Hoon::TisGal(
                    Box::new(Hoon::Limb(from.into())),
                    Box::new(Hoon::Limb("grab".into())),
                );
                let expr = Hoon::SigGar(spin("grab", from, to), Box::new(body));
                let gate = self.expression_ast(&expr, core)?;
                if gate
                    .value
                    .in_space(&self.slab.noun_space())
                    .as_cell()
                    .is_err()
                {
                    return Err(CompilerError::Backend(
                        "Clay grab must produce a gate, not an atom".into(),
                    ));
                }
                return Ok(gate);
            }
        }
        if to == "noun" {
            return self.expression(b"same", self.base);
        }
        Err(CompilerError::Backend(format!(
            "no-cast-between: %{from} %{to}"
        )))
    }

    fn has_conversion_arm(&mut self, core: Subject, arm: &str, mark: &str) -> Result<bool> {
        if !self.has_arm(core.ty, arm)? {
            return Ok(false);
        }
        // Clay catches a failed evaluation of the intermediate grab/grow core.
        let inner = match self.expression(arm.as_bytes(), core) {
            Ok(inner) => inner,
            Err(error @ CompilerError::Io(_)) => return Err(error),
            Err(_) => return Ok(false),
        };
        self.has_arm(inner.ty, mark)
    }

    fn has_arm(&mut self, ty: Noun, name: &str) -> Result<bool> {
        let cold = self.cold_jam();
        let mut slab = NounSlab::new();
        let ty = slab.copy_into(ty, &self.slab.noun_space());
        let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
        ut.load_musk_cold_state(&cold, "evaluated Hoon 135 subject")?;
        ut.has_arm_noun(ty, name)
    }

    fn face(&mut self, subject: Subject, name: &str) -> Subject {
        let tag = term_to_noun(&mut self.slab, "face");
        let name = term_to_noun(&mut self.slab, name);
        Subject {
            ty: T(&mut self.slab, &[tag, name, subject.ty]),
            ..subject
        }
    }

    fn slam(&mut self, gate: Subject, sample: Subject) -> Result<Subject> {
        let subject = self.push(sample, gate, None);
        self.expression(b"%~($ - +)", subject)
    }
}

fn fragment(source: &[u8]) -> Result<Hoon> {
    let file = parse_file(Path::new("<clay>"), source, vec![], false)?;
    let mut forms = match into_compiler_ast(file.body) {
        Hoon::TisSig(forms) => forms,
        expr => return Ok(expr),
    };
    if forms.len() != 1 {
        return Err(CompilerError::Parse(
            "Clay fragment requires one expression".into(),
        ));
    }
    Ok(forms.pop().expect("one Clay expression"))
}

fn spin(arm: &str, from: &str, to: &str) -> TermOrPair {
    let label = hatch::utils::string_to_atom(format!("{arm}-%{from}->%{to}"));
    TermOrPair::Pair(
        "spin".into(),
        Box::new(Hoon::ColTar(vec![Hoon::Sand(
            "t".into(),
            NounExpr::ParsedAtom(label),
        )])),
    )
}

// The typed nave wrappers from Clay's ++bush-to-vase. Native mint compiles the
// wrappers against the resolved mark cores; no Hoon compiler gate is invoked.
const NAVE_INLINE: &str = r#"=/  typ  _+<.cor
=/  dif  _*diff:grad:cor
^-  (nave:clay typ dif)
|%
++  diff  |=([old=typ new=typ] (diff:~(grad cor old) new))
++  form  form:grad:cor
++  join
  |=  [a=dif b=dif]
  ^-  (unit (unit dif))
  ?:  =(a b)  ~
  `(join:grad:cor a b)
++  mash
  |=  [a=[=ship =desk =dif] b=[=ship =desk =dif]]
  ^-  (unit dif)
  ?:  =(dif.a dif.b)  ~
  `(mash:grad:cor a b)
++  pact  |=([v=typ d=dif] (pact:~(grad cor v) d))
++  vale  noun:grab:cor
--
"#;

const NAVE_INHERITED: &str = r#"=/  typ  _+<.cor
=/  dif  _*diff:deg
^-  (nave typ dif)
|%
++  diff
  |=  [old=typ new=typ]
  ^-  dif
  (diff:deg (tub old) (tub new))
++  form  form:deg
++  join  join:deg
++  mash  mash:deg
++  pact
  |=  [v=typ d=dif]
  ^-  typ
  (but (pact:deg (tub v) d))
++  vale  noun:grab:cor
--
"#;

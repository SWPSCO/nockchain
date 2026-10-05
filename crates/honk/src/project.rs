//! Explicit source roots for repositories containing either Hoon dialect.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::errors::{CompilerError, Result};
use crate::native::Dialect;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    project: Vec<Project>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub root: PathBuf,
    pub dialect: Dialect,
    pub prelude: PathBuf,
    pub system: Option<PathBuf>,
}

#[derive(Debug)]
pub struct Workspace {
    path: PathBuf,
    projects: Vec<Project>,
}

impl Workspace {
    pub fn load(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let parent = path.parent().ok_or_else(|| {
            CompilerError::Parse(format!("configuration has no parent: {}", path.display()))
        })?;
        let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)
            .map_err(|error| CompilerError::Parse(format!("{}: {error}", path.display())))?;
        if config.project.is_empty() {
            return Err(CompilerError::Parse(format!(
                "{}: expected at least one [[project]]",
                path.display()
            )));
        }
        let mut roots = HashSet::new();
        for project in &mut config.project {
            project.root = parent.join(&project.root).canonicalize()?;
            project.prelude = parent.join(&project.prelude).canonicalize()?;
            if !project.root.is_dir() || !project.prelude.is_file() {
                return Err(CompilerError::Parse(format!(
                    "{}: project root must be a directory and prelude must be a file",
                    path.display()
                )));
            }
            if let Some(system) = &mut project.system {
                *system = parent.join(&system).canonicalize()?;
                if project.dialect != Dialect::Urbit || !system.is_dir() {
                    return Err(CompilerError::Parse(
                        "system requires an Urbit system directory".into(),
                    ));
                }
            }
            if !roots.insert(project.root.clone()) {
                return Err(CompilerError::Parse(format!(
                    "{}: duplicate project root {}",
                    path.display(),
                    project.root.display()
                )));
            }
        }
        Ok(Self {
            path,
            projects: config.project,
        })
    }

    /// Discover the nearest configuration above the source's physical path.
    pub fn discover(entry: &Path) -> Result<Option<Self>> {
        let entry = match entry.canonicalize() {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        for parent in entry.parent().into_iter().flat_map(Path::ancestors) {
            let path = parent.join("honk.toml");
            match path.try_exists() {
                Ok(true) => return Self::load(&path).map(Some),
                Ok(false) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    /// Nested roots select the most specific project, independent of table order.
    pub fn project_for(&self, entry: &Path) -> Result<&Project> {
        let entry = entry.canonicalize()?;
        self.projects
            .iter()
            .filter(|project| entry.starts_with(&project.root))
            .max_by_key(|project| project.root.components().count())
            .ok_or_else(|| {
                CompilerError::Parse(format!(
                    "{}: no project contains {}",
                    self.path.display(),
                    entry.display()
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(config: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary workspace");
        for root in ["nc", "urbit", "nc/desk", "outside"] {
            let root = directory.path().join(root);
            std::fs::create_dir_all(&root).expect("source root");
            std::fs::write(root.join("entry.hoon"), "42\n").expect("source");
        }
        std::fs::write(directory.path().join("hoon.hoon"), "42\n").expect("prelude");
        std::fs::write(directory.path().join("honk.toml"), config).expect("configuration");
        directory
    }

    const MIXED: &str = r#"
[[project]]
root = "nc/desk"
dialect = "urbit"
prelude = "hoon.hoon"
[[project]]
root = "nc"
dialect = "nockchain"
prelude = "hoon.hoon"
[[project]]
root = "urbit"
dialect = "urbit"
prelude = "hoon.hoon"
"#;

    #[test]
    fn mixed_roots_and_nested_projects_select_the_configured_dialect() {
        let directory = fixture(MIXED);
        let workspace = Workspace::load(&directory.path().join("honk.toml")).expect("workspace");
        for (root, dialect) in [
            ("nc", Dialect::Nockchain),
            ("urbit", Dialect::Urbit),
            ("nc/desk", Dialect::Urbit),
        ] {
            let entry = directory.path().join(root).join("entry.hoon");
            let project = workspace.project_for(&entry).expect("project");
            assert_eq!(project.dialect, dialect);
            assert_eq!(
                project.prelude,
                directory
                    .path()
                    .join("hoon.hoon")
                    .canonicalize()
                    .expect("prelude")
            );
            let discovered = Workspace::discover(&entry)
                .expect("discovery")
                .expect("configuration");
            assert_eq!(
                discovered.project_for(&entry).expect("project").dialect,
                dialect
            );
        }
        assert!(workspace
            .project_for(&directory.path().join("outside/entry.hoon"))
            .is_err());
    }

    #[test]
    fn duplicate_physical_roots_are_rejected() {
        let directory = fixture(&MIXED.replace("root = \"urbit\"", "root = \"nc/../nc\""));
        let error =
            Workspace::load(&directory.path().join("honk.toml")).expect_err("duplicate root");
        assert!(error.to_string().contains("duplicate project root"));
    }

    #[test]
    fn misspelled_configuration_cannot_silently_select_a_compiler() {
        for config in [
            MIXED.replace("nockchain", "hoon137"),
            MIXED.replace("dialect =", "dialcet ="),
            "project = []".into(),
        ] {
            let directory = fixture(&config);
            assert!(Workspace::load(&directory.path().join("honk.toml")).is_err());
        }
    }
}

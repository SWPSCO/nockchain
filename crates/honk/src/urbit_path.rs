//! Vere's mapping between mounted filesystem names and Clay path components.
//!
//! Component escaping and file extension splitting follow `io/unix.c` in Vere.
//! Mapping is separate from the mounted watcher's entry admission rules.

use std::path::{Component, Path, PathBuf};

fn validate_component(component: &str) -> Result<(), String> {
    if component.contains('\0') || component.chars().any(std::path::is_separator) {
        return Err(format!("invalid path component {component:?}"));
    }
    Ok(())
}

/// Encode a Clay component as a filesystem name, escaping special components.
pub fn encode_component(component: &str) -> Result<String, String> {
    validate_component(component)?;
    if component.is_empty() || matches!(component, "." | "..") || component.starts_with('!') {
        Ok(format!("!{component}"))
    } else {
        Ok(component.to_owned())
    }
}

/// Decode a filesystem component by removing exactly one leading bang.
///
/// Aliases such as `!foo` and `foo` both decode to `foo`.
pub fn decode_component(component: &str) -> Result<String, String> {
    validate_component(component)?;
    Ok(component.strip_prefix('!').unwrap_or(component).to_owned())
}

fn relative_components(path: &Path, allow_empty: bool) -> Result<Vec<&str>, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("path is not UTF-8: {path:?}"))?;
    if text.is_empty() && allow_empty {
        return Ok(Vec::new());
    }
    if path
        .components()
        .any(|part| matches!(part, Component::Prefix(_) | Component::RootDir))
    {
        return Err(format!("path must be relative: {path:?}"));
    }
    // Inspect the original spelling: Path::components normalizes dots and slashes.
    let parts: Vec<_> = text.split(std::path::is_separator).collect();
    for part in &parts {
        if part.is_empty() || matches!(*part, "." | "..") {
            return Err(format!(
                "path contains an empty or traversal component: {path:?}"
            ));
        }
        validate_component(part)?;
    }
    Ok(parts)
}

/// Decode a relative file path, splitting only the last filename's final dot.
///
/// Extensionless files map to one final component. Whether the mounted watcher
/// discovers a name is determined separately by [`is_sync_entry`].
pub fn from_relative_path(path: &Path) -> Result<Vec<String>, String> {
    let parts = relative_components(path, false)?;
    let (filename, directories) = parts.split_last().expect("nonempty file path");
    let mut result: Vec<_> = directories
        .iter()
        .map(|part| decode_component(part))
        .collect::<Result<_, _>>()?;
    if let Some((stem, extension)) = filename.rsplit_once('.') {
        result.push(decode_component(stem)?);
        result.push(decode_component(extension)?);
    } else {
        result.push(decode_component(filename)?);
    }
    Ok(result)
}

/// Encode a Clay file path using its last two components as basename and mark.
///
/// Reject paths that cannot survive Vere's final-dot split unchanged.
pub fn to_relative_path(parts: &[String]) -> Result<PathBuf, String> {
    let mut path = PathBuf::new();
    match parts {
        [] => return Err("a Clay file path must contain a component".to_owned()),
        [filename] => path.push(encode_component(filename)?),
        _ => {
            for part in &parts[..parts.len() - 2] {
                path.push(encode_component(part)?);
            }
            path.push(format!(
                "{}.{}",
                encode_component(&parts[parts.len() - 2])?,
                encode_component(&parts[parts.len() - 1])?
            ));
        }
    }
    if from_relative_path(&path)? != parts {
        return Err(format!(
            "Clay file path has no canonical filesystem spelling: {parts:?}"
        ));
    }
    Ok(path)
}

/// Decode directory components without splitting dots. An empty path is the root.
pub fn from_directory_path(path: &Path) -> Result<Vec<String>, String> {
    relative_components(path, true)?
        .into_iter()
        .map(decode_component)
        .collect()
}

/// Encode directory components without joining the final components with a dot.
pub fn to_directory_path(parts: &[String]) -> Result<PathBuf, String> {
    let mut path = PathBuf::new();
    for part in parts {
        path.push(encode_component(part)?);
    }
    if from_directory_path(&path)? != parts {
        return Err(format!(
            "Clay directory path has no canonical filesystem spelling: {parts:?}"
        ));
    }
    Ok(path)
}

fn missing_path(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

fn matching_entries(
    parent: &Path,
    directory: bool,
    matches_name: impl Fn(&str) -> bool,
) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if missing_path(&error) => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read directory {parent:?}: {error}")),
    };
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory {parent:?}: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !matches_name(name) {
            continue;
        }
        let path = entry.path();
        // Follow symlinks for the entry type while retaining its logical path.
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if missing_path(&error) => continue,
            Err(error) => return Err(format!("cannot inspect path {path:?}: {error}")),
        };
        if if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        } {
            matches.push(path);
        }
    }
    Ok(matches)
}

/// Find all physical directories representing a Clay path, retaining aliases.
pub fn matching_directories(root: &Path, parts: &[String]) -> Result<Vec<PathBuf>, String> {
    for part in parts {
        validate_component(part)?;
    }
    let metadata = match std::fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if missing_path(&error) => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot inspect root {root:?}: {error}")),
    };
    if !metadata.is_dir() {
        return Ok(Vec::new());
    }
    let mut matches = vec![root.to_path_buf()];
    for part in parts {
        let mut next = Vec::new();
        for parent in matches {
            next.extend(matching_entries(&parent, true, |name| {
                decode_component(name).is_ok_and(|decoded| decoded == *part)
            })?);
        }
        matches = next;
    }
    Ok(matches)
}

fn unique_match(
    mut matches: Vec<PathBuf>,
    parts: &[String],
    kind: &str,
) -> Result<Option<PathBuf>, String> {
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => Err(format!(
            "ambiguous filesystem aliases for Clay {kind} {parts:?}: {matches:?}"
        )),
    }
}

/// Find a Clay file by decoding actual filesystem names, including bang aliases.
///
/// Both final-dot and extensionless file mappings are considered. Multiple
/// matching files are an error; offline lookup cannot choose an authoritative
/// alias. Symlinks are followed without canonicalizing the returned path.
/// Watcher admission rules do not restrict an explicit lookup.
pub fn lookup_file(root: &Path, parts: &[String]) -> Result<Option<PathBuf>, String> {
    if parts.is_empty() {
        return Err("a Clay file path must contain a component".to_owned());
    }
    for part in parts {
        validate_component(part)?;
    }
    let mut matches = Vec::new();
    for final_count in 1..=2.min(parts.len()) {
        let split = parts.len() - final_count;
        for parent in matching_directories(root, &parts[..split])? {
            matches.extend(matching_entries(&parent, false, |name| {
                from_relative_path(Path::new(name)).is_ok_and(|decoded| decoded == parts[split..])
            })?);
        }
    }
    unique_match(matches, parts, "file")
}

/// Find a Clay directory by decoding actual names without splitting dots.
///
/// Multiple matching directories are an explicit ambiguity error. An empty
/// Clay path denotes the root; returned paths retain their symlink spelling.
/// Watcher admission rules do not restrict an explicit lookup.
pub fn lookup_directory(root: &Path, parts: &[String]) -> Result<Option<PathBuf>, String> {
    unique_match(matching_directories(root, parts)?, parts, "directory")
}

/// Whether the mounted Vere watcher admits a newly discovered filesystem entry.
///
/// Hidden entries are skipped. Files must have a dot, cannot end in `~`, and
/// their whole name after one bang is removed must use the `@ta` alphabet.
/// Directories do not have the file-name restrictions. Vere's initial import
/// has different admission rules; this predicate describes its mounted watcher.
pub fn is_sync_entry(name: &str, is_directory: bool) -> bool {
    if name.is_empty() || name.starts_with('.') || validate_component(name).is_err() {
        return false;
    }
    if is_directory {
        return true;
    }
    name.contains('.')
        && !name.ends_with('~')
        && name.strip_prefix('!').unwrap_or(name).bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'.' | b'~' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn explicit_lookup_resolves_aliases_without_watcher_filtering() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("!app")).unwrap();
        std::fs::write(root.join("!app/!foo.!hoon"), "1").unwrap();
        std::fs::write(root.join("!app/Upper.hoon~"), "1").unwrap();
        std::fs::write(root.join("!app/.hoon"), "1").unwrap();
        std::fs::write(root.join("!app/README"), "1").unwrap();
        for (parts, disk) in [
            (vec!["app", "foo", "hoon"], "!app/!foo.!hoon"),
            (vec!["app", "Upper", "hoon~"], "!app/Upper.hoon~"),
            (vec!["app", "", "hoon"], "!app/.hoon"),
            (vec!["app", "README"], "!app/README"),
        ] {
            assert_eq!(
                lookup_file(root, &strings(&parts)).unwrap(),
                Some(root.join(disk))
            );
        }
        assert_eq!(
            lookup_directory(root, &strings(&["app"])).unwrap(),
            Some(root.join("!app"))
        );
        assert_eq!(
            lookup_directory(root, &[]).unwrap(),
            Some(root.to_path_buf())
        );
        assert_eq!(
            lookup_file(root, &strings(&["missing", "hoon"])).unwrap(),
            None
        );
        assert_eq!(
            lookup_directory(root, &strings(&["missing"])).unwrap(),
            None
        );
        assert_eq!(lookup_directory(&root.join("absent"), &[]).unwrap(), None);
        assert!(lookup_file(root, &[]).is_err());
        assert!(lookup_file(root, &strings(&["a/b", "hoon"])).is_err());
        assert!(lookup_directory(root, &strings(&["a\0b"])).is_err());
    }

    #[test]
    fn lookup_reports_all_ambiguous_file_and_directory_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join("foo.hoon"), "1").unwrap();
        std::fs::write(root.join("!foo.hoon"), "2").unwrap();
        let error = lookup_file(root, &strings(&["foo", "hoon"])).unwrap_err();
        assert!(error.contains("ambiguous filesystem aliases"), "{error}");
        assert!(
            error.contains("foo.hoon") && error.contains("!foo.hoon"),
            "{error}"
        );
        std::fs::create_dir(root.join("app")).unwrap();
        std::fs::create_dir(root.join("!app")).unwrap();
        assert!(lookup_directory(root, &strings(&["app"]))
            .unwrap_err()
            .contains("ambiguous"));
        std::fs::write(root.join("!app/only.hoon"), "1").unwrap();
        assert_eq!(
            lookup_file(root, &strings(&["app", "only", "hoon"])).unwrap(),
            Some(root.join("!app/only.hoon"))
        );
        std::fs::write(root.join("app/only.hoon"), "1").unwrap();
        assert!(lookup_file(root, &strings(&["app", "only", "hoon"]))
            .unwrap_err()
            .contains("ambiguous"));
    }

    #[test]
    fn extensionless_and_dotted_files_can_alias_the_same_clay_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("foo")).unwrap();
        std::fs::write(root.join("foo/hoon"), "1").unwrap();
        let parts = strings(&["foo", "hoon"]);
        assert_eq!(
            lookup_file(root, &parts).unwrap(),
            Some(root.join("foo/hoon"))
        );
        std::fs::write(root.join("foo.hoon"), "2").unwrap();
        let error = lookup_file(root, &parts).unwrap_err();
        assert!(error.contains("ambiguous"), "{error}");
        assert!(
            error.contains("foo.hoon") && error.contains("foo/hoon"),
            "{error}"
        );
    }

    #[test]
    fn lookup_preserves_escaped_special_components() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let directory = root.join("!/!./!../!!");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("!...!"), "1").unwrap();
        assert_eq!(
            lookup_directory(root, &strings(&["", ".", "..", "!"])).unwrap(),
            Some(directory.clone())
        );
        assert_eq!(
            lookup_file(root, &strings(&["", ".", "..", "!", "..", ""])).unwrap(),
            Some(directory.join("!...!"))
        );
        assert_eq!(lookup_directory(root, &strings(&[".."])).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn lookup_follows_symlinks_while_retaining_the_logical_path() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(target.path().join("!foo.hoon"), "1").unwrap();
        symlink(target.path(), root.join("!app")).unwrap();
        let parts = strings(&["app", "foo", "hoon"]);
        assert_eq!(
            lookup_directory(root, &strings(&["app"])).unwrap(),
            Some(root.join("!app"))
        );
        assert_eq!(
            lookup_file(root, &parts).unwrap(),
            Some(root.join("!app/!foo.hoon"))
        );
        symlink(target.path().join("!foo.hoon"), root.join("linked.hoon")).unwrap();
        assert_eq!(
            lookup_file(root, &strings(&["linked", "hoon"])).unwrap(),
            Some(root.join("linked.hoon"))
        );
        symlink(root.join("missing"), root.join("broken.hoon")).unwrap();
        assert_eq!(
            lookup_file(root, &strings(&["broken", "hoon"])).unwrap(),
            None
        );
        symlink(target.path(), root.join("app")).unwrap();
        assert!(lookup_file(root, &parts).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn components_use_veres_single_bang_escape() {
        for (clay, disk) in [
            ("", "!"),
            (".", "!."),
            ("..", "!.."),
            ("!", "!!"),
            ("!foo", "!!foo"),
            ("foo", "foo"),
            ("foo.bar", "foo.bar"),
            ("é", "é"),
        ] {
            assert_eq!(encode_component(clay).unwrap(), disk);
            assert_eq!(decode_component(disk).unwrap(), clay);
        }
        assert_eq!(decode_component("!foo").unwrap(), "foo");
        assert_eq!(decode_component("").unwrap(), "");
        for invalid in ["a/b", "a\0b"] {
            assert!(encode_component(invalid).is_err());
            assert!(decode_component(invalid).is_err());
        }
    }

    #[test]
    fn file_mapping_splits_only_the_final_dot() {
        for (disk, clay) in [
            ("app/foo.hoon", vec!["app", "foo", "hoon"]),
            ("dir.name/foo.bar.json", vec!["dir.name", "foo.bar", "json"]),
            ("!foo.!hoon", vec!["foo", "hoon"]),
            ("foo.", vec!["foo", ""]),
            (".hoon", vec!["", "hoon"]),
            ("README", vec!["README"]),
            ("!/!./!../!!.hoon", vec!["", ".", "..", "!", "hoon"]),
            ("!../!..hoon", vec!["..", ".", "hoon"]),
        ] {
            assert_eq!(from_relative_path(Path::new(disk)).unwrap(), strings(&clay));
        }
    }

    #[test]
    fn canonical_file_names_round_trip_without_traversal() {
        for (clay, disk) in [
            (vec!["app", "foo", "hoon"], "app/foo.hoon"),
            (vec!["dir.name", "foo.bar", "json"], "dir.name/foo.bar.json"),
            (vec!["", ".", "..", "!", "hoon"], "!/!./!../!!.hoon"),
            (vec![".", "hoon"], "!..hoon"),
            (vec!["..", "hoon"], "!...hoon"),
            (vec!["foo", ""], "foo.!"),
            (vec!["foo"], "foo"),
            (vec![""], "!"),
            (vec!["é", "hoon"], "é.hoon"),
        ] {
            let clay = strings(&clay);
            let encoded = to_relative_path(&clay).unwrap();
            assert_eq!(encoded, PathBuf::from(disk));
            assert_eq!(from_relative_path(&encoded).unwrap(), clay);
        }
        for clay in [
            vec![],
            vec!["foo.bar"],
            vec!["."],
            vec!["foo", "a.b"],
            vec!["foo", "."],
            vec!["foo", ".."],
        ] {
            assert!(to_relative_path(&strings(&clay)).is_err(), "{clay:?}");
        }
    }

    #[test]
    fn directory_mapping_preserves_dots_and_root() {
        let clay = strings(&["", ".", "..", "!", "foo.bar"]);
        let encoded = to_directory_path(&clay).unwrap();
        assert_eq!(encoded, PathBuf::from("!/!./!../!!/foo.bar"));
        assert_eq!(from_directory_path(&encoded).unwrap(), clay);
        assert_eq!(to_directory_path(&[]).unwrap(), PathBuf::new());
        assert_eq!(
            from_directory_path(Path::new("")).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn relative_paths_reject_normalization_and_invalid_names() {
        assert!(from_relative_path(Path::new("")).is_err());
        for disk in [
            "/foo.hoon", "./foo.hoon", "../foo.hoon", "a/../foo.hoon", "a/./foo.hoon",
            "a//foo.hoon", "a/", "a\0.hoon",
        ] {
            assert!(from_relative_path(Path::new(disk)).is_err(), "{disk:?}");
            assert!(from_directory_path(Path::new(disk)).is_err(), "{disk:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_reported_and_unix_backslashes_are_preserved() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let invalid = Path::new(OsStr::from_bytes(b"foo\xff.hoon"));
        assert!(from_relative_path(invalid).is_err());
        assert!(from_directory_path(invalid).is_err());
        let clay = strings(&["foo\\bar", "hoon"]);
        assert_eq!(
            from_relative_path(&to_relative_path(&clay).unwrap()).unwrap(),
            clay
        );
    }

    #[test]
    fn mounted_watcher_admission_is_separate_from_path_mapping() {
        for name in ["foo.hoon", "foo.bar.json", "!foo.hoon", "foo.", "!..hoon", "a~b_1.hoon"] {
            assert!(is_sync_entry(name, false), "{name:?}");
        }
        for name in [
            "", ".foo.hoon", "README", "Upper.hoon", "foo.hoon~", "foo.!", "!!foo.hoon", "é.hoon",
            "a/b.hoon", "a\0.hoon",
        ] {
            assert!(!is_sync_entry(name, false), "{name:?}");
        }
        for name in ["Upper", "extensionless", "dir~", "!!", "é"] {
            assert!(is_sync_entry(name, true), "{name:?}");
        }
        for name in ["", ".hidden", ".", "..", "a/b", "a\0b"] {
            assert!(!is_sync_entry(name, true), "{name:?}");
        }
        assert!(from_relative_path(Path::new("é.hoon")).is_ok());
        assert!(!is_sync_entry("é.hoon", false));
    }
}

/// Clay tries literal hyphens before path separators, from left to right.
/// Pruning nonexistent directories avoids enumerating every partition.
pub fn fit_path(root: &Path, category: &str, name: &str) -> Result<PathBuf, String> {
    try_fit_path(root, category, name)?.ok_or_else(|| {
        format!(
            "no desk source matches /{category}/{name}/hoon under {}",
            root.display()
        )
    })
}

pub(crate) fn try_fit_path(
    root: &Path,
    category: &str,
    name: &str,
) -> Result<Option<PathBuf>, String> {
    if !matches!(category, "lib" | "sur" | "mar") {
        return Err("a named import needs a library, structure, or mark category".into());
    }
    encode_component(name)?;
    fn find(
        root: &Path,
        prefix: &mut Vec<String>,
        parts: &[&str],
    ) -> Result<Option<PathBuf>, String> {
        let mut file = prefix.clone();
        file.extend([parts.join("-"), "hoon".into()]);
        if let Some(path) = lookup_file(root, &file)? {
            return Ok(Some(path));
        }
        if parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        }) {
            return Ok(None);
        }
        for end in (1..parts.len()).rev() {
            prefix.push(parts[..end].join("-"));
            if !matching_directories(root, prefix)?.is_empty() {
                if let Some(path) = find(root, prefix, &parts[end..])? {
                    return Ok(Some(path));
                }
            }
            prefix.pop();
        }
        Ok(None)
    }
    find(
        root,
        &mut vec![category.into()],
        &name.split('-').collect::<Vec<_>>(),
    )
}

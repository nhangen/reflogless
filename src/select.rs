use crate::error::{Error, Result};
use crate::repo::Repo;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

pub const PER_FILE_CAP_BYTES: u64 = 10 * 1024 * 1024;

pub const DEFAULT_DENY: &[&str] = &[
    "node_modules/",
    "vendor/",
    ".venv/",
    "target/",
    "dist/",
    "*.log",
];

#[derive(Debug, Clone)]
pub struct SelectedFile {
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub size: u64,
    pub mode: u32,
}

#[derive(Debug, Clone)]
pub enum Skipped {
    TooLarge { rel: PathBuf, size: u64 },
    DenyMatch { rel: PathBuf },
    Missing { rel: PathBuf },
    Unreadable { rel: PathBuf, err: String },
}

#[derive(Debug)]
pub struct Selection {
    pub files: Vec<SelectedFile>,
    pub skipped: Vec<Skipped>,
}

pub fn collect(repo: &Repo) -> Result<Selection> {
    collect_with_cap(repo, PER_FILE_CAP_BYTES, &[], &[])
}

pub fn collect_with_cap(
    repo: &Repo,
    per_file_cap: u64,
    exclude_abs: &[PathBuf],
    track: &[String],
) -> Result<Selection> {
    let entries = repo.status_porcelain()?;
    let deny = build_default_deny(&repo.root)?;
    // Canonicalize excludes so symlinked store paths still match. Skip
    // un-canonicalizable entries silently — they simply won't match.
    let excludes_canon: Vec<PathBuf> = exclude_abs
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();

    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    for e in entries {
        if !e.snapshottable() {
            continue;
        }
        let abs = repo.root.join(&e.path);
        if !abs.exists() {
            skipped.push(Skipped::Missing { rel: e.path });
            continue;
        }
        let abs_canon = std::fs::canonicalize(&abs).unwrap_or_else(|_| abs.clone());
        if excludes_canon
            .iter()
            .any(|root| abs_canon.starts_with(root))
            || exclude_abs.iter().any(|root| abs.starts_with(root))
        {
            skipped.push(Skipped::DenyMatch { rel: e.path });
            continue;
        }
        if deny.matched_path_or_any_parents(&e.path, false).is_ignore() {
            skipped.push(Skipped::DenyMatch { rel: e.path });
            continue;
        }
        let md = match std::fs::metadata(&abs) {
            Ok(m) => m,
            Err(_) => {
                skipped.push(Skipped::Missing { rel: e.path });
                continue;
            }
        };
        if md.is_dir() {
            // git status -uall lists files inside untracked dirs already; ignore the dir entry itself.
            continue;
        }
        let size = md.len();
        if size > per_file_cap {
            skipped.push(Skipped::TooLarge { rel: e.path, size });
            continue;
        }
        let mode = mode_of(&md);
        seen.insert(e.path.clone());
        files.push(SelectedFile {
            rel: e.path,
            abs,
            size,
            mode,
        });
    }

    // Defensive re-check of absolute/`..` for direct callers that bypass
    // Config::load_or_default validation (in-tree tests). Production callers
    // hit the rejection at parse time.
    for t in track {
        let rel = PathBuf::from(t);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(Error::Config(format!(
                "track entry {t:?} must be a repo-relative path without `..`"
            )));
        }
        if seen.contains(&rel) {
            continue;
        }
        let abs = repo.root.join(&rel);
        let md = match std::fs::metadata(&abs) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                skipped.push(Skipped::Unreadable {
                    rel: rel.clone(),
                    err: e.to_string(),
                });
                continue;
            }
        };
        if !md.is_file() {
            continue;
        }
        let abs_canon = std::fs::canonicalize(&abs).unwrap_or_else(|_| abs.clone());
        if excludes_canon
            .iter()
            .any(|root| abs_canon.starts_with(root))
            || exclude_abs.iter().any(|root| abs.starts_with(root))
        {
            skipped.push(Skipped::DenyMatch { rel: rel.clone() });
            continue;
        }
        let size = md.len();
        if size > per_file_cap {
            skipped.push(Skipped::TooLarge { rel, size });
            continue;
        }
        let mode = mode_of(&md);
        seen.insert(rel.clone());
        files.push(SelectedFile {
            rel,
            abs,
            size,
            mode,
        });
    }

    Ok(Selection { files, skipped })
}

#[cfg(unix)]
fn mode_of(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    md.mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_md: &std::fs::Metadata) -> u32 {
    0o644
}

fn build_default_deny(root: &Path) -> Result<Gitignore> {
    let mut b = GitignoreBuilder::new(root);
    for pat in DEFAULT_DENY {
        b.add_line(None, pat)
            .map_err(|e| Error::Config(format!("invalid default-deny pattern {pat:?}: {e}")))?;
    }
    let extra = root.join(".refloglessignore");
    if extra.exists() {
        if let Some(e) = b.add(&extra) {
            return Err(Error::Config(format!(
                ".refloglessignore at {} is malformed: {e}",
                extra.display()
            )));
        }
    }
    b.build()
        .map_err(|e| Error::Config(format!("could not build deny matcher: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn make_repo(td: &Path) -> Repo {
        Command::new("git").arg("init").arg("-q").arg(td).status().unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.email", "t@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.name", "t"])
            .status()
            .unwrap();
        Repo::discover(td).unwrap()
    }

    #[test]
    fn track_captures_gitignored_file() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        std::fs::write(td.path().join(".gitignore"), b".env\n").unwrap();
        std::fs::write(td.path().join(".env"), b"SECRET=1\n").unwrap();

        let no_track = collect_with_cap(&repo, PER_FILE_CAP_BYTES, &[], &[]).unwrap();
        assert!(
            !no_track.files.iter().any(|f| f.rel == Path::new(".env")),
            "without track, gitignored .env must not be captured"
        );

        let with_track =
            collect_with_cap(&repo, PER_FILE_CAP_BYTES, &[], &[".env".to_string()]).unwrap();
        assert!(
            with_track.files.iter().any(|f| f.rel == Path::new(".env")),
            "with track, .env must be captured even though gitignored"
        );
    }

    #[test]
    fn track_missing_file_is_silent_skip() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let sel =
            collect_with_cap(&repo, PER_FILE_CAP_BYTES, &[], &[".env".to_string()]).unwrap();
        assert!(sel.files.is_empty());
        assert!(
            sel.skipped.is_empty(),
            "missing track entry must not produce a Skipped record"
        );
    }

    #[test]
    fn track_entry_already_in_git_status_is_deduped() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        std::fs::write(td.path().join("notes.txt"), b"hi\n").unwrap();
        let sel =
            collect_with_cap(&repo, PER_FILE_CAP_BYTES, &[], &["notes.txt".to_string()]).unwrap();
        let count = sel
            .files
            .iter()
            .filter(|f| f.rel == Path::new("notes.txt"))
            .count();
        assert_eq!(count, 1, "notes.txt should appear exactly once, not duplicated");
    }

    #[test]
    fn track_overrides_default_deny() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        std::fs::write(td.path().join(".gitignore"), b"*.log\n").unwrap();
        std::fs::write(td.path().join("important.log"), b"keep me\n").unwrap();
        let sel = collect_with_cap(
            &repo,
            PER_FILE_CAP_BYTES,
            &[],
            &["important.log".to_string()],
        )
        .unwrap();
        assert!(
            sel.files.iter().any(|f| f.rel == Path::new("important.log")),
            "track must override *.log default-deny"
        );
    }

    #[test]
    fn track_rejects_absolute_path() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let err = collect_with_cap(
            &repo,
            PER_FILE_CAP_BYTES,
            &[],
            &["/etc/passwd".to_string()],
        )
        .unwrap_err();
        match err {
            Error::Config(msg) => assert!(msg.contains("repo-relative"), "msg={msg}"),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn track_rejects_parent_dir_traversal() {
        let td = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let err = collect_with_cap(
            &repo,
            PER_FILE_CAP_BYTES,
            &[],
            &["../escape.txt".to_string()],
        )
        .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn default_deny_blocks_logs_and_node_modules() {
        let td = TempDir::new().unwrap();
        let g = build_default_deny(td.path()).unwrap();
        assert!(g.matched("foo.log", false).is_ignore());
        assert!(g
            .matched_path_or_any_parents("node_modules/x.js", false)
            .is_ignore());
        assert!(!g.matched("src/main.rs", false).is_ignore());
    }

    #[test]
    fn malformed_refloglessignore_returns_config_error() {
        let td = TempDir::new().unwrap();
        std::fs::write(td.path().join(".refloglessignore"), b"\\\n").unwrap();
        let err = build_default_deny(td.path()).unwrap_err();
        match err {
            Error::Config(msg) => assert!(msg.contains(".refloglessignore"), "msg={msg}"),
            other => panic!("expected Config error, got {other:?}"),
        }
    }
}

use crate::error::{Error, Result};
use crate::repo::Repo;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};

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
}

pub struct Selection {
    pub files: Vec<SelectedFile>,
    pub skipped: Vec<Skipped>,
}

pub fn collect(repo: &Repo) -> Result<Selection> {
    collect_with_cap(repo, PER_FILE_CAP_BYTES, &[])
}

pub fn collect_with_cap(
    repo: &Repo,
    per_file_cap: u64,
    exclude_abs: &[PathBuf],
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
        if excludes_canon.iter().any(|root| abs_canon.starts_with(root))
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
        files.push(SelectedFile {
            rel: e.path,
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
    use tempfile::TempDir;

    #[test]
    fn default_deny_blocks_logs_and_node_modules() {
        let td = TempDir::new().unwrap();
        let g = build_default_deny(td.path()).unwrap();
        assert!(g.matched("foo.log", false).is_ignore());
        assert!(g.matched_path_or_any_parents("node_modules/x.js", false).is_ignore());
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

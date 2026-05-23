use crate::error::{Error, Result};
use crate::repo::Repo;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const HOOKS: &[&str] = &[
    "post-checkout",
    "pre-rebase",
    "post-rewrite",
    "reference-transaction",
];

pub const MARKER: &str = "# gitsafe-managed (do not edit manually)";
pub const MARKER_VERSION: &str = "# gitsafe-hook-version: 1";

#[derive(Debug)]
pub struct InstallReport {
    pub hooks_dir: PathBuf,
    pub installed: Vec<String>,
    pub chained: Vec<String>,
}

#[derive(Debug, Default)]
pub struct UninstallReport {
    pub removed: Vec<String>,
    pub restored: Vec<String>,
    pub skipped: Vec<String>,
}

/// Resolves the directory where git looks for hooks for this repo, honoring
/// `core.hooksPath` if set (husky, lefthook, custom).
pub fn hooks_dir(repo: &Repo) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["-C"])
        .arg(&repo.root)
        .args(["config", "--get", "core.hooksPath"])
        .output()
        .map_err(|e| Error::Git(format!("git config: {e}")))?;
    let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !trimmed.is_empty() {
        let p = PathBuf::from(&trimmed);
        return Ok(if p.is_absolute() {
            p
        } else {
            repo.root.join(p)
        });
    }
    Ok(repo.root.join(".git").join("hooks"))
}

pub fn install(repo: &Repo, hook_log_path: &Path) -> Result<InstallReport> {
    let dir = hooks_dir(repo)?;
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let mut installed = Vec::new();
    let mut chained = Vec::new();
    for hook in HOOKS {
        let path = dir.join(hook);
        if path.exists() {
            let existing = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
            if existing.contains(MARKER) {
                write_hook(&path, hook, hook_log_path, None)?;
                installed.push((*hook).to_string());
                continue;
            }
            // Preserve and chain existing third-party hook.
            let backup = path.with_extension("gitsafe-orig");
            if !backup.exists() {
                fs::copy(&path, &backup).map_err(|e| Error::io(&backup, e))?;
            }
            write_hook(&path, hook, hook_log_path, Some(&backup))?;
            chained.push((*hook).to_string());
        } else {
            write_hook(&path, hook, hook_log_path, None)?;
            installed.push((*hook).to_string());
        }
    }
    Ok(InstallReport {
        hooks_dir: dir,
        installed,
        chained,
    })
}

pub fn uninstall(repo: &Repo) -> Result<UninstallReport> {
    let dir = hooks_dir(repo)?;
    let mut report = UninstallReport::default();
    for hook in HOOKS {
        let path = dir.join(hook);
        if !path.exists() {
            continue;
        }
        let body = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        if !body.contains(MARKER) {
            report.skipped.push((*hook).to_string());
            continue;
        }
        let backup = path.with_extension("gitsafe-orig");
        if backup.exists() {
            fs::rename(&backup, &path).map_err(|e| Error::io(&path, e))?;
            report.restored.push((*hook).to_string());
        } else {
            fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
            report.removed.push((*hook).to_string());
        }
    }
    Ok(report)
}

fn write_hook(
    path: &Path,
    hook: &str,
    hook_log_path: &Path,
    prior: Option<&Path>,
) -> Result<()> {
    let body = build_hook_body(hook, hook_log_path, prior);
    fs::write(path, &body).map_err(|e| Error::io(path, e))?;
    make_executable(path)?;
    Ok(())
}

fn build_hook_body(hook: &str, hook_log_path: &Path, prior: Option<&Path>) -> String {
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    s.push_str(MARKER);
    s.push('\n');
    s.push_str(MARKER_VERSION);
    s.push('\n');
    s.push_str(&format!("# hook: {hook}\n"));
    // Best-effort snap. Never block the underlying git op. Stderr is captured
    // to a per-store log so `gitsafe doctor` can surface silent failures.
    // The default log path is single-quote-escaped in a separate assignment
    // (POSIX parameter expansion defaults do not honor inline single quotes
    // when the whole expression is double-quoted).
    let log_q = sh_squote(hook_log_path);
    s.push_str(&format!("__GITSAFE_DEFAULT_LOG={log_q}\n"));
    s.push_str("GITSAFE_HOOK_LOG=\"${GITSAFE_HOOK_LOG:-$__GITSAFE_DEFAULT_LOG}\"\n");
    s.push_str(&format!(
        "gitsafe snap --event {hook} 2>>\"$GITSAFE_HOOK_LOG\" >/dev/null || true\n"
    ));
    if let Some(p) = prior {
        let q = sh_squote(p);
        s.push_str(&format!(
            "if [ -x {q} ]; then\n  exec {q} \"$@\"\nfi\n"
        ));
    }
    s.push_str("exit 0\n");
    s
}

/// POSIX-shell single-quote a path. Single quotes inside the path are escaped
/// via the standard `'\''` end-quote-escape-start-quote trick.
fn sh_squote(p: &Path) -> String {
    let mut out = String::with_capacity(p.as_os_str().len() + 2);
    out.push('\'');
    for ch in p.to_string_lossy().chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).map_err(|e| Error::io(path, e))?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(|e| Error::io(path, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo(td: &Path) -> Repo {
        Command::new("git").arg("init").arg("-q").arg(td).status().unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.email", "t@t"])
            .status()
            .unwrap();
        Command::new("git")
            .args(["-C", td.to_str().unwrap(), "config", "user.name", "t"])
            .status()
            .unwrap();
        Repo::discover(td).unwrap()
    }

    #[test]
    fn install_writes_all_four_hooks() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let log = repo.root.join("hook-errors.log");
        let report = install(&repo, &log).unwrap();
        assert_eq!(report.installed.len(), 4);
        assert!(report.chained.is_empty());
        for hook in HOOKS {
            let p = repo.root.join(".git").join("hooks").join(hook);
            let body = fs::read_to_string(&p).unwrap();
            assert!(body.contains(MARKER), "{hook} missing marker");
            assert!(body.contains(&format!("gitsafe snap --event {hook}")));
        }
    }

    #[test]
    fn install_chains_existing_hook() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        let existing = hooks.join("post-checkout");
        fs::write(&existing, "#!/bin/sh\necho husky\n").unwrap();
        make_executable(&existing).unwrap();
        let log = repo.root.join("hook-errors.log");
        let report = install(&repo, &log).unwrap();
        assert!(report.chained.contains(&"post-checkout".to_string()));
        let backup = hooks.join("post-checkout.gitsafe-orig");
        assert!(backup.exists(), "backup not preserved");
        let body = fs::read_to_string(&existing).unwrap();
        assert!(body.contains("gitsafe snap --event post-checkout"));
        assert!(body.contains("post-checkout.gitsafe-orig"));
        // Chained exec must single-quote the prior path for POSIX safety.
        assert!(body.contains("exec '"));
    }

    #[test]
    fn sh_squote_escapes_dollar_and_backtick() {
        let p = std::path::Path::new("/tmp/foo$bar`baz/file");
        let q = sh_squote(p);
        assert_eq!(q, "'/tmp/foo$bar`baz/file'");
    }

    #[test]
    fn sh_squote_escapes_embedded_single_quote() {
        let p = std::path::Path::new("/tmp/it's-a-path");
        let q = sh_squote(p);
        assert_eq!(q, "'/tmp/it'\\''s-a-path'");
    }

    #[test]
    fn build_hook_body_is_posix_valid() {
        use std::process::Command;
        let path = std::path::PathBuf::from("/tmp/foo$bar/post-checkout.gitsafe-orig");
        let log = std::path::PathBuf::from("/tmp/foo$bar/log");
        let body = build_hook_body("post-checkout", &log, Some(&path));
        // `sh -n` parses the script without executing — catches quoting bugs.
        let mut child = Command::new("sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "sh -n rejected hook body:\n{body}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn install_is_idempotent() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let body_v1 = fs::read_to_string(
            repo.root.join(".git").join("hooks").join("post-checkout"),
        )
        .unwrap();
        let log = repo.root.join("hook-errors.log");
        let report = install(&repo, &log).unwrap();
        // Second install should refresh, not chain.
        assert!(report.chained.is_empty());
        let body_v2 = fs::read_to_string(
            repo.root.join(".git").join("hooks").join("post-checkout"),
        )
        .unwrap();
        assert_eq!(body_v1, body_v2);
    }

    #[test]
    fn uninstall_removes_gitsafe_hooks() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let report = uninstall(&repo).unwrap();
        assert_eq!(report.removed.len(), 4);
        for hook in HOOKS {
            assert!(!repo.root.join(".git").join("hooks").join(hook).exists());
        }
    }

    #[test]
    fn uninstall_restores_chained_third_party_hook() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        let p = hooks.join("post-checkout");
        fs::write(&p, "#!/bin/sh\necho husky\n").unwrap();
        make_executable(&p).unwrap();
        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let report = uninstall(&repo).unwrap();
        assert!(report.restored.contains(&"post-checkout".to_string()));
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(body, "#!/bin/sh\necho husky\n");
        assert!(!hooks.join("post-checkout.gitsafe-orig").exists());
    }

    #[test]
    fn uninstall_leaves_foreign_hook_untouched() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        let p = hooks.join("post-checkout");
        fs::write(&p, "#!/bin/sh\necho not-ours\n").unwrap();
        let report = uninstall(&repo).unwrap();
        assert!(report.skipped.contains(&"post-checkout".to_string()));
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(body, "#!/bin/sh\necho not-ours\n");
    }

    #[cfg(unix)]
    #[test]
    fn install_marks_hooks_executable() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        for h in HOOKS {
            let p = repo.root.join(".git").join("hooks").join(h);
            let mode = fs::metadata(&p).unwrap().permissions().mode();
            assert!(
                mode & 0o111 != 0,
                "{h} not executable: mode={mode:o}"
            );
        }
    }

    #[test]
    fn install_on_non_repo_errors() {
        let td = TempDir::new().unwrap();
        // No `git init` — discovery should fail.
        let err = Repo::discover(td.path()).unwrap_err();
        assert!(matches!(err, crate::Error::NotARepo(_)), "got {err:?}");
    }

    #[test]
    fn uninstall_is_idempotent() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let log = repo.root.join("hook-errors.log");
        install(&repo, &log).unwrap();
        let r1 = uninstall(&repo).unwrap();
        assert_eq!(r1.removed.len(), 4);
        let r2 = uninstall(&repo).unwrap();
        assert_eq!(r2.removed.len(), 0);
        assert_eq!(r2.restored.len(), 0);
        assert_eq!(r2.skipped.len(), 0);
    }

    #[test]
    fn hooks_dir_honors_custom_hookspath() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let custom = repo.root.join(".husky");
        Command::new("git")
            .args([
                "-C",
                repo.root.to_str().unwrap(),
                "config",
                "core.hooksPath",
                ".husky",
            ])
            .status()
            .unwrap();
        let resolved = hooks_dir(&repo).unwrap();
        assert_eq!(resolved, custom);
    }
}

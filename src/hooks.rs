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

pub const MARKER: &str = "# reflogless-managed (do not edit manually)";
pub const MARKER_VERSION: &str = "# reflogless-hook-version: 2";

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
    let repo_id = repo.id();
    let dir = hooks_dir(repo)?;
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let mut installed = Vec::new();
    let mut chained = Vec::new();
    for hook in HOOKS {
        let path = dir.join(hook);
        if path.exists() {
            let existing = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
            if existing.contains(MARKER) {
                write_hook(&path, hook, hook_log_path, &repo_id, None)?;
                installed.push((*hook).to_string());
                continue;
            }
            // Preserve and chain existing third-party hook.
            let backup = path.with_extension("reflogless-orig");
            if !backup.exists() {
                fs::copy(&path, &backup).map_err(|e| Error::io(&backup, e))?;
            }
            write_hook(&path, hook, hook_log_path, &repo_id, Some(&backup))?;
            chained.push((*hook).to_string());
        } else {
            write_hook(&path, hook, hook_log_path, &repo_id, None)?;
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
        let backup = path.with_extension("reflogless-orig");
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
    repo_id: &str,
    prior: Option<&Path>,
) -> Result<()> {
    let body = build_hook_body(hook, hook_log_path, repo_id, prior);
    fs::write(path, &body).map_err(|e| Error::io(path, e))?;
    make_executable(path)?;
    Ok(())
}

fn build_hook_body(hook: &str, hook_log_path: &Path, repo_id: &str, prior: Option<&Path>) -> String {
    // Shell injection guard: repo_id is interpolated unescaped into the
    // generated script. `repo.id()` produces 16 hex chars; if that ever
    // changes, the format! sites below become a shell-injection surface.
    debug_assert!(
        repo_id.len() == 16 && repo_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "repo_id must be 16 ascii hex chars; got {repo_id:?}"
    );
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    s.push_str(MARKER);
    s.push('\n');
    s.push_str(MARKER_VERSION);
    s.push('\n');
    s.push_str(&format!("# hook: {hook}\n"));
    // Resolve the log path at hook *run* time, not install time, so a hook
    // installed under one HOME (host) writes to the store another HOME
    // (container) uses. Priority matches `store::base_data_dir`; install-time
    // absolute path is the no-HOME fallback. Windows shells (MSYS/Cygwin)
    // route to the fallback because `dirs::data_dir()` picks %APPDATA% there,
    // which the POSIX branches can't replicate.
    let fallback_q = sh_squote(hook_log_path);
    s.push_str(&format!("__REFLOGLESS_FALLBACK_LOG={fallback_q}\n"));
    s.push_str(&format!(
        "if [ -n \"${{REFLOGLESS_DATA_DIR:-}}\" ]; then\n  \
            __REFLOGLESS_DEFAULT_LOG=\"$REFLOGLESS_DATA_DIR/reflogless/{repo_id}/hook-errors.log\"\n\
        elif [ -n \"${{XDG_DATA_HOME:-}}\" ]; then\n  \
            __REFLOGLESS_DEFAULT_LOG=\"$XDG_DATA_HOME/reflogless/{repo_id}/hook-errors.log\"\n\
        elif [ -n \"${{HOME:-}}\" ]; then\n  \
            case \"$(uname -s 2>/dev/null)\" in\n    \
                Darwin) __REFLOGLESS_DEFAULT_LOG=\"$HOME/Library/Application Support/reflogless/{repo_id}/hook-errors.log\" ;;\n    \
                MINGW*|MSYS*|CYGWIN*) __REFLOGLESS_DEFAULT_LOG=\"$__REFLOGLESS_FALLBACK_LOG\" ;;\n    \
                *) __REFLOGLESS_DEFAULT_LOG=\"$HOME/.local/share/reflogless/{repo_id}/hook-errors.log\" ;;\n  \
            esac\n\
        else\n  \
            __REFLOGLESS_DEFAULT_LOG=\"$__REFLOGLESS_FALLBACK_LOG\"\n\
        fi\n"
    ));
    s.push_str("REFLOGLESS_HOOK_LOG=\"${REFLOGLESS_HOOK_LOG:-$__REFLOGLESS_DEFAULT_LOG}\"\n");
    // Defense in depth so the redirect below never leaks ENOENT to git's
    // stderr (the WSL-install / Git-for-Windows-run case from #67):
    //   1. mkdir -p the resolved parent; on failure, fall to install-time.
    //   2. If even the install-time parent is absent, redirect to /dev/null.
    s.push_str(
        "mkdir -p \"$(dirname \"$REFLOGLESS_HOOK_LOG\")\" 2>/dev/null \
         || REFLOGLESS_HOOK_LOG=\"$__REFLOGLESS_FALLBACK_LOG\"\n",
    );
    s.push_str(
        "[ -d \"$(dirname \"$REFLOGLESS_HOOK_LOG\")\" ] || REFLOGLESS_HOOK_LOG=/dev/null\n",
    );
    s.push_str(&format!(
        "reflogless snap --event {hook} 2>>\"$REFLOGLESS_HOOK_LOG\" >/dev/null || true\n"
    ));
    if let Some(p) = prior {
        let q = sh_squote(p);
        s.push_str(&format!("if [ -x {q} ]; then\n  exec {q} \"$@\"\nfi\n"));
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
    let mut perms = fs::metadata(path)
        .map_err(|e| Error::io(path, e))?
        .permissions();
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
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td)
            .status()
            .unwrap();
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
            assert!(body.contains(&format!("reflogless snap --event {hook}")));
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
        let backup = hooks.join("post-checkout.reflogless-orig");
        assert!(backup.exists(), "backup not preserved");
        let body = fs::read_to_string(&existing).unwrap();
        assert!(body.contains("reflogless snap --event post-checkout"));
        assert!(body.contains("post-checkout.reflogless-orig"));
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

    /// #67-style: install-time path's parent absent at hook-run time AND the
    /// resolver can't reach a writable dir either. Hook must redirect to
    /// /dev/null rather than leaking ENOENT to git's stderr. Run with
    /// `env -i` so the resolver hits the no-env fallback branch.
    /// #67-style: install-time path's parent absent at hook-run time AND
    /// mkdir -p can't create it (we point at `/dev/null/...` so mkdir errors
    /// with ENOTDIR). The final `[ -d ] || =/dev/null` tier must catch this
    /// and stop the redirect from leaking ENOENT to git's stderr.
    #[cfg(unix)]
    #[test]
    fn hook_fallback_to_dev_null_when_no_writable_log_dir() {
        let td = TempDir::new().unwrap();
        // /dev/null is a char device, not a directory — mkdir -p underneath
        // it returns ENOTDIR, exercising the final /dev/null tier rather
        // than the mkdir-p recovery branch.
        let fallback = std::path::PathBuf::from("/dev/null/cantwrite/hook-errors.log");
        let body = build_hook_body("reference-transaction", &fallback, "0123456789abcdef", None);
        let script = td.path().join("test-hook.sh");
        fs::write(&script, &body).unwrap();
        make_executable(&script).unwrap();
        // env -i with PATH only — strips REFLOGLESS_DATA_DIR/XDG/HOME so the
        // resolver picks the fallback path, then both mkdir-p and the
        // [ -d ] check on the fallback fail.
        let path_env = std::env::var("PATH").unwrap_or_default();
        let out = Command::new("env")
            .arg("-i")
            .arg(format!("PATH={path_env}"))
            .arg("sh")
            .arg(&script)
            .arg("prepared")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.is_empty(),
            "hook must not leak stderr when no writable log dir exists; got: {stderr}"
        );
    }

    /// Run the generated hook body under controlled env and return the path
    /// the resolver chose for `REFLOGLESS_HOOK_LOG`. Strips the snap+exit
    /// suffix so the script doesn't try to exec `reflogless` from PATH.
    /// The fallback path is also a real tempdir so `mkdir -p` succeeds and
    /// doesn't mask the resolved value.
    fn resolved_log_path(env: &[(&str, &std::path::Path)], fallback: &std::path::Path) -> String {
        let body = build_hook_body("post-checkout", fallback, "0123456789abcdef", None);
        let probe = match body.find("reflogless snap --event") {
            Some(i) => format!("{}echo \"$REFLOGLESS_HOOK_LOG\"\nexit 0\n", &body[..i]),
            None => panic!("hook body missing snap line"),
        };
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(probe).env_clear();
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("sh failed");
        assert!(
            out.status.success(),
            "sh exited {:?}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn resolver_branch_reflogless_data_dir_wins() {
        let runtime = TempDir::new().unwrap();
        let xdg = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let fb = TempDir::new().unwrap();
        let got = resolved_log_path(
            &[
                ("REFLOGLESS_DATA_DIR", runtime.path()),
                ("XDG_DATA_HOME", xdg.path()),
                ("HOME", home.path()),
            ],
            &fb.path().join("install.log"),
        );
        assert_eq!(
            got,
            runtime
                .path()
                .join("reflogless/0123456789abcdef/hook-errors.log")
                .to_string_lossy()
        );
    }

    #[test]
    fn resolver_branch_xdg_data_home_wins_over_home() {
        let xdg = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let fb = TempDir::new().unwrap();
        let got = resolved_log_path(
            &[("XDG_DATA_HOME", xdg.path()), ("HOME", home.path())],
            &fb.path().join("install.log"),
        );
        assert_eq!(
            got,
            xdg.path()
                .join("reflogless/0123456789abcdef/hook-errors.log")
                .to_string_lossy()
        );
    }

    #[test]
    fn resolver_branch_home_picks_platform_default() {
        let home = TempDir::new().unwrap();
        let fb = TempDir::new().unwrap();
        let got = resolved_log_path(
            &[("HOME", home.path())],
            &fb.path().join("install.log"),
        );
        let uname = Command::new("uname").arg("-s").output().unwrap();
        let uname_s = String::from_utf8_lossy(&uname.stdout).trim().to_string();
        let expected = match uname_s.as_str() {
            "Darwin" => home
                .path()
                .join("Library/Application Support/reflogless/0123456789abcdef/hook-errors.log")
                .to_string_lossy()
                .to_string(),
            s if s.starts_with("MINGW") || s.starts_with("MSYS") || s.starts_with("CYGWIN") => {
                fb.path().join("install.log").to_string_lossy().to_string()
            }
            _ => home
                .path()
                .join(".local/share/reflogless/0123456789abcdef/hook-errors.log")
                .to_string_lossy()
                .to_string(),
        };
        assert_eq!(got, expected, "uname={uname_s:?}");
    }

    #[test]
    fn resolver_branch_no_env_falls_back_to_install_time_path() {
        let fb = TempDir::new().unwrap();
        let got = resolved_log_path(&[], &fb.path().join("install.log"));
        assert_eq!(got, fb.path().join("install.log").to_string_lossy());
    }

    #[test]
    fn resolver_devcontainer_scenario_uses_runtime_home_not_install_path() {
        // Bug being fixed: install under HOME=A bakes A's path; container
        // runs hook under HOME=B. Resolver must pick B's path, not A's.
        let install_home = TempDir::new().unwrap();
        let runtime_home = TempDir::new().unwrap();
        let got = resolved_log_path(
            &[("HOME", runtime_home.path())],
            &install_home.path().join("install.log"),
        );
        let uname = Command::new("uname").arg("-s").output().unwrap();
        let uname_s = String::from_utf8_lossy(&uname.stdout).trim().to_string();
        if uname_s.starts_with("MINGW") || uname_s.starts_with("MSYS") || uname_s.starts_with("CYGWIN") {
            return;
        }
        let runtime_prefix = runtime_home.path().to_string_lossy().to_string();
        let install_prefix = install_home.path().to_string_lossy().to_string();
        assert!(
            got.starts_with(&runtime_prefix),
            "expected runtime HOME to win; got {got:?}"
        );
        assert!(
            !got.starts_with(&install_prefix),
            "must not have used install-time path; got {got:?}"
        );
    }

    #[test]
    fn build_hook_body_is_posix_valid() {
        use std::process::Command;
        let path = std::path::PathBuf::from("/tmp/foo$bar/post-checkout.reflogless-orig");
        let log = std::path::PathBuf::from("/tmp/foo$bar/log");
        let body = build_hook_body("post-checkout", &log, "0123456789abcdef", Some(&path));
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
        let body_v1 =
            fs::read_to_string(repo.root.join(".git").join("hooks").join("post-checkout")).unwrap();
        let log = repo.root.join("hook-errors.log");
        let report = install(&repo, &log).unwrap();
        // Second install should refresh, not chain.
        assert!(report.chained.is_empty());
        let body_v2 =
            fs::read_to_string(repo.root.join(".git").join("hooks").join("post-checkout")).unwrap();
        assert_eq!(body_v1, body_v2);
    }

    #[test]
    fn uninstall_removes_reflogless_hooks() {
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
        assert!(!hooks.join("post-checkout.reflogless-orig").exists());
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
            assert!(mode & 0o111 != 0, "{h} not executable: mode={mode:o}");
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

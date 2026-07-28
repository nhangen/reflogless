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
    /// Set when `core.hooksPath` named a directory outside this repo, so hooks
    /// went to the repo's own hooks dir instead. Callers surface this.
    pub declined_hooks_path: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct UninstallReport {
    pub removed: Vec<String>,
    pub restored: Vec<String>,
    pub skipped: Vec<String>,
    /// Entries that exist but couldn't be read, so ownership is unknown and they
    /// were left in place. Reported separately from `skipped` — a skipped hook is
    /// known to be someone else's; these might be ours and still firing.
    pub unreadable: Vec<String>,
    pub declined_hooks_path: Option<PathBuf>,
}

/// The repo's own hooks directory — the one git uses absent `core.hooksPath`.
///
/// Resolved through the git **common** dir. Two wrong answers to avoid: `root/.git`
/// is a *file* in a linked worktree, and the per-worktree `git_dir()` is a
/// directory git never reads hooks from. Only the common dir matches what
/// `git rev-parse --git-path hooks` reports. See `Repo::git_common_dir`.
fn own_hooks_dir(repo: &Repo) -> PathBuf {
    repo.git_common_dir().join("hooks")
}

/// `core.hooksPath` as git resolves it for this repo, or `None` if unset.
fn configured_hooks_path(repo: &Repo) -> Result<Option<PathBuf>> {
    let out = Command::new("git")
        .args(["-C"])
        .arg(&repo.root)
        .args(["config", "--get", "core.hooksPath"])
        .output()
        .map_err(|e| Error::Git(format!("git config: {e}")))?;
    let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || trimmed.is_empty() {
        return Ok(None);
    }
    let p = PathBuf::from(&trimmed);
    Ok(Some(if p.is_absolute() {
        p
    } else {
        repo.root.join(p)
    }))
}

/// Resolves the directory where git looks for hooks for this repo, honoring
/// `core.hooksPath` if set (husky, lefthook, custom).
pub fn hooks_dir(repo: &Repo) -> Result<PathBuf> {
    Ok(configured_hooks_path(repo)?.unwrap_or_else(|| own_hooks_dir(repo)))
}

/// Where reflogless will actually write, plus the path it declined if any.
#[derive(Debug)]
pub struct HooksTarget {
    pub dir: PathBuf,
    pub declined: Option<PathBuf>,
}

/// Canonicalize as much of `p` as exists, keeping the rest verbatim.
///
/// `fs::canonicalize` is all-or-nothing: one missing component and it fails, so a
/// not-yet-created directory would be compared raw (`/var/...`) against an
/// already-canonical root (`/private/var/...`) and spuriously look foreign. Since
/// `install` *creates* its target, that path is the common case, not the edge one.
fn canonicalize_existing(p: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.file_name().map(|s| s.to_owned()), cur.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Is `dir` this repo's own hooks territory rather than machine-wide infrastructure?
///
/// Accepts the working tree and the git **common** dir. The common dir is the
/// right boundary: it is where git reads hooks from, it contains `git_dir()` for a
/// linked worktree, and for a primary worktree the two coincide. Testing
/// `git_dir()` instead rejected `main/.git/hooks` — git's own answer for a linked
/// worktree — while telling the user it was machine-shared.
///
/// Both sides are canonicalized as far as they exist so symlinked prefixes
/// (`/var` vs `/private/var`) and not-yet-created directories compare in one
/// namespace.
fn is_within_repo(repo: &Repo, dir: &Path) -> bool {
    let dir_c = canonicalize_existing(dir);
    dir_c.starts_with(canonicalize_existing(&repo.root))
        || dir_c.starts_with(canonicalize_existing(&repo.git_common_dir()))
}

/// Resolve the write target, declining a `core.hooksPath` that lives outside the
/// repo rather than failing.
///
/// A `core.hooksPath` set *globally* names shared infrastructure used by every
/// repo on the machine — commonly a directory of symlinks pointing at one
/// dispatcher. Writing there takes that dispatcher over for every repo, and
/// uninstalling deletes entries reflogless never owned (#73). Refusing outright is
/// no better: `install` then fails on every repo of such a machine.
///
/// So the foreign path is declined and the write goes to the repo's own hooks dir.
/// **This only helps if the configured dispatcher execs the repo's hook, and that
/// is an assumption, not a convention** — husky and lefthook (named in
/// `hooks_dir`'s docs) do not chain. When it doesn't hold, git runs the configured
/// path and never reaches what we installed, so `doctor` checks for that
/// explicitly instead of trusting the assumption: see `shadowed_hooks`.
///
/// `install`, `uninstall`, and `doctor` all resolve through here so they cannot
/// disagree about where hooks live.
pub(crate) fn resolve_hooks_target(repo: &Repo) -> Result<HooksTarget> {
    match configured_hooks_path(repo)? {
        Some(p) if is_within_repo(repo, &p) => Ok(HooksTarget {
            dir: p,
            declined: None,
        }),
        Some(p) => Ok(HooksTarget {
            dir: own_hooks_dir(repo),
            declined: Some(p),
        }),
        None => Ok(HooksTarget {
            dir: own_hooks_dir(repo),
            declined: None,
        }),
    }
}

pub fn install(repo: &Repo, hook_log_path: &Path) -> Result<InstallReport> {
    let repo_id = repo.id();
    let HooksTarget { dir, declined } = resolve_hooks_target(repo)?;
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let mut installed = Vec::new();
    let mut chained = Vec::new();
    for hook in HOOKS {
        let path = dir.join(hook);
        let backup = path.with_extension("reflogless-orig");
        match read_entry(&path) {
            Entry::Missing => {
                write_hook(&path, hook, hook_log_path, &repo_id, None)?;
                installed.push((*hook).to_string());
            }
            // Already ours. Re-chain if a backup is present: passing `None` here
            // rewrote the wrapper without its `exec`, so a second `install`
            // silently stopped running a third-party hook it had preserved.
            Entry::Body(body) if body.contains(MARKER) => {
                let prior = fs::symlink_metadata(&backup)
                    .is_ok()
                    .then_some(backup.as_path());
                write_hook(&path, hook, hook_log_path, &repo_id, prior)?;
                if prior.is_some() {
                    chained.push((*hook).to_string());
                } else {
                    installed.push((*hook).to_string());
                }
            }
            // A link with nothing behind it: `fs::copy` would fail ENOENT and abort
            // the install part-way through. There is no body to preserve, so
            // replace it outright.
            Entry::Symlink { dangling: true } => {
                write_hook(&path, hook, hook_log_path, &repo_id, None)?;
                installed.push((*hook).to_string());
            }
            // Foreign, or unreadable and therefore assumed foreign. Preserve and
            // chain. `fs::copy` resolves a link, so the backup holds the real body
            // and stays runnable after we replace the entry.
            Entry::Symlink { dangling: false } | Entry::Unreadable(_) | Entry::Body(_) => {
                if fs::symlink_metadata(&backup).is_err() {
                    fs::copy(&path, &backup).map_err(|e| Error::io(&path, e))?;
                }
                write_hook(&path, hook, hook_log_path, &repo_id, Some(&backup))?;
                chained.push((*hook).to_string());
            }
        }
    }
    Ok(InstallReport {
        hooks_dir: dir,
        installed,
        chained,
        declined_hooks_path: declined,
    })
}

/// What is sitting at a hook entry path.
///
/// Four outcomes rather than a body string, because collapsing them loses the two
/// distinctions the callers need: `install` must not follow a symlink (writing
/// through one destroyed a shared dispatcher — #73), and `doctor` must not report
/// "someone else owns this hook" when the truth is "I could not read it".
pub(crate) enum Entry {
    Missing,
    /// A symlink. Classified without following it: `read_to_string` would report
    /// the *target's* body, which for a shared dispatcher is not this entry's
    /// content. `dangling` distinguishes a link with nothing behind it — there is
    /// no body to preserve, so it is replaced rather than backed up.
    Symlink {
        dangling: bool,
    },
    /// Present but unreadable — permissions, I/O error, non-UTF-8, or a directory.
    /// Carries the reason so `doctor` can print it.
    Unreadable(String),
    Body(String),
}

/// Of `HOOKS`, the ones git will provably never invoke.
///
/// When `core.hooksPath` is set, git looks **only** there. So for a hook we
/// installed in the repo's own dir after declining `declined`, absence of
/// `declined/<hook>` means nothing can forward to ours — it is dead, with no
/// probing or heuristics required. Presence is not proof of the converse (the
/// entry may not chain), which is why this reports only the certain case.
pub fn shadowed_hooks(declined: &Path) -> Vec<String> {
    HOOKS
        .iter()
        .filter(|h| fs::symlink_metadata(declined.join(h)).is_err())
        .map(|h| (*h).to_string())
        .collect()
}

/// Does this wrapper body forward to `backup`?
///
/// Read from the body rather than from the backup file's existence: an orphaned
/// `.reflogless-orig` next to a wrapper that no longer execs it is exactly the
/// state that made `doctor` report `OK (chained)` for a hook that had stopped
/// running.
pub(crate) fn body_chains_to(body: &str, backup: &Path) -> bool {
    body.contains(&sh_squote(backup))
}

/// Classify a hook entry. Shared by `install`, `uninstall`, and `doctor` so
/// install-time and report-time classification cannot diverge.
pub(crate) fn read_entry(path: &Path) -> Entry {
    let md = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(_) => return Entry::Missing,
    };
    if md.is_symlink() {
        return Entry::Symlink {
            // `metadata` follows the link, so failure here means nothing behind it.
            dangling: fs::metadata(path).is_err(),
        };
    }
    match fs::read_to_string(path) {
        Ok(body) => Entry::Body(body),
        Err(e) => Entry::Unreadable(e.to_string()),
    }
}

pub fn uninstall(repo: &Repo) -> Result<UninstallReport> {
    let HooksTarget { dir, declined } = resolve_hooks_target(repo)?;
    let mut report = UninstallReport {
        declined_hooks_path: declined,
        ..Default::default()
    };
    for hook in HOOKS {
        let path = dir.join(hook);
        match read_entry(&path) {
            Entry::Missing => continue,
            Entry::Body(body) if body.contains(MARKER) => {}
            // Distinct from a legitimate third-party hook: a reflogless-managed
            // hook we can't read stays installed and keeps firing, so saying
            // "not reflogless-managed" and exiting 0 would be a silent partial
            // uninstall.
            Entry::Unreadable(e) => {
                report.unreadable.push(format!("{hook} ({e})"));
                continue;
            }
            Entry::Symlink { .. } | Entry::Body(_) => {
                report.skipped.push((*hook).to_string());
                continue;
            }
        }
        let backup = path.with_extension("reflogless-orig");
        if fs::symlink_metadata(&backup).is_ok() {
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
    // Unlink first. `fs::write` and `set_permissions` both follow symlinks, so
    // writing straight to a symlinked entry rewrites and chmods the *target* —
    // which, when several entries link to one shared dispatcher, destroys that
    // dispatcher instead of replacing the entry. See #73.
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.is_symlink() {
            fs::remove_file(path).map_err(|e| Error::io(path, e))?;
        }
    }
    fs::write(path, &body).map_err(|e| Error::io(path, e))?;
    make_executable(path)?;
    Ok(())
}

fn build_hook_body(
    hook: &str,
    hook_log_path: &Path,
    repo_id: &str,
    prior: Option<&Path>,
) -> String {
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
    s.push_str("[ -d \"$(dirname \"$REFLOGLESS_HOOK_LOG\")\" ] || REFLOGLESS_HOOK_LOG=/dev/null\n");
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

    use crate::testutil::init_repo;

    /// Point the repo's hooks dir at an arbitrary path (absolute or
    /// repo-relative), the way husky/lefthook or a global dispatcher would.
    fn set_hooks_path(repo: &Repo, value: &str) {
        crate::testutil::git_in(&[
            "-C",
            repo.root.to_str().unwrap(),
            "config",
            "--local",
            "core.hooksPath",
            value,
        ]);
    }

    #[test]
    fn install_declines_hooks_dir_outside_repo_and_falls_back() {
        let outside = TempDir::new().unwrap();
        let sentinel = outside.path().join("reference-transaction");
        fs::write(&sentinel, "#!/bin/sh\n# not ours\n").unwrap();

        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        set_hooks_path(&repo, outside.path().to_str().unwrap());

        let report = install(&repo, &repo.root.join("hook-errors.log")).unwrap();

        // Fell back to the repo's own hooks dir, and says which path it declined.
        assert_eq!(report.hooks_dir, repo.git_common_dir().join("hooks"));
        assert_eq!(
            report.declined_hooks_path.as_deref(),
            Some(outside.path()),
            "must report the path it refused to write to"
        );
        // Hooks are actually installed — refusing outright would leave the repo
        // unprotected on any machine with a global core.hooksPath.
        for h in HOOKS {
            let p = report.hooks_dir.join(h);
            assert!(p.exists(), "{h} not installed at {}", p.display());
            assert!(fs::read_to_string(&p).unwrap().contains(MARKER));
        }
        // The shared directory must be untouched — no write, no backup.
        assert_eq!(
            fs::read_to_string(&sentinel).unwrap(),
            "#!/bin/sh\n# not ours\n"
        );
        assert!(!outside
            .path()
            .join("reference-transaction.reflogless-orig")
            .exists());
    }

    #[test]
    fn uninstall_declines_hooks_dir_outside_repo_and_falls_back() {
        let outside = TempDir::new().unwrap();
        let sentinel = outside.path().join("reference-transaction");
        fs::write(&sentinel, format!("{MARKER}\n")).unwrap();

        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        set_hooks_path(&repo, outside.path().to_str().unwrap());

        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        let report = uninstall(&repo).unwrap();

        assert_eq!(
            report.declined_hooks_path.as_deref(),
            Some(outside.path()),
            "must report the path it refused to touch"
        );
        // Removed what it installed...
        assert_eq!(report.removed.len(), HOOKS.len(), "{report:?}");
        for h in HOOKS {
            assert!(!repo.git_common_dir().join("hooks").join(h).exists());
        }
        // ...and did not delete a marker-bearing entry in the shared dir, which it
        // never owned. This is the case that destroyed the real dispatcher.
        assert!(sentinel.exists());
        assert_eq!(
            fs::read_to_string(&sentinel).unwrap(),
            format!("{MARKER}\n")
        );
    }

    #[test]
    fn reinstall_keeps_chaining_a_preserved_third_party_hook() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.git_common_dir().join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        let entry = hooks.join("post-checkout");
        fs::write(&entry, "#!/bin/sh\n# third-party\n").unwrap();

        let log = repo.root.join("hook-errors.log");
        install(&repo, &log).unwrap();
        let after_first = fs::read_to_string(&entry).unwrap();
        let backup = entry.with_extension("reflogless-orig");
        assert!(
            body_chains_to(&after_first, &backup),
            "first install must chain the third-party hook"
        );

        // The bug: the second install took the already-managed branch and rewrote
        // the wrapper with no `prior`, so the preserved hook silently stopped
        // running while the orphaned backup made doctor still report it chained.
        let report = install(&repo, &log).unwrap();
        let after_second = fs::read_to_string(&entry).unwrap();
        assert!(
            body_chains_to(&after_second, &backup),
            "re-install dropped the chain: the third-party hook no longer runs"
        );
        assert!(
            report.chained.contains(&"post-checkout".to_string()),
            "re-install must still report the hook as chained: {report:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_leaves_a_symlink_to_a_marker_bearing_target_alone() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.git_common_dir().join("hooks");
        fs::create_dir_all(&hooks).unwrap();

        // A symlink pointing at something that *looks* reflogless-managed — e.g. a
        // shared dispatcher another repo's install already wrote. Following the link
        // would classify it as ours and delete the link, which is how #73 turned 4
        // of 19 dispatcher symlinks into casualties.
        let shared = repo.root.join("dispatcher.sh");
        fs::write(&shared, format!("{MARKER}\n# shared\n")).unwrap();
        let entry = hooks.join("post-checkout");
        std::os::unix::fs::symlink(&shared, &entry).unwrap();

        let report = uninstall(&repo).unwrap();

        assert!(
            report.skipped.contains(&"post-checkout".to_string()),
            "a symlinked entry is not ours to remove: {report:?}"
        );
        assert!(
            fs::symlink_metadata(&entry).is_ok(),
            "the symlink must survive uninstall"
        );
        assert_eq!(
            fs::read_to_string(&shared).unwrap(),
            format!("{MARKER}\n# shared\n"),
            "the link target must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_replaces_a_dangling_symlink_without_aborting() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.git_common_dir().join("hooks");
        fs::create_dir_all(&hooks).unwrap();
        // A link whose target moved away — #73's own aftermath. `fs::copy` on this
        // fails ENOENT, which aborted install part-way and left earlier hooks
        // installed and later ones not.
        let entry = hooks.join("reference-transaction");
        std::os::unix::fs::symlink(repo.root.join("gone.sh"), &entry).unwrap();

        let report = install(&repo, &repo.root.join("hook-errors.log")).unwrap();

        assert_eq!(
            report.installed.len() + report.chained.len(),
            HOOKS.len(),
            "every hook must be installed, not aborted part-way: {report:?}"
        );
        let body = fs::read_to_string(&entry).unwrap();
        assert!(body.contains(MARKER), "dangling link must be replaced");
        assert!(
            fs::symlink_metadata(entry.with_extension("reflogless-orig")).is_err(),
            "there is no body to preserve, so no backup should be made"
        );
    }

    #[test]
    fn install_honors_hookspath_inside_the_repo() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        set_hooks_path(&repo, ".githooks");

        let report = install(&repo, &repo.root.join("hook-errors.log")).unwrap();

        // A repo-local hooksPath (husky/lefthook style) is legitimate and must
        // still be honored — the fallback is only for out-of-repo paths.
        assert_eq!(report.hooks_dir, repo.root.join(".githooks"));
        assert_eq!(report.declined_hooks_path, None);
        assert!(repo.root.join(".githooks").join("post-checkout").exists());
    }

    #[test]
    fn install_into_linked_worktree_uses_the_dir_git_actually_reads() {
        let main = TempDir::new().unwrap();
        let repo = init_repo(main.path());
        // A commit is required before `git worktree add` will branch.
        fs::write(repo.root.join("f"), b"x").unwrap();
        crate::testutil::git_in(&["-C", main.path().to_str().unwrap(), "add", "f"]);
        crate::testutil::git_in(&["-C", main.path().to_str().unwrap(), "commit", "-qm", "c"]);
        let wt = main.path().parent().unwrap().join(format!(
            "{}-wt",
            main.path().file_name().unwrap().to_str().unwrap()
        ));
        crate::testutil::git_in(&[
            "-C",
            main.path().to_str().unwrap(),
            "worktree",
            "add",
            "-q",
            wt.to_str().unwrap(),
            "-b",
            "wtbranch",
        ]);

        let wt_repo = Repo::discover(&wt).expect("linked worktree is a git repo");
        let report = install(&wt_repo, &wt.join("hook-errors.log")).unwrap();

        assert!(
            wt.join(".git").is_file(),
            "precondition: linked worktree .git is a gitfile"
        );

        // Ask git where it reads hooks and require we wrote exactly there. Asserting
        // a path *shape* instead is what let the per-worktree dir (which git never
        // reads) pass as correct.
        let git_says = Command::new("git")
            .args([
                "-C",
                wt.to_str().unwrap(),
                "rev-parse",
                "--git-path",
                "hooks",
            ])
            .output()
            .unwrap();
        let git_hooks_dir =
            PathBuf::from(String::from_utf8_lossy(&git_says.stdout).trim().to_string());
        assert_eq!(
            canonicalize_existing(&report.hooks_dir),
            canonicalize_existing(&git_hooks_dir),
            "installed into a directory git does not read hooks from"
        );
        // Explicitly *not* the per-worktree admin dir, and not the gitfile path.
        assert!(
            !report
                .hooks_dir
                .to_string_lossy()
                .contains(".git/worktrees/"),
            "hooks must go to the common dir, not per-worktree: {}",
            report.hooks_dir.display()
        );

        // The assertion that actually matters: a git operation in the worktree fires
        // the installed hook. Everything above is a path claim; this is behavior.
        let sentinel = wt.join("fired.txt");
        let hook = report.hooks_dir.join("post-checkout");
        fs::write(
            &hook,
            format!("#!/bin/sh\necho fired >> {}\n", sh_squote(&sentinel)),
        )
        .unwrap();
        make_executable(&hook).unwrap();
        crate::testutil::git_in(&["-C", wt.to_str().unwrap(), "checkout", "-q", "-b", "probe"]);
        assert!(
            sentinel.exists(),
            "post-checkout in {} was not invoked by git — hooks are installed \
             somewhere git does not look",
            report.hooks_dir.display()
        );

        let _ = Command::new("git")
            .args(["-C", main.path().to_str().unwrap(), "worktree", "remove"])
            .arg(&wt)
            .arg("--force")
            .status();
    }

    #[cfg(unix)]
    #[test]
    fn install_replaces_symlink_instead_of_writing_through_it() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).unwrap();

        // A shared dispatcher that several hook entries symlink to — the shape
        // that got destroyed in #73.
        let shared = repo.root.join("dispatcher.sh");
        let shared_body = "#!/bin/sh\n# shared dispatcher — must survive\n";
        fs::write(&shared, shared_body).unwrap();
        let entry = hooks.join("reference-transaction");
        std::os::unix::fs::symlink(&shared, &entry).unwrap();

        install(&repo, &repo.root.join("hook-errors.log")).unwrap();

        // The symlink target must be byte-identical afterwards.
        assert_eq!(fs::read_to_string(&shared).unwrap(), shared_body);
        // And the entry itself is now a real reflogless hook, not a link.
        assert!(!fs::symlink_metadata(&entry).unwrap().is_symlink());
        assert!(fs::read_to_string(&entry).unwrap().contains(MARKER));
    }

    #[cfg(unix)]
    #[test]
    fn install_chains_symlinked_foreign_hook_by_copying_target() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        let hooks = repo.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).unwrap();

        let shared = repo.root.join("foreign.sh");
        let shared_body = "#!/bin/sh\necho foreign\n";
        fs::write(&shared, shared_body).unwrap();
        let entry = hooks.join("post-checkout");
        std::os::unix::fs::symlink(&shared, &entry).unwrap();

        let report = install(&repo, &repo.root.join("hook-errors.log")).unwrap();

        assert!(report.chained.contains(&"post-checkout".to_string()));
        assert_eq!(fs::read_to_string(&shared).unwrap(), shared_body);
        // The chained backup holds the foreign body, so it can still run.
        let backup = hooks.join("post-checkout.reflogless-orig");
        assert_eq!(fs::read_to_string(&backup).unwrap(), shared_body);
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
        let got = resolved_log_path(&[("HOME", home.path())], &fb.path().join("install.log"));
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
        if uname_s.starts_with("MINGW")
            || uname_s.starts_with("MSYS")
            || uname_s.starts_with("CYGWIN")
        {
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

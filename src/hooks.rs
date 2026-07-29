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
/// Bumped to 3 in #74: the body now invokes an absolute binary path via
/// `$__REFLOGLESS_BIN` instead of the bare name.
///
/// Read back by `body_is_current_version`, which `doctor` uses to fail a repo
/// whose hooks predate the current body format. Bumping this without a reader
/// would be inert — a v2 hook still contains `MARKER`, so `install` and `doctor`
/// both classify it as managed and healthy while it keeps resolving the binary
/// off PATH, which is the #74 bug.
pub const MARKER_VERSION: &str = "# reflogless-hook-version: 3";

/// Prefix of the line the generated body uses to bake in the binary path.
const BIN_ASSIGN: &str = "__REFLOGLESS_BIN=";

/// Substring identifying the snap invocation inside a generated hook body,
/// independent of how the binary is addressed. `doctor` keys off this to tell a
/// marker-stripped reflogless hook (tampered) from a genuine third-party hook,
/// so it must not embed the binary name.
///
/// It also must stay broad enough to match a **v2** body, which spells the
/// invocation `reflogless snap --event <hook>`. Narrowing this to something more
/// specific — the `$__REFLOGLESS_BIN` assignment, say — would silently stop
/// classifying marker-stripped legacy hooks as tampered, and they are the ones
/// most likely to have been hand-edited. `body_invokes_snap_on_both_formats`
/// pins that.
///
/// The cost of the looseness is a third-party hook that happens to contain this
/// substring reading as `Tampered`. That direction is the cheap one: it produces
/// a confusing message, while `install` still independently keys on `MARKER` and
/// so preserves and chains the hook rather than clobbering it. A missed tamper
/// would instead hide a hook that has stopped snapshotting.
pub const INVOKE_PROBE: &str = "snap --event";

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
    // Bake the absolute path to the running binary into the hook. Resolution
    // failure is not fatal — the body falls back to a bare `reflogless`, which
    // is exactly the pre-#74 behavior, so a hostile `current_exe` degrades
    // rather than blocking the install.
    let bin = std::env::current_exe().ok().and_then(|p| normalize_bin(&p));
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let mut installed = Vec::new();
    let mut chained = Vec::new();
    for hook in HOOKS {
        let path = dir.join(hook);
        let backup = path.with_extension("reflogless-orig");
        match read_entry(&path) {
            Entry::Missing => {
                write_hook(&path, hook, hook_log_path, &repo_id, None, bin.as_deref())?;
                installed.push((*hook).to_string());
            }
            // Already ours. Re-chain if a backup is present: passing `None` here
            // rewrote the wrapper without its `exec`, so a second `install`
            // silently stopped running a third-party hook it had preserved.
            Entry::Body(body) if body.contains(MARKER) => {
                let prior = fs::symlink_metadata(&backup)
                    .is_ok()
                    .then_some(backup.as_path());
                write_hook(&path, hook, hook_log_path, &repo_id, prior, bin.as_deref())?;
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
                write_hook(&path, hook, hook_log_path, &repo_id, None, bin.as_deref())?;
                installed.push((*hook).to_string());
            }
            // Foreign, or unreadable and therefore assumed foreign. Preserve and
            // chain. `fs::copy` resolves a link, so the backup holds the real body
            // and stays runnable after we replace the entry.
            Entry::Symlink { dangling: false } | Entry::Unreadable(_) | Entry::Body(_) => {
                if fs::symlink_metadata(&backup).is_err() {
                    fs::copy(&path, &backup).map_err(|e| Error::io(&path, e))?;
                }
                write_hook(
                    &path,
                    hook,
                    hook_log_path,
                    &repo_id,
                    Some(&backup),
                    bin.as_deref(),
                )?;
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

/// Make a binary path safe to bake into a hook that outlives this process, or
/// return `None` if it can't be.
///
/// `current_exe()` is not documented to return a canonical path. Invoked as
/// `../rl` it returns `/cwd/../rl`, so the install-time working directory ends up
/// embedded in the hook: rename that directory and the baked path stops resolving
/// even though the binary is still exactly where it was.
///
/// Only the *parent* is canonicalized, with the file name re-joined afterwards.
/// Canonicalizing the whole path would resolve the final symlink too, pinning the
/// hook to today's target and defeating precisely the indirection that makes an
/// install survive upgrades — a version manager's `current` link, a Homebrew
/// `bin/` entry. The link is the stable address; its target is not.
fn normalize_bin(p: &Path) -> Option<PathBuf> {
    let name = p.file_name()?;
    let resolved = p.parent()?.canonicalize().ok()?.join(name);
    resolved.is_absolute().then_some(resolved)
}

/// Was this managed body generated by the current version of `build_hook_body`?
///
/// A stale body is a real protection gap, not cosmetics: a v2 body invokes bare
/// `reflogless` and so skips the snapshot under any PATH that lacks the install
/// dir (#74). Nothing rewrites hooks automatically, so the only way a user learns
/// to re-run `reflogless init` is `doctor` telling them.
pub(crate) fn body_is_current_version(body: &str) -> bool {
    body.contains(MARKER_VERSION)
}

/// The absolute binary path baked into a managed body, if it bakes one.
///
/// Returns `None` for a body that fell back to the bare name (`current_exe()`
/// failed at install time) — there is no path to verify in that case, which is
/// different from a path that has gone bad.
pub(crate) fn extract_hook_binary(body: &str) -> Option<PathBuf> {
    for line in body.lines() {
        let rest = match line.trim_start().strip_prefix(BIN_ASSIGN) {
            Some(r) => r,
            None => continue,
        };
        // Only the baked assignment is single-quoted; the bare-name fallback and
        // the override re-assignments are not, and neither is a path to check.
        if let Some(inner) = rest.strip_prefix('\'') {
            if let Some(end) = inner.rfind('\'') {
                let unescaped = inner[..end].replace("'\\''", "'");
                if !unescaped.is_empty() {
                    return Some(PathBuf::from(unescaped));
                }
            }
        }
    }
    None
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
    bin: Option<&Path>,
) -> Result<()> {
    let body = build_hook_body(hook, hook_log_path, repo_id, prior, bin);
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
    bin: Option<&Path>,
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
    //
    // The parent is derived with `${VAR%/*}`, a shell builtin, not `$(dirname)`.
    // `dirname` is an external command, so under a minimal PATH — a GUI editor,
    // launchd, a sandboxed runner: the very callers #74 is about — the
    // substitution yielded the empty string, `[ -d "" ]` was false, and the log
    // was redirected to /dev/null. The hook then failed *and* discarded the only
    // record of it. `mkdir` is external too and can still fail that way, but its
    // failure is already handled, and step 2 now works with no PATH at all, so
    // an already-existing log directory keeps logging.
    s.push_str(
        "mkdir -p \"${REFLOGLESS_HOOK_LOG%/*}\" 2>/dev/null \
         || REFLOGLESS_HOOK_LOG=\"$__REFLOGLESS_FALLBACK_LOG\"\n",
    );
    s.push_str("[ -d \"${REFLOGLESS_HOOK_LOG%/*}\" ] || REFLOGLESS_HOOK_LOG=/dev/null\n");
    // Address the binary by absolute path. A bare `reflogless` resolves against
    // whatever PATH the git caller happens to have, and a GUI editor, launchd
    // job, or sandboxed runner typically lacks ~/.cargo/bin or
    // /opt/homebrew/bin — the lookup then fails and `|| true` swallows it, so
    // the snapshot is silently skipped (#74).
    //
    // Resolution order: the baked path, overridden by `$REFLOGLESS_BIN` if that
    // names something executable, and bare `reflogless` only as a last resort.
    // The override exists so a relocated install can be pointed at the new
    // binary without reinstalling every hook, and so tests can substitute a stub
    // without depending on PATH.
    //
    // Every step down this chain writes a line naming itself. The earlier
    // version silently rewrote the resolved value to the bare name whenever it
    // wasn't executable, which meant a mistyped `$REFLOGLESS_BIN` discarded a
    // perfectly good baked path and left `reflogless: command not found` in the
    // log — the exact signature of #74, produced by the fix for #74, pointing
    // the next reader at PATH instead of at the override.
    let bare_fallback = "[ -x \"$__REFLOGLESS_BIN\" ] || {\n  \
         echo \"reflogless: $__REFLOGLESS_BIN is not executable; \
         falling back to PATH lookup\" >>\"$REFLOGLESS_HOOK_LOG\"\n  \
         __REFLOGLESS_BIN=reflogless\n\
         }\n";
    match bin {
        Some(p) => {
            s.push_str(&format!("__REFLOGLESS_BIN={}\n", sh_squote(p)));
            // An override is a user instruction. Honor it when it can be
            // honored, and say so when it can't — never swap in a *different*
            // binary behind the user's back.
            s.push_str(
                "if [ -n \"${REFLOGLESS_BIN:-}\" ]; then\n  \
                   if [ -x \"$REFLOGLESS_BIN\" ]; then\n    \
                     __REFLOGLESS_BIN=\"$REFLOGLESS_BIN\"\n  \
                   else\n    \
                     echo \"reflogless: REFLOGLESS_BIN=$REFLOGLESS_BIN is not executable; \
                     using $__REFLOGLESS_BIN\" >>\"$REFLOGLESS_HOOK_LOG\"\n  \
                   fi\n\
                 fi\n",
            );
            s.push_str(bare_fallback);
        }
        None => {
            // No baked path to protect, so an unusable override is left in place
            // deliberately: `sh` then names the real path in the log, which is
            // more informative than a silent substitution.
            s.push_str("__REFLOGLESS_BIN=reflogless\n");
            s.push_str("[ -n \"${REFLOGLESS_BIN:-}\" ] && __REFLOGLESS_BIN=\"$REFLOGLESS_BIN\"\n");
        }
    }
    s.push_str(&format!(
        "\"$__REFLOGLESS_BIN\" {INVOKE_PROBE} {hook} 2>>\"$REFLOGLESS_HOOK_LOG\" >/dev/null || true\n"
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

    #[test]
    fn hook_body_invokes_baked_absolute_binary_with_bare_name_fallback() {
        let bin = Path::new("/opt/somewhere/bin/reflogless");
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            Some(bin),
        );
        assert!(
            body.contains("__REFLOGLESS_BIN='/opt/somewhere/bin/reflogless'"),
            "absolute path not baked in: {body}"
        );
        // Fallback keeps a moved/removed binary from breaking the hook outright.
        // Behavior is covered by `a_dead_baked_path_falls_back_to_path_and_says_so`;
        // this only asserts the fallback exists at all.
        assert!(
            body.contains("__REFLOGLESS_BIN=reflogless"),
            "no bare-name fallback: {body}"
        );
        assert!(body.contains("\"$__REFLOGLESS_BIN\" snap --event post-checkout"));
        // The bare-name invocation is what #74 fixed; it must not survive.
        assert!(
            !body.contains("\nreflogless snap --event"),
            "still invokes bare `reflogless`: {body}"
        );
    }

    /// End-to-end: run a generated hook with a stub binary and confirm it is
    /// actually invoked. This is the behavior #74 restores — under a PATH that
    /// lacks the install dir, the pre-fix hook silently skipped the snapshot.
    #[test]
    fn generated_hook_invokes_the_binary_under_a_stripped_path() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let marker = td.path().join("it-ran");
        let stub = td.path().join("reflogless-stub");
        fs::write(
            &stub,
            format!("#!/bin/sh\necho \"$@\" > {}\n", sh_squote(&marker)),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        let body = build_hook_body(
            "post-checkout",
            &td.path().join("hook-errors.log"),
            "0123456789abcdef",
            None,
            Some(&stub),
        );
        let script = td.path().join("hook.sh");
        fs::write(&script, &body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        // PATH deliberately holds nothing that could resolve a bare
        // `reflogless` — the baked absolute path is the only way through.
        let status = Command::new(&script)
            .env("PATH", "/nonexistent-bin")
            .env("HOME", td.path())
            .status()
            .unwrap();
        assert!(status.success(), "hook must stay best-effort");
        assert_eq!(
            fs::read_to_string(&marker).unwrap().trim(),
            "snap --event post-checkout",
            "stub was not invoked with the expected args"
        );
    }

    /// Write an executable stub that records the name it was invoked under.
    #[cfg(unix)]
    fn stub_at(path: &Path, marker: &Path, label: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            path,
            format!("#!/bin/sh\necho '{label}' >> {}\n", sh_squote(marker)),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Build a hook body for `bin`, run it with `env` applied, and return
    /// `(whichever stub ran, hook-errors.log contents)`.
    ///
    /// Behavioral rather than string-shape: the emitted resolution chain can be
    /// rewritten freely as long as the binary that ends up running is the right
    /// one, which is the property anyone actually depends on.
    #[cfg(unix)]
    fn run_body_with(
        td: &TempDir,
        bin: Option<&Path>,
        env: &[(&str, &str)],
        path_var: &str,
    ) -> (String, String) {
        use std::os::unix::fs::PermissionsExt;
        let marker = td.path().join("who-ran");
        let log = td.path().join("hook-errors.log");
        let body = build_hook_body("post-checkout", &log, "0123456789abcdef", None, bin);
        let script = td.path().join("hook.sh");
        fs::write(&script, &body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut cmd = Command::new(&script);
        // Pin the log explicitly: the body resolves its own default from the
        // data dir, and this test cares about the log's *contents*, not where
        // the resolution lands (covered separately).
        cmd.env("PATH", path_var)
            .env("HOME", td.path())
            .env("REFLOGLESS_HOOK_LOG", &log);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let status = cmd.status().unwrap();
        assert!(status.success(), "hook must stay best-effort:\n{body}");
        (
            fs::read_to_string(&marker)
                .unwrap_or_default()
                .trim()
                .into(),
            fs::read_to_string(&log).unwrap_or_default(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn hook_body_honors_an_executable_reflogless_bin_override() {
        let td = TempDir::new().unwrap();
        let marker = td.path().join("who-ran");
        let baked = td.path().join("baked");
        let over = td.path().join("override");
        stub_at(&baked, &marker, "BAKED");
        stub_at(&over, &marker, "OVERRIDE");

        let (who, _) = run_body_with(
            &td,
            Some(&baked),
            &[("REFLOGLESS_BIN", over.to_str().unwrap())],
            "/nonexistent-bin",
        );
        assert_eq!(who, "OVERRIDE", "explicit override was not used");
    }

    /// The defect this replaced a string-shape test to catch: a mistyped or
    /// not-yet-chmod'd `$REFLOGLESS_BIN` used to overwrite the baked path and
    /// then get rewritten to bare `reflogless`, so a working install produced
    /// `reflogless: command not found` — #74's own signature — and skipped the
    /// snapshot. The override must never cost the user the baked path.
    #[cfg(unix)]
    #[test]
    fn a_non_executable_override_keeps_the_baked_binary_and_says_so() {
        let td = TempDir::new().unwrap();
        let marker = td.path().join("who-ran");
        let baked = td.path().join("baked");
        stub_at(&baked, &marker, "BAKED");
        let not_exec = td.path().join("not-executable");
        fs::write(&not_exec, b"i am not a program").unwrap();

        let (who, log) = run_body_with(
            &td,
            Some(&baked),
            &[("REFLOGLESS_BIN", not_exec.to_str().unwrap())],
            "/nonexistent-bin",
        );
        assert_eq!(
            who, "BAKED",
            "a bad override discarded a working baked binary"
        );
        assert!(
            log.contains("REFLOGLESS_BIN") && log.contains("not executable"),
            "the rejected override left no signal naming it: {log:?}"
        );
        assert!(
            !log.contains("command not found"),
            "reproduced #74's own failure signature: {log:?}"
        );
    }

    /// `current_exe()` can hand back a path containing `..`, which embeds the
    /// install-time working directory in the hook. Renaming that directory then
    /// kills the baked path while the binary sits untouched.
    #[test]
    fn normalize_bin_strips_dot_dot_and_the_install_time_cwd() {
        let td = TempDir::new().unwrap();
        let nested = td.path().join("nested");
        fs::create_dir_all(&nested).unwrap();
        let real = td.path().join("reflogless");
        fs::write(&real, b"binary").unwrap();

        let via_dotdot = nested.join("..").join("reflogless");
        let normalized = normalize_bin(&via_dotdot).expect("should normalize");
        assert!(
            !normalized.to_string_lossy().contains(".."),
            "`..` survived into the baked path: {}",
            normalized.display()
        );
        assert!(normalized.is_absolute());
        assert_eq!(
            fs::canonicalize(&normalized).unwrap(),
            fs::canonicalize(&real).unwrap(),
            "normalization changed which file the path names"
        );
    }

    /// A binary reached through a symlink must keep the *link* address. Resolving
    /// it would pin the hook to today's target and break the indirection that lets
    /// an install survive an upgrade.
    #[cfg(unix)]
    #[test]
    fn normalize_bin_keeps_a_symlinked_binary_addressed_by_its_link() {
        let td = TempDir::new().unwrap();
        let target = td.path().join("reflogless-1.2.3");
        fs::write(&target, b"binary").unwrap();
        let link = td.path().join("reflogless");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let normalized = normalize_bin(&link).expect("should normalize");
        assert_eq!(
            normalized.file_name().unwrap(),
            "reflogless",
            "resolved through the symlink and pinned the versioned target: {}",
            normalized.display()
        );
    }

    #[test]
    fn normalize_bin_rejects_a_path_whose_parent_does_not_exist() {
        assert_eq!(normalize_bin(Path::new("/no/such/dir/reflogless")), None);
        assert_eq!(normalize_bin(Path::new("/")), None);
    }

    #[test]
    fn extract_hook_binary_reads_back_the_path_install_baked_in() {
        let bin = Path::new("/opt/somewhere/bin/reflogless");
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            Some(bin),
        );
        assert_eq!(extract_hook_binary(&body).as_deref(), Some(bin));
    }

    #[test]
    fn extract_hook_binary_round_trips_a_path_with_a_quote_in_it() {
        let bin = Path::new("/opt/it's here/reflogless");
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            Some(bin),
        );
        assert_eq!(extract_hook_binary(&body).as_deref(), Some(bin));
    }

    /// A body that fell back to the bare name bakes no path, which is different
    /// from baking one that has gone bad — `doctor` must not report the former as
    /// stale, since there is nothing to re-point.
    #[test]
    fn extract_hook_binary_is_none_when_the_body_uses_the_bare_name() {
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            None,
        );
        assert_eq!(extract_hook_binary(&body), None);
        assert_eq!(extract_hook_binary("#!/bin/sh\necho hi\n"), None);
        assert_eq!(extract_hook_binary(""), None);
    }

    /// `INVOKE_PROBE` has to match the current body *and* a v2 body, or
    /// marker-stripped legacy hooks quietly stop classifying as tampered. See the
    /// constant's docs for why the resulting looseness is the cheaper direction.
    #[test]
    fn body_invokes_snap_on_both_formats() {
        let current = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            Some(Path::new("/opt/reflogless")),
        );
        assert!(current.contains(INVOKE_PROBE), "current body: {current}");
        // How v2 spelled it, before the binary was addressed by path.
        let v2 = "#!/bin/sh\nreflogless snap --event post-checkout || true\n";
        assert!(v2.contains(INVOKE_PROBE), "v2 body must still match");
        // An ordinary third-party hook must not.
        let third_party = "#!/bin/sh\nnpx lint-staged\nexit 0\n";
        assert!(!third_party.contains(INVOKE_PROBE));
    }

    #[test]
    fn body_version_check_accepts_current_and_rejects_older_bodies() {
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            None,
        );
        assert!(body_is_current_version(&body));
        // A v2 body: marker present, version line one behind.
        let v2 = format!("#!/bin/sh\n{MARKER}\n# reflogless-hook-version: 2\n");
        assert!(!body_is_current_version(&v2));
        // v1 had no version line at all.
        assert!(!body_is_current_version(&format!("#!/bin/sh\n{MARKER}\n")));
    }

    /// The error log must survive the environment the hook is most likely to fail
    /// in. Deriving the log's parent with `$(dirname …)` meant that under a PATH
    /// without coreutils the substitution came back empty, `[ -d "" ]` was false,
    /// and the log went to /dev/null — so a hook running from a GUI editor or
    /// launchd both failed *and* threw away the only record of it. That is the
    /// same class of environment #74 is about, and `hook-errors.log` is where
    /// #74's own evidence came from.
    #[cfg(unix)]
    #[test]
    fn the_error_log_survives_a_hook_run_with_no_usable_path() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let log = td.path().join("nested").join("hook-errors.log");
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        // No baked binary and an empty PATH: the invocation cannot succeed, which
        // is exactly when the log has to work.
        let body = build_hook_body("post-checkout", &log, "0123456789abcdef", None, None);
        let script = td.path().join("hook.sh");
        fs::write(&script, &body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let status = Command::new(&script)
            .env("PATH", "")
            .env("HOME", td.path())
            .env("REFLOGLESS_HOOK_LOG", &log)
            .status()
            .unwrap();
        assert!(status.success(), "hook must stay best-effort");
        let logged = fs::read_to_string(&log).unwrap_or_default();
        assert!(
            !logged.is_empty(),
            "hook failure left no record — the log was discarded, not written"
        );
    }

    /// The baked path can die under the install (upgrade to a new prefix, moved
    /// binary). Falling back to PATH is correct — doing it silently is not,
    /// because the log is the only place this is ever visible.
    #[cfg(unix)]
    #[test]
    fn a_dead_baked_path_falls_back_to_path_and_says_so() {
        let td = TempDir::new().unwrap();
        let marker = td.path().join("who-ran");
        let bindir = td.path().join("bin");
        fs::create_dir_all(&bindir).unwrap();
        stub_at(&bindir.join("reflogless"), &marker, "FROM-PATH");

        let (who, log) = run_body_with(
            &td,
            Some(&td.path().join("deleted-by-an-upgrade")),
            &[],
            bindir.to_str().unwrap(),
        );
        assert_eq!(who, "FROM-PATH", "did not fall back to PATH");
        assert!(
            log.contains("not executable") && log.contains("deleted-by-an-upgrade"),
            "silent fallback — no line names the dead baked path: {log:?}"
        );
    }

    #[test]
    fn hook_body_falls_back_to_bare_name_when_binary_unknown() {
        let body = build_hook_body(
            "post-checkout",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            None,
        );
        assert!(body.contains("__REFLOGLESS_BIN=reflogless"));
        assert!(body.contains("\"$__REFLOGLESS_BIN\" snap --event post-checkout"));
    }

    #[test]
    fn hook_body_squotes_a_binary_path_containing_spaces() {
        let bin = Path::new("/Applications/My Tools/reflogless");
        let body = build_hook_body(
            "pre-rebase",
            Path::new("/tmp/log"),
            "0123456789abcdef",
            None,
            Some(bin),
        );
        assert!(
            body.contains("__REFLOGLESS_BIN='/Applications/My Tools/reflogless'"),
            "space-bearing path not quoted: {body}"
        );
    }

    #[test]
    fn installed_hooks_reference_an_absolute_binary() {
        let td = TempDir::new().unwrap();
        let repo = init_repo(td.path());
        install(&repo, &repo.root.join("hook-errors.log")).unwrap();
        for hook in HOOKS {
            let body = fs::read_to_string(repo.root.join(".git").join("hooks").join(hook)).unwrap();
            // Asserted as properties rather than by comparing against
            // `current_exe()` — building the expectation from the same primitive
            // the code under test calls can only prove the two agree, not that
            // either is right. What the hook needs is a path that resolves from
            // any working directory and names something runnable.
            let baked = extract_hook_binary(&body)
                .unwrap_or_else(|| panic!("{hook} bakes no binary path:\n{body}"));
            assert!(
                baked.is_absolute(),
                "{hook} baked a relative path: {baked:?}"
            );
            assert!(
                !baked.to_string_lossy().contains(".."),
                "{hook} baked the install-time cwd via `..`: {baked:?}"
            );
            assert!(
                baked.exists(),
                "{hook} baked a path that does not resolve: {baked:?}"
            );
        }
    }

    /// The generated body must remain runnable by `/bin/sh`. A quoting or
    /// syntax slip in the binary-resolution block would otherwise only surface
    /// as a silent `|| true` swallow at hook time.
    #[test]
    fn hook_body_is_valid_posix_sh() {
        let bin = Path::new("/Applications/My Tools/reflogless");
        for hook in HOOKS {
            let body = build_hook_body(
                hook,
                Path::new("/tmp/log"),
                "0123456789abcdef",
                None,
                Some(bin),
            );
            let out = Command::new("sh")
                .arg("-n")
                .arg("-c")
                .arg(&body)
                .output()
                .expect("sh failed");
            assert!(
                out.status.success(),
                "sh -n rejected {hook} body: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
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
            assert!(body.contains(&format!("{INVOKE_PROBE} {hook}")));
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
        assert!(body.contains(&format!("{INVOKE_PROBE} post-checkout")));
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
        let body = build_hook_body(
            "reference-transaction",
            &fallback,
            "0123456789abcdef",
            None,
            None,
        );
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
        let body = build_hook_body("post-checkout", fallback, "0123456789abcdef", None, None);
        let probe = match body.find("__REFLOGLESS_BIN=") {
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
        let body = build_hook_body("post-checkout", &log, "0123456789abcdef", Some(&path), None);
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

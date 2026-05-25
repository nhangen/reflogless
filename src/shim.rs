use std::fs;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Recognizable substring in our managed shim script. `doctor` keys off this.
pub const MARKER: &str = "# reflogless-managed shim";

/// Detect whether a `git <args>` invocation modifies the working tree in a
/// way reflogless wants to snapshot.
///
/// Allowlist:
/// - `git clean ...` — every form except `--dry-run` / `-n`.
/// - `git reset --hard ...` — `--hard` anywhere in args.
/// - `git restore ...` — every form except `--staged`-only (index-only).
/// - `git switch -f` / `--discard-changes` — clean switch is refused by
///   git on dirty trees, so only the force form needs snapshotting.
/// - `git checkout -f` / `--force` — force-overwrites worktree.
/// - `git checkout <ref> -- <pathspec>` — pathspec form overwrites the
///   named paths.
///
/// Returns the event tag to use for the snapshot, or `None` to passthrough.
pub fn destructive_event(args: &[String]) -> Option<&'static str> {
    let (idx, subcommand) = find_subcommand(args)?;
    let after = &args[idx + 1..];
    match subcommand {
        "clean" => {
            if is_clean_dry_run(after) {
                None
            } else {
                Some("shim-clean")
            }
        }
        "reset" => {
            if after.iter().any(|a| a == "--hard") {
                Some("shim-reset-hard")
            } else {
                None
            }
        }
        "restore" => {
            // `--staged` without `--worktree` only touches the index, not
            // the working tree — passthrough. Every other form overwrites
            // worktree files.
            let has_staged = after.iter().any(|a| a == "--staged" || a == "-S");
            let has_worktree = after.iter().any(|a| a == "--worktree" || a == "-W");
            if has_staged && !has_worktree {
                None
            } else {
                Some("shim-restore")
            }
        }
        "switch" => {
            // `switch` refuses on dirty trees unless given `-f` /
            // `--discard-changes`; only the force form is destructive.
            if after.iter().any(|a| a == "-f" || a == "--discard-changes") {
                Some("shim-switch-force")
            } else {
                None
            }
        }
        "checkout" => {
            // Two destructive shapes:
            // - `-f` / `--force` anywhere (force-overwrites worktree)
            // - `--` separator (pathspec form: `checkout <ref> -- <path>`
            //   overwrites the named paths from the ref)
            let forced = after.iter().any(|a| a == "-f" || a == "--force");
            let pathspec = after.iter().any(|a| a == "--");
            if forced || pathspec {
                Some("shim-checkout-force")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Detect `git clean --dry-run` / `git clean -n` (including short-flag
/// clusters like `-nd`, `-ndx`, `-fnd`). Arguments after `--` are pathspecs,
/// not flags, and are ignored.
fn is_clean_dry_run(after: &[String]) -> bool {
    for arg in after {
        let a = arg.as_str();
        if a == "--" {
            return false;
        }
        if a == "--dry-run" {
            return true;
        }
        if a.starts_with("--") {
            continue;
        }
        if let Some(short) = a.strip_prefix('-') {
            if short.contains('n') {
                return true;
            }
        }
    }
    false
}

/// Walk past git's global flags to find the subcommand.
///
/// Git's globals that consume the *next* argument as a value: `-C <path>`,
/// `-c <name=value>`. Other globals are either lone switches (`--bare`,
/// `--no-pager`) or attach the value via `=` (`--git-dir=...`). Treating
/// every other dash-prefixed token as a lone switch is accurate for the
/// conservative shim allowlist.
fn find_subcommand(args: &[String]) -> Option<(usize, &str)> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-C" || arg == "-c" {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        return Some((i, arg));
    }
    None
}

#[derive(Debug)]
pub struct InstallReport {
    pub shim_path: PathBuf,
    pub reflogless_bin: PathBuf,
}

/// Install the shim script. Returns the destination path on success.
///
/// Idempotent: re-installing a reflogless-managed shim is a no-op rewrite.
/// Refuses to overwrite a non-reflogless file at the target path
/// (third-party `git` shim, hand-written wrapper, etc.).
pub fn install() -> Result<InstallReport> {
    let shim_dir = resolve_shim_dir()?;
    fs::create_dir_all(&shim_dir).map_err(|e| Error::io(&shim_dir, e))?;
    let shim_path = shim_dir.join(shim_file_name());
    let reflogless_bin = std::env::current_exe().map_err(|e| Error::io("<current_exe>", e))?;

    if shim_path.exists() {
        let body = fs::read_to_string(&shim_path).map_err(|e| Error::io(&shim_path, e))?;
        if !is_managed_shim_body(&body) {
            return Err(Error::Config(format!(
                "refusing to overwrite existing file at {} (not a reflogless-managed shim)",
                shim_path.display()
            )));
        }
    }

    let script = render_shim_script(&reflogless_bin);
    fs::write(&shim_path, &script).map_err(|e| Error::io(&shim_path, e))?;
    set_executable(&shim_path)?;

    Ok(InstallReport {
        shim_path,
        reflogless_bin,
    })
}

/// Remove the shim script. Idempotent. Refuses to remove a non-reflogless
/// file at the target path.
pub fn uninstall() -> Result<Option<PathBuf>> {
    let shim_dir = resolve_shim_dir()?;
    let shim_path = shim_dir.join(shim_file_name());
    if !shim_path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&shim_path).map_err(|e| Error::io(&shim_path, e))?;
    if !is_managed_shim_body(&body) {
        return Err(Error::Config(format!(
            "refusing to remove non-reflogless file at {}",
            shim_path.display()
        )));
    }
    fs::remove_file(&shim_path).map_err(|e| Error::io(&shim_path, e))?;
    Ok(Some(shim_path))
}

/// Resolve the install dir for the shim. Honors `REFLOGLESS_SHIM_DIR` first
/// (primarily for tests), then `dirs::executable_dir()` (XDG —
/// `$XDG_BIN_HOME` then `~/.local/bin` on Linux/BSD), then the directory
/// the reflogless binary itself lives in (which is already on PATH).
pub fn resolve_shim_dir() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("REFLOGLESS_SHIM_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| Error::io("<current_exe>", e))?;
        if let Some(parent) = exe.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(d) = dirs::executable_dir() {
            return Ok(d);
        }
        // `dirs::executable_dir()` returns None on macOS and Windows. Falling
        // back to the reflogless binary's parent would target a system bin
        // (e.g. /opt/homebrew/bin) — default to ~/.local/bin instead.
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".local").join("bin"));
        }
    }
    let exe = std::env::current_exe().map_err(|e| Error::io("<current_exe>", e))?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| Error::Config("could not resolve shim install directory".into()))
}

#[cfg(windows)]
fn shim_file_name() -> &'static str {
    "git.cmd"
}

#[cfg(not(windows))]
fn shim_file_name() -> &'static str {
    "git"
}

/// Detects a reflogless-managed shim by line-anchored marker match.
/// Substring matching would false-positive on user wrappers that mention
/// the marker string in a comment.
fn is_managed_shim_body(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == MARKER || trimmed.eq_ignore_ascii_case("rem # reflogless-managed shim")
    })
}

fn render_shim_script(reflogless_bin: &Path) -> String {
    #[cfg(windows)]
    {
        return render_windows_shim_script(reflogless_bin);
    }
    #[cfg(not(windows))]
    {
        render_unix_shim_script(reflogless_bin)
    }
}

#[cfg(any(not(windows), test))]
fn render_unix_shim_script(reflogless_bin: &Path) -> String {
    format!(
        "#!/bin/sh\n\
{MARKER}\n\
# Managed by `reflogless init --shim`; remove with `reflogless uninstall`.\n\
# Snapshots untracked + dirty files before destructive git subcommands\n\
# (`clean`, `reset --hard`), then execs the real `git`.\n\
exec \"{bin}\" _shim --shim-dir=\"$(dirname \"$0\")\" -- \"$@\"\n",
        bin = reflogless_bin.display(),
    )
}

#[cfg(any(windows, test))]
fn render_windows_shim_script(reflogless_bin: &Path) -> String {
    format!(
        "@echo off\r\n\
REM {MARKER}\r\n\
REM Managed by `reflogless init --shim`; remove with `reflogless uninstall`.\r\n\
REM Snapshots untracked + dirty files before destructive git subcommands.\r\n\
\"{bin}\" _shim --shim-dir=\"%~dp0\" -- %*\r\n\
exit /b %ERRORLEVEL%\r\n",
        bin = reflogless_bin.display(),
    )
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .map_err(|e| Error::io(path, e))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(|e| Error::io(path, e))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Status of the installed shim, as observed from the current process.
#[derive(Debug)]
pub enum ShimStatus {
    /// No reflogless-managed shim at the resolved install dir.
    Off,
    /// Shim present and is the first `git` on PATH.
    On { path: PathBuf },
    /// Shim present but PATH resolves `git` to a different binary that
    /// precedes it — the shim won't run.
    Shadowed { ours: PathBuf, precedes: PathBuf },
    /// A file at the shim path exists but is not reflogless-managed.
    Foreign { path: PathBuf },
    /// A file at the shim path exists but can't be read (EACCES, EIO,
    /// dangling symlink). Distinct from `Foreign` so doctor surfaces the
    /// actual I/O error to the user instead of telling them to remove a
    /// "third-party" file.
    Unreadable { path: PathBuf, error: String },
    /// Shim is reflogless-managed but its hardcoded reflogless binary
    /// path doesn't match the current binary (or doesn't exist at all).
    /// Every `git` invocation through this shim will fail. Fix:
    /// `reflogless init --shim` to refresh the path.
    Stale {
        path: PathBuf,
        script_points_at: PathBuf,
        current_binary_at: Option<PathBuf>,
    },
}

/// Extract the reflogless binary path the shim script will exec. Returns
/// `None` if the body doesn't look like a managed shim or the exec line
/// can't be parsed.
fn extract_shim_target(body: &str) -> Option<PathBuf> {
    for line in body.lines() {
        let trimmed = line.trim_start();
        if !trimmed.contains("_shim") {
            continue;
        }
        let rest = trimmed
            .strip_prefix("exec ")
            .unwrap_or(trimmed)
            .trim_start();
        if let Some(target) = first_quoted_path(rest) {
            return Some(target);
        }
    }
    None
}

fn first_quoted_path(s: &str) -> Option<PathBuf> {
    let after_quote = s.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(PathBuf::from(&after_quote[..end]))
}

/// Inspect the filesystem and PATH to classify the shim.
pub fn observe() -> ShimStatus {
    let shim_dir = match resolve_shim_dir() {
        Ok(d) => d,
        Err(_) => return ShimStatus::Off,
    };
    let shim_path = shim_dir.join(shim_file_name());
    if !shim_path.exists() {
        return ShimStatus::Off;
    }
    let body = match fs::read_to_string(&shim_path) {
        Ok(b) => b,
        Err(e) => {
            return ShimStatus::Unreadable {
                path: shim_path,
                error: e.to_string(),
            }
        }
    };
    if !is_managed_shim_body(&body) {
        return ShimStatus::Foreign { path: shim_path };
    }

    // Detect stale binary path: the shim script bakes in the reflogless
    // path at install time. If reflogless was reinstalled to a new
    // location, the shim still points at the old (now-missing) binary
    // and every `git` invocation fails. Fix: `reflogless init --shim`.
    if let Some(script_target) = extract_shim_target(&body) {
        let current_binary = std::env::current_exe().ok();
        let script_target_exists = script_target.exists();
        let same_target = current_binary
            .as_ref()
            .map(|c| same_file(&script_target, c))
            .unwrap_or(false);
        if !script_target_exists || !same_target {
            return ShimStatus::Stale {
                path: shim_path,
                script_points_at: script_target,
                current_binary_at: current_binary,
            };
        }
    }

    // Walk PATH to confirm our shim is what `git` resolves to.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for candidate in git_candidates_for_dir(&dir) {
                if !candidate.exists() {
                    continue;
                }
                if same_file(&candidate, &shim_path) {
                    return ShimStatus::On { path: shim_path };
                }
                return ShimStatus::Shadowed {
                    ours: shim_path,
                    precedes: candidate,
                };
            }
        }
    }
    // PATH didn't contain any `git` at all but the shim file exists — treat
    // as On (the user's PATH is the user's problem; the shim itself is fine).
    ShimStatus::On { path: shim_path }
}

fn git_candidates_for_dir(dir: &Path) -> Vec<PathBuf> {
    git_candidate_names()
        .into_iter()
        .map(|name| dir.join(name))
        .collect()
}

#[cfg(windows)]
fn git_candidate_names() -> Vec<String> {
    git_candidate_names_from_pathext(std::env::var("PATHEXT").ok().as_deref())
}

#[cfg(not(windows))]
fn git_candidate_names() -> Vec<String> {
    vec!["git".into()]
}

#[cfg(any(windows, test))]
fn git_candidate_names_from_pathext(pathext: Option<&str>) -> Vec<String> {
    let mut names = vec!["git".into()];
    let Some(pathext) = pathext else {
        names.push("git.cmd".into());
        return names;
    };
    for ext in pathext.split(';') {
        if ext.is_empty() {
            continue;
        }
        let ext = ext.trim_start_matches('.');
        names.push(format!("git.{}", ext.to_ascii_lowercase()));
    }
    if !names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("git.cmd"))
    {
        names.push("git.cmd".into());
    }
    names
}

fn same_file(a: &Path, b: &Path) -> bool {
    fn canon(p: &Path) -> Option<PathBuf> {
        fs::canonicalize(p).ok()
    }
    match (canon(a), canon(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// Compute the PATH minus the shim's own directory. Used by the `_shim`
/// runtime when locating real `git` to exec.
pub fn path_without_shim_dir(shim_dir: &Path) -> String {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let cleaned: Vec<PathBuf> = std::env::split_paths(&path_var)
        .filter(|d| !same_file(d, shim_dir))
        .collect();
    std::env::join_paths(cleaned)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or(path_var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests that mutate REFLOGLESS_SHIM_DIR / PATH must serialize — env is
    // process-global and `cargo test` runs in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn destructive_event_clean_any_form() {
        assert_eq!(destructive_event(&args(&["clean"])), Some("shim-clean"));
        assert_eq!(
            destructive_event(&args(&["clean", "-fdx"])),
            Some("shim-clean")
        );
        assert_eq!(
            destructive_event(&args(&["clean", "--force", "-d"])),
            Some("shim-clean")
        );
    }

    #[test]
    fn destructive_event_clean_dry_run_short_circuits() {
        // --dry-run is touch-free; no snapshot needed.
        assert_eq!(destructive_event(&args(&["clean", "--dry-run"])), None);
        assert_eq!(destructive_event(&args(&["clean", "-n"])), None);
        // -n clustered with other short flags
        assert_eq!(destructive_event(&args(&["clean", "-nd"])), None);
        assert_eq!(destructive_event(&args(&["clean", "-ndx"])), None);
        assert_eq!(destructive_event(&args(&["clean", "-fnd"])), None);
        // Dry-run still detected after the global -C subcommand routing
        assert_eq!(
            destructive_event(&args(&["-C", "sub", "clean", "--dry-run"])),
            None
        );
        // Pathspec named "-n" after `--` must NOT trigger dry-run
        assert_eq!(
            destructive_event(&args(&["clean", "-fd", "--", "-n"])),
            Some("shim-clean")
        );
        // --no-dry-run is not --dry-run
        assert_eq!(
            destructive_event(&args(&["clean", "--no-dry-run"])),
            Some("shim-clean")
        );
        // reset --hard has no dry-run; flag should not affect it
        assert_eq!(
            destructive_event(&args(&["reset", "--hard", "-n"])),
            Some("shim-reset-hard")
        );
    }

    #[test]
    fn destructive_event_reset_hard_flag_anywhere() {
        assert_eq!(
            destructive_event(&args(&["reset", "--hard"])),
            Some("shim-reset-hard")
        );
        assert_eq!(
            destructive_event(&args(&["reset", "--hard", "HEAD~1"])),
            Some("shim-reset-hard")
        );
        assert_eq!(
            destructive_event(&args(&["reset", "HEAD~1", "--hard"])),
            Some("shim-reset-hard")
        );
        assert_eq!(
            destructive_event(&args(&["reset", "origin/main", "--hard"])),
            Some("shim-reset-hard")
        );
    }

    #[test]
    fn destructive_event_reset_other_modes_passthrough() {
        assert_eq!(destructive_event(&args(&["reset"])), None);
        assert_eq!(destructive_event(&args(&["reset", "--soft"])), None);
        assert_eq!(destructive_event(&args(&["reset", "--mixed"])), None);
        assert_eq!(destructive_event(&args(&["reset", "HEAD~1"])), None);
        assert_eq!(destructive_event(&args(&["reset", "--keep"])), None);
    }

    #[test]
    fn destructive_event_other_subcommands_passthrough() {
        assert_eq!(destructive_event(&args(&["status"])), None);
        assert_eq!(destructive_event(&args(&["commit"])), None);
        assert_eq!(destructive_event(&args(&["push"])), None);
        assert_eq!(destructive_event(&args(&["pull"])), None);
        // Clean (non-force) checkout/switch don't lose work — passthrough.
        assert_eq!(destructive_event(&args(&["checkout", "main"])), None);
        assert_eq!(
            destructive_event(&args(&["checkout", "-b", "feature"])),
            None
        );
        assert_eq!(destructive_event(&args(&["switch", "main"])), None);
    }

    #[test]
    fn destructive_event_restore_snaps_unless_staged_only() {
        assert_eq!(
            destructive_event(&args(&["restore", "file.txt"])),
            Some("shim-restore")
        );
        assert_eq!(
            destructive_event(&args(&["restore", "--source", "HEAD~1", "file.txt"])),
            Some("shim-restore")
        );
        // --staged only — index-only, no worktree write
        assert_eq!(
            destructive_event(&args(&["restore", "--staged", "file.txt"])),
            None
        );
        assert_eq!(
            destructive_event(&args(&["restore", "-S", "file.txt"])),
            None
        );
        // --staged combined with --worktree → both, destructive
        assert_eq!(
            destructive_event(&args(&["restore", "--staged", "--worktree", "file.txt"])),
            Some("shim-restore")
        );
        // Explicit --worktree
        assert_eq!(
            destructive_event(&args(&["restore", "--worktree", "file.txt"])),
            Some("shim-restore")
        );
    }

    #[test]
    fn destructive_event_switch_snaps_only_with_force() {
        assert_eq!(
            destructive_event(&args(&["switch", "-f", "main"])),
            Some("shim-switch-force")
        );
        assert_eq!(
            destructive_event(&args(&["switch", "main", "-f"])),
            Some("shim-switch-force")
        );
        assert_eq!(
            destructive_event(&args(&["switch", "--discard-changes", "main"])),
            Some("shim-switch-force")
        );
        // Clean switch — git refuses on dirty trees, no need to snap.
        assert_eq!(destructive_event(&args(&["switch", "main"])), None);
        assert_eq!(destructive_event(&args(&["switch", "-c", "feature"])), None);
    }

    #[test]
    fn destructive_event_checkout_snaps_on_force_or_pathspec() {
        assert_eq!(
            destructive_event(&args(&["checkout", "-f"])),
            Some("shim-checkout-force")
        );
        assert_eq!(
            destructive_event(&args(&["checkout", "--force", "main"])),
            Some("shim-checkout-force")
        );
        // Pathspec form — overwrites the named paths from HEAD
        assert_eq!(
            destructive_event(&args(&["checkout", "--", "file.txt"])),
            Some("shim-checkout-force")
        );
        assert_eq!(
            destructive_event(&args(&["checkout", "HEAD~1", "--", "src/foo.rs"])),
            Some("shim-checkout-force")
        );
        // Clean checkout — passthrough
        assert_eq!(destructive_event(&args(&["checkout", "main"])), None);
    }

    #[test]
    fn destructive_event_global_flags_with_expanded_allowlist() {
        // -C subdir restore <file>
        assert_eq!(
            destructive_event(&args(&["-C", "sub", "restore", "f"])),
            Some("shim-restore")
        );
        assert_eq!(
            destructive_event(&args(&["-C", "sub", "switch", "-f", "main"])),
            Some("shim-switch-force")
        );
        assert_eq!(
            destructive_event(&args(&["-c", "foo=bar", "checkout", "-f"])),
            Some("shim-checkout-force")
        );
    }

    #[test]
    fn destructive_event_global_flags_before_subcommand() {
        // git -C dir clean -fdx — global -C before the subcommand
        assert_eq!(
            destructive_event(&args(&["-C", "subdir", "clean", "-fdx"])),
            Some("shim-clean")
        );
        // -c key=val before subcommand
        assert_eq!(
            destructive_event(&args(&["-c", "foo=bar", "reset", "--hard"])),
            Some("shim-reset-hard")
        );
    }

    #[test]
    fn destructive_event_empty_args() {
        assert_eq!(destructive_event(&args(&[])), None);
        assert_eq!(destructive_event(&args(&["--version"])), None);
    }

    #[test]
    fn rendered_script_contains_marker_and_bin() {
        let bin = PathBuf::from("/usr/local/bin/reflogless");
        let s = render_shim_script(&bin);
        assert!(s.contains(MARKER));
        assert!(s.contains("/usr/local/bin/reflogless"));
        assert!(s.contains("_shim"));
        assert!(s.starts_with("#!/bin/sh"));
    }

    #[test]
    fn rendered_windows_script_is_cmd_wrapper() {
        let bin = PathBuf::from(r"C:\Users\me\.cargo\bin\reflogless.exe");
        let s = render_windows_shim_script(&bin);
        assert!(s.starts_with("@echo off\r\n"));
        assert!(s.contains(&format!("REM {MARKER}")));
        assert!(s.contains(r#""C:\Users\me\.cargo\bin\reflogless.exe" _shim"#));
        assert!(s.contains(r#"--shim-dir="%~dp0" -- %*"#));
        assert!(is_managed_shim_body(&s));
        assert_eq!(
            extract_shim_target(&s),
            Some(PathBuf::from(r"C:\Users\me\.cargo\bin\reflogless.exe"))
        );
    }

    #[test]
    fn path_without_shim_dir_removes_only_matching_entry() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("PATH", "/usr/bin:/tmp/shim:/usr/local/bin");
        let pruned = path_without_shim_dir(Path::new("/tmp/shim"));
        let dirs: Vec<&str> = pruned.split(':').collect();
        assert!(!dirs.contains(&"/tmp/shim"));
        assert!(dirs.contains(&"/usr/bin"));
        assert!(dirs.contains(&"/usr/local/bin"));
    }

    #[test]
    fn destructive_event_dash_c_with_no_value_does_not_panic() {
        assert_eq!(destructive_event(&args(&["-C"])), None);
        assert_eq!(destructive_event(&args(&["-c"])), None);
    }

    #[test]
    fn is_managed_shim_body_requires_anchored_marker_line() {
        let managed = format!("#!/bin/sh\n{MARKER}\nexec foo\n");
        assert!(is_managed_shim_body(&managed));

        let mention_in_comment =
            "#!/bin/sh\n# DO NOT use the reflogless-managed shim wrapper\nexec foo\n";
        assert!(
            !is_managed_shim_body(mention_in_comment),
            "substring mention of MARKER must not match"
        );

        let mid_string = "#!/bin/sh\nfoo='# reflogless-managed shim is here'\n";
        assert!(!is_managed_shim_body(mid_string));
    }

    fn install_with_shim_dir(dir: &Path) -> Result<InstallReport> {
        std::env::set_var("REFLOGLESS_SHIM_DIR", dir);
        install()
    }

    #[test]
    fn extract_shim_target_parses_rendered_script() {
        let bin = PathBuf::from("/home/user/.cargo/bin/reflogless");
        let script = render_shim_script(&bin);
        assert_eq!(extract_shim_target(&script), Some(bin));
    }

    #[test]
    fn extract_shim_target_returns_none_on_unmanaged_body() {
        assert_eq!(extract_shim_target("#!/bin/sh\necho hi\n"), None);
        assert_eq!(extract_shim_target(""), None);
        // Malformed exec line (no closing quote)
        assert_eq!(extract_shim_target("exec \"/bin/foo unterminated\n"), None);
    }

    #[test]
    fn git_candidate_names_follow_windows_pathext_order() {
        assert_eq!(
            git_candidate_names_from_pathext(Some(".COM;.EXE;.BAT;.CMD")),
            vec!["git", "git.com", "git.exe", "git.bat", "git.cmd"]
        );
        assert_eq!(
            git_candidate_names_from_pathext(Some(".CMD;.EXE")),
            vec!["git", "git.cmd", "git.exe"]
        );
        assert_eq!(
            git_candidate_names_from_pathext(None),
            vec!["git", "git.cmd"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn observe_reports_unreadable_when_shim_chmod_zero() {
        use std::os::unix::fs::PermissionsExt;
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let shim_path = td.path().join("git");
        fs::write(&shim_path, "#!/bin/sh\nfoo\n").unwrap();
        let mut perms = fs::metadata(&shim_path).unwrap().permissions();
        perms.set_mode(0o0);
        fs::set_permissions(&shim_path, perms).unwrap();

        std::env::set_var("REFLOGLESS_SHIM_DIR", td.path());
        let status = observe();
        // Restore perms before assert so tempdir cleanup works.
        let mut restore = fs::metadata(&shim_path).unwrap().permissions();
        restore.set_mode(0o644);
        let _ = fs::set_permissions(&shim_path, restore);
        match status {
            ShimStatus::Unreadable { path, error } => {
                assert_eq!(path, shim_path);
                assert!(!error.is_empty());
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn observe_reports_stale_when_script_points_to_missing_path() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let shim_path = td.path().join("git");
        // Write a managed-looking shim that points at a path that doesn't exist.
        let body = format!(
            "#!/bin/sh\n{MARKER}\nexec \"/nonexistent/reflogless\" _shim --shim-dir=\"$(dirname \"$0\")\" -- \"$@\"\n"
        );
        fs::write(&shim_path, body).unwrap();

        std::env::set_var("REFLOGLESS_SHIM_DIR", td.path());
        match observe() {
            ShimStatus::Stale {
                path,
                script_points_at,
                ..
            } => {
                assert_eq!(path, shim_path);
                assert_eq!(script_points_at, PathBuf::from("/nonexistent/reflogless"));
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn install_then_uninstall_round_trip() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let report = install_with_shim_dir(td.path()).unwrap();
        assert!(report.shim_path.exists());
        let body = fs::read_to_string(&report.shim_path).unwrap();
        assert!(is_managed_shim_body(&body));

        let removed = uninstall().unwrap();
        assert_eq!(removed, Some(report.shim_path.clone()));
        assert!(!report.shim_path.exists());
    }

    #[test]
    fn install_refuses_to_overwrite_foreign_file() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let shim_path = td.path().join("git");
        let foreign = "#!/bin/sh\necho hi from user wrapper\n";
        fs::write(&shim_path, foreign).unwrap();

        std::env::set_var("REFLOGLESS_SHIM_DIR", td.path());
        let err = install().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert_eq!(fs::read_to_string(&shim_path).unwrap(), foreign);
    }

    #[test]
    fn uninstall_refuses_to_remove_foreign_file() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let shim_path = td.path().join("git");
        let foreign = "#!/bin/sh\necho hi from user wrapper\n";
        fs::write(&shim_path, foreign).unwrap();

        std::env::set_var("REFLOGLESS_SHIM_DIR", td.path());
        let err = uninstall().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert!(shim_path.exists());
    }

    #[test]
    fn uninstall_when_absent_returns_ok_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("REFLOGLESS_SHIM_DIR", td.path());
        assert_eq!(uninstall().unwrap(), None);
    }

    #[test]
    fn install_is_idempotent_on_managed_shim() {
        let _g = ENV_LOCK.lock().unwrap();
        let td = tempfile::tempdir().unwrap();
        let r1 = install_with_shim_dir(td.path()).unwrap();
        let body1 = fs::read_to_string(&r1.shim_path).unwrap();
        let r2 = install().unwrap();
        let body2 = fs::read_to_string(&r2.shim_path).unwrap();
        assert_eq!(body1, body2);
        assert_eq!(r1.shim_path, r2.shim_path);
    }

    #[test]
    fn resolve_shim_dir_env_var_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("REFLOGLESS_SHIM_DIR", "/tmp/reflogless-test-dir");
        assert_eq!(
            resolve_shim_dir().unwrap(),
            PathBuf::from("/tmp/reflogless-test-dir")
        );
    }

    #[test]
    fn resolve_shim_dir_empty_env_var_falls_through() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("REFLOGLESS_SHIM_DIR", "");
        // Falls through to dirs::executable_dir() or ~/.local/bin — both
        // produce a non-empty PathBuf on any reasonable test host.
        let resolved = resolve_shim_dir().unwrap();
        assert!(!resolved.as_os_str().is_empty());
        assert_ne!(resolved, PathBuf::from(""));
    }
}

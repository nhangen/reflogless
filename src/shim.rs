use std::fs;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Recognizable substring in our managed shim script. `doctor` keys off this.
pub const MARKER: &str = "# reflogless-managed shim";

/// Detect whether a `git <args>` invocation modifies the working tree in a
/// way reflogless wants to snapshot.
///
/// Conservative v0.1.x scope:
/// - `git clean ...` (every form — flags can't make `clean` non-destructive
///   except `--dry-run`/`-n`, but over-snapshotting is cheaper than missing
///   a real clean).
/// - `git reset --hard ...` (the `--hard` flag can appear before or after a
///   commit-ish positional argument).
///
/// Returns the event tag to use for the snapshot, or `None` to passthrough.
pub fn destructive_event(args: &[String]) -> Option<&'static str> {
    let (idx, subcommand) = find_subcommand(args)?;
    match subcommand {
        "clean" => Some("shim-clean"),
        "reset" => {
            let after = &args[idx + 1..];
            if after.iter().any(|a| a == "--hard") {
                Some("shim-reset-hard")
            } else {
                None
            }
        }
        _ => None,
    }
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
    let shim_path = shim_dir.join("git");
    let reflogless_bin =
        std::env::current_exe().map_err(|e| Error::io("<current_exe>", e))?;

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
    let shim_path = shim_dir.join("git");
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
    if let Some(d) = dirs::executable_dir() {
        return Ok(d);
    }
    // `dirs::executable_dir()` returns None on macOS and Windows. Falling
    // back to the reflogless binary's parent would target a system bin
    // (e.g. /opt/homebrew/bin) — default to ~/.local/bin instead.
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".local").join("bin"));
    }
    let exe = std::env::current_exe().map_err(|e| Error::io("<current_exe>", e))?;
    exe.parent().map(PathBuf::from).ok_or_else(|| {
        Error::Config("could not resolve shim install directory".into())
    })
}

/// Detects a reflogless-managed shim by line-anchored marker match.
/// Substring matching would false-positive on user wrappers that mention
/// the marker string in a comment.
fn is_managed_shim_body(body: &str) -> bool {
    body.lines().any(|line| line.trim() == MARKER)
}

fn render_shim_script(reflogless_bin: &Path) -> String {
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
    Shadowed {
        ours: PathBuf,
        precedes: PathBuf,
    },
    /// A file at the shim path exists but is not reflogless-managed.
    Foreign { path: PathBuf },
}

/// Inspect the filesystem and PATH to classify the shim.
pub fn observe() -> ShimStatus {
    let shim_dir = match resolve_shim_dir() {
        Ok(d) => d,
        Err(_) => return ShimStatus::Off,
    };
    let shim_path = shim_dir.join("git");
    if !shim_path.exists() {
        return ShimStatus::Off;
    }
    let body = match fs::read_to_string(&shim_path) {
        Ok(b) => b,
        Err(_) => return ShimStatus::Foreign { path: shim_path },
    };
    if !body.contains(MARKER) {
        return ShimStatus::Foreign { path: shim_path };
    }

    // Walk PATH to confirm our shim is what `git` resolves to.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("git");
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
    // PATH didn't contain any `git` at all but the shim file exists — treat
    // as On (the user's PATH is the user's problem; the shim itself is fine).
    ShimStatus::On { path: shim_path }
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
        assert_eq!(destructive_event(&args(&["clean", "-fdx"])), Some("shim-clean"));
        assert_eq!(
            destructive_event(&args(&["clean", "--force", "-d"])),
            Some("shim-clean")
        );
        // We deliberately over-snapshot on --dry-run: detecting it correctly
        // requires parsing every clean flag, and an extra snapshot on a dry
        // run is harmless (CAS dedup → ~0 bytes written).
        assert_eq!(
            destructive_event(&args(&["clean", "--dry-run"])),
            Some("shim-clean")
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
        // Outside the conservative v0.1.x allowlist — restore/switch/checkout
        // -f are tracked as follow-up issues but currently passthrough.
        assert_eq!(destructive_event(&args(&["restore", "file"])), None);
        assert_eq!(destructive_event(&args(&["switch", "-f", "main"])), None);
        assert_eq!(destructive_event(&args(&["checkout", "-f"])), None);
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
    fn path_without_shim_dir_removes_only_matching_entry() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("PATH", "/usr/bin:/tmp/shim:/usr/local/bin");
        let pruned = path_without_shim_dir(Path::new("/tmp/shim"));
        let dirs: Vec<&str> = pruned.split(':').collect();
        assert!(!dirs.iter().any(|d| *d == "/tmp/shim"));
        assert!(dirs.iter().any(|d| *d == "/usr/bin"));
        assert!(dirs.iter().any(|d| *d == "/usr/local/bin"));
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

        let mention_in_comment = "#!/bin/sh\n# DO NOT use the reflogless-managed shim wrapper\nexec foo\n";
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
        assert_eq!(resolve_shim_dir().unwrap(), PathBuf::from("/tmp/reflogless-test-dir"));
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

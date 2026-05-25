use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use reflogless::config::Config;
use reflogless::crypto;
use reflogless::doctor;
use reflogless::hooks;
use reflogless::keystore::{FileStore, KeyStore, KeychainStore};
use reflogless::manifest::Manifest;
use reflogless::repo::Repo;
use reflogless::shim;
use reflogless::snapshot::{restore, snap_with_policy};
use reflogless::store::{CryptoCtx, Store, DEFAULT_MAX_AGE_DAYS, DEFAULT_MAX_STORE_BYTES};

#[derive(Parser)]
#[command(
    name = "reflogless",
    version,
    about = "Local untracked-file safety net for git"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Take a manual snapshot of untracked + modified-unstaged files.
    Snap {
        #[arg(short = 'm', long)]
        message: Option<String>,
        /// Override the auto-tagged event name.
        #[arg(long, default_value = "manual")]
        event: String,
    },
    /// List snapshots for the current repo.
    List,
    /// Show files in a snapshot.
    Show { id: String },
    /// Restore a snapshot (refuses overwrites without --force).
    Restore {
        id: String,
        paths: Vec<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Diff a snapshot file vs the current working tree.
    Diff { id: String, path: Option<PathBuf> },
    /// Run LRU + age eviction.
    Gc {
        #[arg(long, default_value_t = DEFAULT_MAX_AGE_DAYS)]
        max_age_days: i64,
        #[arg(long, default_value_t = DEFAULT_MAX_STORE_BYTES)]
        max_bytes: u64,
    },
    /// Install reflogless hooks into the current repo and provision an
    /// encryption identity (keychain by default; pass --insecure-file-key
    /// to store the key on disk under the store dir).
    Init {
        /// Also install a `git` PATH shim that snapshots before
        /// `git clean` and `git reset --hard`. Opt-in only; see README.
        #[arg(long)]
        shim: bool,
        /// Store the encryption key in a 0600 file under the reflogless store
        /// instead of the OS keychain. Loud warning; doctor surfaces this.
        #[arg(long)]
        insecure_file_key: bool,
    },
    /// Remove reflogless hooks; restore any prior chained third-party hooks.
    Uninstall {
        /// Also delete the on-disk snapshot store for this repo. Requires --yes.
        #[arg(long)]
        purge: bool,
        /// Confirms a destructive operation (required with --purge).
        #[arg(long)]
        yes: bool,
    },
    /// Verify install + store + canary.
    Doctor,
    /// Internal: dispatched by the installed PATH shim. Not for direct use.
    #[command(hide = true)]
    #[command(name = "_shim")]
    Shim {
        /// Directory containing the shim binary; passed by the shim script
        /// so we can strip it from PATH before exec'ing the real `git`.
        #[arg(long)]
        shim_dir: PathBuf,
        /// Verbatim git arguments to forward.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("reflogless: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> reflogless::Result<()> {
    let cli = Cli::parse();

    // _shim runs from arbitrary cwd, may be outside any git repo, and must
    // never abort `git` on internal reflogless errors. Dispatch before the
    // repo-discovery prelude that every other command requires.
    if let Cmd::Shim { shim_dir, args } = cli.cmd {
        return run_shim(shim_dir, args);
    }

    let cwd = std::env::current_dir().map_err(|e| reflogless::Error::io(".", e))?;
    let repo = Repo::discover(&cwd)?;
    repo.assert_safe_ownership()?;
    let raw_store = Store::for_repo(&repo)?;
    let cfg = Config::load_or_default(&repo.root)?;
    let store = attach_identity_if_provisioned(&repo, raw_store)?;

    match cli.cmd {
        Cmd::Shim { .. } => unreachable!("handled above"),
        Cmd::Snap { message, event } => {
            let r = snap_with_policy(&repo, &store, &event, message, cfg.encrypt)?;
            println!(
                "{}\nfiles: {}  bytes: {}  skipped: {}",
                r.manifest_id, r.files_written, r.bytes_written, r.skipped
            );
        }
        Cmd::List => {
            let (mut ms, warnings) = store.list_manifests_lenient()?;
            ms.sort_by_key(|m| m.created_at);
            for m in ms {
                println!(
                    "{}  {}  {} files  {}",
                    m.id,
                    m.event,
                    m.entries.len(),
                    m.message.as_deref().unwrap_or("")
                );
            }
            for (p, e) in warnings {
                eprintln!("reflogless: warning: skipping {}: {e}", p.display());
            }
        }
        Cmd::Show { id } => {
            let m = store.load_manifest(&id)?;
            print_manifest(&m);
        }
        Cmd::Restore { id, paths, force } => {
            let r = restore(&repo, &store, &id, &paths, force)?;
            println!(
                "restored {} from {} (refused {})",
                r.restored,
                r.snap_id,
                r.refused.len()
            );
            for p in r.refused {
                println!("  refused: {} (use --force)", p.display());
            }
        }
        Cmd::Diff { id, path } => {
            let m = store.load_manifest(&id)?;
            diff_snapshot(&repo, &store, &m, path.as_deref())?;
        }
        Cmd::Gc {
            max_age_days,
            max_bytes,
        } => {
            let report = store.gc(max_age_days, max_bytes)?;
            println!(
                "gc: snapshots evicted {} (age) + {} (size) + {} (corrupt); blobs dropped {}",
                report.snapshots_age_evicted,
                report.snapshots_size_evicted,
                report.snapshots_corrupt_evicted,
                report.blobs_evicted
            );
        }
        Cmd::Init {
            shim: install_shim,
            insecure_file_key,
        } => {
            let log = store.root.join("hook-errors.log");
            let report = hooks::install(&repo, &log)?;
            println!("installed into {}", report.hooks_dir.display());
            for h in &report.installed {
                println!("  + {h}");
            }
            for h in &report.chained {
                println!("  chained (preserved existing hook): {h}");
            }
            provision_identity(&repo, &store, insecure_file_key)?;
            if install_shim {
                let r = shim::install()?;
                println!(
                    "installed shim at {} (delegates to {})",
                    r.shim_path.display(),
                    r.reflogless_bin.display()
                );
                println!(
                    "  ensure {} is earlier on PATH than your system git",
                    r.shim_path
                        .parent()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                );
            }
        }
        Cmd::Uninstall { purge, yes } => {
            if purge && !yes {
                return Err(reflogless::Error::Config(
                    "--purge requires --yes (destructive: deletes the snapshot store)".into(),
                ));
            }
            let report = hooks::uninstall(&repo)?;
            for h in &report.removed {
                println!("removed {h}");
            }
            for h in &report.restored {
                println!("restored prior {h}");
            }
            for h in &report.skipped {
                println!("skipped {h} (not reflogless-managed)");
            }
            match shim::uninstall() {
                Ok(Some(p)) => println!("removed shim at {}", p.display()),
                Ok(None) => {}
                Err(e) => eprintln!("reflogless: warning: shim removal: {e}"),
            }
            if purge {
                let mut purge_warnings = 0u32;
                // Key removal before deleting the store dir. Failures surface
                // to stderr (per safety-invariant-scope: destructive command
                // failures must not be silent) but don't abort the disk wipe.
                if let Err(e) = KeychainStore.delete(&repo.id()) {
                    eprintln!("reflogless: warning: keychain entry not removed: {e}");
                    eprintln!(
                        "reflogless:          manually run: security delete-generic-password -s reflogless -a {}",
                        repo.id()
                    );
                    purge_warnings += 1;
                }
                let identity_file = store.root.join("identity.key");
                if identity_file.exists() {
                    if let Err(e) = std::fs::remove_file(&identity_file) {
                        eprintln!(
                            "reflogless: warning: identity file not removed at {}: {e}",
                            identity_file.display()
                        );
                        purge_warnings += 1;
                    }
                }
                if store.root.exists() {
                    std::fs::remove_dir_all(&store.root)
                        .map_err(|e| reflogless::Error::io(&store.root, e))?;
                    println!("purged store at {}", store.root.display());
                } else {
                    println!("store already absent at {}", store.root.display());
                }
                if purge_warnings > 0 {
                    return Err(reflogless::Error::Config(format!(
                        "purge incomplete: {purge_warnings} resource(s) not removed (see stderr)"
                    )));
                }
            }
        }
        Cmd::Doctor => {
            let report = doctor::run(&repo, &store)?;
            print!("{}", report.render());
            if !report.is_healthy() {
                return Err(reflogless::Error::Doctor(
                    report.first_failure().unwrap_or("not healthy").into(),
                ));
            }
        }
    }
    Ok(())
}

fn provision_identity(repo: &Repo, store: &Store, insecure: bool) -> reflogless::Result<()> {
    if store.provisioned_for_encryption() {
        println!(
            "identity already provisioned (recipient: {})",
            store.recipient_path().display()
        );
        return Ok(());
    }
    let identity = crypto::generate_identity();
    let recipient = crypto::recipient_of(&identity);

    // Save the secret half FIRST so a keychain denial / file-write failure
    // doesn't leave recipient.txt on disk. If recipient.txt is present, every
    // subsequent invocation treats the store as "provisioned" and tries to
    // load the identity — failure there would brick `uninstall` itself.
    if insecure {
        let file = store.root.join("identity.key");
        let ks = FileStore::new(&file);
        ks.save(&repo.id(), &identity)?;
        store.save_recipient(&recipient)?;
        store.mark_insecure()?;
        eprintln!(
            "reflogless: WARNING — encryption key stored unencrypted at {}",
            file.display()
        );
        eprintln!(
            "reflogless:           anyone with read access to that file can decrypt every snapshot"
        );
        println!("provisioned identity (file key at {})", file.display());
    } else {
        KeychainStore.save(&repo.id(), &identity)?;
        store.save_recipient(&recipient)?;
        println!(
            "provisioned identity (keychain service=reflogless account={})",
            repo.id()
        );
    }
    Ok(())
}

fn attach_identity_if_provisioned(repo: &Repo, store: Store) -> reflogless::Result<Store> {
    if !store.provisioned_for_encryption() {
        return Ok(store);
    }
    let identity = if store.is_insecure_keyed() {
        let file = store.root.join("identity.key");
        FileStore::new(&file).load(&repo.id())?
    } else {
        KeychainStore.load(&repo.id())?
    };
    Ok(store.with_crypto(CryptoCtx::from_identity(identity)))
}

fn print_manifest(m: &Manifest) {
    println!("id: {}", m.id);
    println!("created: {}", m.created_at);
    println!("event: {}", m.event);
    if let Some(msg) = &m.message {
        println!("message: {msg}");
    }
    println!("entries: {}", m.entries.len());
    for e in &m.entries {
        println!(
            "  {} ({} bytes, mode {:o}) blob {}",
            e.path.display(),
            e.size,
            e.mode,
            &e.blob[..12]
        );
    }
}

fn diff_snapshot(
    repo: &Repo,
    store: &Store,
    m: &Manifest,
    only: Option<&std::path::Path>,
) -> reflogless::Result<()> {
    for e in &m.entries {
        if let Some(p) = only {
            if p != e.path {
                continue;
            }
        }
        let snap_bytes = store.read_entry(e)?;
        let cur_path = repo.root.join(&e.path);
        let (cur_bytes, work_label) = match std::fs::read(&cur_path) {
            Ok(b) => (b, format!("work:{}", e.path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                (Vec::new(), format!("work:{} (missing)", e.path.display()))
            }
            Err(err) => return Err(reflogless::Error::io(&cur_path, err)),
        };
        if snap_bytes == cur_bytes {
            continue;
        }
        let snap_text = String::from_utf8_lossy(&snap_bytes);
        let cur_text = String::from_utf8_lossy(&cur_bytes);
        let diff = similar::TextDiff::from_lines(&snap_text, &cur_text);
        println!("--- snap:{}/{}\n+++ {}", m.id, e.path.display(), work_label);
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };
            print!("{sign}{change}");
        }
    }
    Ok(())
}

/// Body of the hidden `_shim` subcommand. Snapshots the working tree (best
/// effort) when the forwarded git invocation is destructive, then execs the
/// real `git` so the user sees its exit code directly.
///
/// Errors inside this function never propagate to abort the user's git
/// command — they're logged to the per-repo `<store>/shim-errors.log` (or
/// stderr if the store can't be located).
fn run_shim(shim_dir: PathBuf, args: Vec<String>) -> reflogless::Result<()> {
    if let Some(event) = shim::destructive_event(&args) {
        if let Err(e) = snapshot_for_shim(event) {
            log_shim_error(&format!("snapshot for {event}: {e}"));
        }
    }

    let pruned_path = shim::path_without_shim_dir(&shim_dir);
    let safe_path = if pruned_path.is_empty() {
        "/usr/bin:/bin".to_string()
    } else {
        pruned_path
    };
    let mut cmd = std::process::Command::new("git");
    cmd.args(&args);
    cmd.env("PATH", &safe_path);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let exec_err = cmd.exec();
        log_shim_error(&format!(
            "exec git failed, falling back to spawn: {exec_err}"
        ));
    }

    let status = cmd
        .status()
        .map_err(|e| reflogless::Error::Config(format!("failed to spawn git: {e}")))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn snapshot_for_shim(event: &str) -> reflogless::Result<()> {
    let cwd = std::env::current_dir().map_err(|e| reflogless::Error::io(".", e))?;
    let repo = Repo::discover(&cwd)?;
    repo.assert_safe_ownership()?;
    let raw_store = Store::for_repo(&repo)?;
    let cfg = Config::load_or_default(&repo.root)?;
    let store = attach_identity_if_provisioned(&repo, raw_store)?;
    snap_with_policy(&repo, &store, event, None, cfg.encrypt)?;
    Ok(())
}

fn log_shim_error(msg: &str) {
    let store_logged = (|| -> reflogless::Result<()> {
        let cwd = std::env::current_dir().map_err(|e| reflogless::Error::io(".", e))?;
        let repo = Repo::discover(&cwd)?;
        let store = Store::for_repo(&repo)?;
        write_shim_log_line(&store.root.join("shim-errors.log"), msg)
    })();
    if store_logged.is_ok() {
        return;
    }
    if let Some(fallback) = shim_fallback_log_path() {
        if write_shim_log_line(&fallback, msg).is_ok() {
            return;
        }
    }
    eprintln!("reflogless-shim: {msg}");
}

fn write_shim_log_line(path: &std::path::Path, msg: &str) -> reflogless::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| reflogless::Error::io(path, e))?;
    let ts = chrono::Utc::now().to_rfc3339();
    writeln!(f, "{ts}  {msg}").map_err(|e| reflogless::Error::io(path, e))
}

fn shim_fallback_log_path() -> Option<PathBuf> {
    if let Some(s) = dirs::state_dir() {
        return Some(s.join("reflogless").join("shim-errors.log"));
    }
    dirs::home_dir().map(|h| {
        h.join(".local")
            .join("state")
            .join("reflogless")
            .join("shim-errors.log")
    })
}

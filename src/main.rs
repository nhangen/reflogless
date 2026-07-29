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
use reflogless::snapshot::{restore, snap_with_config, SnapshotResult};
use reflogless::store::{
    base_data_dir, list_all_stores, reclaim_stale_stores, CryptoCtx, Store, StoreOriginState,
    DEFAULT_MAX_AGE_DAYS, DEFAULT_MAX_STORE_BYTES,
};

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
enum RemoteAction {
    /// Enable an S3-compatible remote backend for offsite durability. Refuses
    /// unless `encrypt = "all"` is set in `.reflogless.toml` AND an identity
    /// has been provisioned via `reflogless init` — otherwise non-secret blobs
    /// would ride plaintext to S3.
    Enable {
        /// s3://bucket[/optional/prefix]
        url: String,
        /// AWS region (e.g. us-east-1). Required even for non-AWS endpoints —
        /// rust-s3 uses it for signature scoping.
        #[arg(long)]
        region: String,
        /// Custom endpoint URL for non-AWS S3 (MinIO, LocalStack, B2, etc.).
        #[arg(long)]
        endpoint: Option<String>,
        /// Use path-style addressing (`<host>/<bucket>/<key>`). Required for
        /// most non-AWS endpoints. Default off so AWS S3 callers get virtual-
        /// hosted style automatically.
        #[arg(long)]
        path_style: bool,
    },
    /// Disable the remote backend. Removes `<store>/remote.toml`; pending log
    /// is left on disk for inspection.
    Disable,
    /// Upload pending blobs + manifests to the configured remote. Reads AWS
    /// credentials from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+
    /// `AWS_SESSION_TOKEN` if present).
    #[cfg(feature = "remote")]
    Push,
    /// Print remote configuration and pending-log status. No network access.
    Status,
}

#[derive(Subcommand)]
enum WatchAction {
    /// Install the watcher into the per-user supervisor (launchd on macOS,
    /// systemd --user on Linux). Daemon starts immediately + persists across
    /// reboots. macOS: writes ~/Library/LaunchAgents/com.nhangen.reflogless.<repo>.plist
    /// + launchctl bootstrap. Linux: writes ~/.config/systemd/user/reflogless-<repo>.service
    /// + systemctl --user enable --now.
    Install,
    /// Remove the watcher from the supervisor + delete the unit/plist file.
    Uninstall,
    /// Run the watcher loop in the foreground until SIGTERM / SIGINT. Used by
    /// the supervisor; can also be invoked directly for testing.
    Run,
    /// Print the last-written heartbeat state file (raw JSON).
    Status,
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
    /// List snapshots for the current repo, or with --all enumerate every
    /// store under the reflogless data directory (scan-friendly, no decryption).
    List {
        #[arg(long)]
        all: bool,
    },
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
    /// Run LRU + age eviction on this repo's store, or with --stale-stores
    /// reclaim whole stores whose repo has been deleted.
    Gc {
        #[arg(long, default_value_t = DEFAULT_MAX_AGE_DAYS)]
        max_age_days: i64,
        #[arg(long, default_value_t = DEFAULT_MAX_STORE_BYTES)]
        max_bytes: u64,
        /// Reclaim entire stores whose recorded origin repo no longer exists.
        /// Operates across every store under the data dir, not just this repo,
        /// so it runs from anywhere. Reports only unless --yes is also given.
        /// Never touches a store that has no recorded origin: that file's
        /// absence tracks install age, not deadness.
        #[arg(long, conflicts_with_all = ["max_age_days", "max_bytes"])]
        stale_stores: bool,
        /// Confirms the deletion. Without it --stale-stores is a dry run.
        #[arg(long, requires = "stale_stores")]
        yes: bool,
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
    /// Filesystem-watcher daemon (#30). macOS launchd + Linux systemd --user
    /// installers ship. Use `install` for auto-start; `run` for foreground;
    /// `status` for the heartbeat state file.
    Watch {
        #[command(subcommand)]
        action: WatchAction,
    },
    /// Optional offsite remote backend (#31). Pushes are explicit; no auto
    /// network traffic. `enable` refuses unless `encrypt = "all"` is set and
    /// an identity has been provisioned via `init`.
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
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

    // `list --all` operates across stores, not inside a repo. Skip the
    // repo-discovery prelude so the user can run it from anywhere.
    if let Cmd::List { all: true } = cli.cmd {
        return run_list_all();
    }

    // Same for `gc --stale-stores`: the stores it reclaims belong to repos that
    // no longer exist, so requiring the caller to stand inside a repo would be
    // arbitrary — and a `Store` cannot be constructed for a repo that is gone,
    // which is exactly why this can't be a `Store` method (#78).
    if let Cmd::Gc {
        stale_stores: true,
        yes,
        ..
    } = cli.cmd
    {
        return run_reclaim_stale_stores(yes);
    }

    let cwd = std::env::current_dir().map_err(|e| reflogless::Error::io(".", e))?;
    let repo = Repo::discover(&cwd)?;
    repo.assert_safe_ownership()?;
    let raw_store = Store::for_repo(&repo)?;
    let store = attach_identity_if_provisioned(&repo, raw_store)?;

    match cli.cmd {
        Cmd::Shim { .. } => unreachable!("handled above"),
        Cmd::Snap { message, event } => {
            let cfg = Config::load_or_default(&repo.root)?;
            let r = snap_with_config(&repo, &store, &event, message, &cfg)?;
            print_snap_result(None, &r);
        }
        Cmd::List { all: true } => unreachable!("handled above"),
        Cmd::List { all: false } => {
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
            ..
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
            let cfg = Config::load_or_default(&repo.root)?;
            run_init(&repo, &store, &cfg, install_shim, insecure_file_key)?;
        }
        Cmd::Uninstall { purge, yes } => {
            if purge && !yes {
                return Err(reflogless::Error::Config(
                    "--purge requires --yes (destructive: deletes the snapshot store)".into(),
                ));
            }
            let report = hooks::uninstall(&repo)?;
            if let Some(p) = &report.declined_hooks_path {
                eprintln!(
                    "reflogless: note: core.hooksPath is set to {} (outside this repo); \
                     left it untouched and uninstalled from the repo's own hooks dir.",
                    p.display()
                );
            }
            for h in &report.removed {
                println!("removed {h}");
            }
            for h in &report.restored {
                println!("restored prior {h}");
            }
            for h in &report.skipped {
                println!("skipped {h} (not reflogless-managed)");
            }
            for h in &report.unreadable {
                eprintln!(
                    "reflogless: warning: could not read {h} — left in place. If it is \
                     reflogless-managed it is still installed and still running; fix the \
                     permissions and re-run `reflogless uninstall`."
                );
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
        Cmd::Remote { action } => run_remote(&repo, &store, action)?,
        Cmd::Watch { action } => match action {
            WatchAction::Install => {
                let report = reflogless::watch_install::install(&repo, &store)?;
                println!(
                    "installed watcher: {} (plist at {})",
                    report.label,
                    report.unit_path.display(),
                );
            }
            WatchAction::Uninstall => {
                let report = reflogless::watch_install::uninstall(&repo, &store)?;
                println!(
                    "uninstalled watcher: {} (removed {})",
                    report.label,
                    report.unit_path.display(),
                );
            }
            WatchAction::Run => {
                let cfg = Config::load_or_default(&repo.root)?;
                let wcfg = reflogless::watch::WatchConfig::from_config(&cfg.watch);
                reflogless::watch::run(&repo, &store, &cfg, &wcfg)?;
            }
            WatchAction::Status => match reflogless::watch::read_state_raw(&store) {
                Some(raw) => print!("{raw}"),
                None => {
                    println!(
                        "reflogless watch: no state file at {}",
                        reflogless::watch::state_path(&store).display()
                    );
                    println!("  start the daemon with `reflogless watch run`.");
                }
            },
        },
    }
    Ok(())
}

fn run_init(
    repo: &Repo,
    store: &Store,
    cfg: &Config,
    install_shim: bool,
    insecure_file_key: bool,
) -> reflogless::Result<()> {
    let log = store.root.join("hook-errors.log");
    let report = hooks::install(repo, &log)?;
    if let Some(p) = &report.declined_hooks_path {
        eprintln!(
            "reflogless: warning: core.hooksPath is set to {}, which is outside this \
             repo — not writing there (it is shared by every repo on this machine). \
             Installing into {} instead.",
            p.display(),
            report.hooks_dir.display()
        );
        // Git consults only core.hooksPath, so a hook with no entry there cannot be
        // reached at all. Say so at install time rather than leaving the user to
        // discover it from `doctor` — or from a lost file.
        let shadowed = reflogless::hooks::shadowed_hooks(p);
        if shadowed.is_empty() {
            eprintln!(
                "reflogless: warning: these run only if {} forwards to the repo's hook. \
                 Verify with `reflogless doctor`.",
                p.display()
            );
        } else {
            eprintln!(
                "reflogless: warning: {} has no entry for {} — git will never invoke \
                 those hooks, so this repo is NOT protected. Fix by pointing this repo \
                 at its own hooks (`git -C {} config --local core.hooksPath {}`) or by \
                 having that dispatcher forward to them.",
                p.display(),
                shadowed.join(", "),
                repo.root.display(),
                report.hooks_dir.display(),
            );
        }
    }
    println!("installed into {}", report.hooks_dir.display());
    for h in &report.installed {
        println!("  + {h}");
    }
    for h in &report.chained {
        println!("  chained (preserved existing hook): {h}");
    }
    provision_identity(repo, store, insecure_file_key)?;

    // Re-read store: provision_identity just wrote recipient.txt, so the
    // outer store's `provisioned_for_encryption()` is stale and cannot attach
    // crypto. Simplifying to reuse `store` here would silently produce an
    // unencrypted baseline when cfg.encrypt is set.
    let store_with_crypto = attach_identity_if_provisioned(repo, Store::for_repo(repo)?)?;
    let snap = match snap_with_config(repo, &store_with_crypto, "init", None, cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "reflogless: baseline snapshot failed after hooks + identity were installed."
            );
            eprintln!("reflogless:   re-run `reflogless init` to retry the baseline (identity");
            eprintln!(
                "reflogless:   provisioning will be skipped), or `reflogless uninstall --purge"
            );
            eprintln!("reflogless:   --yes` to fully reset.");
            return Err(e);
        }
    };
    print_snap_result(Some("captured baseline snapshot"), &snap);

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
    Ok(())
}

fn print_snap_result(label: Option<&str>, r: &SnapshotResult) {
    if let Some(reason) = &r.skipped_git_busy {
        eprintln!("reflogless: skipped snap — {reason}");
        return;
    }
    match label {
        Some(l) => println!("{l} {}", r.manifest_id),
        None => println!("{}", r.manifest_id),
    }
    println!(
        "files: {}  bytes: {}  skipped: {}",
        r.files_written,
        r.bytes_written,
        r.skipped.len()
    );
    for s in &r.skipped {
        eprintln!("reflogless: skipped {}", format_skipped(s));
    }
}

fn format_skipped(s: &reflogless::select::Skipped) -> String {
    use reflogless::select::Skipped;
    match s {
        Skipped::TooLarge { rel, size } => {
            format!("{} (too large: {} bytes > 10 MB cap)", rel.display(), size)
        }
        Skipped::DenyMatch { rel } => format!("{} (matched deny rule)", rel.display()),
        Skipped::Missing { rel } => format!("{} (missing)", rel.display()),
        Skipped::Unreadable { rel, err } => format!("{} (unreadable: {})", rel.display(), err),
    }
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
fn run_remote(repo: &Repo, store: &Store, action: RemoteAction) -> reflogless::Result<()> {
    match action {
        RemoteAction::Enable {
            url,
            region,
            endpoint,
            path_style,
        } => run_remote_enable(repo, store, &url, &region, endpoint, path_style),
        RemoteAction::Disable => run_remote_disable(store),
        #[cfg(feature = "remote")]
        RemoteAction::Push => run_remote_push(store),
        RemoteAction::Status => run_remote_status(store),
    }
}

fn run_remote_enable(
    repo: &Repo,
    store: &Store,
    url: &str,
    region: &str,
    endpoint: Option<String>,
    path_style: bool,
) -> reflogless::Result<()> {
    use reflogless::config::EncryptPolicy;

    let cfg = Config::load_or_default(&repo.root)?;
    if cfg.encrypt != EncryptPolicy::All {
        eprintln!("reflogless: remote backend requires whole-store encryption.");
        eprintln!("reflogless:   set `encrypt = \"all\"` in .reflogless.toml and re-run");
        eprintln!("reflogless:   `reflogless init` to provision an identity if one isn't already");
        eprintln!(
            "reflogless:   present. Currently `encrypt = \"{:?}\"`.",
            cfg.encrypt
        );
        return Err(reflogless::Error::Config(
            "remote enable refused: encrypt policy is not \"all\"".into(),
        ));
    }
    if store.crypto().is_none() {
        eprintln!("reflogless: remote backend requires an encryption identity.");
        eprintln!("reflogless:   run `reflogless init` to provision one before enabling remote.");
        return Err(reflogless::Error::Config(
            "remote enable refused: no identity attached".into(),
        ));
    }

    let (bucket, base_prefix) = reflogless::remote_config::parse_s3_url(url)?;
    let host = reflogless::remote_config::hostname_segment();
    let key_prefix = reflogless::remote_config::compose_key_prefix(&base_prefix, &host);

    let rc = reflogless::remote_config::RemoteConfig {
        bucket,
        region: region.to_string(),
        endpoint,
        path_style,
        key_prefix,
    };
    rc.save(store)?;
    println!(
        "remote backend enabled at {} (region={}, key_prefix={})",
        rc.s3_url(),
        rc.region,
        rc.key_prefix
    );
    if rc.endpoint.is_none() {
        println!("  credentials read from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY at push time.");
    } else {
        println!(
            "  endpoint override active ({}); credentials still read from AWS_* env vars.",
            rc.endpoint.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn run_remote_disable(store: &Store) -> reflogless::Result<()> {
    use reflogless::remote_config::RemoteConfig;
    if RemoteConfig::remove(store)? {
        println!("remote backend disabled.");
        let pending = reflogless::remote::read_pending(store)?;
        if !pending.is_empty() {
            println!(
                "  note: {} pending upload(s) remain in {}",
                pending.len(),
                store.remote_pending_path().display(),
            );
            println!("  re-enable to drain, or delete the file manually.");
        }
    } else {
        println!("remote backend was not enabled.");
    }
    Ok(())
}

fn run_remote_status(store: &Store) -> reflogless::Result<()> {
    use reflogless::remote_config::{render_status_line, RemoteConfig};
    let cfg = RemoteConfig::load(store)?;
    println!("remote          : {}", render_status_line(cfg.as_ref()));
    if cfg.is_some() {
        let pending = reflogless::remote::read_pending(store)?;
        let oldest = pending
            .iter()
            .map(|e| e.created_at)
            .min()
            .map(format_humanish_age);
        match (pending.len(), oldest) {
            (0, _) => println!("remote.backlog  : 0 pending uploads"),
            (n, Some(age)) => println!("remote.backlog  : {n} pending uploads, oldest {age}"),
            (n, None) => println!("remote.backlog  : {n} pending uploads"),
        }
    }
    Ok(())
}

fn format_humanish_age(t: chrono::DateTime<chrono::Utc>) -> String {
    let delta = chrono::Utc::now().signed_duration_since(t);
    let secs = delta.num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(feature = "remote")]
fn run_remote_push(store: &Store) -> reflogless::Result<()> {
    use reflogless::remote::{drain_pending, RemoteBackend};
    use reflogless::remote_config::RemoteConfig;
    use reflogless::remote_s3::{S3Backend, S3Config};
    use s3::creds::Credentials;
    use s3::region::Region;

    let cfg = RemoteConfig::load(store)?.ok_or_else(|| {
        reflogless::Error::Config("remote not enabled: run `reflogless remote enable` first".into())
    })?;
    let region = if let Some(endpoint) = &cfg.endpoint {
        Region::Custom {
            region: cfg.region.clone(),
            endpoint: endpoint.clone(),
        }
    } else {
        cfg.region.parse::<Region>().map_err(|e| {
            reflogless::Error::Config(format!("invalid region {:?}: {e}", cfg.region))
        })?
    };
    let credentials = Credentials::default().map_err(|e| {
        reflogless::Error::Config(format!(
            "AWS credentials not found: set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY ({e})"
        ))
    })?;
    let backend = S3Backend::new(S3Config {
        bucket: cfg.bucket.clone(),
        region,
        credentials,
        key_prefix: cfg.key_prefix.clone(),
        path_style: cfg.path_style,
    })?;

    let stats = drain_pending(store, |entry| {
        let manifest = match store.load_manifest(&entry.manifest_id) {
            Ok(m) => m,
            Err(reflogless::Error::SnapshotNotFound(_)) => {
                eprintln!(
                    "reflogless remote: manifest {} no longer in store; dropping pending entry",
                    entry.manifest_id
                );
                return Ok(true);
            }
            Err(e) => return Err(e),
        };
        for digest in &entry.blob_digests {
            if backend.head_blob(digest)? {
                continue;
            }
            let bytes = store
                .read_blob(digest)
                .map_err(|e| reflogless::Error::Config(format!("blob {digest}: {e}")))?;
            let mut reader = std::io::Cursor::new(&bytes);
            backend.push_blob(digest, &mut reader, bytes.len() as u64)?;
        }
        backend.push_manifest(&manifest)?;
        Ok(true)
    })?;
    println!(
        "remote push: uploaded {}, deferred {}",
        stats.uploaded, stats.deferred
    );
    Ok(())
}

fn run_list_all() -> reflogless::Result<()> {
    let base = base_data_dir()?;
    let stores = list_all_stores(&base)?;
    if stores.is_empty() {
        println!(
            "no reflogless stores under {}",
            base.join("reflogless").display()
        );
        return Ok(());
    }
    for s in &stores {
        let (state_label, origin_label) = match &s.state {
            StoreOriginState::Active(p) => ("active", p.display().to_string()),
            StoreOriginState::Stale(p) => ("stale", p.display().to_string()),
            StoreOriginState::Legacy => ("legacy", s.store_id.clone()),
            StoreOriginState::Unknown { origin, reason } => (
                "unknown",
                match origin {
                    Some(p) => format!("{} ({reason})", p.display()),
                    None => format!("{} ({reason})", s.store_id),
                },
            ),
        };
        if s.snapshots_unreadable {
            println!("{}  {}  snapshots unreadable", origin_label, state_label,);
        } else {
            println!(
                "{}  {}  {} snapshots",
                origin_label, state_label, s.snapshot_count,
            );
        }
        for id in &s.snapshot_ids {
            println!("  {}", id);
        }
    }
    Ok(())
}

/// `gc --stale-stores`. Dry run unless `apply`. Prints every candidate so the
/// user sees what a subsequent `--yes` would destroy, since a reclaimed store's
/// snapshots are unrecoverable.
fn run_reclaim_stale_stores(apply: bool) -> reflogless::Result<()> {
    let base = base_data_dir()?;
    let report = reclaim_stale_stores(&base, apply)?;

    // Printed before the early return: a store nobody can classify is invisible
    // otherwise, and "no orphaned stores" would be a misleading all-clear.
    for (id, reason) in &report.skipped_unknown {
        eprintln!("reflogless: keeping {id}: {reason}");
    }

    if report.candidates.is_empty() {
        println!(
            "no orphaned stores under {}",
            base.join("reflogless").display()
        );
        return Ok(());
    }

    // A store whose size could not be measured contributes nothing to the total
    // and is flagged in its own line, so the total is a floor, never a claim.
    let measured: u64 = report.candidates.iter().filter_map(|c| c.bytes).sum();
    let any_unmeasured = report.candidates.iter().any(|c| c.bytes.is_none());
    for c in &report.candidates {
        let size = match c.bytes {
            Some(b) => format!("{b} bytes"),
            None => "size unreadable".to_string(),
        };
        let snaps = if c.snapshots_unreadable {
            "snapshots unreadable".to_string()
        } else {
            format!("{} snapshots", c.snapshot_count)
        };
        println!(
            "{}  {}  {}  origin gone: {}",
            c.store_id,
            size,
            snaps,
            c.origin.display()
        );
    }

    let qualifier = if any_unmeasured { " (at least)" } else { "" };

    if report.dry_run {
        println!(
            "would reclaim {} store(s), {measured} bytes{qualifier} — re-run with --yes to delete",
            report.candidates.len(),
        );
        return Ok(());
    }

    println!(
        "reclaimed {} store(s), {} bytes{qualifier}",
        report.removed.len(),
        report.bytes_freed
    );
    for id in &report.revived {
        println!("  kept {id}: origin repo reappeared before the delete");
    }
    for (id, err) in &report.failed {
        eprintln!("reflogless: could not reclaim {id} (left intact): {err}");
    }
    for (id, err) in &report.partial {
        eprintln!("reflogless: PARTIALLY DELETED {id}: {err}");
    }
    let incomplete = report.failed.len() + report.partial.len();
    if incomplete > 0 {
        // Must not exit 0 — this runs under `--yes`, and a caller scripting it
        // would otherwise read silence as success.
        return Err(reflogless::Error::ReclaimIncomplete(format!(
            "{incomplete} store(s) could not be reclaimed{}",
            if report.partial.is_empty() {
                ""
            } else {
                ", and at least one was left partly deleted"
            }
        )));
    }
    Ok(())
}

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
    if !cfg.shim {
        return Ok(());
    }
    let store = attach_identity_if_provisioned(&repo, raw_store)?;
    let r = snap_with_config(&repo, &store, event, None, &cfg)?;
    if let Some(reason) = r.skipped_git_busy {
        // Shim normally runs silent; surface the gate firing so users on an
        // interactive-rebase post-commit path don't see "no snap" with no clue.
        eprintln!("reflogless: skipped shim snap ({event}) — {reason}");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn git(repo: &TempDir, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed with {status}");
    }

    /// `git init` plus the local `core.hooksPath` pin, so a test that installs
    /// hooks can't inherit an ambient global `core.hooksPath` and reach outside
    /// the temp repo. Mirrors `testutil::init_repo`; see #73.
    fn git_init(repo: &TempDir) {
        git(repo, &["init", "-q"]);
        git(repo, &["config", "--local", "core.hooksPath", ".git/hooks"]);
    }

    #[test]
    fn run_init_creates_baseline_manifest() {
        let _guard = ENV_LOCK.lock().unwrap();
        let repo = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let old_data_dir = std::env::var_os("REFLOGLESS_DATA_DIR");
        std::env::set_var("REFLOGLESS_DATA_DIR", data.path());

        git_init(&repo);
        std::fs::write(repo.path().join("untracked.txt"), "baseline\n").unwrap();

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(repo.path()).unwrap();

        let discovered = Repo::discover(repo.path()).unwrap();
        let raw_store = Store::for_repo(&discovered).unwrap();
        let cfg = Config::load_or_default(&discovered.root).unwrap();
        let store = attach_identity_if_provisioned(&discovered, raw_store).unwrap();
        let result = run_init(&discovered, &store, &cfg, false, true);
        let post_store =
            attach_identity_if_provisioned(&discovered, Store::for_repo(&discovered).unwrap())
                .unwrap();
        let listing = post_store.list_manifests_lenient();

        std::env::set_current_dir(cwd).unwrap();
        match old_data_dir {
            Some(v) => std::env::set_var("REFLOGLESS_DATA_DIR", v),
            None => std::env::remove_var("REFLOGLESS_DATA_DIR"),
        }
        result.unwrap();
        let (manifests, warnings) = listing.unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(
            manifests.len(),
            1,
            "init must leave exactly one baseline manifest"
        );
        assert_eq!(manifests[0].event, "init");
        assert!(
            manifests[0]
                .entries
                .iter()
                .any(|e| e.path == std::path::Path::new("untracked.txt")),
            "baseline must include untracked file"
        );
    }

    /// Seed `<data>/reflogless/<id>/` with a manifest and an origin pointer, the
    /// shape `list_all_stores` classifies on.
    fn seed_store(data: &std::path::Path, id: &str, origin: Option<&std::path::Path>) {
        let dir = data.join("reflogless").join(id);
        std::fs::create_dir_all(dir.join("snapshots")).unwrap();
        std::fs::write(dir.join("snapshots").join("2026-01-01-000000.json"), b"{}").unwrap();
        if let Some(o) = origin {
            std::fs::write(dir.join("repo_origin.txt"), o.to_string_lossy().as_bytes()).unwrap();
        }
    }

    /// Run `run_reclaim_stale_stores` against an isolated data dir. Never let this
    /// touch the real one — it deletes stores.
    fn with_data_dir<T>(data: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("REFLOGLESS_DATA_DIR");
        std::env::set_var("REFLOGLESS_DATA_DIR", data);
        let out = f();
        match old {
            Some(v) => std::env::set_var("REFLOGLESS_DATA_DIR", v),
            None => std::env::remove_var("REFLOGLESS_DATA_DIR"),
        }
        out
    }

    /// The dry run is the default because a reclaimed store is unrecoverable.
    /// Nothing may be deleted without `--yes`.
    #[test]
    fn reclaim_dry_run_deletes_nothing_and_exits_zero() {
        let data = TempDir::new().unwrap();
        let gone = data.path().join("deleted-repo");
        seed_store(data.path(), "1111111111111111", Some(&gone));

        let result = with_data_dir(data.path(), || run_reclaim_stale_stores(false));

        result.unwrap();
        assert!(
            data.path()
                .join("reflogless")
                .join("1111111111111111")
                .exists(),
            "dry run deleted a store"
        );
    }

    #[test]
    fn reclaim_apply_removes_the_orphan_and_exits_zero() {
        let data = TempDir::new().unwrap();
        let live = data.path().join("live-repo");
        std::fs::create_dir_all(&live).unwrap();
        let gone = data.path().join("deleted-repo");
        seed_store(data.path(), "2222222222222222", Some(&gone));
        seed_store(data.path(), "3333333333333333", Some(&live));

        let result = with_data_dir(data.path(), || run_reclaim_stale_stores(true));

        result.unwrap();
        let root = data.path().join("reflogless");
        assert!(!root.join("2222222222222222").exists(), "orphan survived");
        assert!(root.join("3333333333333333").exists(), "live store removed");
    }

    /// The exit code is the whole contract for anyone scripting `--yes`: silence
    /// plus exit 0 reads as "everything was reclaimed". A store left behind must
    /// make the command fail.
    #[cfg(unix)]
    #[test]
    fn reclaim_exits_non_zero_when_a_store_could_not_be_reclaimed() {
        use std::os::unix::fs::PermissionsExt;
        let data = TempDir::new().unwrap();
        let gone = data.path().join("deleted-repo");
        seed_store(data.path(), "4444444444444444", Some(&gone));
        let dir = data.path().join("reflogless").join("4444444444444444");
        std::fs::set_permissions(
            dir.join("snapshots"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = with_data_dir(data.path(), || run_reclaim_stale_stores(true));

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dir.join("snapshots"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        match result {
            Err(reflogless::Error::ReclaimIncomplete(msg)) => {
                assert!(msg.contains("could not be reclaimed"), "{msg}")
            }
            other => panic!("expected a non-zero exit, got {other:?}"),
        }
    }

    /// An empty data dir must not look like a failure.
    #[test]
    fn reclaim_reports_nothing_to_do_and_exits_zero() {
        let data = TempDir::new().unwrap();
        with_data_dir(data.path(), || run_reclaim_stale_stores(true)).unwrap();
    }

    #[test]
    fn snapshot_for_shim_respects_repo_opt_out() {
        let _guard = ENV_LOCK.lock().unwrap();
        let repo = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let old_data_dir = std::env::var_os("REFLOGLESS_DATA_DIR");
        std::env::set_var("REFLOGLESS_DATA_DIR", data.path());

        git_init(&repo);
        std::fs::write(repo.path().join(".reflogless.toml"), "shim = false\n").unwrap();
        std::fs::write(repo.path().join("untracked.txt"), "save me\n").unwrap();

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(repo.path()).unwrap();
        let result = snapshot_for_shim("shim-clean");
        std::env::set_current_dir(cwd).unwrap();
        match old_data_dir {
            Some(v) => std::env::set_var("REFLOGLESS_DATA_DIR", v),
            None => std::env::remove_var("REFLOGLESS_DATA_DIR"),
        }

        result.unwrap();
        let discovered = Repo::discover(repo.path()).unwrap();
        let store = Store::for_repo(&discovered).unwrap();
        let (manifests, warnings) = store.list_manifests_lenient().unwrap();
        assert!(warnings.is_empty());
        assert!(manifests.is_empty());
    }
}

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use gitsafe::doctor;
use gitsafe::hooks;
use gitsafe::manifest::Manifest;
use gitsafe::repo::Repo;
use gitsafe::snapshot::{restore, snap};
use gitsafe::store::{Store, DEFAULT_MAX_AGE_DAYS, DEFAULT_MAX_STORE_BYTES};

#[derive(Parser)]
#[command(name = "gitsafe", version, about = "Local untracked-file safety net for git")]
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
    /// Install gitsafe hooks into the current repo.
    Init {
        /// Reserved for Phase 5 — installs a git PATH shim. Currently rejected.
        #[arg(long, hide = true)]
        shim: bool,
    },
    /// Remove gitsafe hooks; restore any prior chained third-party hooks.
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
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gitsafe: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> gitsafe::Result<()> {
    let cli = Cli::parse();
    let cwd = std::env::current_dir().map_err(|e| gitsafe::Error::io(".", e))?;
    let repo = Repo::discover(&cwd)?;
    let store = Store::for_repo(&repo)?;

    match cli.cmd {
        Cmd::Snap { message, event } => {
            let r = snap(&repo, &store, &event, message)?;
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
                eprintln!("gitsafe: warning: skipping {}: {e}", p.display());
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
        Cmd::Init { shim } => {
            if shim {
                return Err(gitsafe::Error::Unimplemented(
                    "--shim lands in Phase 5".into(),
                ));
            }
            let log = store.root.join("hook-errors.log");
            let report = hooks::install(&repo, &log)?;
            println!("installed into {}", report.hooks_dir.display());
            for h in &report.installed {
                println!("  + {h}");
            }
            for h in &report.chained {
                println!("  chained (preserved existing hook): {h}");
            }
        }
        Cmd::Uninstall { purge, yes } => {
            if purge && !yes {
                return Err(gitsafe::Error::Config(
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
                println!("skipped {h} (not gitsafe-managed)");
            }
            if purge {
                if store.root.exists() {
                    std::fs::remove_dir_all(&store.root)
                        .map_err(|e| gitsafe::Error::io(&store.root, e))?;
                    println!("purged store at {}", store.root.display());
                } else {
                    println!("store already absent at {}", store.root.display());
                }
            }
        }
        Cmd::Doctor => {
            let report = doctor::run(&repo, &store)?;
            print!("{}", report.render());
            if !report.is_healthy() {
                return Err(gitsafe::Error::Doctor(
                    report
                        .first_failure()
                        .unwrap_or("not healthy")
                        .into(),
                ));
            }
        }
    }
    Ok(())
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
) -> gitsafe::Result<()> {
    for e in &m.entries {
        if let Some(p) = only {
            if p != e.path {
                continue;
            }
        }
        let snap_bytes = store.read_blob(&e.blob)?;
        let cur_path = repo.root.join(&e.path);
        let (cur_bytes, work_label) = match std::fs::read(&cur_path) {
            Ok(b) => (b, format!("work:{}", e.path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                (Vec::new(), format!("work:{} (missing)", e.path.display()))
            }
            Err(err) => return Err(gitsafe::Error::io(&cur_path, err)),
        };
        if snap_bytes == cur_bytes {
            continue;
        }
        let snap_text = String::from_utf8_lossy(&snap_bytes);
        let cur_text = String::from_utf8_lossy(&cur_bytes);
        let diff = similar::TextDiff::from_lines(&snap_text, &cur_text);
        println!(
            "--- snap:{}/{}\n+++ {}",
            m.id,
            e.path.display(),
            work_label
        );
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

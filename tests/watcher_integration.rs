//! End-to-end smoke test for the filesystem-watcher daemon (issue #30 slice 7).
//!
//! Spawns the actual `reflogless` binary in `watch run` mode against a freshly
//! initialized git repo, touches a tracked file, waits past the debounce
//! window, then SIGTERM's the daemon and asserts a snapshot manifest landed.
//!
//! Caveats:
//! - notify's macos_fsevent backend needs a few hundred ms after `Watcher::watch`
//!   returns before it actually starts delivering events. Our wait budget
//!   accounts for that.
//! - This test is `#[cfg(unix)]` — the daemon doesn't ship a Windows installer
//!   and the SIGTERM mechanism is Unix-only.
//! - Test isolation: we point `REFLOGLESS_DATA_DIR` at a per-test tempdir so we
//!   don't touch the developer's real reflogless store.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_reflogless");

fn git_init(p: &std::path::Path) {
    let st = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(p)
        .status()
        .expect("git init");
    assert!(st.success(), "git init failed");
    let cfg_email = Command::new("git")
        .args(["-C", p.to_str().unwrap(), "config", "user.email", "t@x"])
        .status()
        .expect("git config email");
    let cfg_name = Command::new("git")
        .args(["-C", p.to_str().unwrap(), "config", "user.name", "t"])
        .status()
        .expect("git config name");
    assert!(cfg_email.success() && cfg_name.success());
}

fn send_sigterm(pid: u32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGTERM: i32 = 15;
    unsafe {
        kill(pid as i32, SIGTERM);
    }
}

fn store_root_for(data_dir: &std::path::Path, repo_root: &std::path::Path) -> PathBuf {
    // Mirror Store::for_repo's id derivation: sha256(canonical(repo.root))[:16].
    use sha2::{Digest, Sha256};
    let canon = repo_root
        .canonicalize()
        .expect("canonicalize repo root for store id");
    let mut h = Sha256::new();
    h.update(canon.to_string_lossy().as_bytes());
    let digest = h.finalize();
    // Match the `hex::encode_short` used in src/repo.rs: 16 hex chars of first 8 bytes.
    let id = digest[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    data_dir.join("reflogless").join(id)
}

#[test]
fn watcher_snapshots_a_touched_file() {
    let work = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    git_init(work.path());
    fs::write(work.path().join("seed.txt"), b"baseline\n").unwrap();

    let mut child = Command::new(BIN)
        .arg("watch")
        .arg("run")
        .current_dir(work.path())
        .env("REFLOGLESS_DATA_DIR", data.path())
        // Force --insecure-file-key style path: don't try to provision keychain
        // during the watcher's snap. The default `secrets` encrypt policy will
        // still refuse secret-shaped paths without a key, but our `seed.txt`
        // and `edit.txt` aren't secret-shaped.
        .env("HOME", data.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn reflogless watch run");

    let store_root = store_root_for(data.path(), work.path());
    let state_path = store_root.join("watch-state.json");
    let snapshots_dir = store_root.join("snapshots");

    // Wait for the daemon to install its watcher and write the initial state.
    let started = Instant::now();
    while !state_path.exists() && started.elapsed() < Duration::from_secs(8) {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        state_path.exists(),
        "watcher never wrote watch-state.json under {} after 8s",
        store_root.display()
    );

    // Give notify another moment to actually start delivering events.
    thread::sleep(Duration::from_millis(800));

    // Touch a file. notify should pick this up, daemon debounces (default
    // 2000ms) then snaps.
    fs::write(work.path().join("edit.txt"), b"hello watcher\n").unwrap();

    // Wait up to ~6s for a snapshot manifest to appear.
    let snapshot_seen_at = Instant::now();
    let mut snap_count = 0usize;
    while snapshot_seen_at.elapsed() < Duration::from_secs(6) {
        if let Ok(entries) = fs::read_dir(&snapshots_dir) {
            snap_count = entries.count();
            if snap_count > 0 {
                break;
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    // SIGTERM the daemon and wait for clean exit.
    send_sigterm(child.id());
    let exit = match child.wait() {
        Ok(s) => s,
        Err(e) => panic!("waitpid failed: {e}"),
    };

    assert!(
        snap_count > 0,
        "watcher did not write a snapshot after touching a file (snapshots_dir empty after 6s); daemon exit status = {exit:?}; store_root = {}",
        store_root.display()
    );
    // SIGTERM-handled clean exit should be a success exit code (handler flips
    // the flag and run() returns Ok). Some platforms report 0, others may
    // surface the signal — accept either as long as the snapshot landed.
    if !exit.success() {
        eprintln!("note: daemon exit was non-success ({exit:?}); snapshot still landed");
    }
}

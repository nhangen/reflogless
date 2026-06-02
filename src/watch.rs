//! Filesystem-watcher daemon core (issue #30, design doc 2026-06-01).
//!
//! Listens via `notify` for tree changes under `repo.root`, coalesces them into
//! `debounce_ms` windows, and on each window calls `snap_with_config` against
//! the store. The snap path already enforces the `.snap.lock` from #41 and the
//! git-busy gate from #40, so this module only contributes the polling +
//! debouncing + heartbeat-state surface.
//!
//! No installer here. Slice 3 of the #30 sequencing. The daemon is invokable
//! via `reflogless watch run` for testing; launchd/systemd installers are
//! deferred to later slices.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::snapshot::{snap_with_config, SnapshotResult};
use crate::store::{atomic_write, SnapLockMode, Store};
use chrono::Utc;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

pub const WATCH_STATE_FILENAME: &str = "watch-state.json";

#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub debounce: Duration,
    pub heartbeat: Duration,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(2000),
            heartbeat: Duration::from_secs(60),
        }
    }
}

/// Mutable state the daemon snapshots to disk for `reflogless doctor watch`.
#[derive(Debug, Clone)]
pub struct WatchState {
    pub pid: u32,
    pub start_at_unix: i64,
    pub last_event_at: Option<i64>,
    pub last_snap_at: Option<i64>,
    pub snap_count: u64,
    pub skip_count: u64,
    pub error_count: u64,
    pub last_error: Option<String>,
}

impl Default for WatchState {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchState {
    pub fn new() -> Self {
        Self {
            pid: std::process::id(),
            start_at_unix: Utc::now().timestamp(),
            last_event_at: None,
            last_snap_at: None,
            snap_count: 0,
            skip_count: 0,
            error_count: 0,
            last_error: None,
        }
    }

    pub fn to_json(&self) -> String {
        let last_event = self
            .last_event_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        let last_snap = self
            .last_snap_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string());
        let last_err = match &self.last_error {
            Some(e) => format!("\"{}\"", json_escape(e)),
            None => "null".to_string(),
        };
        format!(
            "{{\"pid\":{},\"start_at_unix\":{},\"last_event_at\":{},\"last_snap_at\":{},\"snap_count\":{},\"skip_count\":{},\"error_count\":{},\"last_error\":{}}}\n",
            self.pid,
            self.start_at_unix,
            last_event,
            last_snap,
            self.snap_count,
            self.skip_count,
            self.error_count,
            last_err,
        )
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn state_path(store: &Store) -> std::path::PathBuf {
    store.root.join(WATCH_STATE_FILENAME)
}

pub fn write_state(store: &Store, state: &WatchState) -> Result<()> {
    atomic_write(&state_path(store), state.to_json().as_bytes())
}

/// Read the daemon's last-written state file. Returns `None` if absent.
pub fn read_state_raw(store: &Store) -> Option<String> {
    std::fs::read_to_string(state_path(store)).ok()
}

/// Decide what the daemon does with a debounced batch. Pure (no IO) so tests
/// can exercise the policy directly without spinning a real watcher.
#[derive(Debug, PartialEq, Eq)]
pub enum BatchOutcome {
    Snapped,
    SkippedByGate(String),
    SkippedByLockHeld,
    NoEvents,
    SnapFailed(String),
}

/// Process one debounced batch. Caller guarantees `events_seen > 0`
/// (otherwise pass through with `NoEvents`).
pub fn process_batch(
    repo: &Repo,
    store: &Store,
    cfg: &Config,
    events_seen: usize,
    state: &mut WatchState,
) -> BatchOutcome {
    if events_seen == 0 {
        return BatchOutcome::NoEvents;
    }
    state.last_event_at = Some(Utc::now().timestamp());
    // Daemon never blocks git; if hooks/shim are mid-snap, skip this window.
    let lock = match store.acquire_snap_lock(SnapLockMode::TryOnce) {
        Ok(Some(l)) => l,
        Ok(None) => {
            state.skip_count += 1;
            return BatchOutcome::SkippedByLockHeld;
        }
        Err(e) => {
            state.error_count += 1;
            state.last_error = Some(format!("snap lock: {e}"));
            return BatchOutcome::SnapFailed(format!("snap lock: {e}"));
        }
    };
    // snap_with_config also re-checks the lock at its own entry — that's the
    // same lock we just acquired in this process, and fs4's flock is per-OFD,
    // so re-entering blocks. Drop ours before calling.
    drop(lock);
    match snap_with_config(repo, store, "watcher", None, cfg) {
        Ok(SnapshotResult {
            skipped_git_busy: Some(reason),
            ..
        }) => {
            state.skip_count += 1;
            BatchOutcome::SkippedByGate(reason)
        }
        Ok(_) => {
            state.snap_count += 1;
            state.last_snap_at = Some(Utc::now().timestamp());
            BatchOutcome::Snapped
        }
        Err(e) => {
            state.error_count += 1;
            let msg = format!("{e}");
            state.last_error = Some(msg.clone());
            BatchOutcome::SnapFailed(msg)
        }
    }
}

/// Filter that decides whether a notify event should count toward the debounce
/// window. Pure — tests pass in synthetic event kinds + paths.
pub fn event_is_interesting(kind: &EventKind, paths: &[&Path], store_root: &Path) -> bool {
    use notify::event::ModifyKind;
    match kind {
        EventKind::Create(_) | EventKind::Remove(_) => {}
        EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Name(_)) => {}
        _ => return false,
    }
    for p in paths {
        // Defensively ignore events under the store itself — snap writes blobs
        // into the same tree if base_dir is inside the repo (test sandboxes).
        if p.starts_with(store_root) {
            continue;
        }
        // Heuristic skips on noisy build dirs; users can extend via
        // `[watch] ignore_extra` once that config slice lands.
        let s = p.to_string_lossy();
        if s.contains("/.git/")
            || s.contains("/node_modules/")
            || s.contains("/target/")
            || s.contains("/dist/")
            || s.contains("/build/")
            || s.contains("/.next/")
            || s.contains("/__pycache__/")
        {
            continue;
        }
        return true;
    }
    false
}

/// Run the watcher loop. Blocks; exits cleanly on channel disconnect.
pub fn run(repo: &Repo, store: &Store, cfg: &Config, wcfg: &WatchConfig) -> Result<()> {
    let mut state = WatchState::new();
    write_state(store, &state)?;
    let (tx, rx) = channel::<notify::Result<notify::Event>>();
    let mut watcher = build_watcher(tx)?;
    watcher
        .watch(&repo.root, RecursiveMode::Recursive)
        .map_err(|e| Error::Config(format!("notify watch: {e}")))?;
    let store_root = store.root.clone();
    let mut last_heartbeat = Instant::now();
    loop {
        let mut events_seen = 0usize;
        // Block until the first event or the heartbeat tick.
        let timeout = wcfg
            .heartbeat
            .saturating_sub(last_heartbeat.elapsed())
            .max(Duration::from_millis(100));
        match rx.recv_timeout(timeout) {
            Ok(Ok(evt)) => {
                if event_is_interesting(
                    &evt.kind,
                    &evt.paths.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
                    &store_root,
                ) {
                    events_seen += 1;
                }
            }
            Ok(Err(_)) => continue,
            Err(RecvTimeoutError::Timeout) => {
                if last_heartbeat.elapsed() >= wcfg.heartbeat {
                    let _ = write_state(store, &state);
                    last_heartbeat = Instant::now();
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        // Open debounce window: drain quickly for `debounce_ms`.
        let window_start = Instant::now();
        while window_start.elapsed() < wcfg.debounce {
            match rx.recv_timeout(wcfg.debounce - window_start.elapsed()) {
                Ok(Ok(evt)) => {
                    if event_is_interesting(
                        &evt.kind,
                        &evt.paths.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
                        &store_root,
                    ) {
                        events_seen += 1;
                    }
                }
                Ok(Err(_)) => continue,
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        let _ = process_batch(repo, store, cfg, events_seen, &mut state);
        let _ = write_state(store, &state);
        last_heartbeat = Instant::now();
    }
}

fn build_watcher(tx: Sender<notify::Result<notify::Event>>) -> Result<RecommendedWatcher> {
    notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| Error::Config(format!("notify init: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SNAP_LOCK_FILENAME;
    use std::process::Command;
    use tempfile::TempDir;

    fn make_repo(td: &Path) -> Repo {
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(td)
            .status()
            .unwrap();
        Repo::discover(td).unwrap()
    }

    #[test]
    fn watch_state_to_json_roundtrip_basic_fields() {
        let mut s = WatchState::new();
        s.last_event_at = Some(1_700_000_000);
        s.last_snap_at = Some(1_700_000_500);
        s.snap_count = 3;
        s.skip_count = 1;
        s.error_count = 0;
        let j = s.to_json();
        assert!(j.contains("\"snap_count\":3"));
        assert!(j.contains("\"skip_count\":1"));
        assert!(j.contains("\"last_event_at\":1700000000"));
        assert!(j.contains("\"last_snap_at\":1700000500"));
        assert!(j.contains("\"last_error\":null"));
    }

    #[test]
    fn watch_state_json_escapes_last_error() {
        let mut s = WatchState::new();
        s.last_error = Some("oh \"no\"\n".to_string());
        let j = s.to_json();
        assert!(j.contains("\"last_error\":\"oh \\\"no\\\"\\n\""));
    }

    #[test]
    fn process_batch_no_events_is_noop() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let mut state = WatchState::new();
        let cfg = Config::default();
        let outcome = process_batch(&repo, &store, &cfg, 0, &mut state);
        assert_eq!(outcome, BatchOutcome::NoEvents);
        assert_eq!(state.snap_count, 0);
    }

    #[test]
    fn process_batch_snaps_on_event_and_increments_state() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        std::fs::write(repo.root.join("a.txt"), b"hello").unwrap();
        let mut state = WatchState::new();
        let cfg = Config::default();
        let outcome = process_batch(&repo, &store, &cfg, 1, &mut state);
        assert_eq!(outcome, BatchOutcome::Snapped);
        assert_eq!(state.snap_count, 1);
        assert!(state.last_event_at.is_some());
        assert!(state.last_snap_at.is_some());
    }

    #[test]
    fn process_batch_skipped_by_gate_when_rebase_in_progress() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        std::fs::create_dir_all(repo.root.join(".git").join("rebase-merge")).unwrap();
        let mut state = WatchState::new();
        let cfg = Config::default();
        let outcome = process_batch(&repo, &store, &cfg, 1, &mut state);
        match outcome {
            BatchOutcome::SkippedByGate(reason) => assert!(reason.contains("rebase")),
            other => panic!("expected SkippedByGate, got {other:?}"),
        }
        assert_eq!(state.snap_count, 0);
        assert_eq!(state.skip_count, 1);
    }

    #[test]
    fn process_batch_skipped_when_external_lock_held() {
        use std::process::Stdio;
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let lockpath = store.root.join(SNAP_LOCK_FILENAME);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lockpath)
            .unwrap();
        let marker = data.path().join("ready");
        let helper = r#"
import fcntl, sys, time
f = open(sys.argv[1], 'r+')
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], 'w').close()
time.sleep(3)
"#;
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(helper)
            .arg(&lockpath)
            .arg(&marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !marker.exists() && start.elapsed().as_secs() < 2 {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(marker.exists());
        let mut state = WatchState::new();
        let cfg = Config::default();
        let outcome = process_batch(&repo, &store, &cfg, 1, &mut state);
        assert_eq!(outcome, BatchOutcome::SkippedByLockHeld);
        assert_eq!(state.skip_count, 1);
        assert_eq!(state.snap_count, 0);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn event_is_interesting_skips_dotgit_and_buildirs() {
        use notify::event::{CreateKind, ModifyKind};
        let store_root = Path::new("/tmp/store");
        // .git change ignored
        assert!(!event_is_interesting(
            &EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
            &[Path::new("/repo/.git/refs/heads/main")],
            store_root,
        ));
        // node_modules ignored
        assert!(!event_is_interesting(
            &EventKind::Create(CreateKind::File),
            &[Path::new("/repo/node_modules/pkg/index.js")],
            store_root,
        ));
        // user file kept
        assert!(event_is_interesting(
            &EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
            &[Path::new("/repo/src/main.rs")],
            store_root,
        ));
        // store path ignored
        assert!(!event_is_interesting(
            &EventKind::Create(CreateKind::File),
            &[Path::new("/tmp/store/objects/aa/bb")],
            store_root,
        ));
    }

    #[test]
    fn event_is_interesting_ignores_access_events() {
        use notify::event::{AccessKind, AccessMode};
        assert!(!event_is_interesting(
            &EventKind::Access(AccessKind::Read),
            &[Path::new("/repo/x")],
            Path::new("/tmp/store"),
        ));
        assert!(!event_is_interesting(
            &EventKind::Access(AccessKind::Open(AccessMode::Read)),
            &[Path::new("/repo/x")],
            Path::new("/tmp/store"),
        ));
    }

    #[test]
    fn write_state_and_read_state_raw_roundtrip() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let s = WatchState::new();
        write_state(&store, &s).unwrap();
        let raw = read_state_raw(&store).expect("state file should exist");
        assert!(raw.contains(&format!("\"pid\":{}", s.pid)));
        assert!(raw.contains("\"snap_count\":0"));
    }
}

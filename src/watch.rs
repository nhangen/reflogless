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
use crate::snapshot::{snap_with_config_lock_mode, SnapshotResult};
use crate::store::{atomic_write, SnapLockMode, Store};
use chrono::Utc;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
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
    /// Opaque identifier that changes on every boot. Doctor uses this to
    /// detect pid reuse across reboots — a `kill -0 pid` reporting "alive"
    /// for a pid whose stored boot_id differs from the current boot_id is
    /// a reused pid, not our daemon. See #46.
    pub boot_id: String,
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
            boot_id: current_boot_id(),
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
            "{{\"pid\":{},\"start_at_unix\":{},\"boot_id\":\"{}\",\"last_event_at\":{},\"last_snap_at\":{},\"snap_count\":{},\"skip_count\":{},\"error_count\":{},\"last_error\":{}}}\n",
            self.pid,
            self.start_at_unix,
            json_escape(&self.boot_id),
            last_event,
            last_snap,
            self.snap_count,
            self.skip_count,
            self.error_count,
            last_err,
        )
    }

    /// Best-effort parse of a `to_json` line back into a WatchState. Used by
    /// doctor to derive liveness. Returns None on any malformed input — doctor
    /// renders that as "stopped" since we can't trust the file.
    pub fn from_json(s: &str) -> Option<ParsedWatchState> {
        let pid = extract_number(s, "pid")?;
        let start_at_unix = extract_number(s, "start_at_unix")?;
        let boot_id = extract_string(s, "boot_id").unwrap_or_default();
        let last_event_at = extract_number(s, "last_event_at");
        let last_snap_at = extract_number(s, "last_snap_at");
        let snap_count = extract_number(s, "snap_count").unwrap_or(0);
        let skip_count = extract_number(s, "skip_count").unwrap_or(0);
        let error_count = extract_number(s, "error_count").unwrap_or(0);
        Some(ParsedWatchState {
            pid: pid as u32,
            start_at_unix,
            boot_id,
            last_event_at,
            last_snap_at,
            snap_count: snap_count as u64,
            skip_count: skip_count as u64,
            error_count: error_count as u64,
        })
    }
}

/// Lightweight read-side view of WatchState — same fields minus `last_error`
/// (doctor doesn't need it for liveness; the raw `watch status` command shows
/// the full state file).
#[derive(Debug, Clone)]
pub struct ParsedWatchState {
    pub pid: u32,
    pub start_at_unix: i64,
    pub boot_id: String,
    pub last_event_at: Option<i64>,
    pub last_snap_at: Option<i64>,
    pub snap_count: u64,
    pub skip_count: u64,
    pub error_count: u64,
}

fn extract_number(s: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{}\":", key);
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '-'))?;
    rest[..end].parse().ok()
}

fn extract_string(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// OS-specific opaque boot identifier. Stored in WatchState to detect pid
/// reuse across reboots.
///
/// - Linux: contents of `/proc/sys/kernel/random/boot_id`.
/// - macOS: `hostname + ":" + kern.boottime` via sysctl (read from `uname` +
///   `sysctl -n kern.boottime` shell-out; cheap enough for once-per-daemon-
///   start + once-per-doctor-call).
/// - Fallback: hostname only (better than nothing; doctor flag still detects
///   a different host's state file).
pub fn current_boot_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return s.trim().to_string();
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let hostname = Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let boot = Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !hostname.is_empty() || !boot.is_empty() {
            return format!("{hostname}|{boot}");
        }
    }
    // Last-resort fallback: hostname env var.
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string())
}

/// Cheap pid-alive probe using `kill(pid, 0)`. Returns true if signal 0 is
/// deliverable, which means the process exists. On Windows this returns
/// `true` unconditionally — Windows pid liveness needs a different syscall
/// path that the watcher slice doesn't cover yet (#30 deferred Windows).
#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // `kill(pid, 0)` returns 0 if signal would be deliverable (process exists
    // and we have permission). Avoids subprocess spawn which was flaky under
    // parallel test execution.
    unsafe { kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
pub fn pid_alive(_pid: u32) -> bool {
    true
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

#[derive(Debug, PartialEq, Eq)]
pub enum WatcherLiveness {
    /// No state file present — daemon never ran here.
    NeverInstalled,
    /// State file unreadable or malformed.
    StateUnreadable,
    /// pid is alive and boot_id matches → daemon is our daemon.
    Running { pid: u32 },
    /// pid is alive but boot_id differs → the pid is reused from before a
    /// reboot, the daemon process from the state file is gone.
    Stale { pid: u32 },
    /// pid is dead.
    Stopped { pid: u32 },
}

pub fn liveness(store: &Store) -> WatcherLiveness {
    let raw = match read_state_raw(store) {
        Some(s) => s,
        None => return WatcherLiveness::NeverInstalled,
    };
    let parsed = match WatchState::from_json(&raw) {
        Some(p) => p,
        None => return WatcherLiveness::StateUnreadable,
    };
    if !pid_alive(parsed.pid) {
        return WatcherLiveness::Stopped { pid: parsed.pid };
    }
    if parsed.boot_id != current_boot_id() {
        return WatcherLiveness::Stale { pid: parsed.pid };
    }
    WatcherLiveness::Running { pid: parsed.pid }
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
    // Single acquisition via snap path with TryOnce — never blocks git. If the
    // lock is held by a hook/shim this returns skipped_lock_held=true without
    // re-entering or sleeping.
    match snap_with_config_lock_mode(repo, store, "watcher", None, cfg, SnapLockMode::TryOnce) {
        Ok(SnapshotResult {
            skipped_lock_held: true,
            ..
        }) => {
            state.skip_count += 1;
            BatchOutcome::SkippedByLockHeld
        }
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

/// Install a SIGTERM + SIGINT handler that flips the returned flag. Used by
/// `run()` to drain its current debounce window and exit cleanly when
/// launchd / systemd / Ctrl-C asks the daemon to stop. See #47.
pub fn install_signal_handler() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        signal_hook::flag::register(SIGTERM, Arc::clone(&flag))
            .map_err(|e| Error::Config(format!("signal-hook SIGTERM: {e}")))?;
        signal_hook::flag::register(SIGINT, Arc::clone(&flag))
            .map_err(|e| Error::Config(format!("signal-hook SIGINT: {e}")))?;
    }
    Ok(flag)
}

/// Run the watcher loop. Blocks; exits cleanly on channel disconnect or when
/// SIGTERM/SIGINT trips the shutdown flag (#47). On shutdown the current
/// in-flight snap is allowed to finish — `snap_with_config` is bounded by
/// the size of the touched file set, which the daemon caps via the standard
/// select() per-file 10 MB limit.
pub fn run(repo: &Repo, store: &Store, cfg: &Config, wcfg: &WatchConfig) -> Result<()> {
    let shutdown = install_signal_handler()?;
    run_with_shutdown(repo, store, cfg, wcfg, shutdown)
}

/// Inner loop with an explicit shutdown flag so tests can simulate signal
/// delivery without going through real signals (which would terminate the
/// test process if our handler hasn't installed yet — fragile under cargo
/// test parallel execution).
pub fn run_with_shutdown(
    repo: &Repo,
    store: &Store,
    cfg: &Config,
    wcfg: &WatchConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
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
        if shutdown.load(Ordering::Relaxed) {
            // Final state write so doctor reflects clean exit.
            let _ = write_state(store, &state);
            return Ok(());
        }
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
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Error::Config(
                    "notify watcher channel disconnected — supervisor should restart".into(),
                ));
            }
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
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Config(
                        "notify watcher channel disconnected — supervisor should restart".into(),
                    ));
                }
            }
        }
        let _ = process_batch(repo, store, cfg, events_seen, &mut state);
        let _ = write_state(store, &state);
        last_heartbeat = Instant::now();
        // Re-check shutdown after the snap — if SIGTERM arrived mid-debounce,
        // exit now rather than blocking on another event. `write_state`
        // already fired above (line just above), so doctor sees the post-snap
        // state on next read.
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
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
    fn watch_state_json_now_includes_boot_id() {
        let s = WatchState::new();
        let j = s.to_json();
        assert!(j.contains("\"boot_id\":\""));
        assert!(!s.boot_id.is_empty(), "boot_id should not be empty");
    }

    #[test]
    fn from_json_parses_back_to_basic_fields() {
        let mut s = WatchState::new();
        s.snap_count = 7;
        s.skip_count = 2;
        s.last_event_at = Some(1_700_000_000);
        let j = s.to_json();
        let p = WatchState::from_json(&j).expect("parse");
        assert_eq!(p.pid, s.pid);
        assert_eq!(p.start_at_unix, s.start_at_unix);
        assert_eq!(p.boot_id, s.boot_id);
        assert_eq!(p.snap_count, 7);
        assert_eq!(p.skip_count, 2);
        assert_eq!(p.last_event_at, Some(1_700_000_000));
    }

    #[test]
    fn from_json_returns_none_on_garbage() {
        assert!(WatchState::from_json("not json at all").is_none());
        assert!(WatchState::from_json("{\"snap_count\":5}").is_none());
    }

    #[test]
    fn liveness_never_installed_when_no_state_file() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        assert_eq!(liveness(&store), WatcherLiveness::NeverInstalled);
    }

    #[test]
    fn liveness_stopped_when_pid_dead() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let mut s = WatchState::new();
        s.pid = 1; // pid 1 likely alive — pick a definitely-dead one.
                   // pid 999999 is well above the typical pid_max range.
        s.pid = 999_999;
        write_state(&store, &s).unwrap();
        match liveness(&store) {
            WatcherLiveness::Stopped { pid } => assert_eq!(pid, 999_999),
            other => panic!("expected Stopped, got {other:?}"),
        }
    }

    #[test]
    fn liveness_stale_when_boot_id_differs() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let mut s = WatchState::new();
        s.pid = std::process::id(); // alive (we are it)
        s.boot_id = "synthetic-different-boot-id".to_string();
        write_state(&store, &s).unwrap();
        match liveness(&store) {
            WatcherLiveness::Stale { pid } => assert_eq!(pid, std::process::id()),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn liveness_running_when_pid_and_boot_id_match() {
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        // Use this process's own pid + boot_id — both must match.
        let mut s = WatchState::new();
        s.pid = std::process::id();
        // boot_id already set to current via WatchState::new()
        write_state(&store, &s).unwrap();
        match liveness(&store) {
            WatcherLiveness::Running { pid } => assert_eq!(pid, std::process::id()),
            other => panic!("expected Running, got {other:?}"),
        }
    }

    #[test]
    fn current_boot_id_is_stable_within_run() {
        let a = current_boot_id();
        let b = current_boot_id();
        assert_eq!(a, b, "boot_id must be stable within a single process");
        assert!(!a.is_empty());
    }

    #[test]
    fn pid_alive_for_self_returns_true() {
        assert!(pid_alive(std::process::id()));
    }

    #[test]
    fn pid_alive_for_definitely_dead_returns_false() {
        assert!(!pid_alive(999_999));
    }

    #[test]
    fn run_with_shutdown_exits_immediately_when_flag_preset() {
        // Flag tripped before the loop starts → first iteration sees it and
        // returns Ok(()). Verifies the shutdown gate is checked before any
        // blocking recv that could otherwise pin the loop.
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let cfg = Config::default();
        let wcfg = WatchConfig {
            debounce: Duration::from_millis(50),
            heartbeat: Duration::from_millis(100),
        };
        let shutdown = Arc::new(AtomicBool::new(true));
        let started = Instant::now();
        let result = run_with_shutdown(&repo, &store, &cfg, &wcfg, Arc::clone(&shutdown));
        assert!(result.is_ok(), "run should exit cleanly on shutdown");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should exit fast; took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn run_with_shutdown_exits_when_flag_set_from_another_thread() {
        // More realistic: loop starts, another thread flips the flag, loop
        // notices on next idle-tick. Verifies the timeout-driven path picks
        // up shutdown without an external event.
        let td = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let repo = make_repo(td.path());
        let store = Store::for_repo_with_base(&repo, data.path().to_path_buf()).unwrap();
        let cfg = Config::default();
        let wcfg = WatchConfig {
            debounce: Duration::from_millis(50),
            heartbeat: Duration::from_millis(150),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            flag_clone.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let result = run_with_shutdown(&repo, &store, &cfg, &wcfg, shutdown);
        assert!(result.is_ok());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should exit within ~heartbeat after flag flip; took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn install_signal_handler_returns_unset_flag() {
        // Just verifies the registration doesn't error and we get a fresh
        // flag back. Can't easily test signal delivery without affecting
        // the test process itself.
        let flag = install_signal_handler().expect("install");
        assert!(!flag.load(Ordering::Relaxed));
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

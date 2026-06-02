use crate::manifest::Manifest;
use crate::store::{SnapLockMode, Store};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRef {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub trait RemoteBackend: Send + Sync {
    fn push_blob(&self, digest: &str, source: &mut dyn Read, len: u64) -> Result<()>;
    fn push_manifest(&self, manifest: &Manifest) -> Result<()>;
    fn head_blob(&self, digest: &str) -> Result<bool>;
    fn fetch_manifest_index(&self) -> Result<Vec<ManifestRef>>;
    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>>;
}

pub struct NullBackend;

impl NullBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteBackend for NullBackend {
    fn push_blob(&self, _digest: &str, source: &mut dyn Read, _len: u64) -> Result<()> {
        let mut sink = std::io::sink();
        std::io::copy(source, &mut sink).map_err(|e| crate::Error::io("<null-backend>", e))?;
        Ok(())
    }

    fn push_manifest(&self, _manifest: &Manifest) -> Result<()> {
        Ok(())
    }

    fn head_blob(&self, _digest: &str) -> Result<bool> {
        Ok(false)
    }

    fn fetch_manifest_index(&self) -> Result<Vec<ManifestRef>> {
        Ok(Vec::new())
    }

    fn fetch_blob(&self, _digest: &str) -> Result<Vec<u8>> {
        Err(crate::Error::Unimplemented(
            "NullBackend does not store blobs; fetch_blob is unreachable in production paths"
                .to_string(),
        ))
    }
}

/// A blob+manifest pair waiting to be uploaded by `reflogless remote push`.
/// Written one-per-line as JSONL to `<store>/remote-pending.jsonl` at snap
/// time when a remote backend is configured.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEntry {
    pub manifest_id: String,
    pub blob_digests: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Append one pending entry. Uses the remote lock in `TryOnce` mode so a
/// snap never blocks a long-running `remote push`. On contention we return
/// `Ok(false)` — the entry will be re-derived from the manifest on the next
/// push and deduped via `head_blob`.
pub fn append_pending(store: &Store, entry: &PendingEntry) -> Result<bool> {
    let Some(_lock) = store.acquire_remote_lock(SnapLockMode::TryOnce)? else {
        return Ok(false);
    };
    let path = store.remote_pending_path();
    let mut line = serde_json::to_string(entry)?;
    line.push('\n');
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    f.write_all(line.as_bytes())
        .map_err(|e| Error::io(&path, e))?;
    Ok(true)
}

/// Read all pending entries. Acquires the remote lock blocking; intended
/// for use by `reflogless remote push`. Returns an empty vec if the log
/// does not exist yet.
pub fn read_pending(store: &Store) -> Result<Vec<PendingEntry>> {
    let _lock = store
        .acquire_remote_lock(SnapLockMode::Block)?
        .expect("Block mode never returns None");
    read_pending_no_lock(store)
}

fn read_pending_no_lock(store: &Store) -> Result<Vec<PendingEntry>> {
    let path = store.remote_pending_path();
    let body = match fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(&path, e)),
    };
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: PendingEntry = serde_json::from_str(trimmed)?;
        out.push(entry);
    }
    Ok(out)
}

/// Replace the pending log with `still_pending`, atomically. Caller must
/// hold the remote lock (typically via `drain_pending`).
fn rewrite_pending(store: &Store, still_pending: &[PendingEntry]) -> Result<()> {
    let path = store.remote_pending_path();
    if still_pending.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::io(&path, e)),
        }
    }
    let mut body = String::new();
    for entry in still_pending {
        body.push_str(&serde_json::to_string(entry)?);
        body.push('\n');
    }
    crate::store::atomic_write(&path, body.as_bytes())
}

/// Drain pending entries through `try_upload`. For each entry the closure
/// returns `Ok(true)` on a successful upload (entry is dropped from the log),
/// `Ok(false)` to keep the entry (still pending — typically network failure),
/// or `Err(_)` to abort the drain and re-persist still-pending entries.
///
/// Holds the remote lock for the duration. Snap-time appends during a drain
/// hit `TryOnce` contention and skip — they'll be re-derived from the
/// manifest on the next push.
pub fn drain_pending<F>(store: &Store, mut try_upload: F) -> Result<DrainStats>
where
    F: FnMut(&PendingEntry) -> Result<bool>,
{
    let _lock = store
        .acquire_remote_lock(SnapLockMode::Block)?
        .expect("Block mode never returns None");
    let entries = read_pending_no_lock(store)?;
    let mut stats = DrainStats::default();
    let mut keep = Vec::new();
    let mut iter = entries.into_iter();
    while let Some(entry) = iter.next() {
        match try_upload(&entry) {
            Ok(true) => stats.uploaded += 1,
            Ok(false) => keep.push(entry),
            Err(e) => {
                keep.push(entry);
                keep.extend(iter);
                rewrite_pending(store, &keep)?;
                return Err(e);
            }
        }
    }
    rewrite_pending(store, &keep)?;
    stats.deferred = keep.len();
    Ok(stats)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    pub uploaded: usize,
    pub deferred: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use std::io::Cursor;

    fn sample_manifest() -> Manifest {
        Manifest::new(
            "snap_test".to_string(),
            "test".to_string(),
            Some("contract roundtrip".to_string()),
            "/tmp/repo".to_string(),
        )
    }

    #[test]
    fn null_backend_push_blob_consumes_reader() {
        let backend = NullBackend::new();
        let data = b"hello world";
        let mut reader = Cursor::new(data);
        backend
            .push_blob("sha256:abc", &mut reader, data.len() as u64)
            .expect("push_blob ok");
        assert_eq!(reader.position(), data.len() as u64);
    }

    #[test]
    fn null_backend_push_manifest_is_noop_ok() {
        let backend = NullBackend::new();
        backend.push_manifest(&sample_manifest()).expect("ok");
    }

    #[test]
    fn null_backend_head_blob_always_false() {
        let backend = NullBackend::new();
        assert!(!backend.head_blob("sha256:xyz").expect("ok"));
    }

    #[test]
    fn null_backend_manifest_index_empty() {
        let backend = NullBackend::new();
        assert!(backend.fetch_manifest_index().expect("ok").is_empty());
    }

    #[test]
    fn null_backend_fetch_blob_errors() {
        let backend = NullBackend::new();
        let err = backend.fetch_blob("sha256:zzz").unwrap_err();
        matches!(err, crate::Error::Unimplemented(_));
    }

    #[test]
    fn null_backend_is_object_safe() {
        let backend: Box<dyn RemoteBackend> = Box::new(NullBackend::new());
        let mut reader = Cursor::new(b"x");
        backend.push_blob("d", &mut reader, 1).expect("ok");
        backend.push_manifest(&sample_manifest()).expect("ok");
    }

    use crate::repo::Repo;
    use tempfile::TempDir;

    fn make_store() -> (TempDir, Store) {
        let td = TempDir::new().unwrap();
        let repo_root = td.path().join("repo");
        std::fs::create_dir_all(repo_root.join(".git")).unwrap();
        let repo = Repo::discover(&repo_root).unwrap();
        let base = td.path().join("data");
        let store = Store::for_repo_with_base(&repo, base).unwrap();
        (td, store)
    }

    fn entry(id: &str, digests: &[&str]) -> PendingEntry {
        PendingEntry {
            manifest_id: id.to_string(),
            blob_digests: digests.iter().map(|s| s.to_string()).collect(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn append_and_read_pending_roundtrip() {
        let (_td, store) = make_store();
        assert!(append_pending(&store, &entry("snap_a", &["sha:1", "sha:2"])).unwrap());
        assert!(append_pending(&store, &entry("snap_b", &["sha:3"])).unwrap());
        let pending = read_pending(&store).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].manifest_id, "snap_a");
        assert_eq!(pending[1].blob_digests, vec!["sha:3"]);
    }

    // Lockdown test for the macOS flock close-to-release lag: without explicit
    // `unlock()` in `RemoteLock::drop`, sequential same-process TryOnce
    // re-acquisitions intermittently return `Ok(false)` even with no other
    // holder. Mutation pin: removing the `Drop for RemoteLock` impl fails this
    // ~50% of the time on macOS (single run is enough most of the time;
    // iterating 50x makes it deterministic on slow runners too).
    #[test]
    fn sequential_tryonce_reacquisition_is_deterministic() {
        let (_td, store) = make_store();
        for i in 0..50 {
            let acquired = append_pending(&store, &entry(&format!("snap_{i}"), &["sha:x"]))
                .unwrap_or_else(|e| panic!("iteration {i}: {e}"));
            assert!(
                acquired,
                "iteration {i} hit TryOnce contention with no other holder"
            );
        }
        assert_eq!(read_pending(&store).unwrap().len(), 50);
    }

    #[test]
    fn read_pending_empty_when_log_missing() {
        let (_td, store) = make_store();
        assert!(read_pending(&store).unwrap().is_empty());
    }

    #[test]
    fn drain_uploads_all_clears_log() {
        let (_td, store) = make_store();
        append_pending(&store, &entry("a", &["sha:1"])).unwrap();
        append_pending(&store, &entry("b", &["sha:2"])).unwrap();
        let stats = drain_pending(&store, |_| Ok(true)).unwrap();
        assert_eq!(stats.uploaded, 2);
        assert_eq!(stats.deferred, 0);
        assert!(read_pending(&store).unwrap().is_empty());
        assert!(!store.remote_pending_path().exists());
    }

    #[test]
    fn drain_keeps_deferred_entries() {
        let (_td, store) = make_store();
        append_pending(&store, &entry("a", &["sha:1"])).unwrap();
        append_pending(&store, &entry("b", &["sha:2"])).unwrap();
        append_pending(&store, &entry("c", &["sha:3"])).unwrap();
        let mut idx = 0;
        let stats = drain_pending(&store, |_| {
            idx += 1;
            Ok(idx == 1 || idx == 3)
        })
        .unwrap();
        assert_eq!(stats.uploaded, 2);
        assert_eq!(stats.deferred, 1);
        let remaining = read_pending(&store).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].manifest_id, "b");
    }

    #[test]
    fn drain_error_persists_remaining_entries() {
        let (_td, store) = make_store();
        append_pending(&store, &entry("a", &["sha:1"])).unwrap();
        append_pending(&store, &entry("b", &["sha:2"])).unwrap();
        append_pending(&store, &entry("c", &["sha:3"])).unwrap();
        let mut count = 0;
        let res = drain_pending(&store, |_| {
            count += 1;
            if count == 2 {
                Err(Error::Config("simulated".into()))
            } else {
                Ok(true)
            }
        });
        assert!(res.is_err());
        let remaining = read_pending(&store).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].manifest_id, "b");
        assert_eq!(remaining[1].manifest_id, "c");
    }

    #[test]
    fn concurrent_append_skips_while_drain_holds_lock() {
        let (_td, store) = make_store();
        append_pending(&store, &entry("a", &["sha:1"])).unwrap();
        let mut saw_contention = false;
        let stats = drain_pending(&store, |e| {
            if e.manifest_id == "a" {
                let result = append_pending(&store, &entry("b", &["sha:2"])).unwrap();
                if !result {
                    saw_contention = true;
                }
            }
            Ok(true)
        })
        .unwrap();
        assert!(
            saw_contention,
            "snap-time append must skip when drain holds the lock"
        );
        assert_eq!(stats.uploaded, 1);
        assert_eq!(stats.deferred, 0);
        assert!(read_pending(&store).unwrap().is_empty());
    }

    #[test]
    fn rewrite_after_full_drain_removes_log_file() {
        let (_td, store) = make_store();
        append_pending(&store, &entry("a", &["sha:1"])).unwrap();
        assert!(store.remote_pending_path().exists());
        drain_pending(&store, |_| Ok(true)).unwrap();
        assert!(!store.remote_pending_path().exists());
    }
}

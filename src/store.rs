use crate::crypto;
use crate::error::{Error, Result};
use crate::manifest::Manifest;
use crate::repo::Repo;
use age::x25519::{Identity, Recipient};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const RECIPIENT_FILENAME: &str = "recipient.txt";
pub const INSECURE_KEY_MARKER: &str = "insecure-file-key";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const DEFAULT_MAX_STORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_AGE_DAYS: i64 = 30;

pub struct Store {
    pub root: PathBuf,
    crypto: Option<CryptoCtx>,
}

/// Bundle of materials needed to encrypt blobs (`recipient`) and decrypt them
/// (`identity`). Stored on `Store` so all manifest/blob read paths can pick up
/// encryption transparently without leaking it into every signature.
#[derive(Clone)]
pub struct CryptoCtx {
    pub identity: Identity,
    pub recipient: Recipient,
}

impl CryptoCtx {
    pub fn from_identity(identity: Identity) -> Self {
        let recipient = crypto::recipient_of(&identity);
        Self { identity, recipient }
    }
}

impl Store {
    pub fn for_repo(repo: &Repo) -> Result<Self> {
        Self::for_repo_with_base(repo, base_data_dir()?)
    }

    pub fn for_repo_with_base(repo: &Repo, base: PathBuf) -> Result<Self> {
        let root = base.join("reflogless").join(repo.id());
        let objects = root.join("objects");
        let snapshots = root.join("snapshots");
        fs::create_dir_all(&objects).map_err(|e| Error::io(&root, e))?;
        fs::create_dir_all(&snapshots).map_err(|e| Error::io(&root, e))?;
        set_dir_perms(&root)?;
        set_dir_perms(&objects)?;
        set_dir_perms(&snapshots)?;
        Ok(Self {
            root,
            crypto: None,
        })
    }

    /// Attach a crypto context. Subsequent manifest writes/reads will encrypt
    /// the manifest body, and `write_blob_via_policy` / `read_entry` will route
    /// through encryption when the policy says so.
    pub fn with_crypto(mut self, ctx: CryptoCtx) -> Self {
        self.crypto = Some(ctx);
        self
    }

    pub fn crypto(&self) -> Option<&CryptoCtx> {
        self.crypto.as_ref()
    }

    /// Path to the on-disk recipient (public key) file. Presence indicates the
    /// store was provisioned for encryption.
    pub fn recipient_path(&self) -> PathBuf {
        self.root.join(RECIPIENT_FILENAME)
    }

    /// Path to the insecure-file-key marker. Presence indicates the identity
    /// lives in a local file rather than the OS keychain. Doctor surfaces this.
    pub fn insecure_marker_path(&self) -> PathBuf {
        self.root.join(INSECURE_KEY_MARKER)
    }

    pub fn provisioned_for_encryption(&self) -> bool {
        self.recipient_path().exists()
    }

    pub fn save_recipient(&self, recipient: &Recipient) -> Result<()> {
        let p = self.recipient_path();
        atomic_write(&p, recipient.to_string().as_bytes())?;
        set_file_perms(&p)?;
        Ok(())
    }

    pub fn load_recipient(&self) -> Result<Recipient> {
        let p = self.recipient_path();
        let s = fs::read_to_string(&p).map_err(|e| Error::io(&p, e))?;
        crypto::parse_recipient(&s)
    }

    pub fn mark_insecure(&self) -> Result<()> {
        let p = self.insecure_marker_path();
        atomic_write(&p, b"")?;
        set_file_perms(&p)
    }

    pub fn is_insecure_keyed(&self) -> bool {
        self.insecure_marker_path().exists()
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    /// Write plaintext bytes to a CAS blob keyed by sha256 of plaintext.
    /// Returns the plaintext digest. Used when no encryption is desired.
    pub fn write_blob(&self, bytes: &[u8]) -> Result<String> {
        self.write_blob_inner(bytes, bytes)
    }

    /// Write a blob whose disk-content is encrypted with `recipient`. CAS key
    /// stays the *plaintext* digest so dedup works across snapshots regardless
    /// of nonce churn. Caller records `encrypted: true` in the manifest entry.
    pub fn write_blob_encrypted(&self, plaintext: &[u8], recipient: &Recipient) -> Result<String> {
        let ciphertext = crypto::encrypt(plaintext, recipient)?;
        self.write_blob_inner(plaintext, &ciphertext)
    }

    fn write_blob_inner(&self, plaintext_for_digest: &[u8], on_disk: &[u8]) -> Result<String> {
        let mut h = Sha256::new();
        h.update(plaintext_for_digest);
        let digest = format!("{:x}", h.finalize());
        let (a, b) = digest.split_at(2);
        let dir = self.objects_dir().join(a);
        let dir_existed = dir.exists();
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        if !dir_existed {
            // 0700 on new shards too, not just the root, so blob existence
            // can't be enumerated by world-readable directory traversal.
            set_dir_perms(&dir)?;
        }
        let p = dir.join(b);
        let rewrite = match fs::metadata(&p) {
            Ok(md) => md.len() != on_disk.len() as u64,
            Err(_) => true,
        };
        if rewrite {
            atomic_write(&p, on_disk)?;
            set_file_perms(&p)?;
        }
        Ok(digest)
    }

    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let (a, b) = digest.split_at(2);
        let p = self.objects_dir().join(a).join(b);
        let mut f = fs::File::open(&p).map_err(|e| Error::io(&p, e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Error::io(&p, e))?;
        Ok(buf)
    }

    /// Read an age-encrypted blob and return decrypted plaintext.
    pub fn read_blob_encrypted(&self, digest: &str, identity: &Identity) -> Result<Vec<u8>> {
        let ct = self.read_blob(digest)?;
        crypto::decrypt(&ct, identity)
    }

    /// Read a manifest entry's bytes, branching on `entry.encrypted` so callers
    /// can't accidentally feed ciphertext into a text-diff or restore path.
    /// Errors loudly when an encrypted entry is read against a store with no
    /// crypto context attached.
    pub fn read_entry(&self, entry: &crate::manifest::ManifestEntry) -> Result<Vec<u8>> {
        if entry.encrypted {
            let ctx = self.crypto.as_ref().ok_or_else(|| {
                Error::Decryption(format!(
                    "entry {} is encrypted but no identity attached to store",
                    entry.path.display()
                ))
            })?;
            self.read_blob_encrypted(&entry.blob, &ctx.identity)
        } else {
            self.read_blob(&entry.blob)
        }
    }

    pub fn delete_blob(&self, digest: &str) -> Result<()> {
        let (a, b) = digest.split_at(2);
        let p = self.objects_dir().join(a).join(b);
        if p.exists() {
            fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
        }
        Ok(())
    }

    /// Write the manifest. When the store has a crypto context attached, the
    /// body is age-encrypted and written as `<id>.json.age`. Otherwise plain
    /// JSON at `<id>.json`.
    pub fn write_manifest(&self, m: &Manifest) -> Result<PathBuf> {
        let json = serde_json::to_vec_pretty(m)?;
        let p = match &self.crypto {
            Some(ctx) => {
                let body = crypto::encrypt(&json, &ctx.recipient)?;
                let p = self.snapshots_dir().join(format!("{}.json.age", m.id));
                atomic_write(&p, &body)?;
                set_file_perms(&p)?;
                p
            }
            None => {
                let p = self.snapshots_dir().join(format!("{}.json", m.id));
                atomic_write(&p, &json)?;
                set_file_perms(&p)?;
                p
            }
        };
        Ok(p)
    }

    pub fn load_manifest(&self, id: &str) -> Result<Manifest> {
        if id.is_empty() {
            return Err(Error::SnapshotNotFound("(empty)".into()));
        }
        // exact match: try encrypted first, then plain, so an encrypted store
        // can still surface a pre-encryption manifest if one lingers.
        let enc = self.snapshots_dir().join(format!("{}.json.age", id));
        if enc.exists() {
            return self.read_manifest_file(&enc);
        }
        let exact = self.snapshots_dir().join(format!("{}.json", id));
        if exact.exists() {
            return self.read_manifest_file(&exact);
        }
        // "latest" alias
        if id == "latest" {
            let (mut all, _warnings) = self.list_manifests_lenient()?;
            all.sort_by_key(|m| m.created_at);
            return all
                .pop()
                .ok_or_else(|| Error::SnapshotNotFound("latest".into()));
        }
        // prefix match
        let matches: Vec<_> = self
            .list_manifest_paths()?
            .into_iter()
            .filter(|p| {
                manifest_id_from_path(p.as_path())
                    .map(|s| s.starts_with(id))
                    .unwrap_or(false)
            })
            .collect();
        match matches.len() {
            0 => Err(Error::SnapshotNotFound(id.into())),
            1 => self.read_manifest_file(&matches[0]),
            _ => {
                let ids: Vec<String> = matches
                    .iter()
                    .filter_map(|p| manifest_id_from_path(p))
                    .collect();
                Err(Error::AmbiguousSnapshot {
                    id: id.into(),
                    matches: ids,
                })
            }
        }
    }

    /// Strict list — errors on the first malformed manifest. Prefer
    /// `list_manifests_lenient` for any user-facing path that needs to survive
    /// partial corruption.
    pub fn list_manifests(&self) -> Result<Vec<Manifest>> {
        let mut out = Vec::new();
        for p in self.list_manifest_paths()? {
            out.push(self.read_manifest_file(&p)?);
        }
        Ok(out)
    }

    /// Returns successfully-parsed manifests plus per-path errors for the rest.
    /// One bad manifest never blinds the user to the N-1 good ones.
    pub fn list_manifests_lenient(&self) -> Result<(Vec<Manifest>, Vec<(PathBuf, Error)>)> {
        let mut ok = Vec::new();
        let mut warnings = Vec::new();
        for p in self.list_manifest_paths()? {
            match self.read_manifest_file(&p) {
                Ok(m) => ok.push(m),
                Err(e) => warnings.push((p, e)),
            }
        }
        Ok((ok, warnings))
    }

    fn list_manifest_paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.snapshots_dir();
        let mut paths = Vec::new();
        let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
        for entry in rd {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let p = entry.path();
            let name = match p.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            if name.ends_with(".json") || name.ends_with(".json.age") {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    fn read_manifest_file(&self, p: &Path) -> Result<Manifest> {
        let mut f = fs::File::open(p).map_err(|e| Error::io(p, e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Error::io(p, e))?;
        let plaintext = if is_encrypted_manifest_path(p) {
            let ctx = self.crypto.as_ref().ok_or_else(|| {
                Error::Decryption(format!(
                    "encrypted manifest {} but no identity attached",
                    p.display()
                ))
            })?;
            crypto::decrypt(&buf, &ctx.identity)?
        } else {
            buf
        };
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Evict snapshots older than `max_age_days`, then enforce `max_bytes` by LRU
    /// (oldest snapshots dropped first), then drop unreferenced blobs.
    ///
    /// Manifests that fail to parse are treated as eviction candidates rather
    /// than aborting the whole GC pass.
    pub fn gc(&self, max_age_days: i64, max_bytes: u64) -> Result<GcReport> {
        let mut report = GcReport::default();
        let cutoff = Utc::now() - Duration::days(max_age_days);

        let mut retained: Vec<(PathBuf, Manifest)> = Vec::new();
        for p in self.list_manifest_paths()? {
            match self.read_manifest_file(&p) {
                Ok(m) => {
                    if m.created_at < cutoff {
                        fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
                        report.snapshots_age_evicted += 1;
                    } else {
                        retained.push((p, m));
                    }
                }
                Err(_) => {
                    // Unreadable manifest is itself store rot — drop it.
                    fs::remove_file(&p).map_err(|e| Error::io(&p, e))?;
                    report.snapshots_corrupt_evicted += 1;
                }
            }
        }

        // Oldest first by manifest-declared time, not filesystem mtime.
        retained.sort_by_key(|(_, m)| m.created_at);

        let mut total = self.total_blob_bytes()?;
        let mut idx = 0;
        while total > max_bytes && idx < retained.len() {
            let (p, _) = &retained[idx];
            fs::remove_file(p).map_err(|e| Error::io(p, e))?;
            report.snapshots_size_evicted += 1;
            idx += 1;
            let keep: HashSet<String> = retained
                .iter()
                .skip(idx)
                .flat_map(|(_, m)| m.entries.iter().map(|e| e.blob.clone()))
                .collect();
            total = self.objects_size_filtered(&keep)?;
        }

        let kept: HashSet<String> = retained
            .iter()
            .skip(idx)
            .flat_map(|(_, m)| m.entries.iter().map(|e| e.blob.clone()))
            .collect();
        report.blobs_evicted = self.drop_unreferenced_blobs(&kept)?;
        Ok(report)
    }

    fn total_blob_bytes(&self) -> Result<u64> {
        let mut total = 0;
        let dir = self.objects_dir();
        for d in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let d = d.map_err(|e| Error::io(&dir, e))?;
            if !d.path().is_dir() {
                continue;
            }
            for f in fs::read_dir(d.path()).map_err(|e| Error::io(d.path(), e))? {
                let f = f.map_err(|e| Error::io(d.path(), e))?;
                let m = f.metadata().map_err(|e| Error::io(f.path(), e))?;
                total += m.len();
            }
        }
        Ok(total)
    }

    fn objects_size_filtered(&self, keep: &HashSet<String>) -> Result<u64> {
        let mut total = 0;
        for digest in keep {
            let (a, b) = digest.split_at(2);
            let p = self.objects_dir().join(a).join(b);
            if let Ok(m) = fs::metadata(&p) {
                total += m.len();
            }
        }
        Ok(total)
    }

    fn drop_unreferenced_blobs(&self, keep: &HashSet<String>) -> Result<usize> {
        let mut dropped = 0;
        let dir = self.objects_dir();
        for d in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let d = d.map_err(|e| Error::io(&dir, e))?;
            if !d.path().is_dir() {
                continue;
            }
            let a = d.file_name();
            for f in fs::read_dir(d.path()).map_err(|e| Error::io(d.path(), e))? {
                let f = f.map_err(|e| Error::io(d.path(), e))?;
                let b = f.file_name();
                let digest = format!("{}{}", a.to_string_lossy(), b.to_string_lossy());
                if !keep.contains(&digest) {
                    fs::remove_file(f.path()).map_err(|e| Error::io(f.path(), e))?;
                    dropped += 1;
                }
            }
        }
        Ok(dropped)
    }
}

#[derive(Debug, Default)]
pub struct GcReport {
    pub snapshots_age_evicted: usize,
    pub snapshots_size_evicted: usize,
    pub snapshots_corrupt_evicted: usize,
    pub blobs_evicted: usize,
}

/// Strip `.json` or `.json.age` extension and return the manifest id portion of
/// a snapshot filename. Returns None when the filename has neither suffix.
fn manifest_id_from_path(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_str()?;
    if let Some(stem) = name.strip_suffix(".json.age") {
        return Some(stem.to_string());
    }
    if let Some(stem) = name.strip_suffix(".json") {
        return Some(stem.to_string());
    }
    None
}

fn is_encrypted_manifest_path(p: &Path) -> bool {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|n| n.ends_with(".json.age"))
        .unwrap_or(false)
}

fn base_data_dir() -> Result<PathBuf> {
    // Explicit override beats platform default.
    if let Ok(p) = std::env::var("REFLOGLESS_DATA_DIR") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    if let Ok(p) = std::env::var("XDG_DATA_HOME") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    dirs::data_dir().ok_or_else(|| Error::Config("could not resolve data dir".into()))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".reflogless-tmp-{}-{}",
        std::process::id(),
        n
    ));
    let write_result = (|| -> Result<()> {
        let mut f = fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
        f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
        f.sync_all().map_err(|e| Error::io(&tmp, e))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(path, e));
    }
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(p, perms).map_err(|e| Error::io(p, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_perms(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(p, perms).map_err(|e| Error::io(p, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_perms(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestEntry;
    use chrono::DateTime;
    use tempfile::TempDir;

    fn ephemeral_store() -> (TempDir, Store) {
        let td = TempDir::new().unwrap();
        let root = td.path().join("reflogless").join("test");
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("snapshots")).unwrap();
        (
            td,
            Store {
                root,
                crypto: None,
            },
        )
    }

    #[test]
    fn write_and_read_blob_roundtrips() {
        let (_td, store) = ephemeral_store();
        let bytes = b"hello world";
        let digest = store.write_blob(bytes).unwrap();
        let got = store.read_blob(&digest).unwrap();
        assert_eq!(got, bytes);
    }

    #[test]
    fn dedup_writes_one_file_on_disk() {
        let (_td, store) = ephemeral_store();
        let d1 = store.write_blob(b"same").unwrap();
        let d2 = store.write_blob(b"same").unwrap();
        assert_eq!(d1, d2);
        let (a, b) = d1.split_at(2);
        let p = store.objects_dir().join(a).join(b);
        assert!(p.exists());
        // No tmp file should be lying around.
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|d| d.ok())
            .filter(|d| d.file_name().to_string_lossy().starts_with(".reflogless-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "tmp leftover: {leftovers:?}");
    }

    #[test]
    fn load_manifest_prefers_encrypted_when_both_exist() {
        // Pre-Phase-3 manifests may linger next to their re-encrypted siblings
        // during migration. The encrypted file is canonical for a crypto-attached
        // store and must win.
        use crate::crypto;
        let (_td, store) = ephemeral_store();
        let id_str = "20260523T000000000Z-manual";
        // Write plaintext directly.
        let m = make_manifest(id_str, Utc::now(), vec![]);
        let plain_json = serde_json::to_vec_pretty(&m).unwrap();
        atomic_write(&store.snapshots_dir().join(format!("{id_str}.json")), &plain_json).unwrap();
        // Write encrypted with a different message under same id.
        let id = crypto::generate_identity();
        let recipient = crypto::recipient_of(&id);
        let store = store.with_crypto(CryptoCtx::from_identity(id));
        let mut m2 = make_manifest(id_str, Utc::now(), vec![]);
        m2.message = Some("from-encrypted".into());
        let body = serde_json::to_vec_pretty(&m2).unwrap();
        let ct = crypto::encrypt(&body, &recipient).unwrap();
        atomic_write(&store.snapshots_dir().join(format!("{id_str}.json.age")), &ct).unwrap();

        let loaded = store.load_manifest(id_str).unwrap();
        assert_eq!(loaded.message.as_deref(), Some("from-encrypted"));
    }

    #[test]
    fn gc_evicts_corrupt_encrypted_manifest() {
        use crate::crypto;
        let (_td, store) = ephemeral_store();
        let id = crypto::generate_identity();
        let store = store.with_crypto(CryptoCtx::from_identity(id));
        // Sabotage an encrypted manifest path with non-ciphertext bytes.
        fs::write(
            store.snapshots_dir().join("20260523T000000000Z-manual.json.age"),
            b"not-age-encrypted",
        )
        .unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.snapshots_corrupt_evicted, 1);
    }

    #[test]
    fn write_blob_repairs_truncated_existing_object() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"hello").unwrap();
        let (a, b) = digest.split_at(2);
        let p = store.objects_dir().join(a).join(b);
        fs::write(&p, b"").unwrap();
        // Re-writing the same bytes should restore the truncated blob.
        store.write_blob(b"hello").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    fn make_manifest(id: &str, created: DateTime<Utc>, entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            version: crate::manifest::MANIFEST_VERSION,
            id: id.into(),
            created_at: created,
            event: "manual".into(),
            message: None,
            repo_root: "/".into(),
            entries,
        }
    }

    #[test]
    fn load_manifest_rejects_empty_id() {
        let (_td, store) = ephemeral_store();
        let m = make_manifest("only", Utc::now(), vec![]);
        store.write_manifest(&m).unwrap();
        assert!(matches!(
            store.load_manifest(""),
            Err(Error::SnapshotNotFound(_))
        ));
    }

    #[test]
    fn load_manifest_latest_returns_newest_by_created_at() {
        let (_td, store) = ephemeral_store();
        let older = make_manifest("a", Utc::now() - Duration::hours(2), vec![]);
        let newer = make_manifest("b", Utc::now(), vec![]);
        store.write_manifest(&older).unwrap();
        store.write_manifest(&newer).unwrap();
        let m = store.load_manifest("latest").unwrap();
        assert_eq!(m.id, "b");
    }

    #[test]
    fn load_manifest_prefix_match_returns_unique() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest("20260520T000000000Z-manual", Utc::now(), vec![]))
            .unwrap();
        store
            .write_manifest(&make_manifest("20260521T000000000Z-manual", Utc::now(), vec![]))
            .unwrap();
        let m = store.load_manifest("20260520").unwrap();
        assert_eq!(m.id, "20260520T000000000Z-manual");
    }

    #[test]
    fn load_manifest_ambiguous_prefix_errors() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest("20260520T000000000Z-manual", Utc::now(), vec![]))
            .unwrap();
        store
            .write_manifest(&make_manifest("20260520T000000001Z-manual", Utc::now(), vec![]))
            .unwrap();
        match store.load_manifest("20260520") {
            Err(Error::AmbiguousSnapshot { matches, .. }) => assert_eq!(matches.len(), 2),
            other => panic!("expected AmbiguousSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn list_manifests_lenient_skips_corrupt_files() {
        let (_td, store) = ephemeral_store();
        store
            .write_manifest(&make_manifest("good", Utc::now(), vec![]))
            .unwrap();
        fs::write(store.snapshots_dir().join("bad.json"), b"{not json").unwrap();
        let (ok, warnings) = store.list_manifests_lenient().unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(ok[0].id, "good");
    }

    #[test]
    fn gc_evicts_snapshots_older_than_cutoff() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"payload").unwrap();
        let entries = vec![ManifestEntry {
            path: PathBuf::from("a.txt"),
            blob: digest.clone(),
            size: 7,
            mode: 0o644,
            encrypted: false,
        }];
        store
            .write_manifest(&make_manifest(
                "old",
                Utc::now() - Duration::days(60),
                entries,
            ))
            .unwrap();
        let report = store.gc(30, u64::MAX).unwrap();
        assert_eq!(report.snapshots_age_evicted, 1);
        assert_eq!(report.blobs_evicted, 1);
        let (a, b) = digest.split_at(2);
        assert!(!store.objects_dir().join(a).join(b).exists());
    }

    #[test]
    fn gc_size_cap_evicts_oldest_first() {
        let (_td, store) = ephemeral_store();
        let d1 = store.write_blob(&vec![1u8; 1000]).unwrap();
        let d2 = store.write_blob(&vec![2u8; 1000]).unwrap();
        let d3 = store.write_blob(&vec![3u8; 1000]).unwrap();
        let mk = |id, secs: i64, digest: &str| {
            make_manifest(
                id,
                Utc::now() - Duration::seconds(secs),
                vec![ManifestEntry {
                    path: PathBuf::from(format!("{id}.bin")),
                    blob: digest.into(),
                    size: 1000,
                    mode: 0o644,
                    encrypted: false,
                }],
            )
        };
        store.write_manifest(&mk("A", 30, &d1)).unwrap();
        store.write_manifest(&mk("B", 20, &d2)).unwrap();
        store.write_manifest(&mk("C", 10, &d3)).unwrap();
        // Cap at 2050 bytes — must evict A.
        let report = store.gc(365, 2050).unwrap();
        assert_eq!(report.snapshots_size_evicted, 1);
        assert!(store.load_manifest("A").is_err());
        assert!(store.load_manifest("B").is_ok());
        assert!(store.load_manifest("C").is_ok());
    }

    #[test]
    fn gc_drops_unreferenced_blobs() {
        let (_td, store) = ephemeral_store();
        store.write_blob(b"orphan").unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.blobs_evicted, 1);
    }

    #[test]
    fn gc_empty_store_is_noop() {
        let (_td, store) = ephemeral_store();
        let report = store.gc(30, u64::MAX).unwrap();
        assert_eq!(report.snapshots_age_evicted, 0);
        assert_eq!(report.snapshots_size_evicted, 0);
        assert_eq!(report.snapshots_corrupt_evicted, 0);
        assert_eq!(report.blobs_evicted, 0);
    }

    #[test]
    fn gc_drops_corrupt_manifests_instead_of_aborting() {
        let (_td, store) = ephemeral_store();
        let digest = store.write_blob(b"x").unwrap();
        store
            .write_manifest(&make_manifest(
                "good",
                Utc::now(),
                vec![ManifestEntry {
                    path: PathBuf::from("x"),
                    blob: digest.clone(),
                    size: 1,
                    mode: 0o644,
                    encrypted: false,
                }],
            ))
            .unwrap();
        fs::write(store.snapshots_dir().join("bad.json"), b"not json").unwrap();
        let report = store.gc(365, u64::MAX).unwrap();
        assert_eq!(report.snapshots_corrupt_evicted, 1);
        assert!(store.load_manifest("good").is_ok());
    }

}

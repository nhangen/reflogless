use crate::manifest::Manifest;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::io::Read;

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
}

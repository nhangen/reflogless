use crate::manifest::Manifest;
use crate::remote::{ManifestRef, RemoteBackend};
use crate::{Error, Result};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use std::io::Read;

const BLOBS_PREFIX: &str = "blobs/";
const MANIFESTS_PREFIX: &str = "manifests/";

pub struct S3Config {
    pub bucket: String,
    pub region: Region,
    pub credentials: Credentials,
    pub key_prefix: String,
    /// Use path-style addressing (`https://endpoint/bucket/key`) instead of
    /// virtual-hosted-style (`https://bucket.endpoint/key`). Required for
    /// MinIO and most other S3-compatible servers without wildcard DNS.
    /// AWS itself works either way; leave `false` (the default) for AWS.
    pub path_style: bool,
}

pub struct S3Backend {
    bucket: Box<Bucket>,
    key_prefix: String,
}

impl S3Backend {
    pub fn new(cfg: S3Config) -> Result<Self> {
        let bucket = Bucket::new(&cfg.bucket, cfg.region, cfg.credentials)
            .map_err(|e| Error::Config(format!("S3 bucket: {e}")))?;
        let bucket = if cfg.path_style {
            bucket.with_path_style()
        } else {
            bucket
        };
        Ok(Self {
            bucket,
            key_prefix: normalize_prefix(&cfg.key_prefix),
        })
    }

    fn blob_key(&self, digest: &str) -> String {
        format!("{}{}{}", self.key_prefix, BLOBS_PREFIX, digest)
    }

    fn manifest_key(&self, id: &str) -> String {
        format!("{}{}{}.json", self.key_prefix, MANIFESTS_PREFIX, id)
    }
}

fn normalize_prefix(p: &str) -> String {
    let trimmed = p.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

fn map_s3_err(e: s3::error::S3Error) -> Error {
    Error::Config(format!("s3: {e}"))
}

impl RemoteBackend for S3Backend {
    fn push_blob(&self, digest: &str, source: &mut dyn Read, len: u64) -> Result<()> {
        let key = self.blob_key(digest);
        let mut buf = Vec::with_capacity(len as usize);
        source
            .read_to_end(&mut buf)
            .map_err(|e| Error::io(&key, e))?;
        self.bucket
            .put_object(&key, &buf)
            .map(|_| ())
            .map_err(map_s3_err)
    }

    fn push_manifest(&self, manifest: &Manifest) -> Result<()> {
        let body = serde_json::to_vec(manifest)?;
        let key = self.manifest_key(&manifest.id);
        self.bucket
            .put_object_with_content_type(&key, &body, "application/json")
            .map(|_| ())
            .map_err(map_s3_err)
    }

    fn head_blob(&self, digest: &str) -> Result<bool> {
        let key = self.blob_key(digest);
        match self.bucket.head_object(&key) {
            Ok((_, 200)) => Ok(true),
            Ok((_, 404)) => Ok(false),
            Ok((_, status)) => Err(Error::Config(format!(
                "s3 head_object {key}: unexpected status {status}"
            ))),
            Err(e) => Err(map_s3_err(e)),
        }
    }

    fn fetch_manifest_index(&self) -> Result<Vec<ManifestRef>> {
        let prefix = format!("{}{}", self.key_prefix, MANIFESTS_PREFIX);
        let results = self
            .bucket
            .list(prefix.clone(), Some("/".to_string()))
            .map_err(map_s3_err)?;
        let mut refs = Vec::new();
        for page in results {
            for obj in page.contents {
                if let Some(id) = obj
                    .key
                    .strip_prefix(&prefix)
                    .and_then(|k| k.strip_suffix(".json"))
                {
                    let created_at = obj
                        .last_modified
                        .parse::<chrono::DateTime<chrono::Utc>>()
                        .unwrap_or_else(|_| chrono::Utc::now());
                    refs.push(ManifestRef {
                        id: id.to_string(),
                        created_at,
                    });
                }
            }
        }
        Ok(refs)
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let key = self.blob_key(digest);
        let resp = self.bucket.get_object(&key).map_err(map_s3_err)?;
        Ok(resp.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_config() -> S3Config {
        S3Config {
            bucket: "reflogless-test".to_string(),
            region: Region::Custom {
                region: "us-east-1".to_string(),
                endpoint: "http://localhost:9000".to_string(),
            },
            credentials: Credentials::new(Some("AKIATEST"), Some("secrettest"), None, None, None)
                .unwrap(),
            key_prefix: "host-A".to_string(),
            path_style: true,
        }
    }

    #[test]
    fn s3backend_constructs_against_custom_endpoint() {
        let backend = S3Backend::new(fake_config()).expect("construct");
        assert_eq!(backend.key_prefix, "host-A/");
    }

    #[test]
    fn normalize_prefix_shapes() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
        assert_eq!(normalize_prefix("foo"), "foo/");
        assert_eq!(normalize_prefix("foo/"), "foo/");
        assert_eq!(normalize_prefix("/foo/bar"), "foo/bar/");
        assert_eq!(normalize_prefix("/foo/bar/"), "foo/bar/");
    }

    #[test]
    fn blob_and_manifest_keys() {
        let backend = S3Backend::new(fake_config()).unwrap();
        assert_eq!(backend.blob_key("sha256:abc"), "host-A/blobs/sha256:abc");
        assert_eq!(
            backend.manifest_key("snap_20260602T120000"),
            "host-A/manifests/snap_20260602T120000.json"
        );
    }

    #[test]
    fn blob_key_with_empty_prefix() {
        let mut cfg = fake_config();
        cfg.key_prefix = "".to_string();
        let backend = S3Backend::new(cfg).unwrap();
        assert_eq!(backend.blob_key("sha256:x"), "blobs/sha256:x");
    }

    #[test]
    fn s3backend_is_remote_backend_object_safe() {
        let backend = S3Backend::new(fake_config()).unwrap();
        let _trait_obj: Box<dyn RemoteBackend> = Box::new(backend);
    }
}

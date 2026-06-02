//! Integration smoke test for [`reflogless::remote_s3::S3Backend`] against a
//! real S3-compatible endpoint. Skipped unless `REFLOGLESS_S3_ENDPOINT` is set
//! in the environment so `cargo test` stays green on machines without docker
//! / MinIO available.
//!
//! Local run:
//!
//! ```bash
//! docker run -d --rm -p 9000:9000 --name reflogless-minio \
//!     -e MINIO_ROOT_USER=minioadmin \
//!     -e MINIO_ROOT_PASSWORD=minioadmin \
//!     quay.io/minio/minio server /data
//!
//! docker exec reflogless-minio mkdir -p /data/reflogless-test
//!
//! REFLOGLESS_S3_ENDPOINT=http://localhost:9000 \
//! REFLOGLESS_S3_BUCKET=reflogless-test \
//! REFLOGLESS_S3_ACCESS_KEY=minioadmin \
//! REFLOGLESS_S3_SECRET_KEY=minioadmin \
//!     cargo test --features remote --test remote_integration -- --nocapture
//!
//! docker rm -f reflogless-minio
//! ```

#![cfg(feature = "remote")]

use reflogless::manifest::Manifest;
use reflogless::remote::RemoteBackend;
use reflogless::remote_s3::{S3Backend, S3Config};
use s3::creds::Credentials;
use s3::region::Region;
use std::env;
use std::io::Cursor;

struct EnvConfig {
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    region_name: String,
}

fn env_config() -> Option<EnvConfig> {
    Some(EnvConfig {
        endpoint: env::var("REFLOGLESS_S3_ENDPOINT").ok()?,
        bucket: env::var("REFLOGLESS_S3_BUCKET").ok()?,
        access_key: env::var("REFLOGLESS_S3_ACCESS_KEY").ok()?,
        secret_key: env::var("REFLOGLESS_S3_SECRET_KEY").ok()?,
        region_name: env::var("REFLOGLESS_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
    })
}

fn build_backend(cfg: &EnvConfig, prefix: &str) -> S3Backend {
    let region = Region::Custom {
        region: cfg.region_name.clone(),
        endpoint: cfg.endpoint.clone(),
    };
    let credentials = Credentials::new(
        Some(&cfg.access_key),
        Some(&cfg.secret_key),
        None,
        None,
        None,
    )
    .expect("credentials");
    S3Backend::new(S3Config {
        bucket: cfg.bucket.clone(),
        region,
        credentials,
        key_prefix: prefix.to_string(),
        path_style: true,
    })
    .expect("construct backend")
}

fn unique_prefix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-{nanos}")
}

#[test]
fn s3backend_roundtrip_against_minio() {
    let Some(cfg) = env_config() else {
        eprintln!(
            "skipping: REFLOGLESS_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY not set; \
             see test file for MinIO setup instructions"
        );
        return;
    };
    let prefix = unique_prefix();
    let backend = build_backend(&cfg, &prefix);

    let payload = b"the quick brown fox jumps over the lazy dog";
    let digest = "sha256:e4d909c290d0fb1ca068ffaddf22cbd0";

    let mut reader = Cursor::new(payload);
    backend
        .push_blob(digest, &mut reader, payload.len() as u64)
        .expect("push_blob ok");

    assert!(backend.head_blob(digest).expect("head_blob ok"));
    assert!(!backend
        .head_blob("sha256:does-not-exist")
        .expect("head_blob ok"));

    let fetched = backend.fetch_blob(digest).expect("fetch_blob ok");
    assert_eq!(fetched, payload);

    let manifest = Manifest::new(
        "snap_integration_test".to_string(),
        "integration".to_string(),
        Some("roundtrip".to_string()),
        "/tmp/repo".to_string(),
    );
    backend.push_manifest(&manifest).expect("push_manifest ok");

    let index = backend
        .fetch_manifest_index()
        .expect("fetch_manifest_index ok");
    assert!(
        index.iter().any(|m| m.id == "snap_integration_test"),
        "manifest index missing seeded id; got {index:?}"
    );
}

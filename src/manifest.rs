use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub event: String,
    pub message: Option<String>,
    pub repo_root: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: PathBuf,
    pub blob: String,
    pub size: u64,
    pub mode: u32,
}

impl Manifest {
    pub fn new(id: String, event: String, message: Option<String>, repo_root: String) -> Self {
        Self {
            version: MANIFEST_VERSION,
            id,
            created_at: Utc::now(),
            event,
            message,
            repo_root,
            entries: Vec::new(),
        }
    }
}

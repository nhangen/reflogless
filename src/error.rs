use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not inside a git repository (searched up from {0})")]
    NotARepo(PathBuf),

    #[error("git command failed: {0}")]
    Git(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("ambiguous snapshot id {id}: {} matches", matches.len())]
    AmbiguousSnapshot { id: String, matches: Vec<String> },

    #[error("path not in snapshot {snap_id}: {}", missing.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    NotInSnapshot {
        snap_id: String,
        missing: Vec<PathBuf>,
    },

    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error("refusing to overwrite existing path {0} without --force")]
    Overwrite(PathBuf),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

// SPDX-License-Identifier: MIT
//! Storage backends (local filesystem, S3, etc.).

mod blob_reader;
mod local;

pub use blob_reader::{BlobReader, DecryptFn};
pub use local::LocalStorage;

use anyhow::Result;

/// Abstraction over backup storage locations.
pub trait Storage: Send + Sync {
    /// Read the full contents of a path relative to the backup root.
    fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// List entries (files/dirs) at a path relative to the backup root.
    fn list(&self, path: &str) -> Result<Vec<String>>;

    /// Check whether a path exists.
    #[allow(dead_code)]
    fn exists(&self, path: &str) -> Result<bool>;
}

// SPDX-License-Identifier: MIT
//! Local filesystem storage backend.

use super::Storage;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn full_path(&self, rel: &str) -> PathBuf {
        // Strip leading '/' to prevent PathBuf::join() from treating
        // the relative path as absolute (which would ignore the root).
        let rel = rel.strip_prefix('/').unwrap_or(rel);
        self.root.join(rel)
    }
}

impl Storage for LocalStorage {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let p = self.full_path(path);
        fs::read(&p).with_context(|| format!("failed to read {}", p.display()))
    }

    fn list(&self, path: &str) -> Result<Vec<String>> {
        let p = self.full_path(path);
        let mut entries = Vec::new();
        for entry in fs::read_dir(&p).with_context(|| format!("failed to list {}", p.display()))? {
            let entry = entry.context("failed to read dir entry")?;
            let name = entry.file_name().to_string_lossy().into_owned();
            entries.push(name);
        }
        Ok(entries)
    }

    fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.full_path(path).exists())
    }
}

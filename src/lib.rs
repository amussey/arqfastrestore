// SPDX-License-Identifier: MIT
//! arqfastrestore — Fast, parallel restore tool for Arq backups (Arq5 and Arq7).
//!
//! This library exposes the core modules for use by integration test binaries and
//! other internal tools. The primary entry point is the `arqfastrestore` binary.

pub mod crypto;
pub mod format;
pub mod restore;
pub mod storage;

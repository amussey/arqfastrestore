// SPDX-License-Identifier: MIT
//! Cryptography for Arq5 and Arq7 backups.
//!
//! Arq5: PBKDF2/HMAC-SHA1, 200,000 rounds, 3×32-byte master keys, AES-256-CBC.
//! Arq7: PBKDF2/HMAC-SHA256, 200,000 rounds, variable-length master keys, two-level AES-256-CBC.

mod arq5;
mod arq7;

#[allow(unused_imports)]
pub use arq5::{Arq5Keys, decrypt_arq5_object};
pub use arq7::{Arq7Keys, decrypt_arq7_object};

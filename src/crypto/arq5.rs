// SPDX-License-Identifier: MIT
//! Arq5 decryption.
#![allow(dead_code)]
//!
//! ## Key derivation (encryptionv2.dat)
//!
//! The file format is:
//! ```text
//! "ENCRYPTIONV2" (12 bytes ASCII header)
//! salt           (8 bytes for PBKDF2)
//! HMAC-SHA256    (32 bytes, over IV + ciphertext)
//! IV             (16 bytes for AES-256-CBC)
//! ciphertext     (80 bytes, PKCS7-padded encrypted master keys)
//! ```
//!
//! PBKDF2-HMAC-SHA1, 200,000 rounds, 8-byte salt → 64-byte derived key.
//! First 32 bytes = AES encryption key, last 32 bytes = HMAC verification key.
//!
//! The decrypted master keys are either:
//! - 64 bytes → 2 keys × 32 bytes (encryptionV2)
//! - 96 bytes → 3 keys × 32 bytes (encryptionV3 stored in v2 container)
//!
//! ## Encrypted object (ARQO) — two-layer encryption
//!
//! Format:
//! ```text
//! "ARQO"           (4 bytes magic)
//! HMAC-SHA256      (32 bytes, over master_iv + enc_session + ciphertext, using master_key[1])
//! master_iv        (16 bytes)
//! enc_session      (64 bytes, AES-256-CBC(master_key[0], master_iv, data_iv || session_key))
//! ciphertext       (variable, AES-256-CBC(session_key, data_iv, plaintext))
//! ```
//!
//! Decryption is two-layer:
//! 1. Outer: AES-256-CBC decrypt enc_session with master_key[0] + master_iv → data_iv(16) + session_key(32)
//! 2. Inner: AES-256-CBC decrypt ciphertext with session_key + data_iv → plaintext

use aes::Aes256;
use anyhow::{Context, Result, bail};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;
use sha2::Sha256;

const HEADER: &[u8] = b"ENCRYPTIONV2";
const ARQO_MAGIC: &[u8] = b"ARQO";
const PBKDF2_ROUNDS: u32 = 200_000;
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const HMAC_SIZE: usize = 32;
const SALT_SIZE: usize = 8;
/// enc_session = IV(16) + PKCS7-padded AES-CBC(data_iv(16) + session_key(32)) = 64 bytes
const ENC_SESSION_BLOB_SIZE: usize = 64;

/// Master keys derived from `encryptionv2.dat`.
///
/// - `keys[0]`: AES encryption key (32 bytes) — used for outer ARQO decryption
/// - `keys[1]`: HMAC key (32 bytes) — used for ARQO HMAC verification
/// - `keys[2]`: Optional third key (32 bytes, only in V3 format) — unused for now
#[derive(Debug, Clone)]
pub struct Arq5Keys {
    pub keys: Vec<[u8; KEY_SIZE]>,
}

impl Arq5Keys {
    /// Derive master keys from `encryptionv2.dat` content and the user's password.
    ///
    /// The file has a 12-byte "ENCRYPTIONV2" header, followed by:
    /// salt(8) + HMAC-SHA256(32) + IV(16) + ciphertext(80).
    pub fn from_dat(dat: &[u8], password: &str) -> Result<Self> {
        if !dat.starts_with(HEADER) {
            bail!(
                "missing ENCRYPTIONV2 header (got {:?})",
                &dat[..std::cmp::min(12, dat.len())]
            );
        }

        let body = &dat[HEADER.len()..];
        let min_body = SALT_SIZE + HMAC_SIZE + IV_SIZE + 16; // at least one AES block
        if body.len() < min_body {
            bail!(
                "encryptionv2.dat body too short: {} bytes (need >= {min_body})",
                body.len()
            );
        }

        let salt = &body[..SALT_SIZE];
        let stored_hmac = &body[SALT_SIZE..SALT_SIZE + HMAC_SIZE];
        let iv = &body[SALT_SIZE + HMAC_SIZE..SALT_SIZE + HMAC_SIZE + IV_SIZE];
        let ciphertext = &body[SALT_SIZE + HMAC_SIZE + IV_SIZE..];

        // Derive 64 bytes from password: first 32 = AES key, last 32 = HMAC key
        let mut derived = [0u8; 64];
        pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut derived)
            .context("PBKDF2 derivation failed")?;
        let aes_key = &derived[..32];
        let hmac_key = &derived[32..];

        // Verify HMAC-SHA256 over (IV + ciphertext)
        let hmac_data = &body[SALT_SIZE + HMAC_SIZE..]; // IV + ciphertext
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).context("HMAC key init failed")?;
        mac.update(hmac_data);
        mac.verify_slice(stored_hmac)
            .map_err(|_| anyhow::anyhow!("HMAC verification failed — wrong password?"))?;

        // Decrypt the master keys
        let mut buf = ciphertext.to_vec();
        let plaintext = cbc::Decryptor::<Aes256>::new_from_slices(aes_key, iv)
            .context("AES init failed for master keys")?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for master keys: {e:?}"))?;

        // Determine V2 (2 keys, 64 bytes) vs V3 (3 keys, 96 bytes)
        let num_keys = match plaintext.len() {
            64 => 2,
            96 => 3,
            n => bail!("unexpected master key plaintext length {n} (expected 64 or 96)"),
        };

        let mut keys = Vec::with_capacity(num_keys);
        for i in 0..num_keys {
            let offset = i * KEY_SIZE;
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&plaintext[offset..offset + KEY_SIZE]);
            keys.push(key);
        }

        Ok(Self { keys })
    }

    /// Convenience method to decrypt an ARQO-format encrypted object.
    pub fn decrypt_object(&self, data: &[u8]) -> Result<Vec<u8>> {
        decrypt_arq5_object(data, self)
    }
}

/// Decrypt an Arq5 ARQO-format encrypted object.
///
/// Two-layer encryption:
/// 1. Outer AES-256-CBC: decrypt enc_session with master_key[0] + master_iv
///    → data_iv(16) + session_key(32)
/// 2. Inner AES-256-CBC: decrypt ciphertext with session_key + data_iv
///    → plaintext
pub fn decrypt_arq5_object(data: &[u8], keys: &Arq5Keys) -> Result<Vec<u8>> {
    let min_len = ARQO_MAGIC.len() + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE;
    if data.len() < min_len {
        bail!(
            "encrypted object too short: {} bytes (need >= {min_len})",
            data.len()
        );
    }

    if &data[..4] != ARQO_MAGIC {
        bail!("missing ARQO magic (got {:?})", &data[..4]);
    }

    if keys.keys.len() < 2 {
        bail!("need at least 2 master keys, have {}", keys.keys.len());
    }

    let stored_hmac = &data[4..4 + HMAC_SIZE];
    let master_iv = &data[4 + HMAC_SIZE..4 + HMAC_SIZE + IV_SIZE];
    let enc_session =
        &data[4 + HMAC_SIZE + IV_SIZE..4 + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE];
    let ciphertext = &data[4 + HMAC_SIZE + IV_SIZE + ENC_SESSION_BLOB_SIZE..];

    // Verify HMAC-SHA256 of (master_iv + enc_session + ciphertext) using key[1]
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&keys.keys[1]).context("HMAC key[1] init failed")?;
    mac.update(master_iv);
    mac.update(enc_session);
    mac.update(ciphertext);
    mac.verify_slice(stored_hmac)
        .map_err(|_| anyhow::anyhow!("ARQO HMAC verification failed"))?;

    // Layer 1: Decrypt enc_session with master_key[0] + master_iv
    // → data_iv(16) + session_key(32)
    let mut session_buf = enc_session.to_vec();
    let session_plain = cbc::Decryptor::<Aes256>::new_from_slices(&keys.keys[0], master_iv)
        .context("AES init failed for session blob")?
        .decrypt_padded_mut::<Pkcs7>(&mut session_buf)
        .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for session blob: {e:?}"))?;

    if session_plain.len() < IV_SIZE + KEY_SIZE {
        bail!(
            "session blob plaintext too short: {} bytes (need {})",
            session_plain.len(),
            IV_SIZE + KEY_SIZE
        );
    }
    let data_iv = &session_plain[..IV_SIZE];
    let session_key = &session_plain[IV_SIZE..IV_SIZE + KEY_SIZE];

    // Layer 2: Decrypt ciphertext with session_key + data_iv
    let mut buf = ciphertext.to_vec();
    let plaintext = cbc::Decryptor::<Aes256>::new_from_slices(session_key, data_iv)
        .context("AES init failed for data")?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("PKCS7 unpad failed for data: {e:?}"))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_header_rejected() {
        assert!(Arq5Keys::from_dat(b"WRONG_HEADER", "password").is_err());
    }

    #[test]
    fn short_body_rejected() {
        // Valid header but truncated body
        let mut dat = HEADER.to_vec();
        dat.extend_from_slice(&[0u8; 10]);
        assert!(Arq5Keys::from_dat(&dat, "password").is_err());
    }

    #[test]
    fn arqo_magic_check() {
        let keys = Arq5Keys {
            keys: vec![[0u8; 32]; 2],
        };
        let bad = b"NOPE" as &[u8];
        assert!(decrypt_arq5_object(bad, &keys).is_err());
    }

    #[test]
    fn short_object_rejected() {
        let keys = Arq5Keys {
            keys: vec![[0u8; 32]; 2],
        };
        assert!(decrypt_arq5_object(&[0u8; 10], &keys).is_err());
    }

    #[test]
    fn non_arqo_rejected() {
        let keys = Arq5Keys {
            keys: vec![[0u8; 32]; 2],
        };
        // Right length but wrong magic
        assert!(decrypt_arq5_object(&[0u8; 200], &keys).is_err());
    }

    /// Integration test: derive keys from a real Arq5 encryptionv2.dat.
    /// Skipped unless ARQ5_TEST_PATH and ARQ5_TEST_PASSWORD env vars are set.
    #[test]
    fn real_encryptionv2_homebase() {
        let (path, password_owned) = match (
            std::env::var("ARQ5_TEST_PATH"),
            std::env::var("ARQ5_TEST_PASSWORD"),
        ) {
            (Ok(p), Ok(pw)) => (format!("{p}/encryptionv2.dat"), pw),
            _ => {
                eprintln!("SKIP: set ARQ5_TEST_PATH and ARQ5_TEST_PASSWORD to run");
                return;
            }
        };
        let dat = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("SKIP: {path} not available");
                return;
            }
        };
        let password = password_owned.as_str();

        let keys = Arq5Keys::from_dat(&dat, password)
            .expect("key derivation should succeed with correct password");

        // Should be V2 format (2 keys) — 148 bytes dat → 80 bytes ciphertext → 64 bytes plaintext
        assert_eq!(keys.keys.len(), 2, "expected 2 master keys for V2 format");

        // Keys should not be all-zeros (basic sanity)
        assert_ne!(keys.keys[0], [0u8; 32], "key[0] should not be all zeros");
        assert_ne!(keys.keys[1], [0u8; 32], "key[1] should not be all zeros");

        eprintln!(
            "✓ Derived {} master keys from encryptionv2.dat",
            keys.keys.len()
        );
        eprintln!("  key[0] prefix: {:02x?}", &keys.keys[0][..8]);
        eprintln!("  key[1] prefix: {:02x?}", &keys.keys[1][..8]);
    }

    /// Integration test: wrong password should fail HMAC verification.
    /// Skipped unless ARQ5_TEST_PATH env var is set.
    #[test]
    fn real_encryptionv2_wrong_password() {
        let path = match std::env::var("ARQ5_TEST_PATH") {
            Ok(p) => format!("{p}/encryptionv2.dat"),
            _ => {
                eprintln!("SKIP: set ARQ5_TEST_PATH to run");
                return;
            }
        };
        let dat = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("SKIP: {path} not available");
                return;
            }
        };

        let err =
            Arq5Keys::from_dat(&dat, "wrong-password").expect_err("wrong password should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("HMAC") || msg.contains("wrong password"),
            "expected HMAC failure, got: {msg}"
        );
    }

    /// Integration test: decrypt a real Arq5 bucket plist.
    /// Skipped unless ARQ5_TEST_PATH, ARQ5_TEST_PASSWORD, and ARQ5_TEST_BUCKET env vars are set.
    ///
    /// Arq5 encrypted files have a 9-byte "encrypted" prefix before the ARQO blob.
    #[test]
    fn real_decrypt_bucket_plist() {
        let (backup_path, password_owned, bucket_uuid) = match (
            std::env::var("ARQ5_TEST_PATH"),
            std::env::var("ARQ5_TEST_PASSWORD"),
            std::env::var("ARQ5_TEST_BUCKET"),
        ) {
            (Ok(p), Ok(pw), Ok(b)) => (p, pw, b),
            _ => {
                eprintln!(
                    "SKIP: set ARQ5_TEST_PATH, ARQ5_TEST_PASSWORD, ARQ5_TEST_BUCKET to run"
                );
                return;
            }
        };
        let key_path = format!("{backup_path}/encryptionv2.dat");
        let bucket_path = format!("{backup_path}/buckets/{bucket_uuid}");
        let password = password_owned.as_str();

        let key_dat = match std::fs::read(&key_path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("SKIP: {key_path} not available");
                return;
            }
        };
        let bucket_dat = std::fs::read(&bucket_path).expect("bucket plist should be readable");

        let keys = Arq5Keys::from_dat(&key_dat, password).expect("key derivation should succeed");

        // Arq5 encrypted files start with "encrypted" (9 bytes) before the ARQO blob
        assert!(
            bucket_dat.starts_with(b"encrypted"),
            "expected 'encrypted' prefix"
        );
        let arqo_data = &bucket_dat[9..]; // Skip "encrypted" prefix

        let plaintext =
            decrypt_arq5_object(arqo_data, &keys).expect("bucket plist decryption should succeed");

        // The decrypted data should be a binary plist
        eprintln!("✓ Decrypted bucket plist: {} bytes", plaintext.len());
        // Binary plists start with "bplist"
        if plaintext.starts_with(b"bplist") {
            eprintln!("  Format: binary plist ✓");
        } else if plaintext.starts_with(b"<?xml") || plaintext.starts_with(b"<plist") {
            eprintln!("  Format: XML plist ✓");
        } else {
            eprintln!(
                "  First bytes: {:02x?}",
                &plaintext[..std::cmp::min(20, plaintext.len())]
            );
        }

        assert!(!plaintext.is_empty(), "decrypted plist should not be empty");

        // Print the full plist for debugging
        if let Ok(s) = std::str::from_utf8(&plaintext) {
            eprintln!("  Content:\n{s}");
        }
    }
}

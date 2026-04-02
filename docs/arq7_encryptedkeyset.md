# Arq7 `encryptedkeyset.dat` — Format Reference

**Source:** Official Arq restore tool — `arqbackup/arq_restore` repository  
**Files:** `arq7restore/Arq7KeySet.m` (implementation), `arq7restore/Arq7KeySet.h` (interface), `arq7_data_format.html` (spec)  
**Confidence:** 100% — direct from official source code, not reverse engineering.

---

## Table of Contents

1. [Overview](#1-overview)
2. [File Structure](#2-file-structure)
3. [Visual Guide](#3-visual-guide)
4. [Field Specifications](#4-field-specifications)
5. [Key Derivation (PBKDF2)](#5-key-derivation-pbkdf2)
6. [HMAC Verification](#6-hmac-verification)
7. [AES-256-CBC Decryption](#7-aes-256-cbc-decryption)
8. [Decrypted Plaintext Format](#8-decrypted-plaintext-format)
9. [Official C Constants](#9-official-c-constants)
10. [Official Code Flow (Objective-C)](#10-official-code-flow-objective-c)
11. [Rust Implementation Guide](#11-rust-implementation-guide)
12. [Error Conditions](#12-error-conditions)
13. [Byte Offset Quick Reference](#13-byte-offset-quick-reference)

---

## 1. Overview

The `encryptedkeyset.dat` file contains the master encryption and HMAC keys for an Arq 7 backup set. It is encrypted with the user's backup encryption password using PBKDF2-SHA256 key derivation and AES-256-CBC encryption, protected by an HMAC-SHA256 integrity check.

**Decryption process (high-level):**
1. Validate header
2. Extract 8-byte salt → run PBKDF2-HMAC-SHA256 (200,000 iterations) → 64-byte derived key
3. Split derived key: bytes [0:32] = AES key, bytes [32:64] = HMAC key
4. Verify HMAC-SHA256 of (IV + ciphertext) against stored HMAC
5. AES-256-CBC decrypt ciphertext using IV
6. Remove PKCS7 padding
7. Parse plaintext to extract master encryption key, HMAC key, and blob ID salt

---

## 2. File Structure

### Layout Table

| Byte Range | Size     | Field         | Description                                         |
|------------|----------|---------------|-----------------------------------------------------|
| **0–24**   | 25 bytes | HEADER        | `ARQ_ENCRYPTED_MASTER_KEYS` (ASCII, **no newline**) |
| **25–32**  | 8 bytes  | SALT          | Random salt for PBKDF2                              |
| **33–64**  | 32 bytes | HMAC-SHA256   | HMAC of (IV + ciphertext), i.e. `file[65:]`         |
| **65–80**  | 16 bytes | IV            | AES-256-CBC initialization vector                  |
| **81+**    | variable | CIPHERTEXT    | AES-256-CBC encrypted plaintext (PKCS7 padded)      |

**Minimum file size:** 25 + 8 + 32 + 16 + 1 = **82 bytes**  
**Typical file size:** 209 bytes (with 104-byte ciphertext → 128-byte with padding)

### Byte Offset Formulas

```
HEADER_LEN  = 25
SALT_LEN    = 8
HMAC_LEN    = 32
IV_LEN      = 16

salt_start        = 0 + HEADER_LEN                         = 25
hmac_start        = salt_start + SALT_LEN                  = 33
iv_start          = hmac_start + HMAC_LEN                  = 65
ciphertext_start  = iv_start + IV_LEN                      = 81
ciphertext_len    = file_size - ciphertext_start

HMAC input:  file[65:]            (IV + ciphertext)
HMAC stored: file[33:65]
```

### Example Hex Breakdown (209-byte file)

```
Offset   Hex Bytes                                Field
──────────────────────────────────────────────────────────────
0–24     41 52 51 5F 45 4E 43 52 59 50 54 45 44   Header (25 bytes)
         5F 4D 41 53 54 45 52 5F 4B 45 59 53
25–32    XX XX XX XX XX XX XX XX                   Salt (8 bytes)
33–64    XX XX XX XX XX XX XX XX XX XX XX XX       HMAC-SHA256 (32 bytes)
         XX XX XX XX XX XX XX XX XX XX XX XX
         XX XX XX XX XX XX XX XX
65–80    XX XX XX XX XX XX XX XX XX XX XX XX       IV (16 bytes)
         XX XX XX XX
81–184   XX XX XX XX XX XX XX XX ...               Ciphertext (~104 bytes)
──────────────────────────────────────────────────────────────
Total: 185 body bytes + (no, header is counted): 25 + 8 + 32 + 16 + 128 = 209 bytes
```

---

## 3. Visual Guide

### File Structure Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    encryptedkeyset.dat (209 bytes, typical)             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  HEADER (25 bytes, no newline)                                          │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ 41 52 51 5F 45 4E 43 52 59 50 54 45 44 5F 4D 41 53 54 45 52   │     │
│  │ 5F 4B 45 59 53                                                 │     │
│  │ "ARQ_ENCRYPTED_MASTER_KEYS"          Offset 0–24              │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                               ↓                                         │
│  SALT (8 bytes)                                                         │
│  ┌──────────────────────────────┐                                       │
│  │ XX XX XX XX XX XX XX XX      │  Offset 25–32                         │
│  └──────────────────────────────┘                                       │
│                               ↓                                         │
│  HMAC-SHA256 (32 bytes)                                                 │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX                │     │
│  │ XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX                │     │
│  │ Offset 33–64                                                   │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                               ↓                                         │
│  IV (16 bytes)                                                          │
│  ┌──────────────────────────────────────────────────────┐               │
│  │ XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX      │               │
│  │ Offset 65–80                                         │               │
│  └──────────────────────────────────────────────────────┘               │
│                               ↓                                         │
│  CIPHERTEXT (variable, ~104–128 bytes in PKCS7 blocks)                  │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX ...            │     │
│  │ Offset 81–(end)                                                │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

```
     PASSWORD (UTF-8 bytes)
          │
          ├──────────────────────────────────────┐
          │                                      │
          │                             SALT (file[25:33], 8 bytes)
          │                                      │
          ↓                                      ↓
     ┌────────────────────────────────────────────────┐
     │           PBKDF2-HMAC-SHA256                   │
     │           (200,000 iterations → 64 bytes)      │
     └────────────────────────────────────────────────┘
                          │
                          ↓
                  64-byte derived key
                          │
              ┌───────────┴────────────┐
              │                        │
              ↓                        ↓
      AES-256 Key                HMAC-SHA256 Key
    (bytes 0–31)                (bytes 32–63)
              │                        │
              │                        ├──────────────────────┐
              │                        │                      │
              │                        │          ┌───────────────────────┐
              │                        │          │  VERIFY:              │
              │                        │          │  HMAC(key, file[65:]) │
              │                        │          │  == file[33:65]?      │
              │                        └─────────→│  ✓ continue           │
              │                                   │  ✗ wrong password     │
              │                                   └───────────────────────┘
              │
              ├──────────────────────────────────────────┐
              │                                          │
              ↓                                          ↓
      IV = file[65:81]                      Ciphertext = file[81:]
              │                                          │
              └─────────────────┬────────────────────────┘
                                ↓
              ┌─────────────────────────────────┐
              │       AES-256-CBC DECRYPT        │
              │       + PKCS7 unpad             │
              └─────────────────┬───────────────┘
                                ↓
              ┌─────────────────────────────────┐
              │  Plaintext: version, keys, salt │
              │  (parsed as big-endian)         │
              └─────────────────────────────────┘
```

### PBKDF2 Output Split

```
┌──────────────────────────────────────────────────────┐
│           64-byte derived key from PBKDF2            │
├──────────────────────────────────────────────────────┤
│  [0]                                           [31]  │
│  ┌──────────────────────────────────────────────┐    │
│  │        AES-256 Encryption Key (32 bytes)     │    │
│  └──────────────────────────────────────────────┘    │
│  [32]                                          [63]  │
│  ┌──────────────────────────────────────────────┐    │
│  │        HMAC-SHA256 Key (32 bytes)            │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

### HMAC Coverage Map

```
File bytes:
┌──────────────────────────────────────────────────────────────────────┐
│  Header  │ Salt  │  HMAC  │  IV      │  Ciphertext                  │
│  0–24    │ 25–32 │ 33–64  │ 65–80    │  81+                         │
└──────────────────────────────────────────────────────────────────────┘
                    ↑                                                    ↑
                    │◄─── NOT HMAC'd ────►│◄──────── HMAC'd ──────────►│

HMAC Input  = file[65:]     (IV + Ciphertext)
Stored HMAC = file[33:65]
```

---

## 4. Field Specifications

### Header (Bytes 0–24)

- **Length:** exactly 25 bytes
- **Value:** `ARQ_ENCRYPTED_MASTER_KEYS` (ASCII)
- **Hex:** `41 52 51 5F 45 4E 43 52 59 50 54 45 44 5F 4D 41 53 54 45 52 5F 4B 45 59 53`
- **No terminator, no newline** — binary data begins immediately at byte 25
- Validated with `strncmp()` — exact match required

### Salt (Bytes 25–32)

- **Length:** 8 bytes (not 32!)
- Random bytes used as PBKDF2 salt input
- Binary data (not text)

### HMAC-SHA256 (Bytes 33–64)

- **Length:** 32 bytes
- HMAC-SHA256 computed over `file[65:]` (IV + ciphertext)
- HMAC key is `derivedKey[32:64]` (second half of PBKDF2 output)
- Mismatch indicates wrong password

### IV (Bytes 65–80)

- **Length:** 16 bytes
- Initialization vector for AES-256-CBC decryption
- Randomly generated at encryption time

### Ciphertext (Bytes 81+)

- **Length:** variable; `file_size - 81`
- AES-256-CBC encrypted plaintext
- PKCS7 padded (block size 16); ciphertext length is always a multiple of 16
- Typically 104–128 bytes in a standard keyset file

---

## 5. Key Derivation (PBKDF2)

### Parameters

| Parameter         | Value                         |
|-------------------|-------------------------------|
| Algorithm         | PBKDF2-HMAC-SHA256            |
| Iterations        | **200,000**                   |
| Salt              | `file[25:33]` — 8 bytes       |
| Password encoding | UTF-8 bytes                   |
| Output length     | **64 bytes**                  |
| Key split         | [0:32] → AES key, [32:64] → HMAC key |

### Pseudocode

```
derived_key = PBKDF2_HMAC_SHA256(
    password  = password_as_UTF8_bytes,
    salt      = file[25:33],     // 8 bytes
    iterations = 200_000,
    output_len = 64
)

aes_key  = derived_key[0:32]    // First 32 bytes  → AES-256 encryption
hmac_key = derived_key[32:64]   // Second 32 bytes → HMAC-SHA256 verification
```

---

## 6. HMAC Verification

| Aspect        | Value                                              |
|---------------|----------------------------------------------------|
| Algorithm     | HMAC-SHA256                                        |
| Key           | `derived_key[32:64]` (32 bytes)                    |
| Input data    | `file[65:]` — IV + ciphertext                      |
| Stored value  | `file[33:65]` (32 bytes)                           |
| Verification  | `HMAC_SHA256(hmac_key, file[65:]) == file[33:65]`  |
| Failure       | Return error: "incorrect encryption password"      |

---

## 7. AES-256-CBC Decryption

| Parameter     | Value                                              |
|---------------|----------------------------------------------------|
| Algorithm     | AES (256-bit key)                                  |
| Mode          | CBC (Cipher Block Chaining)                        |
| Padding       | PKCS7 (remove after decryption)                    |
| Key           | `derived_key[0:32]` (32 bytes)                     |
| IV            | `file[65:81]` (16 bytes)                           |
| Ciphertext    | `file[81:]`                                        |

> **Note:** CommonCrypto uses `kCCAlgorithmAES128` as the algorithm identifier, but the
> key size determines AES-128 vs AES-256. Passing a 32-byte (`kCCKeySizeAES256`) key
> results in AES-256 despite the constant name.

---

## 8. Decrypted Plaintext Format

After decryption and PKCS7 padding removal, the plaintext is a sequence of big-endian
integers and variable-length byte fields:

```
Offset      Size     Type       Field
──────────────────────────────────────────────────────────
0           4        uint32     version          (big-endian; typically 3)
4           8        uint64     encryptionKeyLen (big-endian)
12          N        bytes      encryptionKey    (N = encryptionKeyLen; must be 32)
12+N        8        uint64     hmacKeyLen       (big-endian)
20+N        M        bytes      hmacKey          (M = hmacKeyLen; must be 32 or 0)
20+N+M      8        uint64     blobIdSaltLen    (big-endian)
28+N+M      K        bytes      blobIdSalt       (K = blobIdSaltLen; typically 32)
```

All multi-byte integers are **big-endian** (network byte order).

### Typical Values

- `version` = 3
- `encryptionKeyLen` = 32 → `encryptionKey` = 32-byte AES-256 master key
- `hmacKeyLen` = 32 → `hmacKey` = 32-byte HMAC-SHA256 master key  
  (or `hmacKeyLen` = 0 → `hmacKey` absent; tolerated for backward compatibility)
- `blobIdSaltLen` = 32 → `blobIdSalt` = 32-byte content-addressable blob salt

### Validation Rules

- `encryptionKey` length **must be exactly 32 bytes**
- `hmacKey` length must be **32 or 0** (other values are an error)

### Plaintext Diagram (typical 96-byte plaintext)

```
┌──────────────────────────────────────────────────────────┐
│          Plaintext (~80–100 bytes after unpadding)       │
├──────────────────────────────────────────────────────────┤
│  [0–3]   version (uint32, big-endian)                    │
│          Example: 00 00 00 03                            │
│                                                          │
│  [4–11]  encKeyLen (uint64, big-endian)                  │
│          Example: 00 00 00 00 00 00 00 20  (= 32)        │
│                                                          │
│  [12–43] encryptionKey (32 bytes)                        │
│          Master AES-256 encryption key                   │
│                                                          │
│  [44–51] hmacKeyLen (uint64, big-endian)                 │
│          Example: 00 00 00 00 00 00 00 20  (= 32)        │
│                   00 00 00 00 00 00 00 00  (= 0, ok)     │
│                                                          │
│  [52–83] hmacKey (32 bytes, or absent if len == 0)       │
│          Master HMAC-SHA256 key                          │
│                                                          │
│  [84–91] blobIdSaltLen (uint64, big-endian)              │
│          Example: 00 00 00 00 00 00 00 20  (= 32)        │
│                                                          │
│  [92–123] blobIdSalt (32 bytes)                          │
│          Content-addressable blob identifier salt        │
└──────────────────────────────────────────────────────────┘
```

---

## 9. Official C Constants

From `arq7restore/Arq7KeySet.m`:

```c
#define ARQ7_KEYSET_HEADER          "ARQ_ENCRYPTED_MASTER_KEYS"
#define ARQ7_KEYSET_HEADER_LEN      (25)
#define ARQ7_KEYSET_SALT_LEN        (8)
#define ARQ7_KEYSET_IV_LEN          (16)
#define ARQ7_KEY_DERIVATION_ROUNDS  (200000)
#define ARQ7_DERIVED_KEY_LEN        (64)      // 32-byte AES key + 32-byte HMAC key
#define ARQ7_BUFFERSIZE             (65536)
#define CC_SHA256_DIGEST_LENGTH     (32)
#define kCCKeySizeAES256            (32)
```

---

## 10. Official Code Flow (Objective-C)

### Step 1 — Header Validation

```objc
if (strncmp((const char *)bytes, ARQ7_KEYSET_HEADER, ARQ7_KEYSET_HEADER_LEN) != 0) {
    SETNSERROR(@"encryptedkeyset.dat has invalid header");
    return nil;
}
```

### Step 2 — Extract Salt & Derive Key

```objc
const unsigned char *saltBytes = bytes + ARQ7_KEYSET_HEADER_LEN;  // bytes + 25

NSData *passwordData = [thePassword dataUsingEncoding:NSUTF8StringEncoding];
unsigned char derivedKey[ARQ7_DERIVED_KEY_LEN];

CCKeyDerivationPBKDF(
    kCCPBKDF2,
    (const char *)[passwordData bytes],
    [passwordData length],
    saltBytes,
    ARQ7_KEYSET_SALT_LEN,          // 8
    kCCPRFHmacAlgSHA256,
    ARQ7_KEY_DERIVATION_ROUNDS,    // 200000
    derivedKey,
    ARQ7_DERIVED_KEY_LEN           // 64
);

const unsigned char *aesKey  = derivedKey;                   // [0:32]
const unsigned char *hmacKey = derivedKey + kCCKeySizeAES256; // [32:64]
```

### Step 3 — Verify HMAC

```objc
// HMAC covers everything from the IV onwards (bytes 65+)
const unsigned char *hmacStart = bytes
    + ARQ7_KEYSET_HEADER_LEN        // + 25
    + ARQ7_KEYSET_SALT_LEN          // + 8
    + CC_SHA256_DIGEST_LENGTH;      // + 32  → = bytes + 65

NSUInteger hmacDataLen = dataLen
    - (ARQ7_KEYSET_HEADER_LEN + ARQ7_KEYSET_SALT_LEN + CC_SHA256_DIGEST_LENGTH);
    // = dataLen - 65

unsigned char calculatedHMAC[CC_SHA256_DIGEST_LENGTH];
CCHmac(
    kCCHmacAlgSHA256,
    hmacKey, kCCKeySizeAES256,      // 32-byte HMAC key
    hmacStart, hmacDataLen,
    calculatedHMAC
);

const unsigned char *storedHMAC = bytes
    + ARQ7_KEYSET_HEADER_LEN        // + 25
    + ARQ7_KEYSET_SALT_LEN;         // + 8  → = bytes + 33

if (memcmp(calculatedHMAC, storedHMAC, CC_SHA256_DIGEST_LENGTH) != 0) {
    SETNSERROR([self errorDomain], ERROR_INVALID_PASSWORD,
               @"incorrect encryption password for encryptedkeyset.dat");
    return nil;
}
```

### Step 4 — Extract IV & Decrypt

```objc
const unsigned char *iv = bytes
    + ARQ7_KEYSET_HEADER_LEN        // + 25
    + ARQ7_KEYSET_SALT_LEN          // + 8
    + CC_SHA256_DIGEST_LENGTH;      // + 32  → = bytes + 65

const unsigned char *ciphertext = iv + ARQ7_KEYSET_IV_LEN;   // bytes + 81

NSUInteger ciphertextLen = dataLen
    - (ARQ7_KEYSET_HEADER_LEN + ARQ7_KEYSET_SALT_LEN
       + CC_SHA256_DIGEST_LENGTH + ARQ7_KEYSET_IV_LEN);
    // = dataLen - 81

NSMutableData *plaintext = [NSMutableData dataWithLength:ARQ7_BUFFERSIZE];
size_t plaintextActualLen = 0;

CCCryptorStatus status = CCCrypt(
    kCCDecrypt,
    kCCAlgorithmAES128,       // Despite name: 256-bit key = AES-256
    kCCOptionPKCS7Padding,
    aesKey, kCCKeySizeAES256, // 32-byte key
    iv,
    ciphertext, ciphertextLen,
    [plaintext mutableBytes], [plaintext length],
    &plaintextActualLen
);
```

### Step 5 — Parse Decrypted Plaintext

```objc
// Format: uint32(version) + DataIO(encryptionKey) + DataIO(hmacKey) + DataIO(blobIdSalt)
// where DataIO = uint64(length) + bytes (both big-endian)

DataInputStream *dis = [[DataInputStream alloc] initWithData:plaintext];
BufferedInputStream *bis = [[BufferedInputStream alloc] initWithUnderlyingStream:dis];

uint32_t encVersion = 0;
[IntegerIO readUInt32:&encVersion from:bis error:error];

uint64_t encKeyLen = 0;
[IntegerIO readUInt64:&encKeyLen from:bis error:error];
NSData *encKeyBytes = [bis readExactly:(NSUInteger)encKeyLen error:error];
_encryptionKey = encKeyBytes;

uint64_t hmacKeyLen = 0;
[IntegerIO readUInt64:&hmacKeyLen from:bis error:error];
NSData *hmacKeyBytes = [bis readExactly:(NSUInteger)hmacKeyLen error:error];
_hmacKey = hmacKeyBytes;

// Key size validation
if ([_encryptionKey length] != kCCKeySizeAES256) {
    SETNSERROR(@"unexpected encryption key length: %lu (expected 32)",
               [_encryptionKey length]);
    return nil;
}
if ([_hmacKey length] != 0 && [_hmacKey length] != kCCKeySizeAES256) {
    SETNSERROR(@"unexpected HMAC key length: %lu", [_hmacKey length]);
    return nil;
}
```

---

## 11. Rust Implementation Guide

### Required Crates

```toml
[dependencies]
pbkdf2 = "0.12"
hmac   = "0.12"
sha2   = "0.10"
aes    = "0.8"
cbc    = { version = "0.1", features = ["alloc"] }
```

### Implementation Pattern

```rust
use pbkdf2::pbkdf2_hmac_sha256;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use aes::Aes256;
use cbc::Decryptor;
use anyhow::{bail, Context, Result};

pub fn decrypt_keyset(file: &[u8], password: &str) -> Result<KeySet> {
    // 1. Validate minimum length
    if file.len() < 82 {
        bail!("encryptedkeyset.dat is too short ({} bytes)", file.len());
    }

    // 2. Validate header
    if &file[0..25] != b"ARQ_ENCRYPTED_MASTER_KEYS" {
        bail!("encryptedkeyset.dat has invalid header");
    }

    // 3. Extract salt and derive key
    let salt = &file[25..33];                         // 8 bytes
    let password_bytes = password.as_bytes();         // UTF-8
    let mut derived_key = [0u8; 64];
    pbkdf2_hmac_sha256(password_bytes, salt, 200_000, &mut derived_key);

    let aes_key  = &derived_key[0..32];               // first 32 bytes
    let hmac_key = &derived_key[32..64];              // second 32 bytes

    // 4. Verify HMAC-SHA256 over IV + ciphertext (file[65:])
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
        .context("invalid HMAC key length")?;
    mac.update(&file[65..]);
    mac.verify_slice(&file[33..65])
        .map_err(|_| anyhow::anyhow!("incorrect encryption password for encryptedkeyset.dat"))?;

    // 5. AES-256-CBC decrypt
    let iv         = &file[65..81];
    let ciphertext = &file[81..];

    let cipher = Decryptor::<Aes256>::new(aes_key.into(), iv.into());
    let plaintext = cipher
        .decrypt_vec(ciphertext)
        .context("failed to decrypt encryptedkeyset.dat")?;

    // 6. Parse plaintext (big-endian)
    parse_plaintext(&plaintext)
}

fn parse_plaintext(data: &[u8]) -> Result<KeySet> {
    let mut pos = 0;

    let version = u32::from_be_bytes(data[pos..pos+4].try_into()?);
    pos += 4;

    let enc_key_len = u64::from_be_bytes(data[pos..pos+8].try_into()?) as usize;
    pos += 8;
    let encryption_key = data[pos..pos+enc_key_len].to_vec();
    pos += enc_key_len;

    if encryption_key.len() != 32 {
        bail!("unexpected encryption key length: {} (expected 32)", encryption_key.len());
    }

    let hmac_key_len = u64::from_be_bytes(data[pos..pos+8].try_into()?) as usize;
    pos += 8;
    let hmac_key = data[pos..pos+hmac_key_len].to_vec();
    pos += hmac_key_len;

    if hmac_key.len() != 0 && hmac_key.len() != 32 {
        bail!("unexpected HMAC key length: {}", hmac_key.len());
    }

    let blob_salt_len = u64::from_be_bytes(data[pos..pos+8].try_into()?) as usize;
    pos += 8;
    let blob_id_salt = data[pos..pos+blob_salt_len].to_vec();

    Ok(KeySet { version, encryption_key, hmac_key, blob_id_salt })
}
```

### Implementation Checklist

- [ ] Add crates: `pbkdf2`, `hmac`, `sha2`, `aes`, `cbc`
- [ ] Read `encryptedkeyset.dat` into byte slice
- [ ] Validate `file.len() >= 82`
- [ ] Validate `file[0..25] == b"ARQ_ENCRYPTED_MASTER_KEYS"`
- [ ] Extract `salt = file[25..33]`
- [ ] Run `pbkdf2_hmac_sha256(password_utf8, salt, 200_000, &mut derived_key)` → 64 bytes
- [ ] Split: `aes_key = derived_key[0..32]`, `hmac_key = derived_key[32..64]`
- [ ] Verify `HMAC_SHA256(hmac_key, file[65..]) == file[33..65]`
- [ ] AES-256-CBC decrypt `file[81..]` with key `aes_key` and IV `file[65..81]`
- [ ] Remove PKCS7 padding (handled by `cbc::Decryptor::decrypt_vec`)
- [ ] Parse plaintext: `u32` version, `u64` lengths, key bytes (all big-endian)
- [ ] Validate: `encryption_key.len() == 32`, `hmac_key.len() == 0 || 32`

---

## 12. Error Conditions

| Condition                              | Error Message                                              |
|----------------------------------------|------------------------------------------------------------|
| `file.len() < 82`                      | "encryptedkeyset.dat is too short"                         |
| `file[0..25] != b"ARQ_ENCRYPTED_MASTER_KEYS"` | "encryptedkeyset.dat has invalid header"          |
| HMAC mismatch                          | "incorrect encryption password for encryptedkeyset.dat"    |
| AES decryption failure                 | "failed to decrypt encryptedkeyset.dat"                    |
| `encryption_key.len() != 32`           | "unexpected encryption key length (expected 32)"           |
| `hmac_key.len() != 0 && != 32`         | "unexpected HMAC key length"                               |

---

## 13. Byte Offset Quick Reference

| Component  | Start | End (inclusive) | Length   | Notes                       |
|------------|-------|-----------------|----------|-----------------------------|
| Header     | 0     | 24              | 25 bytes | `ARQ_ENCRYPTED_MASTER_KEYS` |
| Salt       | 25    | 32              | 8 bytes  | PBKDF2 salt (not 32!)       |
| HMAC       | 33    | 64              | 32 bytes | Covers `file[65:]`          |
| IV         | 65    | 80              | 16 bytes | AES-256-CBC IV              |
| Ciphertext | 81    | end             | variable | AES-256-CBC + PKCS7         |

### Verified Facts

- ✅ **NO newline** after header — header is exactly 25 bytes
- ✅ **Salt is 8 bytes** — not 16, not 32
- ✅ **HMAC covers IV+ciphertext** — `file[65:]`, not `file[25:]`
- ✅ **HMAC key is second 32 bytes** of derived key `[32:64]`
- ✅ **AES key is first 32 bytes** of derived key `[0:32]`
- ✅ **200,000 PBKDF2 iterations** — confirmed in official source
- ✅ **AES-256-CBC with PKCS7** padding
- ✅ **Big-endian integers** in decrypted plaintext (network byte order)

---

**Source:** `arqbackup/arq_restore` — https://github.com/arqbackup/arq_restore  
**Reference files:** `arq7restore/Arq7KeySet.m`, `arq7restore/Arq7KeySet.h`, `arq7_data_format.html`

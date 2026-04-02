// SPDX-License-Identifier: MIT
//! Big-endian binary primitives for Arq on-disk formats.
//!
//! Arq string encoding: 1-byte null flag (0x00 = non-null, 0x01 = null) +
//!   8-byte big-endian length + UTF-8 bytes.

use anyhow::{Context, Result, bail};

/// Cursor-based binary reader over a byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.data.len() {
            bail!(
                "read_bytes({n}): only {} bytes remain at offset {}",
                self.remaining(),
                self.pos
            );
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read exactly `n` bytes as owned Vec.
    #[allow(dead_code)]
    pub fn read_bytes_owned(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.read_bytes(n)?.to_vec())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.read_bytes(1)?;
        Ok(b[0])
    }

    #[allow(dead_code)]
    pub fn read_u16_be(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn read_u64_be(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn read_i32_be(&mut self) -> Result<i32> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn read_i64_be(&mut self) -> Result<i64> {
        let b = self.read_bytes(8)?;
        Ok(i64::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    /// Arq string: 1-byte isNotNull flag + (if not null) 8-byte BE length + UTF-8 data.
    /// The flag byte is 0x01 = string present, 0x00 = null.
    pub fn read_string(&mut self) -> Result<Option<String>> {
        let is_not_null = self.read_u8()?;
        if is_not_null == 0 {
            return Ok(None);
        }
        let len = self.read_u64_be()? as usize;
        let bytes = self.read_bytes(len)?;
        let s = std::str::from_utf8(bytes)
            .context("Arq string is not valid UTF-8")?
            .to_owned();
        Ok(Some(s))
    }

    /// Like `read_string` but fails if null.
    pub fn read_string_required(&mut self) -> Result<String> {
        self.read_string()?.context("unexpected null Arq string")
    }

    /// Read a 20-byte SHA1 digest, returned as hex string.
    #[allow(dead_code)]
    pub fn read_sha1_hex(&mut self) -> Result<String> {
        let b = self.read_bytes(20)?;
        Ok(hex::encode(b))
    }

    /// Peek at the next `n` bytes without advancing the cursor.
    #[allow(dead_code)]
    pub fn peek_bytes(&self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.data.len() {
            bail!(
                "peek_bytes({n}): only {} bytes remain at offset {}",
                self.remaining(),
                self.pos
            );
        }
        Ok(&self.data[self.pos..end])
    }

    /// Reset the cursor to a previously saved position.
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Skip `n` bytes.
    #[allow(dead_code)]
    pub fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            bail!(
                "skip({n}): only {} bytes remain at offset {}",
                self.remaining(),
                self.pos
            );
        }
        self.pos += n;
        Ok(())
    }

    /// Read a raw data blob: `[u64 BE: length][bytes]`.
    #[allow(dead_code)]
    pub fn read_data(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u64_be()? as usize;
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Read an Arq date: `[bool: is_not_null]` + if true `[u64 BE: ms since epoch]`.
    #[allow(dead_code)]
    pub fn read_date(&mut self) -> Result<Option<u64>> {
        let is_not_null = self.read_bool()?;
        if is_not_null {
            Ok(Some(self.read_u64_be()?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_primitives() {
        let _data = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        // null_flag=0, len=5 (as u8+u64 needs more bytes — let's test simpler)
        let mut r = Reader::new(&[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(r.read_u32_be().unwrap(), 0x00010203);
        assert!(r.is_empty());
    }

    #[test]
    fn read_string_null() {
        // isNotNull=0x00 means null — only 1 byte consumed, no length field
        let data = vec![0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_string().unwrap(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn read_string_value() {
        let s = "hello";
        let mut data = vec![0x01]; // isNotNull=0x01 means string present
        data.extend_from_slice(&(s.len() as u64).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
        let mut r = Reader::new(&data);
        assert_eq!(r.read_string().unwrap(), Some("hello".to_owned()));
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::length::encode_length;
use crate::tag::{BOOLEAN, ENUMERATED, INTEGER, OCTET_STRING, Tag};

/// BER encoder that writes into an owned byte buffer.
pub struct BerWriter {
    buf: Vec<u8>,
}

impl BerWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Reset the buffer without deallocating.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Write a constructed element. The closure fills in the content;
    /// the length is back-patched after the closure returns.
    pub fn write_sequence<F>(&mut self, tag: Tag, f: F) -> &mut Self
    where
        F: FnOnce(&mut BerWriter),
    {
        let tag_bytes = tag.with_constructed(true).encode();
        self.buf.extend_from_slice(&tag_bytes);

        let mut inner = BerWriter::new();
        f(&mut inner);
        let content = inner.into_bytes();

        let len_bytes = encode_length(content.len());
        self.buf.extend_from_slice(&len_bytes);
        self.buf.extend_from_slice(&content);
        self
    }

    pub fn write_integer(&mut self, value: i64) -> &mut Self {
        let tag_bytes = Tag::universal(INTEGER).encode();
        self.buf.extend_from_slice(&tag_bytes);

        let content = encode_signed_integer(value);
        let len_bytes = encode_length(content.len());
        self.buf.extend_from_slice(&len_bytes);
        self.buf.extend_from_slice(&content);
        self
    }

    pub fn write_octet_string(&mut self, tag: Tag, value: &[u8]) -> &mut Self {
        let tag_bytes = tag.with_constructed(false).encode();
        self.buf.extend_from_slice(&tag_bytes);

        let len_bytes = encode_length(value.len());
        self.buf.extend_from_slice(&len_bytes);
        self.buf.extend_from_slice(value);
        self
    }

    pub fn write_boolean(&mut self, value: bool) -> &mut Self {
        let tag_bytes = Tag::universal(BOOLEAN).encode();
        self.buf.extend_from_slice(&tag_bytes);
        self.buf.push(1); // length = 1
        self.buf.push(if value { 0xFF } else { 0x00 });
        self
    }

    pub fn write_enumerated(&mut self, value: i64) -> &mut Self {
        let tag_bytes = Tag::universal(ENUMERATED).encode();
        self.buf.extend_from_slice(&tag_bytes);

        let content = encode_signed_integer(value);
        let len_bytes = encode_length(content.len());
        self.buf.extend_from_slice(&len_bytes);
        self.buf.extend_from_slice(&content);
        self
    }

    pub fn write_null(&mut self) -> &mut Self {
        self.buf.push(0x05); // NULL tag
        self.buf.push(0x00); // length 0
        self
    }

    /// Write raw pre-encoded bytes.
    pub fn write_raw(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Convenience: write a UTF-8 string as an OCTET STRING.
    pub fn write_string(&mut self, tag: Tag, value: &str) -> &mut Self {
        self.write_octet_string(tag, value.as_bytes())
    }

    /// Convenience: write with universal OCTET_STRING tag.
    pub fn write_bytes(&mut self, value: &[u8]) -> &mut Self {
        self.write_octet_string(Tag::universal(OCTET_STRING), value)
    }
}

impl Default for BerWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode an i64 as minimal BER integer bytes (without tag/length).
pub fn encode_i64_bytes(value: i64) -> Vec<u8> {
    encode_signed_integer(value)
}

fn encode_signed_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }

    let bytes = value.to_be_bytes();
    // Find the first significant byte, preserving the sign.
    let mut start = 0;
    if value > 0 {
        while start < 7 && bytes[start] == 0x00 {
            start += 1;
        }
        // If the high bit is set, prepend a 0x00 to keep it positive.
        if bytes[start] & 0x80 != 0 {
            start -= 1;
        }
    } else {
        while start < 7 && bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }
    bytes[start..].to_vec()
}

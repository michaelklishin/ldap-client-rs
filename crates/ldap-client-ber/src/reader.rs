// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::BerError;
use crate::length::decode_length;
use crate::tag::{BOOLEAN, Class, ENUMERATED, INTEGER, OCTET_STRING, Tag};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trailing {
    Reject,
    Allow,
}

/// Zero-copy BER decoder over a byte slice.
pub struct BerReader<'a> {
    input: &'a [u8],
    depth: u16,
    max_depth: u16,
    max_element_size: u32,
}

impl<'a> BerReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            depth: 0,
            max_depth: 32,
            max_element_size: 10 * 1024 * 1024,
        }
    }

    pub fn with_max_depth(mut self, max: u16) -> Self {
        self.max_depth = max;
        self
    }

    pub fn with_max_element_size(mut self, max: u32) -> Self {
        self.max_element_size = max;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.input
    }

    /// Peek at the tag of the next element without consuming it.
    pub fn peek_tag(&self) -> Result<Tag, BerError> {
        if self.input.is_empty() {
            return Err(BerError::Truncated { need: 1, have: 0 });
        }
        let (tag, _) = parse_tag(self.input)?;
        Ok(tag)
    }

    /// Read the next TLV element, returning `(tag, value_bytes)`.
    pub fn read_element(&mut self) -> Result<(Tag, &'a [u8]), BerError> {
        let (tag, tag_len) = parse_tag(self.input)?;

        let rest = &self.input[tag_len..];
        let (len_size, value_len) = decode_length(rest)?.ok_or(BerError::Truncated {
            need: 1,
            have: rest.len(),
        })?;

        if value_len as u64 > self.max_element_size as u64 {
            return Err(BerError::ElementTooLarge {
                size: value_len as u64,
                max: self.max_element_size,
            });
        }

        let header_len = tag_len + len_size;
        let total = header_len + value_len;
        if self.input.len() < total {
            return Err(BerError::Truncated {
                need: total,
                have: self.input.len(),
            });
        }

        let value = &self.input[header_len..total];
        self.input = &self.input[total..];
        Ok((tag, value))
    }

    /// Read a constructed element (SEQUENCE, SET, or context-tagged),
    /// passing a sub-reader scoped to its contents.
    pub fn read_sequence<F, T>(&mut self, expected_tag: Tag, f: F) -> Result<T, BerError>
    where
        F: FnOnce(&mut BerReader<'a>) -> Result<T, BerError>,
    {
        self.enter(expected_tag, Trailing::Reject, f)
    }

    /// Like `read_sequence` but allows trailing data in the constructed element.
    pub fn read_sequence_lax<F, T>(&mut self, expected_tag: Tag, f: F) -> Result<T, BerError>
    where
        F: FnOnce(&mut BerReader<'a>) -> Result<T, BerError>,
    {
        self.enter(expected_tag, Trailing::Allow, f)
    }

    fn enter<F, T>(&mut self, expected_tag: Tag, trailing: Trailing, f: F) -> Result<T, BerError>
    where
        F: FnOnce(&mut BerReader<'a>) -> Result<T, BerError>,
    {
        let (tag, value) = self.read_element()?;
        if tag != expected_tag {
            return Err(BerError::UnexpectedTag {
                expected: expected_tag,
                actual: tag,
            });
        }

        if self.depth >= self.max_depth {
            return Err(BerError::RecursionLimit {
                max: self.max_depth,
            });
        }

        let mut sub = BerReader {
            input: value,
            depth: self.depth + 1,
            max_depth: self.max_depth,
            max_element_size: self.max_element_size,
        };
        let result = f(&mut sub)?;
        if trailing == Trailing::Reject {
            sub.finish()?;
        }
        Ok(result)
    }

    fn read_primitive(&mut self, expected: Tag) -> Result<&'a [u8], BerError> {
        let (tag, value) = self.read_element()?;
        if tag != expected {
            return Err(BerError::UnexpectedTag {
                expected,
                actual: tag,
            });
        }
        Ok(value)
    }

    pub fn read_integer(&mut self) -> Result<i64, BerError> {
        decode_integer(self.read_primitive(Tag::universal(INTEGER))?)
    }

    pub fn read_octet_string(&mut self) -> Result<&'a [u8], BerError> {
        let expected = Tag::universal(OCTET_STRING);
        match self.peek_tag()? {
            tag if tag == expected.with_constructed(true) => Err(BerError::ConstructedPrimitive),
            _ => self.read_primitive(expected),
        }
    }

    pub fn read_boolean(&mut self) -> Result<bool, BerError> {
        match self.read_primitive(Tag::universal(BOOLEAN))? {
            [byte] => Ok(*byte != 0),
            _ => Err(BerError::InvalidBoolean),
        }
    }

    pub fn read_enumerated(&mut self) -> Result<i64, BerError> {
        decode_integer(self.read_primitive(Tag::universal(ENUMERATED))?)
    }

    /// Read an element with any tag, returning its raw bytes.
    pub fn read_tagged_value(&mut self) -> Result<(Tag, &'a [u8]), BerError> {
        self.read_element()
    }

    pub fn read_implicit(&mut self, tag: Tag) -> Result<&'a [u8], BerError> {
        self.read_primitive(tag)
    }

    pub fn read_tagged_implicit_octet_string(
        &mut self,
        expected_number: u32,
    ) -> Result<&'a [u8], BerError> {
        self.read_implicit(Tag::context(expected_number))
    }

    pub fn read_each<T, F>(&mut self, mut f: F) -> Result<Vec<T>, BerError>
    where
        F: FnMut(&mut BerReader<'a>) -> Result<T, BerError>,
    {
        let mut items = Vec::new();
        while !self.is_empty() {
            items.push(f(self)?);
        }
        Ok(items)
    }

    /// Whether the next element has exactly this tag. False on empty or
    /// malformed input; the read that follows reports the error.
    pub fn peek_is(&self, tag: Tag) -> bool {
        self.peek_tag().is_ok_and(|t| t == tag)
    }

    pub fn finish(&self) -> Result<(), BerError> {
        match self.input.len() {
            0 => Ok(()),
            remaining => Err(BerError::TrailingData { remaining }),
        }
    }
}

fn parse_tag(input: &[u8]) -> Result<(Tag, usize), BerError> {
    if input.is_empty() {
        return Err(BerError::Truncated { need: 1, have: 0 });
    }

    let first = input[0];
    let class = Class::from_byte(first);
    let constructed = (first & 0x20) != 0;
    let tag_bits = first & 0x1F;

    if tag_bits < 0x1F {
        return Ok((
            Tag {
                class,
                constructed,
                number: tag_bits as u32,
            },
            1,
        ));
    }

    // High-tag-number form (at most 5 continuation bytes for u32).
    let mut number: u32 = 0;
    let mut i = 1;
    loop {
        if i >= input.len() {
            return Err(BerError::Truncated {
                need: i + 1,
                have: input.len(),
            });
        }
        if i > 5 {
            return Err(BerError::TagOverflow);
        }
        let b = input[i];
        number = number
            .checked_shl(7)
            .and_then(|n| n.checked_add((b & 0x7F) as u32))
            .ok_or(BerError::TagOverflow)?;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }

    Ok((
        Tag {
            class,
            constructed,
            number,
        },
        i,
    ))
}

pub fn decode_i64_bytes(bytes: &[u8]) -> Result<i64, BerError> {
    decode_integer(bytes)
}

fn decode_integer(bytes: &[u8]) -> Result<i64, BerError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(BerError::InvalidInteger);
    }

    let negative = bytes[0] & 0x80 != 0;
    let mut result: i64 = if negative { -1 } else { 0 };

    for &b in bytes {
        result = (result << 8) | b as i64;
    }
    Ok(result)
}

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Character-level rules shared by the DN, filter and URL parsers.

use std::borrow::Cow;
use std::fmt::Write;

use ldap_client_ber::BerError;

pub(crate) fn to_utf8(bytes: &[u8]) -> Result<String, BerError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| BerError::InvalidUtf8)
}

pub(crate) fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let high = char::from(high).to_digit(16)?;
    let low = char::from(low).to_digit(16)?;
    Some((high << 4 | low) as u8)
}

pub(crate) fn hex_pair_at(bytes: &[u8], at: usize) -> Option<u8> {
    match bytes.get(at..at + 2)? {
        [high, low] => hex_pair(*high, *low),
        _ => None,
    }
}

const fn is_type_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')
}

const fn is_description_byte(b: u8) -> bool {
    is_type_byte(b) || b == b';'
}

pub(crate) fn is_attribute_type(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_type_byte)
}

pub(crate) fn is_attribute_description(s: &str) -> bool {
    let mut parts = s.split(';');
    parts.next().is_some_and(is_attribute_type) && parts.all(is_attribute_type)
}

fn escape_outside(s: &str, valid: bool, allowed: fn(u8) -> bool) -> Cow<'_, str> {
    if valid {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if allowed(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\{b:02x}");
        }
    }
    Cow::Owned(out)
}

/// An attribute type that fails `is_attribute_type` is written with every
/// byte outside its character set as `\XX`, so that the text cannot be read
/// back as a valid one.
pub(crate) fn escape_attribute_type(s: &str) -> Cow<'_, str> {
    escape_outside(s, is_attribute_type(s), is_type_byte)
}

pub(crate) fn escape_attribute_description(s: &str) -> Cow<'_, str> {
    escape_outside(s, is_attribute_description(s), is_description_byte)
}

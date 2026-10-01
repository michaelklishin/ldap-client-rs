// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4514 Distinguished Name parser.

use std::fmt::{self, Write};

use crate::ProtoError;
use crate::syntax::{escape_attribute_type, hex_pair, hex_pair_at, is_attribute_type};

const ESCAPABLE: &[u8] = b"\\\"+,;<>#= ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn {
    pub rdns: Vec<Rdn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    pub components: Vec<(String, AttributeValue)>,
}

/// An RDN value: text, or the BER encoding that RFC 4514 section 2.4 writes
/// as `#` and hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributeValue {
    Text(String),
    Ber(Vec<u8>),
}

impl AttributeValue {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Ber(_) => None,
        }
    }
}

impl From<&str> for AttributeValue {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for AttributeValue {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl PartialEq<str> for AttributeValue {
    fn eq(&self, other: &str) -> bool {
        self.as_text() == Some(other)
    }
}

impl PartialEq<&str> for AttributeValue {
    fn eq(&self, other: &&str) -> bool {
        self.as_text() == Some(*other)
    }
}

impl Dn {
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let input = input.trim_start();
        if input.is_empty() {
            return Ok(Dn { rdns: Vec::new() });
        }
        let mut parser = Parser { input, pos: 0 };
        Ok(Dn {
            rdns: parser.rdns()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// The DN without its first RDN, or `None` for a DN of one RDN or none.
    pub fn parent(&self) -> Option<Dn> {
        match self.rdns.split_first() {
            Some((_, rest)) if !rest.is_empty() => Some(Dn {
                rdns: rest.to_vec(),
            }),
            _ => None,
        }
    }
}

/// A cursor that only stops on ASCII bytes, so every index it slices the
/// input at is a character boundary.
struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(is_trailing_whitespace) {
            self.pos += 1;
        }
    }

    fn error_at(&self, pos: usize, what: &str) -> ProtoError {
        ProtoError::Protocol(format!("{what} at byte {pos}"))
    }

    fn error(&self, what: &str) -> ProtoError {
        self.error_at(self.pos, what)
    }

    fn rdns(&mut self) -> Result<Vec<Rdn>, ProtoError> {
        let mut rdns = vec![self.rdn()?];
        while self.peek() == Some(b',') {
            self.pos += 1;
            rdns.push(self.rdn()?);
        }
        match self.peek() {
            None => Ok(rdns),
            Some(_) => Err(self.error("expected ',' or end of DN")),
        }
    }

    fn rdn(&mut self) -> Result<Rdn, ProtoError> {
        let mut components = vec![self.ava()?];
        while self.peek() == Some(b'+') {
            self.pos += 1;
            components.push(self.ava()?);
        }
        Ok(Rdn { components })
    }

    fn ava(&mut self) -> Result<(String, AttributeValue), ProtoError> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| !matches!(b, b'=' | b',' | b'+'))
        {
            self.pos += 1;
        }
        if self.peek() != Some(b'=') {
            return Err(self.error("expected '=' in attribute value assertion"));
        }
        let attr = self.input[start..self.pos].trim();
        if attr.is_empty() {
            return Err(self.error_at(start, "empty attribute type"));
        }
        if !is_attribute_type(attr) {
            return Err(self.error_at(start, &format!("invalid attribute type {attr:?}")));
        }
        self.pos += 1;

        let value = match self.peek() {
            Some(b'#') => self.hex_value()?,
            Some(b'"') => self.quoted_value()?,
            _ => self.text_value()?,
        };
        Ok((attr.to_owned(), value))
    }

    fn hex_value(&mut self) -> Result<AttributeValue, ProtoError> {
        self.pos += 1;
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| !matches!(b, b',' | b'+') && !is_trailing_whitespace(b))
        {
            self.pos += 1;
        }
        let digits = &self.input.as_bytes()[start..self.pos];
        let (pairs, odd) = digits.as_chunks::<2>();
        let bytes = odd
            .is_empty()
            .then(|| {
                pairs
                    .iter()
                    .map(|[high, low]| hex_pair(*high, *low))
                    .collect::<Option<Vec<u8>>>()
            })
            .flatten();
        match bytes {
            Some(bytes) if !bytes.is_empty() => {
                self.skip_whitespace();
                Ok(AttributeValue::Ber(bytes))
            }
            _ => Err(self.error_at(
                start,
                "invalid hex-string in DN value: expected even number of hex digits after '#'",
            )),
        }
    }

    fn quoted_value(&mut self) -> Result<AttributeValue, ProtoError> {
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some_and(|b| b != b'"') {
            self.pos += 1;
        }
        if self.peek().is_none() {
            return Err(self.error_at(start, "unterminated quoted string in DN"));
        }
        let value = self.input[start..self.pos].to_owned();
        self.pos += 1;
        self.skip_whitespace();
        Ok(AttributeValue::Text(value))
    }

    fn text_value(&mut self) -> Result<AttributeValue, ProtoError> {
        let bytes = self.input.as_bytes();
        let mut out = Vec::new();
        // Only unescaped trailing whitespace is trimmed. RFC 4514 names the space;
        // tab, CR and LF are trimmed as well, as the surrounding `trim` used to.
        let mut keep = 0;
        while let Some(b) = self.peek() {
            match b {
                b',' | b'+' => break,
                b'\\' => {
                    let at = self.pos;
                    self.pos += 1;
                    if let Some(byte) = hex_pair_at(bytes, self.pos) {
                        out.push(byte);
                        self.pos += 2;
                    } else if let Some(c) = self.peek().filter(|c| ESCAPABLE.contains(c)) {
                        out.push(c);
                        self.pos += 1;
                    } else {
                        return Err(self.error_at(at, "invalid escape in DN value"));
                    }
                    keep = out.len();
                }
                _ => {
                    out.push(b);
                    self.pos += 1;
                    if !is_trailing_whitespace(b) {
                        keep = out.len();
                    }
                }
            }
        }
        out.truncate(keep);
        String::from_utf8(out)
            .map(AttributeValue::Text)
            .map_err(|e| ProtoError::Protocol(format!("invalid UTF-8 in DN value: {e}")))
    }
}

const fn is_trailing_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Escape a DN value per RFC 4514 §2.4.
pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    let mut first = true;

    while let Some(ch) = chars.next() {
        let is_last = chars.peek().is_none();
        let needs_escape = match ch {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => true,
            '#' if first => true,
            ' ' if first || is_last => true,
            '\0' => true,
            '\t' | '\n' | '\r' if is_last => true,
            _ => false,
        };
        if needs_escape {
            if ch.is_ascii_control() {
                let _ = write!(out, "\\{:02x}", ch as u8);
            } else {
                out.push('\\');
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        first = false;
    }
    out
}

impl fmt::Display for Dn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, rdn) in self.rdns.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{rdn}")?;
        }
        Ok(())
    }
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(&escape_dn_value(text)),
            Self::Ber(bytes) => {
                f.write_char('#')?;
                bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
        }
    }
}

impl fmt::Display for Rdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (attr, value)) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str("+")?;
            }
            write!(f, "{}={value}", escape_attribute_type(attr))?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Dn {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

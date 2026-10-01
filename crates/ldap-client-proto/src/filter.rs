// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write;

use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerError, BerReader, BerWriter};

use crate::ProtoError;
use crate::syntax::{
    escape_attribute_description, escape_attribute_type, hex_pair_at, is_attribute_description,
    is_attribute_type, to_utf8,
};

const AND: Tag = Tag::context_constructed(0);
const OR: Tag = Tag::context_constructed(1);
const NOT: Tag = Tag::context_constructed(2);
const EQUALITY_MATCH: Tag = Tag::context_constructed(3);
const SUBSTRINGS: Tag = Tag::context_constructed(4);
const GREATER_OR_EQUAL: Tag = Tag::context_constructed(5);
const LESS_OR_EQUAL: Tag = Tag::context_constructed(6);
const PRESENT: Tag = Tag::context(7);
const APPROX_MATCH: Tag = Tag::context_constructed(8);
const EXTENSIBLE_MATCH: Tag = Tag::context_constructed(9);

const INITIAL: Tag = Tag::context(0);
const ANY: Tag = Tag::context(1);
const FINAL: Tag = Tag::context(2);

const MATCHING_RULE: Tag = Tag::context(1);
const MATCH_TYPE: Tag = Tag::context(2);
const MATCH_VALUE: Tag = Tag::context(3);
const DN_ATTRIBUTES: Tag = Tag::context(4);

/// An attribute value assertion's value. Values are octets, and text is the
/// common case.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AssertionValue(Vec<u8>);

impl AssertionValue {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl From<&str> for AssertionValue {
    fn from(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}

impl From<String> for AssertionValue {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

impl From<&[u8]> for AssertionValue {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<Vec<u8>> for AssertionValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// LDAP search filter (RFC 4515).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Eq(String, AssertionValue),
    Approx(String, AssertionValue),
    Gte(String, AssertionValue),
    Lte(String, AssertionValue),
    Present(String),
    Substring {
        attr: String,
        initial: Option<AssertionValue>,
        any: Vec<AssertionValue>,
        r#final: Option<AssertionValue>,
    },
    ExtensibleMatch {
        matching_rule: Option<String>,
        attr: Option<String>,
        value: AssertionValue,
        dn_attributes: bool,
    },
}

impl Filter {
    pub fn eq(attr: impl Into<String>, value: impl Into<AssertionValue>) -> Self {
        Self::Eq(attr.into(), value.into())
    }

    pub fn present(attr: impl Into<String>) -> Self {
        Self::Present(attr.into())
    }

    pub fn and(filters: Vec<Filter>) -> Self {
        Self::And(filters)
    }

    pub fn or(filters: Vec<Filter>) -> Self {
        Self::Or(filters)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(filter: Filter) -> Self {
        Self::Not(Box::new(filter))
    }

    pub fn approx(attr: impl Into<String>, value: impl Into<AssertionValue>) -> Self {
        Self::Approx(attr.into(), value.into())
    }

    pub fn gte(attr: impl Into<String>, value: impl Into<AssertionValue>) -> Self {
        Self::Gte(attr.into(), value.into())
    }

    pub fn lte(attr: impl Into<String>, value: impl Into<AssertionValue>) -> Self {
        Self::Lte(attr.into(), value.into())
    }

    pub fn substring(
        attr: impl Into<String>,
        initial: Option<String>,
        any: Vec<String>,
        r#final: Option<String>,
    ) -> Self {
        Self::Substring {
            attr: attr.into(),
            initial: initial.map(Into::into),
            any: any.into_iter().map(Into::into).collect(),
            r#final: r#final.map(Into::into),
        }
    }

    pub fn extensible_match(
        rule: Option<impl Into<String>>,
        attr: Option<impl Into<String>>,
        value: impl Into<AssertionValue>,
        dn_attributes: bool,
    ) -> Self {
        Self::ExtensibleMatch {
            matching_rule: rule.map(Into::into),
            attr: attr.map(Into::into),
            value: value.into(),
            dn_attributes,
        }
    }

    /// Escape a value for RFC 4515 filter strings.
    pub fn escape_value(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        write_escaped(&mut out, input.as_bytes());
        out
    }

    /// Serialize to RFC 4515 string.
    ///
    /// An attribute or matching rule with characters outside RFC 4512's
    /// attribute syntax is written with `\XX` escapes, which `Filter::parse`
    /// refuses, so the output is never a different valid filter.
    pub fn to_filter_string(&self) -> String {
        let mut out = String::new();
        self.write_string(&mut out);
        out
    }

    fn write_string(&self, out: &mut String) {
        out.push('(');
        match self {
            Self::And(filters) => write_list(out, '&', filters),
            Self::Or(filters) => write_list(out, '|', filters),
            Self::Not(filter) => {
                out.push('!');
                filter.write_string(out);
            }
            Self::Eq(attr, value) => write_assertion(out, attr, "=", value),
            Self::Approx(attr, value) => write_assertion(out, attr, "~=", value),
            Self::Gte(attr, value) => write_assertion(out, attr, ">=", value),
            Self::Lte(attr, value) => write_assertion(out, attr, "<=", value),
            Self::Present(attr) => {
                out.push_str(&escape_attribute_description(attr));
                out.push_str("=*");
            }
            Self::Substring {
                attr,
                initial,
                any,
                r#final,
            } => {
                out.push_str(&escape_attribute_description(attr));
                out.push('=');
                if let Some(initial) = initial {
                    write_escaped(out, initial.as_bytes());
                }
                out.push('*');
                for part in any {
                    write_escaped(out, part.as_bytes());
                    out.push('*');
                }
                if let Some(last) = r#final {
                    write_escaped(out, last.as_bytes());
                }
            }
            Self::ExtensibleMatch {
                matching_rule,
                attr,
                value,
                dn_attributes,
            } => {
                if let Some(attr) = attr {
                    out.push_str(&escape_attribute_description(attr));
                }
                if *dn_attributes {
                    out.push_str(":dn");
                }
                if let Some(rule) = matching_rule {
                    out.push(':');
                    out.push_str(&escape_attribute_type(rule));
                }
                out.push_str(":=");
                write_escaped(out, value.as_bytes());
            }
        }
        out.push(')');
    }

    /// Parse an RFC 4515 filter string.
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ProtoError::FilterParse("empty filter".into()));
        }
        let mut parser = Parser { input, pos: 0 };
        let filter = parser.filter(0)?;
        if parser.pos < input.len() {
            return Err(parser.error("trailing data"));
        }
        Ok(filter)
    }

    /// Encode to BER bytes.
    pub fn encode(&self, w: &mut BerWriter) {
        match self {
            Self::And(filters) => encode_list(w, AND, filters),
            Self::Or(filters) => encode_list(w, OR, filters),
            Self::Not(filter) => {
                w.write_sequence(NOT, |inner| filter.encode(inner));
            }
            Self::Eq(attr, value) => encode_ava(w, EQUALITY_MATCH, attr, value),
            Self::Approx(attr, value) => encode_ava(w, APPROX_MATCH, attr, value),
            Self::Gte(attr, value) => encode_ava(w, GREATER_OR_EQUAL, attr, value),
            Self::Lte(attr, value) => encode_ava(w, LESS_OR_EQUAL, attr, value),
            Self::Present(attr) => {
                w.write_octet_string(PRESENT, attr.as_bytes());
            }
            Self::Substring {
                attr,
                initial,
                any,
                r#final,
            } => {
                w.write_sequence(SUBSTRINGS, |inner| {
                    inner.write_bytes(attr.as_bytes());
                    inner.write_sequence(Tag::sequence(), |parts| {
                        if let Some(initial) = initial {
                            parts.write_octet_string(INITIAL, initial.as_bytes());
                        }
                        for part in any {
                            parts.write_octet_string(ANY, part.as_bytes());
                        }
                        if let Some(last) = r#final {
                            parts.write_octet_string(FINAL, last.as_bytes());
                        }
                    });
                });
            }
            Self::ExtensibleMatch {
                matching_rule,
                attr,
                value,
                dn_attributes,
            } => {
                w.write_sequence(EXTENSIBLE_MATCH, |inner| {
                    if let Some(rule) = matching_rule {
                        inner.write_octet_string(MATCHING_RULE, rule.as_bytes());
                    }
                    if let Some(attr) = attr {
                        inner.write_octet_string(MATCH_TYPE, attr.as_bytes());
                    }
                    inner.write_octet_string(MATCH_VALUE, value.as_bytes());
                    if *dn_attributes {
                        inner.write_octet_string(DN_ATTRIBUTES, &[0xFF]);
                    }
                });
            }
        }
    }

    /// Decode from BER.
    pub fn decode(r: &mut BerReader<'_>) -> Result<Self, BerError> {
        match r.peek_tag()? {
            AND => decode_list(r, AND).map(Self::And),
            OR => decode_list(r, OR).map(Self::Or),
            NOT => {
                let filter = r.read_sequence(NOT, Filter::decode)?;
                Ok(Self::Not(Box::new(filter)))
            }
            EQUALITY_MATCH => decode_ava(r, EQUALITY_MATCH).map(|(a, v)| Self::Eq(a, v)),
            GREATER_OR_EQUAL => decode_ava(r, GREATER_OR_EQUAL).map(|(a, v)| Self::Gte(a, v)),
            LESS_OR_EQUAL => decode_ava(r, LESS_OR_EQUAL).map(|(a, v)| Self::Lte(a, v)),
            APPROX_MATCH => decode_ava(r, APPROX_MATCH).map(|(a, v)| Self::Approx(a, v)),
            PRESENT => Ok(Self::Present(to_utf8(r.read_implicit(PRESENT)?)?)),
            SUBSTRINGS => r.read_sequence(SUBSTRINGS, |inner| {
                let attr = to_utf8(inner.read_octet_string()?)?;
                let mut initial = None;
                let mut any = Vec::new();
                let mut r#final = None;

                inner.read_sequence(Tag::sequence(), |parts| {
                    while !parts.is_empty() {
                        let (tag, value) = parts.read_element()?;
                        let value = AssertionValue::from(value);
                        match tag {
                            INITIAL => initial = Some(value),
                            ANY => any.push(value),
                            FINAL => r#final = Some(value),
                            _ => {}
                        }
                    }
                    Ok(())
                })?;

                Ok(Self::Substring {
                    attr,
                    initial,
                    any,
                    r#final,
                })
            }),
            EXTENSIBLE_MATCH => r.read_sequence(EXTENSIBLE_MATCH, |inner| {
                let mut matching_rule = None;
                let mut attr = None;
                let mut value = AssertionValue::default();
                let mut dn_attributes = false;

                while !inner.is_empty() {
                    match inner.peek_tag()? {
                        MATCHING_RULE => {
                            matching_rule = Some(to_utf8(inner.read_implicit(MATCHING_RULE)?)?);
                        }
                        MATCH_TYPE => attr = Some(to_utf8(inner.read_implicit(MATCH_TYPE)?)?),
                        MATCH_VALUE => value = inner.read_implicit(MATCH_VALUE)?.into(),
                        DN_ATTRIBUTES => {
                            let flag = inner.read_implicit(DN_ATTRIBUTES)?;
                            dn_attributes = flag.first().is_some_and(|&b| b != 0);
                        }
                        _ => {
                            inner.read_element()?;
                        }
                    }
                }

                Ok(Self::ExtensibleMatch {
                    matching_rule,
                    attr,
                    value,
                    dn_attributes,
                })
            }),
            actual => Err(BerError::UnexpectedTag {
                expected: Tag::context(0),
                actual,
            }),
        }
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_filter_string())
    }
}

impl std::str::FromStr for Filter {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Escapes `*`, `(`, `)`, `\` and NUL in valid text as RFC 4515 requires,
/// and every byte of an invalid UTF-8 sequence.
fn write_escaped(out: &mut String, value: &[u8]) {
    for chunk in value.utf8_chunks() {
        for ch in chunk.valid().chars() {
            match ch {
                '*' | '(' | ')' | '\\' | '\0' => {
                    let _ = write!(out, "\\{:02x}", ch as u32);
                }
                _ => out.push(ch),
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(out, "\\{byte:02x}");
        }
    }
}

fn write_list(out: &mut String, operator: char, filters: &[Filter]) {
    out.push(operator);
    for filter in filters {
        filter.write_string(out);
    }
}

fn write_assertion(out: &mut String, attr: &str, operator: &str, value: &AssertionValue) {
    out.push_str(&escape_attribute_description(attr));
    out.push_str(operator);
    write_escaped(out, value.as_bytes());
}

fn encode_list(w: &mut BerWriter, tag: Tag, filters: &[Filter]) {
    w.write_sequence(tag, |inner| {
        for filter in filters {
            filter.encode(inner);
        }
    });
}

fn decode_list(r: &mut BerReader<'_>, tag: Tag) -> Result<Vec<Filter>, BerError> {
    let mut filters = Vec::new();
    r.read_sequence_lax(tag, |inner| {
        while !inner.is_empty() {
            filters.push(Filter::decode(inner)?);
        }
        Ok(())
    })?;
    Ok(filters)
}

fn encode_ava(w: &mut BerWriter, tag: Tag, attr: &str, value: &AssertionValue) {
    w.write_sequence(tag, |inner| {
        inner.write_bytes(attr.as_bytes());
        inner.write_bytes(value.as_bytes());
    });
}

fn decode_ava(r: &mut BerReader<'_>, tag: Tag) -> Result<(String, AssertionValue), BerError> {
    r.read_sequence(tag, |inner| {
        let attr = to_utf8(inner.read_octet_string()?)?;
        let value = inner.read_octet_string()?.into();
        Ok((attr, value))
    })
}

// ---------- RFC 4515 filter string parser ----------

const MAX_FILTER_DEPTH: usize = 128;
const MAX_SUBSTRING_PARTS: usize = 64;

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn error_at(&self, pos: usize, what: &str) -> ProtoError {
        ProtoError::FilterParse(format!("{what} at byte {pos}"))
    }

    fn error(&self, what: &str) -> ProtoError {
        self.error_at(self.pos, what)
    }

    fn expect(&mut self, byte: u8) -> Result<(), ProtoError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", char::from(byte))))
        }
    }

    fn filter(&mut self, depth: usize) -> Result<Filter, ProtoError> {
        if depth >= MAX_FILTER_DEPTH {
            return Err(self.error("filter nesting too deep"));
        }
        self.expect(b'(')?;
        let filter = match self.peek() {
            Some(b'&') => {
                self.pos += 1;
                Filter::And(self.list(depth)?)
            }
            Some(b'|') => {
                self.pos += 1;
                Filter::Or(self.list(depth)?)
            }
            Some(b'!') => {
                self.pos += 1;
                Filter::Not(Box::new(self.filter(depth + 1)?))
            }
            _ => self.item()?,
        };
        self.expect(b')')?;
        Ok(filter)
    }

    fn list(&mut self, depth: usize) -> Result<Vec<Filter>, ProtoError> {
        let mut filters = Vec::new();
        while self.peek() == Some(b'(') {
            filters.push(self.filter(depth + 1)?);
        }
        if filters.is_empty() {
            return Err(self.error("empty filter list"));
        }
        Ok(filters)
    }

    fn item(&mut self) -> Result<Filter, ProtoError> {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| !matches!(b, b'=' | b'>' | b'<' | b'~' | b')'))
        {
            self.pos += 1;
        }
        let head = &self.input[start..self.pos];

        let operator = match (self.peek(), self.input.as_bytes().get(self.pos + 1)) {
            (None | Some(b')'), _) => return Err(self.error("missing operator")),
            (Some(b'>'), Some(b'=')) => Operator::Gte,
            (Some(b'<'), Some(b'=')) => Operator::Lte,
            (Some(b'~'), Some(b'=')) => Operator::Approx,
            (Some(b'='), _) => Operator::Eq,
            _ => return Err(self.error("unknown operator")),
        };

        if head.contains(':') {
            return match (operator, head.strip_suffix(':')) {
                (Operator::Eq, Some(prefix)) => {
                    self.pos += 1;
                    self.extensible_match(start, prefix)
                }
                _ => Err(self.error_at(start, "malformed extensible match")),
            };
        }
        if !is_attribute_description(head) {
            return Err(self.error_at(start, &format!("invalid attribute description {head:?}")));
        }
        self.pos += operator.len();

        let attr = head.to_owned();
        match operator {
            Operator::Eq => {
                let parts = self.value(true)?;
                match parts.as_slice() {
                    [value] => Ok(Filter::Eq(attr, value.clone().into())),
                    [first, last] if first.is_empty() && last.is_empty() => {
                        Ok(Filter::Present(attr))
                    }
                    _ => substring(attr, parts)
                        .ok_or_else(|| self.error_at(start, "substring filter has no assertions")),
                }
            }
            Operator::Gte => Ok(Filter::Gte(attr, self.single_value()?)),
            Operator::Lte => Ok(Filter::Lte(attr, self.single_value()?)),
            Operator::Approx => Ok(Filter::Approx(attr, self.single_value()?)),
        }
    }

    // Format: [attr][:dn][:rule]:=value, with the colon before `=` already
    // removed from `prefix`.
    fn extensible_match(&mut self, start: usize, prefix: &str) -> Result<Filter, ProtoError> {
        let parts: Vec<&str> = prefix.split(':').collect();
        let (attr, dn_attributes, rule) = match parts.as_slice() {
            [attr] => (*attr, false, ""),
            [attr, "dn"] => (*attr, true, ""),
            [attr, rule] => (*attr, false, *rule),
            [attr, "dn", rule] => (*attr, true, *rule),
            _ => return Err(self.error_at(start, "malformed extensible match")),
        };

        let attr = (!attr.is_empty()).then_some(attr);
        let rule = (!rule.is_empty()).then_some(rule);
        if attr.is_some_and(|a| !is_attribute_description(a)) {
            return Err(self.error_at(start, "invalid attribute description"));
        }
        if rule.is_some_and(|r| !is_attribute_type(r)) {
            return Err(self.error_at(start, "invalid matching rule"));
        }
        // RFC 4515 section 3: at least one of attr, matching rule or :dn: is required.
        if attr.is_none() && rule.is_none() && !dn_attributes {
            return Err(self.error_at(
                start,
                "extensible match requires at least one of attr, matching rule, or :dn:",
            ));
        }

        Ok(Filter::ExtensibleMatch {
            matching_rule: rule.map(str::to_owned),
            attr: attr.map(str::to_owned),
            value: self.single_value()?,
            dn_attributes,
        })
    }

    fn single_value(&mut self) -> Result<AssertionValue, ProtoError> {
        let parts = self.value(false)?;
        Ok(parts.into_iter().next().unwrap_or_default().into())
    }

    /// Reads a value up to its closing `)`, decoding escapes. With
    /// `wildcards`, an unescaped `*` starts a new part. A `\` must be
    /// followed by two hex digits, as RFC 4515 defines it.
    fn value(&mut self, wildcards: bool) -> Result<Vec<Vec<u8>>, ProtoError> {
        let bytes = self.input.as_bytes();
        let mut parts = Vec::new();
        let mut current = Vec::new();
        while let Some(b) = self.peek() {
            match b {
                b')' => break,
                b'\\' => match hex_pair_at(bytes, self.pos + 1) {
                    Some(byte) => {
                        current.push(byte);
                        self.pos += 3;
                    }
                    None => return Err(self.error("invalid escape in filter value")),
                },
                b'*' if wildcards => {
                    if parts.len() + 1 >= MAX_SUBSTRING_PARTS {
                        return Err(self.error("substring filter has too many wildcard parts"));
                    }
                    parts.push(std::mem::take(&mut current));
                    self.pos += 1;
                }
                _ => {
                    current.push(b);
                    self.pos += 1;
                }
            }
        }
        parts.push(current);
        Ok(parts)
    }
}

#[derive(Clone, Copy)]
enum Operator {
    Eq,
    Gte,
    Lte,
    Approx,
}

impl Operator {
    fn len(self) -> usize {
        match self {
            Self::Eq => 1,
            Self::Gte | Self::Lte | Self::Approx => 2,
        }
    }
}

/// The parts of a value split at its wildcards: the first is the initial
/// assertion, the last is the final one, and the rest are `any`.
fn substring(attr: String, mut parts: Vec<Vec<u8>>) -> Option<Filter> {
    let last = parts.pop().filter(|p| !p.is_empty());
    let initial = Some(parts.remove(0)).filter(|p| !p.is_empty());
    let any: Vec<AssertionValue> = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .map(Into::into)
        .collect();

    if initial.is_none() && any.is_empty() && last.is_none() {
        return None;
    }
    Some(Filter::Substring {
        attr,
        initial: initial.map(Into::into),
        any,
        r#final: last.map(Into::into),
    })
}

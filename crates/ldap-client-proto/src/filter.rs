// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerReader, BerWriter};

use crate::ProtoError;

/// LDAP search filter (RFC 4515).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Eq(String, String),
    Approx(String, String),
    Gte(String, String),
    Lte(String, String),
    Present(String),
    Substring {
        attr: String,
        initial: Option<String>,
        any: Vec<String>,
        r#final: Option<String>,
    },
    ExtensibleMatch {
        matching_rule: Option<String>,
        attr: Option<String>,
        value: String,
        dn_attributes: bool,
    },
}

impl Filter {
    pub fn eq(attr: impl Into<String>, value: impl Into<String>) -> Self {
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

    pub fn approx(attr: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Approx(attr.into(), value.into())
    }

    pub fn gte(attr: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Gte(attr.into(), value.into())
    }

    pub fn lte(attr: impl Into<String>, value: impl Into<String>) -> Self {
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
            initial,
            any,
            r#final,
        }
    }

    pub fn extensible_match(
        rule: Option<impl Into<String>>,
        attr: Option<impl Into<String>>,
        value: impl Into<String>,
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
        use std::fmt::Write;
        let mut out = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                '*' | '(' | ')' | '\\' | '\0' => {
                    let _ = write!(out, "\\{:02x}", ch as u32);
                }
                _ => out.push(ch),
            }
        }
        out
    }

    /// Serialize to RFC 4515 string.
    pub fn to_filter_string(&self) -> String {
        match self {
            Self::And(filters) => {
                let inner: String = filters.iter().map(|f| f.to_filter_string()).collect();
                format!("(&{inner})")
            }
            Self::Or(filters) => {
                let inner: String = filters.iter().map(|f| f.to_filter_string()).collect();
                format!("(|{inner})")
            }
            Self::Not(f) => format!("(!{})", f.to_filter_string()),
            Self::Eq(a, v) => format!("({}={})", a, Self::escape_value(v)),
            Self::Approx(a, v) => format!("({}~={})", a, Self::escape_value(v)),
            Self::Gte(a, v) => format!("({}>={})", a, Self::escape_value(v)),
            Self::Lte(a, v) => format!("({}<={})", a, Self::escape_value(v)),
            Self::Present(a) => format!("({a}=*)"),
            Self::Substring {
                attr,
                initial,
                any,
                r#final,
            } => {
                let mut val = String::new();
                if let Some(init) = initial {
                    val.push_str(&Self::escape_value(init));
                }
                val.push('*');
                for a in any {
                    val.push_str(&Self::escape_value(a));
                    val.push('*');
                }
                if let Some(fin) = r#final {
                    val.push_str(&Self::escape_value(fin));
                }
                format!("({attr}={val})")
            }
            Self::ExtensibleMatch {
                matching_rule,
                attr,
                value,
                dn_attributes,
            } => {
                let mut s = String::from("(");
                if let Some(a) = attr {
                    s.push_str(a);
                }
                if *dn_attributes {
                    s.push_str(":dn");
                }
                if let Some(r) = matching_rule {
                    s.push(':');
                    s.push_str(r);
                }
                s.push_str(":=");
                s.push_str(&Self::escape_value(value));
                s.push(')');
                s
            }
        }
    }

    /// Parse an RFC 4515 filter string.
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ProtoError::FilterParse("empty filter".into()));
        }
        let (filter, rest) = parse_filter(input, 0)?;
        if !rest.is_empty() {
            return Err(ProtoError::FilterParse(format!("trailing data: {rest:?}")));
        }
        Ok(filter)
    }

    /// Encode to BER bytes.
    pub fn encode(&self, w: &mut BerWriter) {
        match self {
            Self::And(filters) => {
                w.write_sequence(Tag::context_constructed(0), |inner| {
                    for f in filters {
                        f.encode(inner);
                    }
                });
            }
            Self::Or(filters) => {
                w.write_sequence(Tag::context_constructed(1), |inner| {
                    for f in filters {
                        f.encode(inner);
                    }
                });
            }
            Self::Not(f) => {
                w.write_sequence(Tag::context_constructed(2), |inner| {
                    f.encode(inner);
                });
            }
            Self::Eq(attr, value) => {
                encode_ava(w, 3, attr, value);
            }
            Self::Approx(attr, value) => {
                encode_ava(w, 8, attr, value);
            }
            Self::Gte(attr, value) => {
                encode_ava(w, 5, attr, value);
            }
            Self::Lte(attr, value) => {
                encode_ava(w, 6, attr, value);
            }
            Self::Present(attr) => {
                w.write_octet_string(Tag::context(7), attr.as_bytes());
            }
            Self::Substring {
                attr,
                initial,
                any,
                r#final,
            } => {
                w.write_sequence(Tag::context_constructed(4), |inner| {
                    inner.write_bytes(attr.as_bytes());
                    inner.write_sequence(Tag::sequence(), |subseq| {
                        if let Some(init) = initial {
                            subseq.write_octet_string(Tag::context(0), init.as_bytes());
                        }
                        for a in any {
                            subseq.write_octet_string(Tag::context(1), a.as_bytes());
                        }
                        if let Some(fin) = r#final {
                            subseq.write_octet_string(Tag::context(2), fin.as_bytes());
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
                w.write_sequence(Tag::context_constructed(9), |inner| {
                    if let Some(rule) = matching_rule {
                        inner.write_octet_string(Tag::context(1), rule.as_bytes());
                    }
                    if let Some(a) = attr {
                        inner.write_octet_string(Tag::context(2), a.as_bytes());
                    }
                    inner.write_octet_string(Tag::context(3), value.as_bytes());
                    if *dn_attributes {
                        inner.write_octet_string(Tag::context(4), &[0xFF]);
                    }
                });
            }
        }
    }

    /// Decode from BER.
    pub fn decode(r: &mut BerReader<'_>) -> Result<Self, ldap_client_ber::BerError> {
        let tag = r.peek_tag()?;
        if tag.class != ldap_client_ber::Class::Context {
            return Err(ldap_client_ber::BerError::UnexpectedTag {
                expected: Tag::context(0),
                actual: tag,
            });
        }

        match tag.number {
            0 => {
                let mut filters = Vec::new();
                r.read_sequence_lax(Tag::context_constructed(0), |inner| {
                    while !inner.is_empty() {
                        filters.push(Filter::decode(inner)?);
                    }
                    Ok(())
                })?;
                Ok(Self::And(filters))
            }
            1 => {
                let mut filters = Vec::new();
                r.read_sequence_lax(Tag::context_constructed(1), |inner| {
                    while !inner.is_empty() {
                        filters.push(Filter::decode(inner)?);
                    }
                    Ok(())
                })?;
                Ok(Self::Or(filters))
            }
            2 => {
                let f = r.read_sequence(Tag::context_constructed(2), Filter::decode)?;
                Ok(Self::Not(Box::new(f)))
            }
            3 => decode_ava_ber(r, 3).map(|(a, v)| Self::Eq(a, v)),
            5 => decode_ava_ber(r, 5).map(|(a, v)| Self::Gte(a, v)),
            6 => decode_ava_ber(r, 6).map(|(a, v)| Self::Lte(a, v)),
            7 => {
                let value = r.read_tagged_implicit_octet_string(7)?;
                Ok(Self::Present(String::from_utf8_lossy(value).into_owned()))
            }
            8 => decode_ava_ber(r, 8).map(|(a, v)| Self::Approx(a, v)),
            4 => r.read_sequence(Tag::context_constructed(4), |inner| {
                let attr = String::from_utf8_lossy(inner.read_octet_string()?).into_owned();
                let mut initial = None;
                let mut any = Vec::new();
                let mut r#final = None;

                inner.read_sequence(Tag::sequence(), |subseq| {
                    while !subseq.is_empty() {
                        let (tag, value) = subseq.read_element()?;
                        let s = String::from_utf8_lossy(value).into_owned();
                        match tag.number {
                            0 => initial = Some(s),
                            1 => any.push(s),
                            2 => r#final = Some(s),
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
            9 => r.read_sequence(Tag::context_constructed(9), |inner| {
                let mut matching_rule = None;
                let mut attr = None;
                let mut value = String::new();
                let mut dn_attributes = false;

                while !inner.is_empty() {
                    let tag = inner.peek_tag()?;
                    match (tag.class, tag.number) {
                        (ldap_client_ber::Class::Context, 1) => {
                            let v = inner.read_tagged_implicit_octet_string(1)?;
                            matching_rule = Some(String::from_utf8_lossy(v).into_owned());
                        }
                        (ldap_client_ber::Class::Context, 2) => {
                            let v = inner.read_tagged_implicit_octet_string(2)?;
                            attr = Some(String::from_utf8_lossy(v).into_owned());
                        }
                        (ldap_client_ber::Class::Context, 3) => {
                            let v = inner.read_tagged_implicit_octet_string(3)?;
                            value = String::from_utf8_lossy(v).into_owned();
                        }
                        (ldap_client_ber::Class::Context, 4) => {
                            let v = inner.read_tagged_implicit_octet_string(4)?;
                            dn_attributes = v.first().is_some_and(|&b| b != 0);
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
            _ => Err(ldap_client_ber::BerError::UnexpectedTag {
                expected: Tag::context(0),
                actual: tag,
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

fn encode_ava(w: &mut BerWriter, tag_num: u32, attr: &str, value: &str) {
    w.write_sequence(Tag::context_constructed(tag_num), |inner| {
        inner.write_bytes(attr.as_bytes());
        inner.write_bytes(value.as_bytes());
    });
}

fn decode_ava_ber(
    r: &mut BerReader<'_>,
    tag_num: u32,
) -> Result<(String, String), ldap_client_ber::BerError> {
    r.read_sequence(Tag::context_constructed(tag_num), |inner| {
        let attr = String::from_utf8_lossy(inner.read_octet_string()?).into_owned();
        let value = String::from_utf8_lossy(inner.read_octet_string()?).into_owned();
        Ok((attr, value))
    })
}

// ---------- RFC 4515 filter string parser ----------

const MAX_FILTER_DEPTH: usize = 128;

fn parse_filter(input: &str, depth: usize) -> Result<(Filter, &str), ProtoError> {
    if depth >= MAX_FILTER_DEPTH {
        return Err(ProtoError::FilterParse("filter nesting too deep".into()));
    }

    let input = input
        .strip_prefix('(')
        .ok_or_else(|| ProtoError::FilterParse("expected '('".into()))?;

    let (filter, rest) = parse_filter_comp(input, depth)?;

    let rest = rest
        .strip_prefix(')')
        .ok_or_else(|| ProtoError::FilterParse("expected ')'".into()))?;

    Ok((filter, rest))
}

fn parse_filter_comp(input: &str, depth: usize) -> Result<(Filter, &str), ProtoError> {
    match input.chars().next() {
        Some('&') => parse_filter_list(&input[1..], Filter::And, depth),
        Some('|') => parse_filter_list(&input[1..], Filter::Or, depth),
        Some('!') => {
            let (f, rest) = parse_filter(&input[1..], depth + 1)?;
            Ok((Filter::Not(Box::new(f)), rest))
        }
        _ => parse_item(input),
    }
}

fn parse_filter_list(
    mut input: &str,
    ctor: fn(Vec<Filter>) -> Filter,
    depth: usize,
) -> Result<(Filter, &str), ProtoError> {
    let mut filters = Vec::new();
    while input.starts_with('(') {
        let (f, rest) = parse_filter(input, depth + 1)?;
        filters.push(f);
        input = rest;
    }
    if filters.is_empty() {
        return Err(ProtoError::FilterParse("empty filter list".into()));
    }
    Ok((ctor(filters), input))
}

fn parse_item(input: &str) -> Result<(Filter, &str), ProtoError> {
    // Find the operator position.
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() && !matches!(bytes[i], b'=' | b'>' | b'<' | b'~' | b')') {
        i += 1;
    }

    if i >= bytes.len() || bytes[i] == b')' {
        return Err(ProtoError::FilterParse("missing operator".into()));
    }

    let attr = &input[..i];

    // Check for extensible match: attr:dn:rule:= or just :rule:= patterns
    if attr.contains(':') {
        return parse_extensible_match(input);
    }

    let (op_len, filter_type) = match (bytes.get(i), bytes.get(i + 1)) {
        (Some(b'>'), Some(b'=')) => (2, ">="),
        (Some(b'<'), Some(b'=')) => (2, "<="),
        (Some(b'~'), Some(b'=')) => (2, "~="),
        (Some(b'='), _) => (1, "="),
        _ => return Err(ProtoError::FilterParse("unknown operator".into())),
    };

    let value_start = i + op_len;
    let value_end = find_value_end(&input[value_start..]);
    let raw_value = &input[value_start..value_start + value_end];
    let rest = &input[value_start + value_end..];

    match filter_type {
        "=" => {
            if raw_value == "*" {
                Ok((Filter::Present(attr.to_string()), rest))
            } else if raw_value.contains('*') {
                Ok((parse_substring(attr, raw_value)?, rest))
            } else {
                Ok((
                    Filter::Eq(attr.to_string(), unescape_value(raw_value)?),
                    rest,
                ))
            }
        }
        ">=" => Ok((
            Filter::Gte(attr.to_string(), unescape_value(raw_value)?),
            rest,
        )),
        "<=" => Ok((
            Filter::Lte(attr.to_string(), unescape_value(raw_value)?),
            rest,
        )),
        "~=" => Ok((
            Filter::Approx(attr.to_string(), unescape_value(raw_value)?),
            rest,
        )),
        _ => unreachable!(),
    }
}

fn parse_extensible_match(input: &str) -> Result<(Filter, &str), ProtoError> {
    // Format: [attr][:dn][:rule]:=value
    let eq_pos = input
        .find(":=")
        .ok_or_else(|| ProtoError::FilterParse("extensible match missing ':='".into()))?;

    let prefix = &input[..eq_pos];
    let value_start = eq_pos + 2;
    let value_end = find_value_end(&input[value_start..]);
    let raw_value = &input[value_start..value_start + value_end];
    let rest = &input[value_start + value_end..];

    let mut attr = None;
    let mut matching_rule = None;
    let mut dn_attributes = false;

    let parts: Vec<&str> = prefix.split(':').collect();
    match parts.len() {
        1 => {
            if !parts[0].is_empty() {
                attr = Some(parts[0].to_string());
            }
        }
        2 => {
            if !parts[0].is_empty() {
                attr = Some(parts[0].to_string());
            }
            if parts[1] == "dn" {
                dn_attributes = true;
            } else if !parts[1].is_empty() {
                matching_rule = Some(parts[1].to_string());
            }
        }
        3 => {
            if !parts[0].is_empty() {
                attr = Some(parts[0].to_string());
            }
            if parts[1] == "dn" {
                dn_attributes = true;
            }
            if !parts[2].is_empty() {
                matching_rule = Some(parts[2].to_string());
            }
        }
        _ => {
            return Err(ProtoError::FilterParse(
                "too many colon-separated parts in extensible match".into(),
            ));
        }
    }

    // RFC 4515 §3: at least one of attr, matching_rule, or dn_attributes must be present.
    if attr.is_none() && matching_rule.is_none() && !dn_attributes {
        return Err(ProtoError::FilterParse(
            "extensible match requires at least one of attr, matching rule, or :dn:".into(),
        ));
    }

    Ok((
        Filter::ExtensibleMatch {
            matching_rule,
            attr,
            value: unescape_value(raw_value)?,
            dn_attributes,
        },
        rest,
    ))
}

fn parse_substring(attr: &str, raw_value: &str) -> Result<Filter, ProtoError> {
    let parts: Vec<&str> = raw_value.split('*').collect();
    let initial = if !parts[0].is_empty() {
        Some(unescape_value(parts[0])?)
    } else {
        None
    };
    let r#final = match parts.last().filter(|s| !s.is_empty()) {
        Some(s) => Some(unescape_value(s)?),
        None => None,
    };
    let any: Vec<String> = parts[1..parts.len() - 1]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| unescape_value(s))
        .collect::<Result<_, _>>()?;

    if initial.is_none() && any.is_empty() && r#final.is_none() {
        return Err(ProtoError::FilterParse(
            "substring filter has no assertions".into(),
        ));
    }

    Ok(Filter::Substring {
        attr: attr.to_string(),
        initial,
        any,
        r#final,
    })
}

fn find_value_end(input: &str) -> usize {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b')' {
        if bytes[i] == b'\\'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            i += 3;
        } else {
            i += 1;
        }
    }
    i
}

fn unescape_value(input: &str) -> Result<String, ProtoError> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 2 < bytes.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out)
        .map_err(|e| ProtoError::FilterParse(format!("invalid UTF-8 in filter value: {e}")))
}

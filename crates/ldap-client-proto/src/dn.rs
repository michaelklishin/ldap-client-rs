// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4514 Distinguished Name parser.

use std::fmt;

use crate::ProtoError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn {
    pub rdns: Vec<Rdn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    pub components: Vec<(String, String)>,
}

impl Dn {
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(Dn { rdns: Vec::new() });
        }

        let mut rdns = Vec::new();
        let mut remaining = input;
        loop {
            let (rdn, rest) = parse_rdn(remaining)?;
            rdns.push(rdn);
            if rest.is_empty() {
                break;
            }
            if let Some(r) = rest.strip_prefix(',') {
                remaining = r;
            } else {
                return Err(ProtoError::Protocol(format!(
                    "expected ',' or end of DN, got {:?}",
                    &rest[..rest.len().min(10)]
                )));
            }
        }
        Ok(Dn { rdns })
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }
}

fn parse_rdn(input: &str) -> Result<(Rdn, &str), ProtoError> {
    let mut components = Vec::new();
    let mut remaining = input;
    loop {
        let (attr, value, rest) = parse_ava(remaining)?;
        components.push((attr, value));
        if let Some(r) = rest.strip_prefix('+') {
            remaining = r;
        } else {
            return Ok((Rdn { components }, rest));
        }
    }
}

fn parse_ava(input: &str) -> Result<(String, String, &str), ProtoError> {
    // Only search for '=' before any unescaped ',' or '+' (those are RDN/AVA separators).
    let limit = find_unescaped_separator(input);
    let eq_pos = input[..limit]
        .find('=')
        .ok_or_else(|| ProtoError::Protocol("expected '=' in attribute value assertion".into()))?;
    let attr = input[..eq_pos].trim().to_string();
    if attr.is_empty() {
        return Err(ProtoError::Protocol("empty attribute type".into()));
    }
    let rest = &input[eq_pos + 1..];

    if let Some(hex_rest) = rest.strip_prefix('#') {
        // Hex-encoded BER value (RFC 4514 §2.4)
        let end = hex_rest.find([',', '+']).unwrap_or(hex_rest.len());
        let hex = &hex_rest[..end];
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProtoError::Protocol(
                "invalid hex-string in DN value: expected even number of hex digits after '#'"
                    .into(),
            ));
        }
        let value = format!("#{hex}");
        Ok((attr, value, &hex_rest[end..]))
    } else if let Some(after_quote) = rest.strip_prefix('"') {
        // Quoted string (legacy, but we should parse it)
        let end = after_quote
            .find('"')
            .ok_or_else(|| ProtoError::Protocol("unterminated quoted string in DN".into()))?;
        let value = after_quote[..end].to_string();
        Ok((attr, value, &after_quote[end + 1..]))
    } else {
        let (value, rest) = parse_dn_value(rest)?;
        Ok((attr, value, rest))
    }
}

fn find_unescaped_separator(input: &str) -> usize {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b',' | b'+' => return i,
            b'\\' => {
                i += 1;
                if i + 1 < bytes.len()
                    && bytes[i].is_ascii_hexdigit()
                    && bytes[i + 1].is_ascii_hexdigit()
                {
                    i += 2;
                } else if i < bytes.len() {
                    // Skip the full escaped character (multi-byte safe).
                    let ch = input[i..].chars().next().unwrap();
                    i += ch.len_utf8();
                }
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

fn parse_dn_value(input: &str) -> Result<(String, &str), ProtoError> {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    // Track position of last non-space or escaped character for trailing-space trim.
    // RFC 4514 §3: trailing spaces are trimmed only when unescaped.
    let mut last_non_trimmable = 0;

    while i < bytes.len() {
        match bytes[i] {
            b',' | b'+' => break,
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    break;
                }
                // Hex pair?
                if i + 1 < bytes.len()
                    && bytes[i].is_ascii_hexdigit()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && let Ok(byte) =
                        u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or(""), 16)
                {
                    // Accumulate raw bytes for multi-byte UTF-8
                    let mut raw = vec![byte];
                    i += 2;
                    while i + 2 < bytes.len()
                        && bytes[i] == b'\\'
                        && bytes[i + 1].is_ascii_hexdigit()
                        && bytes[i + 2].is_ascii_hexdigit()
                    {
                        if let Ok(b) = u8::from_str_radix(
                            std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                            16,
                        ) {
                            // Only continue if this looks like a continuation byte
                            if b & 0xC0 != 0x80 {
                                break;
                            }
                            raw.push(b);
                            i += 3;
                        } else {
                            break;
                        }
                    }
                    let decoded = String::from_utf8(raw).map_err(|e| {
                        ProtoError::Protocol(format!("invalid UTF-8 in DN value: {e}"))
                    })?;
                    out.push_str(&decoded);
                    last_non_trimmable = out.len();
                    continue;
                }
                // Escaped special character (always ASCII per RFC 4514)
                out.push(bytes[i] as char);
                last_non_trimmable = out.len();
                i += 1;
            }
            _ => {
                // Decode full UTF-8 character to handle multi-byte sequences.
                let ch = input[i..].chars().next().unwrap();
                out.push(ch);
                if ch != ' ' {
                    last_non_trimmable = out.len();
                }
                i += ch.len_utf8();
            }
        }
    }

    // Trim unescaped trailing spaces (per RFC 4514 §3).
    out.truncate(last_non_trimmable);
    Ok((out, &input[i..]))
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
            _ => false,
        };
        if needs_escape {
            if ch == '\0' {
                out.push_str("\\00");
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

impl fmt::Display for Rdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (attr, value)) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str("+")?;
            }
            write!(f, "{}={}", attr, escape_dn_value(value))?;
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

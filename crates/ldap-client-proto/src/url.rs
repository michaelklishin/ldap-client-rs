// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4516 LDAP URL parser.

use std::fmt;

use crate::ProtoError;
use crate::message::SearchScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrl {
    pub scheme: LdapScheme,
    pub host: String,
    pub port: Option<u16>,
    pub base_dn: Option<String>,
    pub attributes: Vec<String>,
    pub scope: Option<SearchScope>,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapScheme {
    Ldap,
    Ldaps,
}

impl LdapUrl {
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let (scheme, rest) = if let Some(r) = input.strip_prefix("ldaps://") {
            (LdapScheme::Ldaps, r)
        } else if let Some(r) = input.strip_prefix("ldap://") {
            (LdapScheme::Ldap, r)
        } else {
            return Err(ProtoError::Protocol(
                "LDAP URL must start with ldap:// or ldaps://".into(),
            ));
        };

        // Split host[:port] from the path at the first '/'
        let (hostport, path) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, ""),
        };

        // Parse host and port
        let (host, port) = if hostport.starts_with('[') {
            // IPv6
            let bracket_end = hostport
                .find(']')
                .ok_or_else(|| ProtoError::Protocol("unterminated IPv6 address".into()))?;
            let h = &hostport[1..bracket_end];
            let after = &hostport[bracket_end + 1..];
            let p = if let Some(port_str) = after.strip_prefix(':') {
                Some(
                    port_str
                        .parse::<u16>()
                        .map_err(|e| ProtoError::Protocol(format!("invalid port: {e}")))?,
                )
            } else {
                None
            };
            (h.to_string(), p)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => {
                    let port = p
                        .parse::<u16>()
                        .map_err(|e| ProtoError::Protocol(format!("invalid port: {e}")))?;
                    (h.to_string(), Some(port))
                }
                None => (hostport.to_string(), None),
            }
        };

        if host.is_empty() {
            return Err(ProtoError::Protocol("missing host in LDAP URL".into()));
        }

        // Parse path components: base_dn?attributes?scope?filter
        let parts: Vec<&str> = path.splitn(4, '?').collect();

        let base_dn = parts
            .first()
            .filter(|s| !s.is_empty())
            .map(|s| percent_decode(s));

        let attributes = parts
            .get(1)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .filter(|a| !a.is_empty())
                    .map(percent_decode)
                    .collect()
            })
            .unwrap_or_default();

        let scope = parts
            .get(2)
            .filter(|s| !s.is_empty())
            .map(|s| parse_scope(s))
            .transpose()?;

        let filter = parts
            .get(3)
            .filter(|s| !s.is_empty())
            .map(|s| percent_decode(s));

        Ok(LdapUrl {
            scheme,
            host,
            port,
            base_dn,
            attributes,
            scope,
            filter,
        })
    }

    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.scheme {
            LdapScheme::Ldap => 389,
            LdapScheme::Ldaps => 636,
        })
    }
}

fn parse_scope(s: &str) -> Result<SearchScope, ProtoError> {
    match s.to_ascii_lowercase().as_str() {
        "base" => Ok(SearchScope::BaseObject),
        "one" => Ok(SearchScope::SingleLevel),
        "sub" => Ok(SearchScope::WholeSubtree),
        _ => Err(ProtoError::Protocol(format!("unknown scope: {s}"))),
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
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
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'=' | b',') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

impl fmt::Display for LdapUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.scheme {
            LdapScheme::Ldap => "ldap",
            LdapScheme::Ldaps => "ldaps",
        };
        write!(f, "{scheme}://")?;

        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        write!(f, "/")?;

        if let Some(dn) = &self.base_dn {
            write!(f, "{}", percent_encode(dn))?;
        }

        // Only print subsequent fields if there's something to show
        let has_attrs = !self.attributes.is_empty();
        let has_scope = self.scope.is_some();
        let has_filter = self.filter.is_some();

        if has_attrs || has_scope || has_filter {
            write!(f, "?")?;
            if has_attrs {
                let attrs: Vec<String> =
                    self.attributes.iter().map(|a| percent_encode(a)).collect();
                write!(f, "{}", attrs.join(","))?;
            }
        }

        if has_scope || has_filter {
            write!(f, "?")?;
            if let Some(scope) = &self.scope {
                let scope_str = match scope {
                    SearchScope::BaseObject => "base",
                    SearchScope::SingleLevel => "one",
                    SearchScope::WholeSubtree => "sub",
                };
                write!(f, "{scope_str}")?;
            }
        }

        if has_filter {
            write!(f, "?")?;
            if let Some(filter) = &self.filter {
                write!(f, "{}", percent_encode(filter))?;
            }
        }

        Ok(())
    }
}

impl std::str::FromStr for LdapUrl {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

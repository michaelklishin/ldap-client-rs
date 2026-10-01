// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4516 LDAP URL parser.

use std::fmt;

use crate::ProtoError;
use crate::message::SearchScope;
use crate::syntax::hex_pair_at;

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

        // base_dn?attributes?scope?filter?extensions
        let parts: Vec<&str> = path.splitn(6, '?').collect();
        if parts.len() > 5 {
            return Err(ProtoError::Protocol(
                "too many '?'-separated fields in LDAP URL".into(),
            ));
        }
        let field = |i: usize| parts.get(i).copied().filter(|s| !s.is_empty());

        // The client implements no extension, so a critical one must be refused (RFC 4516 section 2).
        if let Some(critical) =
            field(4).and_then(|exts| exts.split(',').find(|e| e.starts_with('!')))
        {
            return Err(ProtoError::Protocol(format!(
                "unsupported critical LDAP URL extension: {critical}"
            )));
        }

        let base_dn = field(0).map(percent_decode).transpose()?;

        let attributes = field(1)
            .map(|s| {
                s.split(',')
                    .filter(|a| !a.is_empty())
                    .map(percent_decode)
                    .collect::<Result<_, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        let scope = field(2).map(str::parse).transpose()?;

        let filter = field(3).map(percent_decode).transpose()?;

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
        self.port.unwrap_or(self.scheme.default_port())
    }
}

impl LdapScheme {
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Ldap => 389,
            Self::Ldaps => 636,
        }
    }
}

/// A `%` that does not start a pair of hex digits stays as text: servers
/// write the referral URLs this reads, and a literal `%` is unambiguous.
fn percent_decode(s: &str) -> Result<String, ProtoError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = hex_pair_at(bytes, i + 1)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| ProtoError::Protocol("invalid UTF-8 in percent-encoded LDAP URL field".into()))
}

/// `extra_safe` lists the bytes besides the unreserved ones that stay as they are.
fn percent_encode(s: &str, extra_safe: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || extra_safe.contains(&b)
        {
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

        if self.host.contains(':') || self.host.starts_with('[') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        write!(f, "/")?;

        if let Some(dn) = &self.base_dn {
            write!(f, "{}", percent_encode(dn, b"=,"))?;
        }

        // Only print subsequent fields if there's something to show
        let has_attrs = !self.attributes.is_empty();
        let has_scope = self.scope.is_some();
        let has_filter = self.filter.is_some();

        if has_attrs || has_scope || has_filter {
            write!(f, "?")?;
            if has_attrs {
                let attrs: Vec<String> = self
                    .attributes
                    .iter()
                    .map(|a| percent_encode(a, b"="))
                    .collect();
                write!(f, "{}", attrs.join(","))?;
            }
        }

        if has_scope || has_filter {
            write!(f, "?")?;
            if let Some(scope) = &self.scope {
                write!(f, "{scope}")?;
            }
        }

        if has_filter {
            write!(f, "?")?;
            if let Some(filter) = &self.filter {
                write!(f, "{}", percent_encode(filter, b"=,"))?;
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

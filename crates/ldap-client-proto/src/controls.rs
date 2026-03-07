// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerReader, BerWriter};

use crate::ProtoError;
use crate::result_code::ResultCode;

pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";
pub const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";
pub const SERVER_SORT_REQUEST_OID: &str = "1.2.840.113556.1.4.473";
pub const SERVER_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";
pub const DOMAIN_SCOPE_OID: &str = "1.2.840.113556.1.4.1339";

// Keep old name for backwards compat
pub const SERVER_SORT_OID: &str = SERVER_SORT_REQUEST_OID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub oid: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

/// Simple paged results control (RFC 2696).
#[derive(Debug, Clone)]
pub struct PagedResultsControl {
    pub size: i32,
    pub cookie: Vec<u8>,
}

impl PagedResultsControl {
    pub fn new(size: i32) -> Self {
        Self {
            size,
            cookie: Vec::new(),
        }
    }

    pub fn with_cookie(mut self, cookie: Vec<u8>) -> Self {
        self.cookie = cookie;
        self
    }

    pub fn to_control(&self) -> Control {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |inner| {
            inner.write_integer(self.size as i64);
            inner.write_bytes(&self.cookie);
        });
        Control {
            oid: PAGED_RESULTS_OID.to_string(),
            critical: false,
            value: Some(w.into_bytes()),
        }
    }

    pub fn from_control(control: &Control) -> Result<Self, ProtoError> {
        let value = control
            .value
            .as_deref()
            .ok_or_else(|| ProtoError::Protocol("paged results control missing value".into()))?;
        let mut r = BerReader::new(value);
        r.read_sequence(Tag::sequence(), |inner| {
            let size = inner.read_integer()? as i32;
            let cookie = inner.read_octet_string()?.to_vec();
            Ok(Self { size, cookie })
        })
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct ManageDsaItControl {
    pub critical: bool,
}

impl ManageDsaItControl {
    pub fn new(critical: bool) -> Self {
        Self { critical }
    }

    pub fn to_control(&self) -> Control {
        Control {
            oid: MANAGE_DSA_IT_OID.to_string(),
            critical: self.critical,
            value: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainScopeControl {
    pub critical: bool,
}

impl DomainScopeControl {
    pub fn new(critical: bool) -> Self {
        Self { critical }
    }

    pub fn to_control(&self) -> Control {
        Control {
            oid: DOMAIN_SCOPE_OID.to_string(),
            critical: self.critical,
            value: None,
        }
    }
}

/// A single sort key for server-side sort (RFC 2891).
#[derive(Debug, Clone)]
pub struct SortKey {
    pub attribute_type: String,
    pub ordering_rule: Option<String>,
    pub reverse_order: bool,
}

impl SortKey {
    pub fn new(attribute_type: impl Into<String>) -> Self {
        Self {
            attribute_type: attribute_type.into(),
            ordering_rule: None,
            reverse_order: false,
        }
    }

    pub fn reverse(mut self) -> Self {
        self.reverse_order = true;
        self
    }

    pub fn ordering_rule(mut self, rule: impl Into<String>) -> Self {
        self.ordering_rule = Some(rule.into());
        self
    }
}

/// Server-side sort request control value (RFC 2891).
#[derive(Debug, Clone)]
pub struct SortKeyList {
    pub keys: Vec<SortKey>,
}

impl SortKeyList {
    pub fn new(keys: Vec<SortKey>) -> Self {
        Self { keys }
    }

    pub fn to_control(&self, critical: bool) -> Control {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |seq| {
            for key in &self.keys {
                seq.write_sequence(Tag::sequence(), |inner| {
                    inner.write_bytes(key.attribute_type.as_bytes());
                    if let Some(rule) = &key.ordering_rule {
                        inner.write_octet_string(Tag::context(0), rule.as_bytes());
                    }
                    if key.reverse_order {
                        inner.write_octet_string(Tag::context(1), &[0xFF]);
                    }
                });
            }
        });
        Control {
            oid: SERVER_SORT_REQUEST_OID.to_string(),
            critical,
            value: Some(w.into_bytes()),
        }
    }
}

/// Server-side sort response control value (RFC 2891).
#[derive(Debug, Clone)]
pub struct SortResult {
    pub result_code: ResultCode,
    pub attribute_type: Option<String>,
}

impl SortResult {
    pub fn from_control(control: &Control) -> Result<Self, ProtoError> {
        let value = control
            .value
            .as_deref()
            .ok_or_else(|| ProtoError::Protocol("sort response control missing value".into()))?;
        let mut r = BerReader::new(value);
        r.read_sequence(Tag::sequence(), |inner| {
            let code = ResultCode::from_i64(inner.read_enumerated()?);
            let attr = if !inner.is_empty() {
                let tag = inner.peek_tag()?;
                if tag.class == ldap_client_ber::Class::Context && tag.number == 0 {
                    Some(
                        String::from_utf8_lossy(inner.read_tagged_implicit_octet_string(0)?)
                            .into_owned(),
                    )
                } else {
                    None
                }
            } else {
                None
            };
            Ok(Self {
                result_code: code,
                attribute_type: attr,
            })
        })
        .map_err(Into::into)
    }
}

pub fn encode_controls(w: &mut BerWriter, controls: &[Control]) {
    w.write_sequence(Tag::context_constructed(0), |outer| {
        for ctrl in controls {
            outer.write_sequence(Tag::sequence(), |inner| {
                inner.write_bytes(ctrl.oid.as_bytes());
                if ctrl.critical {
                    inner.write_boolean(true);
                }
                if let Some(val) = &ctrl.value {
                    inner.write_bytes(val);
                }
            });
        }
    });
}

pub fn decode_controls(r: &mut BerReader<'_>) -> Result<Vec<Control>, ldap_client_ber::BerError> {
    let mut controls = Vec::new();
    r.read_sequence_lax(Tag::context_constructed(0), |outer| {
        while !outer.is_empty() {
            outer.read_sequence(Tag::sequence(), |inner| {
                let oid = String::from_utf8_lossy(inner.read_octet_string()?).into_owned();
                let mut critical = false;
                let mut value = None;

                while !inner.is_empty() {
                    let tag = inner.peek_tag()?;
                    if tag == Tag::universal(ldap_client_ber::tag::BOOLEAN) {
                        critical = inner.read_boolean()?;
                    } else {
                        value = Some(inner.read_octet_string()?.to_vec());
                    }
                }

                controls.push(Control {
                    oid,
                    critical,
                    value,
                });
                Ok(())
            })?;
        }
        Ok(())
    })?;
    Ok(controls)
}

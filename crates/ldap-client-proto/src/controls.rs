// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::tag::{BOOLEAN, Tag};
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

pub(crate) const CONTROLS: Tag = Tag::context_constructed(0);
const ORDERING_RULE: Tag = Tag::context(0);
const REVERSE_ORDER: Tag = Tag::context(1);
const ATTRIBUTE_TYPE: Tag = Tag::context(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub oid: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

pub trait ControlType {
    const OID: &'static str;
}

/// A control the client sends. Criticality belongs to the `Control` that
/// carries the value, not to the value.
pub trait RequestControl: ControlType {
    fn value(&self) -> Option<Vec<u8>>;
}

pub trait ResponseControl: ControlType + Sized {
    fn from_value(value: Option<&[u8]>) -> Result<Self, ProtoError>;
}

impl Control {
    pub fn new<C: RequestControl>(control: &C, critical: bool) -> Self {
        Self {
            oid: C::OID.to_string(),
            critical,
            value: control.value(),
        }
    }

    pub fn decode<C: ResponseControl>(&self) -> Result<C, ProtoError> {
        if self.oid != C::OID {
            return Err(ProtoError::Protocol(format!(
                "expected control {}, got {}",
                C::OID,
                self.oid
            )));
        }
        C::from_value(self.value.as_deref())
    }

    /// The decoded control with OID `C::OID`, if the server sent one. A
    /// control that is present and does not decode is an error.
    pub fn find<C: ResponseControl>(controls: &[Control]) -> Result<Option<C>, ProtoError> {
        controls
            .iter()
            .find(|c| c.oid == C::OID)
            .map(Control::decode)
            .transpose()
    }
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
        Control::new(self, false)
    }

    pub fn from_control(control: &Control) -> Result<Self, ProtoError> {
        control.decode()
    }
}

impl ControlType for PagedResultsControl {
    const OID: &'static str = PAGED_RESULTS_OID;
}

impl RequestControl for PagedResultsControl {
    fn value(&self) -> Option<Vec<u8>> {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |inner| {
            inner.write_integer(i64::from(self.size));
            inner.write_bytes(&self.cookie);
        });
        Some(w.into_bytes())
    }
}

impl ResponseControl for PagedResultsControl {
    fn from_value(value: Option<&[u8]>) -> Result<Self, ProtoError> {
        let value = value
            .ok_or_else(|| ProtoError::Protocol("paged results control missing value".into()))?;
        let (size, cookie) = BerReader::new(value).read_sequence(Tag::sequence(), |inner| {
            Ok((inner.read_integer()?, inner.read_octet_string()?.to_vec()))
        })?;
        let size = i32::try_from(size)
            .map_err(|_| ProtoError::Protocol("paged results size out of range".into()))?;
        Ok(Self { size, cookie })
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
        Control::new(self, self.critical)
    }
}

impl ControlType for ManageDsaItControl {
    const OID: &'static str = MANAGE_DSA_IT_OID;
}

impl RequestControl for ManageDsaItControl {
    fn value(&self) -> Option<Vec<u8>> {
        None
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
        Control::new(self, self.critical)
    }
}

impl ControlType for DomainScopeControl {
    const OID: &'static str = DOMAIN_SCOPE_OID;
}

impl RequestControl for DomainScopeControl {
    fn value(&self) -> Option<Vec<u8>> {
        None
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
        Control::new(self, critical)
    }
}

impl ControlType for SortKeyList {
    const OID: &'static str = SERVER_SORT_REQUEST_OID;
}

impl RequestControl for SortKeyList {
    fn value(&self) -> Option<Vec<u8>> {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |seq| {
            for key in &self.keys {
                seq.write_sequence(Tag::sequence(), |inner| {
                    inner.write_bytes(key.attribute_type.as_bytes());
                    if let Some(rule) = &key.ordering_rule {
                        inner.write_octet_string(ORDERING_RULE, rule.as_bytes());
                    }
                    if key.reverse_order {
                        inner.write_octet_string(REVERSE_ORDER, &[0xFF]);
                    }
                });
            }
        });
        Some(w.into_bytes())
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
        control.decode()
    }
}

impl ControlType for SortResult {
    const OID: &'static str = SERVER_SORT_RESPONSE_OID;
}

impl ResponseControl for SortResult {
    fn from_value(value: Option<&[u8]>) -> Result<Self, ProtoError> {
        let value = value
            .ok_or_else(|| ProtoError::Protocol("sort response control missing value".into()))?;
        BerReader::new(value)
            .read_sequence(Tag::sequence(), |inner| {
                let result_code = ResultCode::from_i64(inner.read_enumerated()?);
                let attribute_type = if inner.peek_is(ATTRIBUTE_TYPE) {
                    let raw = inner.read_implicit(ATTRIBUTE_TYPE)?;
                    Some(String::from_utf8_lossy(raw).into_owned())
                } else {
                    None
                };
                Ok(Self {
                    result_code,
                    attribute_type,
                })
            })
            .map_err(Into::into)
    }
}

pub fn encode_controls(w: &mut BerWriter, controls: &[Control]) {
    w.write_sequence(CONTROLS, |outer| {
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
    r.read_sequence_lax(CONTROLS, |outer| {
        outer.read_each(|outer| {
            outer.read_sequence(Tag::sequence(), |inner| {
                let oid = String::from_utf8_lossy(inner.read_octet_string()?).into_owned();
                let critical = if inner.peek_is(Tag::universal(BOOLEAN)) {
                    inner.read_boolean()?
                } else {
                    false
                };
                let value = if inner.is_empty() {
                    None
                } else {
                    Some(inner.read_octet_string()?.to_vec())
                };

                Ok(Control {
                    oid,
                    critical,
                    value,
                })
            })
        })
    })
}

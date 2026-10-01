// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use ldap_client_ber::reader::decode_i64_bytes;
use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerError, BerReader, BerWriter};
use zeroize::Zeroizing;

use crate::ProtoError;
use crate::controls::{CONTROLS, Control, decode_controls, encode_controls};
use crate::filter::Filter;
use crate::result_code::ResultCode;
use crate::syntax::to_utf8;

/// A message id is `0..=i32::MAX`. A request takes an id from `FIRST` up;
/// `UNSOLICITED` is the id of a server's notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub i32);

impl MessageId {
    pub const UNSOLICITED: MessageId = MessageId(0);
    pub const FIRST: MessageId = MessageId(1);

    pub const fn get(self) -> i32 {
        self.0
    }

    /// The id after this one. It wraps from `i32::MAX` to `FIRST`, so the
    /// result is never `UNSOLICITED`.
    pub fn next(self) -> MessageId {
        match self.0.checked_add(1) {
            Some(next) => MessageId(next),
            None => MessageId::FIRST,
        }
    }
}

impl TryFrom<i64> for MessageId {
    type Error = BerError;

    fn try_from(id: i64) -> Result<Self, Self::Error> {
        i32::try_from(id)
            .ok()
            .filter(|id| *id >= 0)
            .map(MessageId)
            .ok_or(BerError::InvalidInteger)
    }
}

/// Top-level LDAP PDU (RFC 4511 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    pub message_id: MessageId,
    pub operation: LdapOperation,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapOperation {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    SearchResultReference(Vec<String>),
    ModifyRequest(ModifyRequest),
    ModifyResponse(LdapResult),
    AddRequest(AddRequest),
    AddResponse(LdapResult),
    DeleteRequest(String),
    DeleteResponse(LdapResult),
    ModifyDnRequest(ModifyDnRequest),
    ModifyDnResponse(LdapResult),
    CompareRequest(CompareRequest),
    CompareResponse(LdapResult),
    AbandonRequest(MessageId),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
    IntermediateResponse(IntermediateResponse),
}

pub const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
pub const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";
pub const WHO_AM_I_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

// Tags named after the fields of RFC 4511's ASN.1.
const BIND_REQUEST: Tag = Tag::application(0);
const BIND_RESPONSE: Tag = Tag::application(1);
const UNBIND_REQUEST: Tag = Tag::application_primitive(2);
const SEARCH_REQUEST: Tag = Tag::application(3);
const SEARCH_RESULT_ENTRY: Tag = Tag::application(4);
const SEARCH_RESULT_DONE: Tag = Tag::application(5);
const MODIFY_REQUEST: Tag = Tag::application(6);
const MODIFY_RESPONSE: Tag = Tag::application(7);
const ADD_REQUEST: Tag = Tag::application(8);
const ADD_RESPONSE: Tag = Tag::application(9);
const DEL_REQUEST: Tag = Tag::application_primitive(10);
const DEL_RESPONSE: Tag = Tag::application(11);
const MODIFY_DN_REQUEST: Tag = Tag::application(12);
const MODIFY_DN_RESPONSE: Tag = Tag::application(13);
const COMPARE_REQUEST: Tag = Tag::application(14);
const COMPARE_RESPONSE: Tag = Tag::application(15);
const ABANDON_REQUEST: Tag = Tag::application_primitive(16);
const SEARCH_RESULT_REFERENCE: Tag = Tag::application(19);
const EXTENDED_REQUEST: Tag = Tag::application(23);
const EXTENDED_RESPONSE: Tag = Tag::application(24);
const INTERMEDIATE_RESPONSE: Tag = Tag::application(25);

const SIMPLE: Tag = Tag::context(0);
const SASL: Tag = Tag::context_constructed(3);
const REFERRAL: Tag = Tag::context_constructed(3);
const SERVER_SASL_CREDS: Tag = Tag::context(7);
const NEW_SUPERIOR: Tag = Tag::context(0);
const REQUEST_NAME: Tag = Tag::context(0);
const REQUEST_VALUE: Tag = Tag::context(1);
const RESPONSE_NAME: Tag = Tag::context(10);
const RESPONSE_VALUE: Tag = Tag::context(11);
const INTERMEDIATE_NAME: Tag = Tag::context(0);
const INTERMEDIATE_VALUE: Tag = Tag::context(1);

// --- Request/Response types ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    pub version: i64,
    pub name: String,
    pub authentication: BindAuthentication,
}

#[derive(Clone, PartialEq, Eq)]
pub enum BindAuthentication {
    Simple(Zeroizing<Vec<u8>>),
    Sasl {
        mechanism: String,
        credentials: Option<Zeroizing<Vec<u8>>>,
    },
}

impl fmt::Debug for BindAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple(_) => f.debug_tuple("Simple").field(&"[REDACTED]").finish(),
            Self::Sasl { mechanism, .. } => f
                .debug_struct("Sasl")
                .field("mechanism", mechanism)
                .field("credentials", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResponse {
    pub result: LdapResult,
    pub server_sasl_creds: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    pub code: ResultCode,
    pub matched_dn: String,
    pub diagnostic_message: String,
    pub referral: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

impl SearchScope {
    pub const ALL: [SearchScope; 3] = [Self::BaseObject, Self::SingleLevel, Self::WholeSubtree];

    /// The name RFC 4516 gives the scope in an LDAP URL.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseObject => "base",
            Self::SingleLevel => "one",
            Self::WholeSubtree => "sub",
        }
    }
}

impl fmt::Display for SearchScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SearchScope {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| ProtoError::Protocol(format!("unknown scope: {s}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

impl TryFrom<i64> for SearchScope {
    type Error = ProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::BaseObject),
            1 => Ok(Self::SingleLevel),
            2 => Ok(Self::WholeSubtree),
            n => Err(ProtoError::Protocol(format!("invalid search scope: {n}"))),
        }
    }
}

impl TryFrom<i64> for DerefAliases {
    type Error = ProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NeverDerefAliases),
            1 => Ok(Self::DerefInSearching),
            2 => Ok(Self::DerefFindingBaseObj),
            3 => Ok(Self::DerefAlways),
            n => Err(ProtoError::Protocol(format!("invalid deref aliases: {n}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base_dn: String,
    pub scope: SearchScope,
    pub deref_aliases: DerefAliases,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    pub dn: String,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialAttribute {
    pub name: String,
    pub values: Vec<Vec<u8>>,
}

impl PartialAttribute {
    pub fn string_values(&self) -> Vec<&str> {
        self.values
            .iter()
            .filter_map(|v| std::str::from_utf8(v).ok())
            .collect()
    }

    pub fn first_string_value(&self) -> Option<&str> {
        self.values
            .first()
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    pub fn first_value(&self) -> Option<&[u8]> {
        self.values.first().map(|v| v.as_slice())
    }
}

impl SearchResultEntry {
    pub fn attr(&self, name: &str) -> Option<&PartialAttribute> {
        self.attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
    }

    pub fn first_value(&self, attr: &str) -> Option<&[u8]> {
        self.attr(attr).and_then(|a| a.first_value())
    }

    pub fn first_string_value(&self, attr: &str) -> Option<&str> {
        self.attr(attr).and_then(|a| a.first_string_value())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    pub dn: String,
    pub attr: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    pub dn: String,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    pub dn: String,
    pub changes: Vec<Modification>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modification {
    pub operation: ModifyOperation,
    pub attribute: PartialAttribute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifyOperation {
    Add = 0,
    Delete = 1,
    Replace = 2,
    Increment = 3,
}

impl TryFrom<i64> for ModifyOperation {
    type Error = ProtoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Add),
            1 => Ok(Self::Delete),
            2 => Ok(Self::Replace),
            3 => Ok(Self::Increment),
            n => Err(ProtoError::Protocol(format!(
                "invalid modify operation: {n}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyDnRequest {
    pub dn: String,
    pub new_rdn: String,
    pub delete_old_rdn: bool,
    pub new_superior: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    pub oid: String,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub oid: Option<String>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntermediateResponse {
    pub oid: Option<String>,
    pub value: Option<Vec<u8>>,
}

pub trait HasLdapResult {
    fn result(&self) -> &LdapResult;

    fn is_success(&self) -> bool {
        self.result().code.is_success()
    }

    fn is_referral(&self) -> bool {
        self.result().code.is_referral()
    }

    fn referral_urls(&self) -> &[String] {
        &self.result().referral
    }
}

impl HasLdapResult for LdapResult {
    fn result(&self) -> &LdapResult {
        self
    }
}

impl HasLdapResult for BindResponse {
    fn result(&self) -> &LdapResult {
        &self.result
    }
}

impl HasLdapResult for ExtendedResponse {
    fn result(&self) -> &LdapResult {
        &self.result
    }
}

// --- Encoding ---

impl LdapMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |msg| {
            msg.write_integer(i64::from(self.message_id.get()));
            encode_operation(msg, &self.operation);
            if !self.controls.is_empty() {
                encode_controls(msg, &self.controls);
            }
        });
        w.into_bytes()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        let mut r = BerReader::new(data);
        let (message_id, tag, value, controls) = r.read_sequence_lax(Tag::sequence(), |msg| {
            let message_id = MessageId::try_from(msg.read_integer()?)?;
            let (tag, value) = msg.read_element()?;
            let controls = if msg.peek_is(CONTROLS) {
                decode_controls(msg)?
            } else {
                Vec::new()
            };
            Ok((message_id, tag, value, controls))
        })?;
        r.finish()?;

        Ok(LdapMessage {
            message_id,
            operation: decode_operation(tag, value)?,
            controls,
        })
    }
}

fn encode_operation(w: &mut BerWriter, op: &LdapOperation) {
    match op {
        LdapOperation::BindRequest(req) => {
            w.write_sequence(BIND_REQUEST, |inner| {
                inner.write_integer(req.version);
                inner.write_bytes(req.name.as_bytes());
                match &req.authentication {
                    BindAuthentication::Simple(pw) => {
                        inner.write_octet_string(SIMPLE, pw);
                    }
                    BindAuthentication::Sasl {
                        mechanism,
                        credentials,
                    } => {
                        inner.write_sequence(SASL, |sasl| {
                            sasl.write_bytes(mechanism.as_bytes());
                            if let Some(creds) = credentials {
                                sasl.write_bytes(creds);
                            }
                        });
                    }
                }
            });
        }
        LdapOperation::BindResponse(resp) => {
            w.write_sequence(BIND_RESPONSE, |inner| {
                encode_ldap_result(inner, &resp.result);
                if let Some(creds) = &resp.server_sasl_creds {
                    inner.write_octet_string(SERVER_SASL_CREDS, creds);
                }
            });
        }
        LdapOperation::UnbindRequest => {
            w.write_octet_string(UNBIND_REQUEST, &[]);
        }
        LdapOperation::SearchRequest(req) => {
            w.write_sequence(SEARCH_REQUEST, |inner| {
                inner.write_bytes(req.base_dn.as_bytes());
                inner.write_enumerated(req.scope as i64);
                inner.write_enumerated(req.deref_aliases as i64);
                inner.write_integer(i64::from(req.size_limit));
                inner.write_integer(i64::from(req.time_limit));
                inner.write_boolean(req.types_only);
                req.filter.encode(inner);
                inner.write_sequence(Tag::sequence(), |attrs| {
                    for attr in &req.attributes {
                        attrs.write_bytes(attr.as_bytes());
                    }
                });
            });
        }
        LdapOperation::SearchResultEntry(entry) => {
            w.write_sequence(SEARCH_RESULT_ENTRY, |inner| {
                inner.write_bytes(entry.dn.as_bytes());
                encode_attributes(inner, &entry.attributes);
            });
        }
        LdapOperation::SearchResultDone(result) => {
            encode_result_operation(w, SEARCH_RESULT_DONE, result);
        }
        LdapOperation::SearchResultReference(urls) => {
            w.write_sequence(SEARCH_RESULT_REFERENCE, |inner| {
                for url in urls {
                    inner.write_bytes(url.as_bytes());
                }
            });
        }
        LdapOperation::ModifyRequest(req) => {
            w.write_sequence(MODIFY_REQUEST, |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_sequence(Tag::sequence(), |changes| {
                    for modification in &req.changes {
                        changes.write_sequence(Tag::sequence(), |change| {
                            change.write_enumerated(modification.operation as i64);
                            encode_partial_attribute(change, &modification.attribute);
                        });
                    }
                });
            });
        }
        LdapOperation::ModifyResponse(result) => {
            encode_result_operation(w, MODIFY_RESPONSE, result);
        }
        LdapOperation::AddRequest(req) => {
            w.write_sequence(ADD_REQUEST, |inner| {
                inner.write_bytes(req.dn.as_bytes());
                encode_attributes(inner, &req.attributes);
            });
        }
        LdapOperation::AddResponse(result) => {
            encode_result_operation(w, ADD_RESPONSE, result);
        }
        LdapOperation::DeleteRequest(dn) => {
            w.write_octet_string(DEL_REQUEST, dn.as_bytes());
        }
        LdapOperation::DeleteResponse(result) => {
            encode_result_operation(w, DEL_RESPONSE, result);
        }
        LdapOperation::ModifyDnRequest(req) => {
            w.write_sequence(MODIFY_DN_REQUEST, |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_bytes(req.new_rdn.as_bytes());
                inner.write_boolean(req.delete_old_rdn);
                if let Some(sup) = &req.new_superior {
                    inner.write_octet_string(NEW_SUPERIOR, sup.as_bytes());
                }
            });
        }
        LdapOperation::ModifyDnResponse(result) => {
            encode_result_operation(w, MODIFY_DN_RESPONSE, result);
        }
        LdapOperation::CompareRequest(req) => {
            w.write_sequence(COMPARE_REQUEST, |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_sequence(Tag::sequence(), |ava| {
                    ava.write_bytes(req.attr.as_bytes());
                    ava.write_bytes(&req.value);
                });
            });
        }
        LdapOperation::CompareResponse(result) => {
            encode_result_operation(w, COMPARE_RESPONSE, result);
        }
        LdapOperation::AbandonRequest(id) => {
            let bytes = ldap_client_ber::writer::encode_i64_bytes(i64::from(id.get()));
            w.write_octet_string(ABANDON_REQUEST, &bytes);
        }
        LdapOperation::ExtendedRequest(req) => {
            w.write_sequence(EXTENDED_REQUEST, |inner| {
                inner.write_octet_string(REQUEST_NAME, req.oid.as_bytes());
                if let Some(val) = &req.value {
                    inner.write_octet_string(REQUEST_VALUE, val);
                }
            });
        }
        LdapOperation::ExtendedResponse(resp) => {
            w.write_sequence(EXTENDED_RESPONSE, |inner| {
                encode_ldap_result(inner, &resp.result);
                if let Some(oid) = &resp.oid {
                    inner.write_octet_string(RESPONSE_NAME, oid.as_bytes());
                }
                if let Some(val) = &resp.value {
                    inner.write_octet_string(RESPONSE_VALUE, val);
                }
            });
        }
        LdapOperation::IntermediateResponse(resp) => {
            w.write_sequence(INTERMEDIATE_RESPONSE, |inner| {
                if let Some(oid) = &resp.oid {
                    inner.write_octet_string(INTERMEDIATE_NAME, oid.as_bytes());
                }
                if let Some(val) = &resp.value {
                    inner.write_octet_string(INTERMEDIATE_VALUE, val);
                }
            });
        }
    }
}

fn encode_result_operation(w: &mut BerWriter, tag: Tag, result: &LdapResult) {
    w.write_sequence(tag, |inner| encode_ldap_result(inner, result));
}

fn encode_ldap_result(w: &mut BerWriter, result: &LdapResult) {
    w.write_enumerated(i64::from(result.code.code()));
    w.write_bytes(result.matched_dn.as_bytes());
    w.write_bytes(result.diagnostic_message.as_bytes());
    if !result.referral.is_empty() {
        w.write_sequence(REFERRAL, |urls| {
            for url in &result.referral {
                urls.write_bytes(url.as_bytes());
            }
        });
    }
}

fn encode_attributes(w: &mut BerWriter, attributes: &[PartialAttribute]) {
    w.write_sequence(Tag::sequence(), |attrs| {
        for attr in attributes {
            encode_partial_attribute(attrs, attr);
        }
    });
}

fn encode_partial_attribute(w: &mut BerWriter, attr: &PartialAttribute) {
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_bytes(attr.name.as_bytes());
        inner.write_sequence(Tag::set(), |vals| {
            for val in &attr.values {
                vals.write_bytes(val);
            }
        });
    });
}

// --- Decoding ---

fn decode_operation(tag: Tag, value: &[u8]) -> Result<LdapOperation, ProtoError> {
    let mut r = BerReader::new(value);

    let operation = match tag {
        BIND_REQUEST => {
            let version = r.read_integer()?;
            let name = to_utf8(r.read_octet_string()?)?;
            let authentication = match r.peek_tag()? {
                SIMPLE => {
                    BindAuthentication::Simple(Zeroizing::new(r.read_implicit(SIMPLE)?.to_vec()))
                }
                SASL => r.read_sequence(SASL, |sasl| {
                    let mechanism = to_utf8(sasl.read_octet_string()?)?;
                    let credentials = if sasl.is_empty() {
                        None
                    } else {
                        Some(Zeroizing::new(sasl.read_octet_string()?.to_vec()))
                    };
                    Ok(BindAuthentication::Sasl {
                        mechanism,
                        credentials,
                    })
                })?,
                actual => {
                    return Err(BerError::UnexpectedTag {
                        expected: SIMPLE,
                        actual,
                    }
                    .into());
                }
            };
            LdapOperation::BindRequest(BindRequest {
                version,
                name,
                authentication,
            })
        }
        BIND_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            let server_sasl_creds = if r.peek_is(SERVER_SASL_CREDS) {
                Some(r.read_implicit(SERVER_SASL_CREDS)?.to_vec())
            } else {
                None
            };
            LdapOperation::BindResponse(BindResponse {
                result,
                server_sasl_creds,
            })
        }
        UNBIND_REQUEST => LdapOperation::UnbindRequest,
        SEARCH_REQUEST => {
            let base_dn = to_utf8(r.read_octet_string()?)?;
            let scope = SearchScope::try_from(r.read_enumerated()?)?;
            let deref_aliases = DerefAliases::try_from(r.read_enumerated()?)?;
            let size_limit = to_i32(r.read_integer()?, "size limit")?;
            let time_limit = to_i32(r.read_integer()?, "time limit")?;
            let types_only = r.read_boolean()?;
            let filter = Filter::decode(&mut r)?;
            let attributes = r.read_sequence(Tag::sequence(), |attrs| {
                attrs.read_each(|attr| to_utf8(attr.read_octet_string()?))
            })?;
            LdapOperation::SearchRequest(SearchRequest {
                base_dn,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            })
        }
        SEARCH_RESULT_ENTRY => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let attributes = decode_attributes(&mut r)?;
            LdapOperation::SearchResultEntry(SearchResultEntry { dn, attributes })
        }
        SEARCH_RESULT_DONE => LdapOperation::SearchResultDone(decode_ldap_result(&mut r)?),
        SEARCH_RESULT_REFERENCE => {
            LdapOperation::SearchResultReference(r.read_each(|r| to_utf8(r.read_octet_string()?))?)
        }
        MODIFY_REQUEST => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let changes = r.read_sequence(Tag::sequence(), |changes| {
                changes.read_each(|change| {
                    change.read_sequence(Tag::sequence(), |change| {
                        let operation = change.read_enumerated()?;
                        let attribute = decode_partial_attribute(change)?;
                        Ok((operation, attribute))
                    })
                })
            })?;
            let changes = changes
                .into_iter()
                .map(|(operation, attribute)| {
                    Ok(Modification {
                        operation: ModifyOperation::try_from(operation)?,
                        attribute,
                    })
                })
                .collect::<Result<_, ProtoError>>()?;
            LdapOperation::ModifyRequest(ModifyRequest { dn, changes })
        }
        MODIFY_RESPONSE => LdapOperation::ModifyResponse(decode_ldap_result(&mut r)?),
        ADD_REQUEST => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let attributes = decode_attributes(&mut r)?;
            LdapOperation::AddRequest(AddRequest { dn, attributes })
        }
        ADD_RESPONSE => LdapOperation::AddResponse(decode_ldap_result(&mut r)?),
        DEL_REQUEST => LdapOperation::DeleteRequest(to_utf8(value)?),
        DEL_RESPONSE => LdapOperation::DeleteResponse(decode_ldap_result(&mut r)?),
        MODIFY_DN_REQUEST => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let new_rdn = to_utf8(r.read_octet_string()?)?;
            let delete_old_rdn = r.read_boolean()?;
            let new_superior = if r.peek_is(NEW_SUPERIOR) {
                Some(to_utf8(r.read_implicit(NEW_SUPERIOR)?)?)
            } else {
                None
            };
            LdapOperation::ModifyDnRequest(ModifyDnRequest {
                dn,
                new_rdn,
                delete_old_rdn,
                new_superior,
            })
        }
        MODIFY_DN_RESPONSE => LdapOperation::ModifyDnResponse(decode_ldap_result(&mut r)?),
        COMPARE_REQUEST => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let (attr, value) = r.read_sequence(Tag::sequence(), |ava| {
                Ok((
                    to_utf8(ava.read_octet_string()?)?,
                    ava.read_octet_string()?.to_vec(),
                ))
            })?;
            LdapOperation::CompareRequest(CompareRequest { dn, attr, value })
        }
        COMPARE_RESPONSE => LdapOperation::CompareResponse(decode_ldap_result(&mut r)?),
        ABANDON_REQUEST => {
            LdapOperation::AbandonRequest(MessageId::try_from(decode_i64_bytes(value)?)?)
        }
        EXTENDED_REQUEST => {
            let oid = to_utf8(r.read_implicit(REQUEST_NAME)?)?;
            let value = if r.peek_is(REQUEST_VALUE) {
                Some(r.read_implicit(REQUEST_VALUE)?.to_vec())
            } else {
                None
            };
            LdapOperation::ExtendedRequest(ExtendedRequest { oid, value })
        }
        EXTENDED_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            let mut oid = None;
            let mut value = None;
            while !r.is_empty() {
                match r.peek_tag()? {
                    RESPONSE_NAME => oid = Some(to_utf8(r.read_implicit(RESPONSE_NAME)?)?),
                    RESPONSE_VALUE => value = Some(r.read_implicit(RESPONSE_VALUE)?.to_vec()),
                    _ => {
                        r.read_element()?;
                    }
                }
            }
            LdapOperation::ExtendedResponse(ExtendedResponse { result, oid, value })
        }
        INTERMEDIATE_RESPONSE => {
            let mut oid = None;
            let mut value = None;
            while !r.is_empty() {
                match r.peek_tag()? {
                    INTERMEDIATE_NAME => {
                        oid = Some(to_utf8(r.read_implicit(INTERMEDIATE_NAME)?)?);
                    }
                    INTERMEDIATE_VALUE => {
                        value = Some(r.read_implicit(INTERMEDIATE_VALUE)?.to_vec());
                    }
                    _ => {
                        r.read_element()?;
                    }
                }
            }
            LdapOperation::IntermediateResponse(IntermediateResponse { oid, value })
        }
        other => {
            return Err(ProtoError::Protocol(format!(
                "unknown operation tag: {other:?}"
            )));
        }
    };
    Ok(operation)
}

fn to_i32(value: i64, what: &str) -> Result<i32, ProtoError> {
    i32::try_from(value).map_err(|_| ProtoError::Protocol(format!("{what} out of range: {value}")))
}

fn decode_ldap_result(r: &mut BerReader<'_>) -> Result<LdapResult, ProtoError> {
    let code = ResultCode::from_i64(r.read_enumerated()?);
    let matched_dn = to_utf8(r.read_octet_string()?)?;
    // Diagnostic messages use lossy conversion: some servers produce non-UTF-8 here.
    let diagnostic_message = String::from_utf8_lossy(r.read_octet_string()?).into_owned();

    let referral = if r.peek_is(REFERRAL) {
        r.read_sequence(REFERRAL, |urls| {
            urls.read_each(|url| to_utf8(url.read_octet_string()?))
        })?
    } else {
        Vec::new()
    };

    Ok(LdapResult {
        code,
        matched_dn,
        diagnostic_message,
        referral,
    })
}

fn decode_attributes(r: &mut BerReader<'_>) -> Result<Vec<PartialAttribute>, BerError> {
    r.read_sequence(Tag::sequence(), |attrs| {
        attrs.read_each(decode_partial_attribute)
    })
}

fn decode_partial_attribute(r: &mut BerReader<'_>) -> Result<PartialAttribute, BerError> {
    r.read_sequence(Tag::sequence(), |attr| {
        let name = to_utf8(attr.read_octet_string()?)?;
        let values = attr.read_sequence(Tag::set(), |vals| {
            vals.read_each(|val| Ok(val.read_octet_string()?.to_vec()))
        })?;
        Ok(PartialAttribute { name, values })
    })
}

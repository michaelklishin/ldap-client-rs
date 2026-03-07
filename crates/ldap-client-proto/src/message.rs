// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerReader, BerWriter, Class};
use zeroize::Zeroizing;

use crate::ProtoError;
use crate::controls::Control;
use crate::filter::Filter;
use crate::result_code::ResultCode;

/// LDAP message IDs are positive i32 values. 0 is reserved for unsolicited notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(pub i32);

/// Top-level LDAP PDU (RFC 4511 §4.1.1).
#[derive(Debug, Clone)]
pub struct LdapMessage {
    pub message_id: MessageId,
    pub operation: LdapOperation,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone)]
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

// Application tags from RFC 4511.
const APP_BIND_REQUEST: u32 = 0;
const APP_BIND_RESPONSE: u32 = 1;
const APP_UNBIND_REQUEST: u32 = 2;
const APP_SEARCH_REQUEST: u32 = 3;
const APP_SEARCH_RESULT_ENTRY: u32 = 4;
const APP_SEARCH_RESULT_DONE: u32 = 5;
const APP_MODIFY_REQUEST: u32 = 6;
const APP_MODIFY_RESPONSE: u32 = 7;
const APP_ADD_REQUEST: u32 = 8;
const APP_ADD_RESPONSE: u32 = 9;
const APP_DEL_REQUEST: u32 = 10;
const APP_DEL_RESPONSE: u32 = 11;
const APP_MODIFY_DN_REQUEST: u32 = 12;
const APP_MODIFY_DN_RESPONSE: u32 = 13;
const APP_COMPARE_REQUEST: u32 = 14;
const APP_COMPARE_RESPONSE: u32 = 15;
const APP_ABANDON_REQUEST: u32 = 16;
const APP_SEARCH_RESULT_REFERENCE: u32 = 19;
const APP_EXTENDED_REQUEST: u32 = 23;
const APP_EXTENDED_RESPONSE: u32 = 24;
const APP_INTERMEDIATE_RESPONSE: u32 = 25;

// --- Request/Response types ---

#[derive(Debug, Clone)]
pub struct BindRequest {
    pub version: i64,
    pub name: String,
    pub authentication: BindAuthentication,
}

#[derive(Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct CompareRequest {
    pub dn: String,
    pub attr: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AddRequest {
    pub dn: String,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Debug, Clone)]
pub struct ModifyRequest {
    pub dn: String,
    pub changes: Vec<Modification>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct ModifyDnRequest {
    pub dn: String,
    pub new_rdn: String,
    pub delete_old_rdn: bool,
    pub new_superior: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExtendedRequest {
    pub oid: String,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub oid: Option<String>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
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
            msg.write_integer(self.message_id.0 as i64);
            encode_operation(msg, &self.operation);
            if !self.controls.is_empty() {
                crate::controls::encode_controls(msg, &self.controls);
            }
        });
        w.into_bytes()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        let mut r = BerReader::new(data);
        let (message_id, op_tag, op_value, controls) =
            r.read_sequence_lax(Tag::sequence(), |msg| {
                let raw_id = msg.read_integer()?;
                if raw_id < 0 || raw_id > i32::MAX as i64 {
                    return Err(ldap_client_ber::BerError::InvalidInteger);
                }
                let message_id = MessageId(raw_id as i32);
                let (tag, value) = msg.read_element()?;
                let op_value = value.to_vec();

                let mut controls = Vec::new();
                if !msg.is_empty() {
                    let peek = msg.peek_tag()?;
                    if peek.class == Class::Context && peek.number == 0 && peek.constructed {
                        controls = crate::controls::decode_controls(msg)?;
                    }
                }

                Ok((message_id, tag, op_value, controls))
            })?;

        let operation = decode_operation(op_tag, &op_value)?;

        Ok(LdapMessage {
            message_id,
            operation,
            controls,
        })
    }
}

fn encode_operation(w: &mut BerWriter, op: &LdapOperation) {
    match op {
        LdapOperation::BindRequest(req) => {
            w.write_sequence(Tag::application(APP_BIND_REQUEST), |inner| {
                inner.write_integer(req.version);
                inner.write_bytes(req.name.as_bytes());
                match &req.authentication {
                    BindAuthentication::Simple(pw) => {
                        inner.write_octet_string(Tag::context(0), pw);
                    }
                    BindAuthentication::Sasl {
                        mechanism,
                        credentials,
                    } => {
                        inner.write_sequence(Tag::context_constructed(3), |sasl| {
                            sasl.write_bytes(mechanism.as_bytes());
                            if let Some(creds) = credentials {
                                sasl.write_bytes(creds);
                            }
                        });
                    }
                }
            });
        }
        LdapOperation::UnbindRequest => {
            // UnbindRequest is [APPLICATION 2] NULL-like (no content).
            w.write_octet_string(Tag::application_primitive(APP_UNBIND_REQUEST), &[]);
        }
        LdapOperation::SearchRequest(req) => {
            w.write_sequence(Tag::application(APP_SEARCH_REQUEST), |inner| {
                inner.write_bytes(req.base_dn.as_bytes());
                inner.write_enumerated(req.scope as i64);
                inner.write_enumerated(req.deref_aliases as i64);
                inner.write_integer(req.size_limit as i64);
                inner.write_integer(req.time_limit as i64);
                inner.write_boolean(req.types_only);
                req.filter.encode(inner);
                inner.write_sequence(Tag::sequence(), |attrs| {
                    for attr in &req.attributes {
                        attrs.write_bytes(attr.as_bytes());
                    }
                });
            });
        }
        LdapOperation::CompareRequest(req) => {
            w.write_sequence(Tag::application(APP_COMPARE_REQUEST), |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_sequence(Tag::sequence(), |ava| {
                    ava.write_bytes(req.attr.as_bytes());
                    ava.write_bytes(&req.value);
                });
            });
        }
        LdapOperation::AddRequest(req) => {
            w.write_sequence(Tag::application(APP_ADD_REQUEST), |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_sequence(Tag::sequence(), |attrs| {
                    for attr in &req.attributes {
                        encode_partial_attribute(attrs, attr);
                    }
                });
            });
        }
        LdapOperation::DeleteRequest(dn) => {
            // DelRequest is [APPLICATION 10] LDAPDN (primitive octet string).
            w.write_octet_string(Tag::application_primitive(APP_DEL_REQUEST), dn.as_bytes());
        }
        LdapOperation::ModifyRequest(req) => {
            w.write_sequence(Tag::application(APP_MODIFY_REQUEST), |inner| {
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
        LdapOperation::ModifyDnRequest(req) => {
            w.write_sequence(Tag::application(APP_MODIFY_DN_REQUEST), |inner| {
                inner.write_bytes(req.dn.as_bytes());
                inner.write_bytes(req.new_rdn.as_bytes());
                inner.write_boolean(req.delete_old_rdn);
                if let Some(sup) = &req.new_superior {
                    inner.write_octet_string(Tag::context(0), sup.as_bytes());
                }
            });
        }
        LdapOperation::AbandonRequest(id) => {
            // AbandonRequest is [APPLICATION 16] MessageID (implicit integer).
            let bytes = ldap_client_ber::writer::encode_i64_bytes(id.0 as i64);
            w.write_octet_string(Tag::application_primitive(APP_ABANDON_REQUEST), &bytes);
        }
        LdapOperation::ExtendedRequest(req) => {
            w.write_sequence(Tag::application(APP_EXTENDED_REQUEST), |inner| {
                inner.write_octet_string(Tag::context(0), req.oid.as_bytes());
                if let Some(val) = &req.value {
                    inner.write_octet_string(Tag::context(1), val);
                }
            });
        }
        _ => unreachable!("attempted to encode a response operation"),
    }
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

fn to_utf8(bytes: &[u8]) -> Result<String, ldap_client_ber::BerError> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| ldap_client_ber::BerError::InvalidUtf8)
}

fn decode_operation(tag: Tag, value: &[u8]) -> Result<LdapOperation, ProtoError> {
    if tag.class != Class::Application {
        return Err(ProtoError::Protocol(format!(
            "expected APPLICATION tag, got {tag:?}"
        )));
    }

    let mut r = BerReader::new(value);

    match tag.number {
        APP_BIND_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            let server_sasl_creds = if !r.is_empty() {
                let tag = r.peek_tag()?;
                if tag.class == Class::Context && tag.number == 7 {
                    Some(r.read_tagged_implicit_octet_string(7)?.to_vec())
                } else {
                    None
                }
            } else {
                None
            };
            Ok(LdapOperation::BindResponse(BindResponse {
                result,
                server_sasl_creds,
            }))
        }
        APP_SEARCH_RESULT_ENTRY => {
            let dn = to_utf8(r.read_octet_string()?)?;
            let mut attributes = Vec::new();
            r.read_sequence(Tag::sequence(), |attrs| {
                while !attrs.is_empty() {
                    attrs.read_sequence(Tag::sequence(), |attr| {
                        let name = to_utf8(attr.read_octet_string()?)?;
                        let mut values = Vec::new();
                        attr.read_sequence(Tag::set(), |vals| {
                            while !vals.is_empty() {
                                values.push(vals.read_octet_string()?.to_vec());
                            }
                            Ok(())
                        })?;
                        attributes.push(PartialAttribute { name, values });
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
            Ok(LdapOperation::SearchResultEntry(SearchResultEntry {
                dn,
                attributes,
            }))
        }
        APP_SEARCH_RESULT_DONE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::SearchResultDone(result))
        }
        APP_SEARCH_RESULT_REFERENCE => {
            let mut urls = Vec::new();
            while !r.is_empty() {
                urls.push(to_utf8(r.read_octet_string()?)?);

            }
            Ok(LdapOperation::SearchResultReference(urls))
        }
        APP_MODIFY_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::ModifyResponse(result))
        }
        APP_ADD_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::AddResponse(result))
        }
        APP_DEL_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::DeleteResponse(result))
        }
        APP_MODIFY_DN_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::ModifyDnResponse(result))
        }
        APP_COMPARE_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            Ok(LdapOperation::CompareResponse(result))
        }
        APP_EXTENDED_RESPONSE => {
            let result = decode_ldap_result(&mut r)?;
            let mut oid = None;
            let mut ext_value = None;
            while !r.is_empty() {
                let tag = r.peek_tag()?;
                match (tag.class, tag.number) {
                    (Class::Context, 10) => {
                        oid = Some(to_utf8(r.read_tagged_implicit_octet_string(10)?)?);
                    }
                    (Class::Context, 11) => {
                        ext_value = Some(r.read_tagged_implicit_octet_string(11)?.to_vec());
                    }
                    _ => {
                        r.read_element()?;
                    }
                }
            }
            Ok(LdapOperation::ExtendedResponse(ExtendedResponse {
                result,
                oid,
                value: ext_value,
            }))
        }
        APP_INTERMEDIATE_RESPONSE => {
            let mut oid = None;
            let mut value = None;
            while !r.is_empty() {
                let tag = r.peek_tag()?;
                match (tag.class, tag.number) {
                    (Class::Context, 0) => {
                        oid = Some(to_utf8(r.read_tagged_implicit_octet_string(0)?)?);
                    }
                    (Class::Context, 1) => {
                        value = Some(r.read_tagged_implicit_octet_string(1)?.to_vec());
                    }
                    _ => {
                        r.read_element()?;
                    }
                }
            }
            Ok(LdapOperation::IntermediateResponse(IntermediateResponse {
                oid,
                value,
            }))
        }
        n => Err(ProtoError::Protocol(format!(
            "unknown application tag: {n}"
        ))),
    }
}

fn decode_ldap_result(r: &mut BerReader<'_>) -> Result<LdapResult, ProtoError> {
    let code = ResultCode::from_i64(r.read_enumerated()?);
    let matched_dn = to_utf8(r.read_octet_string()?)?;
    // Diagnostic messages use lossy conversion: some servers produce non-UTF-8 here.
    let diagnostic_message = String::from_utf8_lossy(r.read_octet_string()?).into_owned();

    let mut referral = Vec::new();
    if !r.is_empty() {
        let tag = r.peek_tag()?;
        if tag.class == Class::Context && tag.number == 3 {
            r.read_sequence(Tag::context_constructed(3), |inner| {
                while !inner.is_empty() {
                    referral.push(to_utf8(inner.read_octet_string()?)?);

                }
                Ok(())
            })?;
        }
    }

    Ok(LdapResult {
        code,
        matched_dn,
        diagnostic_message,
        referral,
    })
}

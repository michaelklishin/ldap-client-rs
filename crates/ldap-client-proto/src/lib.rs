// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod controls;
pub mod dn;
pub mod filter;
pub mod message;
pub mod result_code;
mod syntax;
pub mod url;

pub use controls::{
    Control, ControlType, DOMAIN_SCOPE_OID, DomainScopeControl, MANAGE_DSA_IT_OID,
    ManageDsaItControl, PAGED_RESULTS_OID, PagedResultsControl, RequestControl, ResponseControl,
    SERVER_SORT_OID, SERVER_SORT_REQUEST_OID, SERVER_SORT_RESPONSE_OID, SortKey, SortKeyList,
    SortResult,
};
pub use dn::{AttributeValue, Dn, Rdn, escape_dn_value};
pub use filter::{AssertionValue, Filter};
pub use message::*;
pub use result_code::ResultCode;
pub use url::{LdapScheme, LdapUrl};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    #[error("BER error: {0}")]
    Ber(#[from] ldap_client_ber::BerError),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("filter parse error: {0}")]
    FilterParse(String),
}

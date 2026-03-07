// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod controls;
pub mod dn;
pub mod filter;
pub mod message;
pub mod result_code;
pub mod url;

pub use controls::{
    Control, DOMAIN_SCOPE_OID, DomainScopeControl, MANAGE_DSA_IT_OID, ManageDsaItControl,
    PAGED_RESULTS_OID, PagedResultsControl, SERVER_SORT_OID, SERVER_SORT_REQUEST_OID,
    SERVER_SORT_RESPONSE_OID, SortKey, SortKeyList, SortResult,
};
pub use dn::{Dn, Rdn, escape_dn_value};
pub use filter::Filter;
pub use message::*;
pub use result_code::ResultCode;
pub use url::{LdapScheme, LdapUrl};

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("BER error: {0}")]
    Ber(#[from] ldap_client_ber::BerError),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("filter parse error: {0}")]
    FilterParse(String),
}

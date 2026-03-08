// SPDX-License-Identifier: MIT OR Apache-2.0

mod client;
mod conn;
mod error;
pub mod tls_config;

pub use client::{
    BindCredentials, Client, ClientBuilder, PagedSearch, ReferralPolicy, SearchResult, Transport,
    UnsolicitedHandler, parse_range_option,
};
#[cfg(feature = "danger-disable-verify")]
pub use conn::danger_no_verify_tls_config;
pub use error::Error;
pub use tls_config::{TlsConfig, TlsVersion, TrustAnchors};

pub use ldap_client_proto::{
    Control, DOMAIN_SCOPE_OID, DerefAliases, Dn, DomainScopeControl, ExtendedResponse, Filter,
    HasLdapResult, LdapUrl, MANAGE_DSA_IT_OID, ManageDsaItControl, MessageId, Modification,
    ModifyOperation, PAGED_RESULTS_OID, PagedResultsControl, PartialAttribute, Rdn, ResultCode,
    SERVER_SORT_OID, SERVER_SORT_REQUEST_OID, SERVER_SORT_RESPONSE_OID, SearchResultEntry,
    SearchScope, SortKey, SortKeyList, SortResult, escape_dn_value,
};
pub use secrecy::SecretString;
pub use zeroize::Zeroizing;

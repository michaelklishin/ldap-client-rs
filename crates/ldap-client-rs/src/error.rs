// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::ResultCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("BER error: {0}")]
    Ber(#[from] ldap_client_ber::BerError),

    #[error("protocol error: {0}")]
    Proto(#[from] ldap_client_proto::ProtoError),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("LDAP error: {code} - {message}")]
    Ldap {
        code: ResultCode,
        message: String,
        matched_dn: String,
    },

    #[error("referral to {}", urls.join(", "))]
    Referral {
        result: ldap_client_proto::LdapResult,
        urls: Vec<String>,
    },

    #[error("connection closed")]
    ConnectionClosed,

    #[error("timeout")]
    Timeout,

    #[error("StartTLS failed: {0}")]
    StartTls(String),

    #[error("search returned multiple results when at most one was expected")]
    MultipleResults,

    #[error("referral hop limit exceeded")]
    ReferralHopLimitExceeded,
}

impl Error {
    pub fn ldap(result: &ldap_client_proto::LdapResult) -> Self {
        Self::Ldap {
            code: result.code,
            message: result.diagnostic_message.clone(),
            matched_dn: result.matched_dn.clone(),
        }
    }

    pub fn result_code(&self) -> Option<ResultCode> {
        match self {
            Self::Ldap { code, .. } => Some(*code),
            Self::Referral { result, .. } => Some(result.code),
            _ => None,
        }
    }
}

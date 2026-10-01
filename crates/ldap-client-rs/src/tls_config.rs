// SPDX-License-Identifier: MIT OR Apache-2.0

//! Convenience types for building a [`rustls::ClientConfig`] without
//! touching Rustls directly.

use std::sync::Arc;

use rustls::client::WantsClientCert;
use rustls::{ClientConfig, ConfigBuilder, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Where to source trust anchors (root CA certificates).
#[non_exhaustive]
pub enum TrustAnchors {
    /// Use the system/Mozilla roots **plus** any additional certs provided.
    SystemPlusAdditional(Vec<CertificateDer<'static>>),
    /// Trust **only** the supplied certificates (no system roots).
    ExplicitOnly(Vec<CertificateDer<'static>>),
}

/// Minimum TLS version to accept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    #[default]
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// High-level TLS configuration that can be converted into a
/// [`rustls::ClientConfig`] via [`build`](Self::build).
#[non_exhaustive]
pub struct TlsConfig {
    trust_anchors: TrustAnchors,
    client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    min_tls_version: TlsVersion,
    #[cfg(feature = "danger-disable-verify")]
    danger_disable_verification: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            trust_anchors: TrustAnchors::SystemPlusAdditional(Vec::new()),
            client_cert: None,
            min_tls_version: TlsVersion::default(),
            #[cfg(feature = "danger-disable-verify")]
            danger_disable_verification: false,
        }
    }
}

impl TlsConfig {
    pub fn trust_anchors(mut self, anchors: TrustAnchors) -> Self {
        self.trust_anchors = anchors;
        self
    }

    pub fn client_certificate(
        mut self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert = Some((chain, key));
        self
    }

    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    #[cfg(feature = "danger-disable-verify")]
    pub fn danger_disable_verification(mut self) -> Self {
        self.danger_disable_verification = true;
        self
    }

    /// Build a [`rustls::ClientConfig`] from these settings.
    pub fn build(self) -> Result<Arc<ClientConfig>, rustls::Error> {
        #[cfg(feature = "danger-disable-verify")]
        if self.danger_disable_verification {
            let config = crate::conn::danger_no_verify_tls_config();
            return Ok(Arc::new(config));
        }

        let root_store = match self.trust_anchors {
            TrustAnchors::SystemPlusAdditional(extra) => {
                let mut store = webpki_root_store();
                for cert in extra {
                    store.add(cert)?;
                }
                store
            }
            TrustAnchors::ExplicitOnly(certs) => {
                let mut store = RootCertStore::empty();
                for cert in certs {
                    store.add(cert)?;
                }
                store
            }
        };

        let builder = config_builder(self.min_tls_version, root_store);
        let config = match self.client_cert {
            Some((certs, key)) => builder.with_client_auth_cert(certs, key)?,
            None => builder.with_no_client_auth(),
        };

        Ok(Arc::new(config))
    }
}

pub(crate) fn default_client_config() -> ClientConfig {
    config_builder(TlsVersion::default(), webpki_root_store()).with_no_client_auth()
}

fn webpki_root_store() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

/// The one place a minimum version becomes a set of protocol versions.
fn config_builder(
    min_version: TlsVersion,
    roots: RootCertStore,
) -> ConfigBuilder<ClientConfig, WantsClientCert> {
    let versions: &[&rustls::SupportedProtocolVersion] = match min_version {
        TlsVersion::Tls13 => &[&rustls::version::TLS13],
        TlsVersion::Tls12 => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };
    ClientConfig::builder_with_protocol_versions(versions).with_root_certificates(roots)
}

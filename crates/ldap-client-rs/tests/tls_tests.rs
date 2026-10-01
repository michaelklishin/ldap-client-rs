// SPDX-License-Identifier: MIT OR Apache-2.0

mod common;

use common::{MockServer, Step, TestCertificate, bind_response};
use ldap_client::tls_config::{TlsConfig, TlsVersion, TrustAnchors};
use ldap_client::{Client, ClientBuilder, Error, ResultCode, SecretString, Transport};

async fn connect_over_tls(
    server: &MockServer,
    certificate: &TestCertificate,
    config: TlsConfig,
) -> Result<Client, Error> {
    ClientBuilder::new("localhost", server.port())
        .transport(Transport::Tls)
        .timeout(std::time::Duration::from_secs(5))
        .tls(config.trust_anchors(TrustAnchors::ExplicitOnly(vec![certificate.der.clone()])))?
        .connect()
        .await
}

async fn tls_server(
    certificate: &TestCertificate,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> MockServer {
    MockServer::start_connections(
        vec![vec![Step::respond(bind_response(ResultCode::Success))]],
        Some(certificate.server_config(versions)),
    )
    .await
}

#[tokio::test]
async fn the_default_minimum_connects_to_a_tls12_only_server() {
    let certificate = TestCertificate::new();
    let server = tls_server(&certificate, &[&rustls::version::TLS12]).await;

    let client = connect_over_tls(&server, &certificate, TlsConfig::default())
        .await
        .unwrap();
    client
        .simple_bind("cn=a", &SecretString::from("pw"))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_default_minimum_connects_to_a_tls13_server() {
    let certificate = TestCertificate::new();
    let server = tls_server(&certificate, &[&rustls::version::TLS13]).await;

    let client = connect_over_tls(&server, &certificate, TlsConfig::default())
        .await
        .unwrap();
    client
        .simple_bind("cn=a", &SecretString::from("pw"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_tls13_minimum_refuses_a_tls12_only_server() {
    let certificate = TestCertificate::new();
    let server = tls_server(&certificate, &[&rustls::version::TLS12]).await;

    let config = TlsConfig::default().min_tls_version(TlsVersion::Tls13);
    assert!(
        connect_over_tls(&server, &certificate, config)
            .await
            .is_err()
    );
}

#[test]
fn the_default_minimum_version_is_tls12() {
    assert_eq!(TlsVersion::default(), TlsVersion::Tls12);
}

// SPDX-License-Identifier: MIT OR Apache-2.0

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    MockServer, Step, TestCertificate, bind_response, connect_plain, entry, extended_response,
    result, search_done,
};
use ldap_client::tls_config::{TlsConfig, TrustAnchors};
use ldap_client::{
    Client, ClientBuilder, Error, Filter, ResultCode, SearchScope, SecretString, Transport,
};
use ldap_client_proto::{
    ExtendedResponse, LdapMessage, LdapOperation, MessageId, NOTICE_OF_DISCONNECTION_OID,
    STARTTLS_OID,
};

fn password() -> SecretString {
    SecretString::from("secret")
}

async fn connect_with_timeout(server: &MockServer, timeout: Duration) -> Client {
    ClientBuilder::new(server.host(), server.port())
        .request_timeout(timeout)
        .connect()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_late_response_after_a_timeout_is_not_read_as_the_next_answer() {
    let server = MockServer::start(vec![
        Step::respond(bind_response(ResultCode::Success)).delayed(Duration::from_millis(300)),
        Step::respond(bind_response(ResultCode::InvalidCredentials)),
    ])
    .await;
    let client = connect_with_timeout(&server, Duration::from_millis(200)).await;

    let first = client.simple_bind("cn=a", &password()).await.unwrap_err();
    assert!(matches!(first, Error::Timeout), "{first:?}");
    assert!(!client.is_connected());

    let second = client.simple_bind("cn=a", &password()).await.unwrap_err();
    assert!(matches!(second, Error::ConnectionClosed), "{second:?}");
    assert_eq!(server.received().await.len(), 1);
}

#[tokio::test]
async fn a_dropped_request_breaks_the_connection() {
    let server = MockServer::start(vec![
        Step::respond(entry("cn=a"))
            .and(search_done(ResultCode::Success))
            .delayed(Duration::from_millis(300)),
    ])
    .await;
    let client = connect_plain(&server).await;

    let search = client.search(
        "dc=x",
        SearchScope::WholeSubtree,
        Filter::present("cn"),
        vec![],
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), search)
            .await
            .is_err()
    );
    assert!(!client.is_connected());

    let err = client.simple_bind("cn=a", &password()).await.unwrap_err();
    assert!(matches!(err, Error::ConnectionClosed), "{err:?}");
}

#[tokio::test]
async fn an_ldap_error_keeps_the_connection_open() {
    let server = MockServer::start(vec![
        Step::respond(LdapOperation::DeleteResponse(result(
            ResultCode::NoSuchObject,
        ))),
        Step::respond(bind_response(ResultCode::Success)),
    ])
    .await;
    let client = connect_plain(&server).await;

    let err = client.delete("cn=gone,dc=x").await.unwrap_err();
    assert_eq!(err.result_code(), Some(ResultCode::NoSuchObject));
    assert!(client.is_connected());
    client.simple_bind("cn=a", &password()).await.unwrap();
}

#[tokio::test]
async fn unbind_closes_the_connection() {
    let server = MockServer::start(vec![Step::silent()]).await;
    let client = connect_plain(&server).await;

    client.unbind().await.unwrap();
    assert!(!client.is_connected());
    let err = client.delete("cn=a").await.unwrap_err();
    assert!(matches!(err, Error::ConnectionClosed), "{err:?}");
    assert_eq!(
        server.received_operations().await,
        vec![LdapOperation::UnbindRequest]
    );
}

#[tokio::test]
async fn an_answer_with_another_message_id_breaks_the_connection() {
    let server = MockServer::start(vec![
        Step::respond(bind_response(ResultCode::Success)).with_id(7),
    ])
    .await;
    let client = connect_plain(&server).await;

    let err = client.simple_bind("cn=a", &password()).await.unwrap_err();
    assert!(matches!(err, Error::Proto(_)), "{err:?}");
    assert!(err.to_string().contains("message 1"), "{err}");
    assert!(!client.is_connected());
}

#[tokio::test]
async fn an_unsolicited_notification_invokes_the_handler() {
    let custom_oid = "1.2.3.4.5.6.7.8.9";
    let server = MockServer::start(vec![
        Step::respond(extended_response(ResultCode::Success, Some(custom_oid)))
            .with_id(0)
            .and(bind_response(ResultCode::Success)),
    ])
    .await;

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let client = ClientBuilder::new(server.host(), server.port())
        .on_unsolicited_notification(move |resp: &ExtendedResponse| {
            if let Some(oid) = &resp.oid {
                sink.lock().unwrap().push(oid.clone());
            }
        })
        .connect()
        .await
        .unwrap();

    client.simple_bind("cn=test", &password()).await.unwrap();
    assert_eq!(&*captured.lock().unwrap(), &[custom_oid]);
}

#[tokio::test]
async fn notice_of_disconnection_closes_connection() {
    let server = MockServer::start(vec![
        Step::respond(extended_response(
            ResultCode::Success,
            Some(NOTICE_OF_DISCONNECTION_OID),
        ))
        .with_id(0),
    ])
    .await;
    let client = connect_plain(&server).await;

    let err = client
        .simple_bind("cn=test", &password())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::ConnectionClosed), "{err:?}");
    assert!(!client.is_connected());
}

fn starttls_client_builder(server: &MockServer, certificate: &TestCertificate) -> ClientBuilder {
    ClientBuilder::new("localhost", server.port())
        .transport(Transport::StartTls)
        .tls(
            TlsConfig::default()
                .trust_anchors(TrustAnchors::ExplicitOnly(vec![certificate.der.clone()])),
        )
        .unwrap()
}

#[tokio::test]
async fn a_refused_starttls_is_a_starttls_error() {
    let server = MockServer::start(vec![Step::respond(extended_response(
        ResultCode::Unavailable,
        None,
    ))])
    .await;
    let certificate = TestCertificate::new();

    let err = starttls_client_builder(&server, &certificate)
        .connect()
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::StartTls(_)), "{err:?}");
}

#[tokio::test]
async fn data_after_the_starttls_answer_is_refused() {
    let mut bytes = LdapMessage {
        message_id: MessageId::FIRST,
        operation: extended_response(ResultCode::Success, None),
        controls: vec![],
    }
    .encode();
    bytes.extend(
        LdapMessage {
            message_id: MessageId(2),
            operation: bind_response(ResultCode::Success),
            controls: vec![],
        }
        .encode(),
    );
    let server = MockServer::start(vec![Step::raw(bytes)]).await;
    let certificate = TestCertificate::new();

    let err = starttls_client_builder(&server, &certificate)
        .connect()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&err, Error::StartTls(m) if m.contains("buffered")),
        "{err:?}"
    );
}

#[tokio::test]
async fn starttls_then_a_bind_uses_message_ids_one_and_two() {
    let certificate = TestCertificate::new();
    let server = MockServer::start(vec![
        Step::respond(extended_response(ResultCode::Success, None))
            .then_tls(certificate.server_config(&[&rustls::version::TLS13])),
        Step::respond(bind_response(ResultCode::Success)),
    ])
    .await;

    let client = starttls_client_builder(&server, &certificate)
        .connect()
        .await
        .unwrap();
    client.simple_bind("cn=a", &password()).await.unwrap();

    let received = server.received().await;
    let ids: Vec<i32> = received.iter().map(|m| m.message_id.get()).collect();
    assert_eq!(ids, [1, 2]);
    assert!(matches!(
        &received[0].operation,
        LdapOperation::ExtendedRequest(req) if req.oid == STARTTLS_OID
    ));
    assert!(matches!(
        &received[1].operation,
        LdapOperation::BindRequest(_)
    ));
}

#[tokio::test]
async fn rebind_without_a_service_account_is_an_error() {
    let server = MockServer::start(vec![]).await;
    let client = connect_plain(&server).await;

    assert!(client.rebind_service_account().await.is_err());
    assert!(server.received().await.is_empty());
}

#[tokio::test]
async fn reconnect_rebinds_the_service_account() {
    let server = MockServer::start_connections(
        vec![
            vec![],
            vec![Step::respond(bind_response(ResultCode::Success))],
        ],
        None,
    )
    .await;
    let client = ClientBuilder::new(server.host(), server.port())
        .service_account("cn=svc,dc=x", password())
        .connect()
        .await
        .unwrap();

    client.reconnect().await.unwrap();
    assert!(client.is_connected());

    let operations = server.received_operations().await;
    assert!(matches!(
        &operations[..],
        [LdapOperation::BindRequest(req)] if req.name == "cn=svc,dc=x"
    ));
}

#[tokio::test]
async fn reconnect_after_a_timeout_makes_the_client_usable_again() {
    let server = MockServer::start_connections(
        vec![
            vec![Step::silent()],
            vec![Step::respond(bind_response(ResultCode::Success))],
        ],
        None,
    )
    .await;
    let client = connect_with_timeout(&server, Duration::from_millis(100)).await;

    assert!(client.simple_bind("cn=a", &password()).await.is_err());
    assert!(!client.is_connected());

    client.reconnect().await.unwrap();
    client.simple_bind("cn=a", &password()).await.unwrap();
}

#[tokio::test]
async fn the_futures_a_client_returns_are_send() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Client>();

    let server = MockServer::start(vec![]).await;
    let client = connect_plain(&server).await;
    let filter = Filter::present("cn");

    assert_send(client.simple_bind("cn=a", &password()));
    assert_send(client.delete("cn=a"));
    assert_send(client.search("", SearchScope::BaseObject, filter.clone(), vec![]));
    assert_send(client.search_paged("", SearchScope::BaseObject, filter.clone(), vec![], 10));
    assert_send(client.reconnect());
    assert_send(client.unbind());
    let mut pages = client.search_paged_stream("", SearchScope::BaseObject, filter, vec![], 10);
    assert_send(pages.next_page());
}

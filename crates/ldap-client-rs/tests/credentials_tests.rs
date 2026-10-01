// SPDX-License-Identifier: MIT OR Apache-2.0

mod common;

use common::{MockServer, Step, bind_response, connect_plain};
use ldap_client::{BindCredentials, ClientBuilder, Error, ResultCode, SecretString};
use ldap_client_proto::{BindAuthentication, LdapOperation};

#[tokio::test]
async fn a_dn_with_an_empty_password_is_refused_before_sending() {
    let server = MockServer::start(vec![Step::respond(bind_response(ResultCode::Success))]).await;
    let client = connect_plain(&server).await;

    let err = client
        .simple_bind("cn=a,dc=x", &SecretString::from(""))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnauthenticatedBind), "{err:?}");
    assert!(server.received().await.is_empty());
    assert!(client.is_connected());
}

#[tokio::test]
async fn an_empty_dn_and_password_is_an_anonymous_bind() {
    let server = MockServer::start(vec![Step::respond(bind_response(ResultCode::Success))]).await;
    let client = connect_plain(&server).await;

    client
        .simple_bind("", &SecretString::from(""))
        .await
        .unwrap();

    let operations = server.received_operations().await;
    assert!(matches!(
        &operations[..],
        [LdapOperation::BindRequest(req)]
            if req.name.is_empty() && matches!(&req.authentication, BindAuthentication::Simple(pw) if pw.is_empty())
    ));
}

#[tokio::test]
async fn bind_credentials_simple_with_an_empty_password_is_refused() {
    let server = MockServer::start(vec![]).await;
    let client = connect_plain(&server).await;
    let password = SecretString::from("");

    let err = client
        .bind(BindCredentials::Simple {
            dn: "cn=a",
            password: &password,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnauthenticatedBind), "{err:?}");
    assert!(server.received().await.is_empty());
}

#[tokio::test]
async fn connect_refuses_a_service_account_with_an_empty_password() {
    // Nothing listens on port 1: the refusal comes before a connection is tried.
    let err = ClientBuilder::new("127.0.0.1", 1)
        .service_account("cn=svc,dc=x", SecretString::from(""))
        .connect()
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::UnauthenticatedBind), "{err:?}");
}

#[tokio::test]
async fn a_non_empty_password_is_sent_as_given() {
    let server = MockServer::start(vec![Step::respond(bind_response(ResultCode::Success))]).await;
    let client = connect_plain(&server).await;

    client
        .simple_bind("cn=a", &SecretString::from("secret"))
        .await
        .unwrap();

    let operations = server.received_operations().await;
    assert!(matches!(
        &operations[..],
        [LdapOperation::BindRequest(req)]
            if matches!(&req.authentication, BindAuthentication::Simple(pw) if pw.as_slice() == b"secret")
    ));
}

#[tokio::test]
async fn an_invalid_credentials_answer_is_an_ldap_error_and_keeps_the_connection() {
    let server = MockServer::start(vec![Step::respond(bind_response(
        ResultCode::InvalidCredentials,
    ))])
    .await;
    let client = connect_plain(&server).await;

    let err = client
        .simple_bind("cn=a", &SecretString::from("wrong"))
        .await
        .unwrap_err();
    assert_eq!(err.result_code(), Some(ResultCode::InvalidCredentials));
    assert!(err.to_string().contains("invalidCredentials (49)"), "{err}");
    assert!(client.is_connected());
}

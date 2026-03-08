// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{Arc, Mutex};

use ldap_client::{ClientBuilder, Error, SecretString, parse_range_option};
use ldap_client_ber::{BerWriter, Tag};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn range_option_mid() {
    assert_eq!(
        parse_range_option("member;range=0-1499"),
        Some(("member", 0, Some(1499)))
    );
}

#[test]
fn range_option_final() {
    assert_eq!(
        parse_range_option("member;range=1500-*"),
        Some(("member", 1500, None))
    );
}

#[test]
fn range_option_none() {
    assert_eq!(parse_range_option("member"), None);
    assert_eq!(parse_range_option("member;binary"), None);
}

#[test]
fn range_option_multi_semicolon() {
    // Attribute with multiple options: member;binary;range=0-1499
    assert_eq!(
        parse_range_option("member;binary;range=0-1499"),
        Some(("member", 0, Some(1499)))
    );
    assert_eq!(
        parse_range_option("member;binary;range=1500-*"),
        Some(("member", 1500, None))
    );
}

const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";

/// Encode an LDAP message with an application-tagged constructed body.
fn encode_ldap_message(
    message_id: i32,
    app_tag: u32,
    body_fn: impl FnOnce(&mut BerWriter),
) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(message_id as i64);
        msg.write_sequence(Tag::application(app_tag), body_fn);
    });
    w.into_bytes()
}

/// Encode an ExtendedResponse (app tag 24) with the given result code and OID.
fn encode_extended_response(message_id: i32, result_code: i64, oid: Option<&str>) -> Vec<u8> {
    encode_ldap_message(message_id, 24, |body| {
        body.write_enumerated(result_code);
        body.write_bytes(b""); // matchedDN
        body.write_bytes(b""); // diagnosticMessage
        if let Some(oid) = oid {
            body.write_octet_string(Tag::context(10), oid.as_bytes());
        }
    })
}

/// Encode a BindResponse (app tag 1) with success.
fn encode_bind_response(message_id: i32) -> Vec<u8> {
    encode_ldap_message(message_id, 1, |body| {
        body.write_enumerated(0);
        body.write_bytes(b""); // matchedDN
        body.write_bytes(b""); // diagnosticMessage
    })
}

/// Drain one LDAP message from the socket (we don't parse it).
async fn drain_one_message(sock: &mut TcpStream) {
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "expected an LDAP message");
}

#[tokio::test]
async fn unsolicited_notification_invokes_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let custom_oid = "1.2.3.4.5.6.7.8.9";

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        drain_one_message(&mut sock).await;

        // Unsolicited notification followed by the actual bind response.
        sock.write_all(&encode_extended_response(0, 0, Some(custom_oid)))
            .await
            .unwrap();
        sock.write_all(&encode_bind_response(1)).await.unwrap();
    });

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();

    let client = ClientBuilder::new(addr.ip().to_string(), addr.port())
        .on_unsolicited_notification(move |resp| {
            if let Some(oid) = &resp.oid {
                captured_clone.lock().unwrap().push(oid.clone());
            }
        })
        .connect()
        .await
        .unwrap();

    let password = SecretString::from("test");
    client.simple_bind("cn=test", &password).await.unwrap();
    server.await.unwrap();

    let oids = captured.lock().unwrap();
    assert_eq!(&*oids, &[custom_oid]);
}

#[tokio::test]
async fn notice_of_disconnection_closes_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        drain_one_message(&mut sock).await;

        // Send Notice of Disconnection instead of a bind response.
        sock.write_all(&encode_extended_response(
            0,
            0,
            Some(NOTICE_OF_DISCONNECTION_OID),
        ))
        .await
        .unwrap();
    });

    let client = ClientBuilder::new(addr.ip().to_string(), addr.port())
        .connect()
        .await
        .unwrap();

    let password = SecretString::from("test");
    let err = client.simple_bind("cn=test", &password).await.unwrap_err();
    assert!(
        matches!(err, Error::ConnectionClosed),
        "expected ConnectionClosed, got {err:?}"
    );

    server.await.unwrap();
}

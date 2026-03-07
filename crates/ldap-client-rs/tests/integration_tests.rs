// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests against a local OpenLDAP container.
// Run with: cargo nextest run -p ldap-client --features integration-tests

#![cfg(feature = "integration-tests")]

use ldap_client::{
    Client, ClientBuilder, Filter, Modification, ModifyOperation, PartialAttribute, ResultCode,
    SearchScope,
};
use secrecy::SecretString;

const LDAP_HOST: &str = "localhost";
const LDAP_PORT: u16 = 1389;
const BASE_DN: &str = "dc=example,dc=com";
const ADMIN_DN: &str = "cn=admin,dc=example,dc=com";
const ADMIN_PW: &str = "adminpassword";

fn admin_password() -> SecretString {
    SecretString::from(ADMIN_PW.to_string())
}

async fn connect_and_bind() -> Client {
    let client = ClientBuilder::new(LDAP_HOST, LDAP_PORT)
        .connect()
        .await
        .expect("connect failed");
    client
        .simple_bind(ADMIN_DN, &admin_password())
        .await
        .expect("bind failed");
    client
}

#[tokio::test]
async fn connect_plain() {
    let client = ClientBuilder::new(LDAP_HOST, LDAP_PORT)
        .connect()
        .await
        .expect("connect failed");
    client.unbind().await.ok();
}

#[tokio::test]
async fn connect_from_url() {
    let client = ClientBuilder::from_url(&format!("ldap://{LDAP_HOST}:{LDAP_PORT}"))
        .unwrap()
        .connect()
        .await
        .expect("connect failed");
    client.unbind().await.ok();
}

#[tokio::test]
async fn simple_bind_success() {
    let client = ClientBuilder::new(LDAP_HOST, LDAP_PORT)
        .connect()
        .await
        .unwrap();
    client
        .simple_bind(ADMIN_DN, &admin_password())
        .await
        .expect("bind should succeed");
    client.unbind().await.ok();
}

#[tokio::test]
async fn simple_bind_wrong_password() {
    let client = ClientBuilder::new(LDAP_HOST, LDAP_PORT)
        .connect()
        .await
        .unwrap();
    let bad_pw = SecretString::from("wrong".to_string());
    let err = client
        .simple_bind(ADMIN_DN, &bad_pw)
        .await
        .expect_err("bind should fail");
    assert_eq!(err.result_code(), Some(ResultCode::InvalidCredentials));
}

#[tokio::test]
async fn search_base_dn() {
    let client = connect_and_bind().await;
    let entries = client
        .search(
            BASE_DN,
            SearchScope::BaseObject,
            Filter::present("objectClass"),
            vec![],
        )
        .await
        .expect("search failed");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].dn, BASE_DN);
    client.unbind().await.ok();
}

#[tokio::test]
async fn search_subtree() {
    let client = connect_and_bind().await;
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::present("objectClass"),
            vec!["dn".into()],
        )
        .await
        .expect("search failed");
    assert!(!entries.is_empty());
    client.unbind().await.ok();
}

#[tokio::test]
async fn search_with_eq_filter() {
    let client = connect_and_bind().await;
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("objectClass", "organization"),
            vec![],
        )
        .await
        .expect("search failed");
    assert!(!entries.is_empty());
    client.unbind().await.ok();
}

#[tokio::test]
async fn add_search_modify_delete() {
    let client = connect_and_bind().await;
    let test_dn = "cn=testuser,dc=example,dc=com";

    // Clean up if leftover from a previous run.
    let _ = client.delete(test_dn).await;

    // Add
    client
        .add(
            test_dn,
            vec![
                PartialAttribute {
                    name: "objectClass".into(),
                    values: vec![
                        b"inetOrgPerson".to_vec(),
                        b"organizationalPerson".to_vec(),
                        b"person".to_vec(),
                    ],
                },
                PartialAttribute {
                    name: "cn".into(),
                    values: vec![b"testuser".to_vec()],
                },
                PartialAttribute {
                    name: "sn".into(),
                    values: vec![b"User".to_vec()],
                },
                PartialAttribute {
                    name: "mail".into(),
                    values: vec![b"test@example.com".to_vec()],
                },
            ],
        )
        .await
        .expect("add failed");

    // Search for the new entry.
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("cn", "testuser"),
            vec!["cn".into(), "mail".into()],
        )
        .await
        .expect("search failed");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].attr("mail").unwrap().first_string_value(),
        Some("test@example.com")
    );

    // Modify
    client
        .modify(
            test_dn,
            vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: PartialAttribute {
                    name: "mail".into(),
                    values: vec![b"updated@example.com".to_vec()],
                },
            }],
        )
        .await
        .expect("modify failed");

    // Verify modification.
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("cn", "testuser"),
            vec!["mail".into()],
        )
        .await
        .expect("search failed");
    assert_eq!(
        entries[0].attr("mail").unwrap().first_string_value(),
        Some("updated@example.com")
    );

    // Delete
    client.delete(test_dn).await.expect("delete failed");

    // Verify deletion.
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("cn", "testuser"),
            vec![],
        )
        .await
        .expect("search failed");
    assert!(entries.is_empty());

    client.unbind().await.ok();
}

#[tokio::test]
async fn compare_true_and_false() {
    let client = connect_and_bind().await;
    let test_dn = "cn=cmpuser,dc=example,dc=com";

    let _ = client.delete(test_dn).await;

    client
        .add(
            test_dn,
            vec![
                PartialAttribute {
                    name: "objectClass".into(),
                    values: vec![
                        b"inetOrgPerson".to_vec(),
                        b"organizationalPerson".to_vec(),
                        b"person".to_vec(),
                    ],
                },
                PartialAttribute {
                    name: "cn".into(),
                    values: vec![b"cmpuser".to_vec()],
                },
                PartialAttribute {
                    name: "sn".into(),
                    values: vec![b"Compare".to_vec()],
                },
            ],
        )
        .await
        .expect("add failed");

    let result = client
        .compare(test_dn, "sn", b"Compare")
        .await
        .expect("compare failed");
    assert!(result);

    let result = client
        .compare(test_dn, "sn", b"Wrong")
        .await
        .expect("compare failed");
    assert!(!result);

    client.delete(test_dn).await.expect("delete failed");
    client.unbind().await.ok();
}

#[tokio::test]
async fn modify_dn_rename() {
    let client = connect_and_bind().await;
    let old_dn = "cn=renametest,dc=example,dc=com";
    let new_dn = "cn=renamed,dc=example,dc=com";

    let _ = client.delete(old_dn).await;
    let _ = client.delete(new_dn).await;

    client
        .add(
            old_dn,
            vec![
                PartialAttribute {
                    name: "objectClass".into(),
                    values: vec![
                        b"inetOrgPerson".to_vec(),
                        b"organizationalPerson".to_vec(),
                        b"person".to_vec(),
                    ],
                },
                PartialAttribute {
                    name: "cn".into(),
                    values: vec![b"renametest".to_vec()],
                },
                PartialAttribute {
                    name: "sn".into(),
                    values: vec![b"Test".to_vec()],
                },
            ],
        )
        .await
        .expect("add failed");

    client
        .modify_dn(old_dn, "cn=renamed", true, None)
        .await
        .expect("modify_dn failed");

    // Old entry should not exist.
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("cn", "renametest"),
            vec![],
        )
        .await
        .expect("search failed");
    assert!(entries.is_empty());

    // New entry should exist.
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::eq("cn", "renamed"),
            vec![],
        )
        .await
        .expect("search failed");
    assert_eq!(entries.len(), 1);

    client.delete(new_dn).await.expect("delete failed");
    client.unbind().await.ok();
}

#[tokio::test]
async fn delete_nonexistent_entry() {
    let client = connect_and_bind().await;
    let err = client
        .delete("cn=doesnotexist,dc=example,dc=com")
        .await
        .expect_err("should fail");
    assert_eq!(err.result_code(), Some(ResultCode::NoSuchObject));
    client.unbind().await.ok();
}

#[tokio::test]
async fn search_complex_filter() {
    let client = connect_and_bind().await;

    // AND filter with present and eq
    let entries = client
        .search(
            BASE_DN,
            SearchScope::WholeSubtree,
            Filter::and(vec![
                Filter::present("objectClass"),
                Filter::eq("dc", "example"),
            ]),
            vec![],
        )
        .await
        .expect("search failed");
    assert!(!entries.is_empty());

    client.unbind().await.ok();
}

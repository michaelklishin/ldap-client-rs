// SPDX-License-Identifier: MIT OR Apache-2.0

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ldap-client"))
        .args(args)
        .env_remove("LDAP_URL")
        .env_remove("LDAP_HOST")
        .env_remove("LDAP_PORT")
        .env_remove("LDAP_BIND_DN")
        .env_remove("LDAP_PASSWORD")
        .env_remove("LDAP_BASE_DN")
        .output()
        .unwrap()
}

fn assert_usage_error(args: &[&str]) {
    let output = cli(args);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tls_without_a_port_connects_to_636() {
    let output = Command::new(env!("CARGO_BIN_EXE_ldap-client"))
        .args(["--host", "127.0.0.1", "--tls", "--timeout", "1", "whoami"])
        .env("RUST_LOG", "debug")
        .env_remove("LDAP_PORT")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("127.0.0.1:636"), "{stdout}");
}

#[test]
fn a_bind_dn_without_a_password_is_a_usage_error() {
    assert_usage_error(&["--bind-dn", "cn=a,dc=x", "whoami"]);
}

#[test]
fn a_password_without_a_bind_dn_is_a_usage_error() {
    assert_usage_error(&["--password", "secret", "whoami"]);
}

#[test]
fn bind_without_a_bind_dn_is_a_usage_error() {
    assert_usage_error(&["bind"]);
}

#[test]
fn an_unknown_scope_is_a_usage_error() {
    assert_usage_error(&["search", "--scope", "subtree"]);
}

#[test]
fn a_malformed_filter_is_a_usage_error() {
    assert_usage_error(&["search", "--filter", "cn=a"]);
}

#[test]
fn an_attribute_without_an_equals_sign_is_a_usage_error() {
    assert_usage_error(&["add", "--dn", "cn=a,dc=x", "--attr", "cn"]);
}

#[test]
fn a_modify_assignment_without_an_equals_sign_is_a_usage_error() {
    assert_usage_error(&["modify", "--dn", "cn=a,dc=x", "--add", "cn"]);
}

#[test]
fn url_with_tls_is_a_usage_error() {
    assert_usage_error(&["--url", "ldap://localhost", "--tls", "whoami"]);
}

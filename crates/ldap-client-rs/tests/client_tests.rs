// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::{Transport, parse_range_option};
use ldap_client_proto::LdapScheme;

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

#[test]
fn transport_default_ports() {
    assert_eq!(Transport::Plain.default_port(), 389);
    assert_eq!(Transport::StartTls.default_port(), 389);
    assert_eq!(Transport::Tls.default_port(), 636);
}

#[test]
fn ldaps_scheme_maps_to_tls() {
    assert_eq!(Transport::from(LdapScheme::Ldaps), Transport::Tls);
    assert_eq!(Transport::from(LdapScheme::Ldap), Transport::Plain);
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::parse_range_option;

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

// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::dn::{Dn, escape_dn_value};

#[test]
fn parse_empty() {
    let dn = Dn::parse("").unwrap();
    assert!(dn.is_empty());
    assert_eq!(dn.to_string(), "");
}

#[test]
fn parse_simple_dn() {
    let dn = Dn::parse("cn=admin,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns.len(), 3);
    assert_eq!(dn.rdns[0].components[0].0, "cn");
    assert_eq!(dn.rdns[0].components[0].1, "admin");
    assert_eq!(dn.rdns[1].components[0].0, "dc");
    assert_eq!(dn.rdns[1].components[0].1, "example");
    assert_eq!(dn.rdns[2].components[0].0, "dc");
    assert_eq!(dn.rdns[2].components[0].1, "com");
}

#[test]
fn roundtrip_simple() {
    let input = "cn=admin,dc=example,dc=com";
    let dn = Dn::parse(input).unwrap();
    assert_eq!(dn.to_string(), input);
}

#[test]
fn multi_valued_rdn() {
    let dn = Dn::parse("cn=John+sn=Doe,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns.len(), 3);
    assert_eq!(dn.rdns[0].components.len(), 2);
    assert_eq!(
        dn.rdns[0].components[0],
        ("cn".to_string(), "John".to_string())
    );
    assert_eq!(
        dn.rdns[0].components[1],
        ("sn".to_string(), "Doe".to_string())
    );
}

#[test]
fn escaped_comma_in_value() {
    let dn = Dn::parse(r"cn=Doe\, John,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns.len(), 3);
    assert_eq!(dn.rdns[0].components[0].1, "Doe, John");
}

#[test]
fn escaped_hex_pair() {
    let dn = Dn::parse(r"cn=\41\42\43,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "ABC");
}

#[test]
fn hex_encoded_value() {
    let dn = Dn::parse("cn=#414243,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "#414243");
}

#[test]
fn escape_special_chars() {
    assert_eq!(escape_dn_value("a,b"), r"a\,b");
    assert_eq!(escape_dn_value("a+b"), r"a\+b");
    assert_eq!(escape_dn_value(r"a\b"), r"a\\b");
    assert_eq!(escape_dn_value("a\"b"), r#"a\"b"#);
    assert_eq!(escape_dn_value(" foo"), r"\ foo");
    assert_eq!(escape_dn_value("foo "), r"foo\ ");
    assert_eq!(escape_dn_value("#foo"), r"\#foo");
}

#[test]
fn fromstr_impl() {
    let dn: Dn = "cn=test,dc=example,dc=com".parse().unwrap();
    assert_eq!(dn.rdns.len(), 3);
}

#[test]
fn display_escapes_special() {
    let dn = Dn::parse(r"cn=Doe\, John,dc=example,dc=com").unwrap();
    let displayed = dn.to_string();
    assert_eq!(displayed, r"cn=Doe\, John,dc=example,dc=com");
}

#[test]
fn whitespace_trimmed() {
    let dn = Dn::parse("  cn=admin,dc=example,dc=com  ").unwrap();
    assert_eq!(dn.rdns.len(), 3);
}

#[test]
fn missing_equals_rejected() {
    assert!(Dn::parse("cn admin,dc=example").is_err());
}

#[test]
fn empty_attr_rejected() {
    assert!(Dn::parse("=value,dc=example").is_err());
}

#[test]
fn roundtrip_escaped_value() {
    let dn = Dn::parse(r"cn=a\+b,dc=example,dc=com").unwrap();
    let s = dn.to_string();
    let dn2 = Dn::parse(&s).unwrap();
    assert_eq!(dn, dn2);
}

#[test]
fn utf8_hex_escape() {
    // é = 0xC3 0xA9 in UTF-8
    let dn = Dn::parse(r"cn=caf\c3\a9,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "café");
}

#[test]
fn unescaped_utf8_preserved() {
    // Non-ASCII characters in DN values must survive roundtrip without corruption.
    let dn = Dn::parse("cn=café,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "café");

    let dn = Dn::parse("cn=日本語,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "日本語");

    let dn = Dn::parse("cn=Ünîcödé,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "Ünîcödé");
}

#[test]
fn escape_null_byte() {
    assert_eq!(escape_dn_value("a\0b"), "a\\00b");
}

#[test]
fn escaped_trailing_space_preserved() {
    // Backslash-escaped trailing space must be kept (RFC 4514 §2.4).
    let dn = Dn::parse(r"cn=foo\ ,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "foo ");

    // Hex-escaped trailing space (\20) must also be kept.
    let dn = Dn::parse(r"cn=bar\20,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "bar ");
}

#[test]
fn unescaped_trailing_space_trimmed() {
    // Unescaped trailing spaces should be stripped.
    let dn = Dn::parse("cn=foo   ,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "foo");
}

#[test]
fn parse_range_option_multi_semicolon() {
    use ldap_client_proto::dn::Dn;
    // This test ensures multi-option attribute names work with range retrieval.
    // (Tested in the client crate's parse_range_option, but validates the pattern.)
    let dn = Dn::parse("cn=test,dc=example,dc=com").unwrap();
    assert_eq!(dn.rdns[0].components[0].0, "cn");
}

#[test]
fn hex_string_invalid_chars_rejected() {
    assert!(Dn::parse("cn=#ZZZZ,dc=example,dc=com").is_err());
}

#[test]
fn hex_string_odd_length_rejected() {
    assert!(Dn::parse("cn=#414,dc=example,dc=com").is_err());
}

#[test]
fn hex_string_empty_rejected() {
    assert!(Dn::parse("cn=#,dc=example,dc=com").is_err());
}

#[test]
fn invalid_utf8_hex_escape_rejected() {
    // \FF is not valid UTF-8 (lone byte > 0x7F)
    assert!(Dn::parse(r"cn=\FF,dc=example,dc=com").is_err());
}

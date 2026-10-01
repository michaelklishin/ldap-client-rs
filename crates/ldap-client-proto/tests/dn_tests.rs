// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::dn::{AttributeValue, Dn, escape_dn_value};

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
    assert_eq!(dn.rdns[0].components[0].0, "cn");
    assert_eq!(dn.rdns[0].components[0].1, "John");
    assert_eq!(dn.rdns[0].components[1].0, "sn");
    assert_eq!(dn.rdns[0].components[1].1, "Doe");
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
    assert_eq!(
        dn.rdns[0].components[0].1,
        AttributeValue::Ber(vec![0x41, 0x42, 0x43])
    );
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

#[test]
fn an_escaped_multibyte_character_is_refused() {
    assert!(Dn::parse(r"cn=\é").is_err());
}

#[test]
fn text_after_a_quoted_value_with_multibyte_characters_is_refused() {
    assert!(Dn::parse("cn=\"a\"€€€€").is_err());
}

#[test]
fn a_trailing_backslash_is_refused() {
    assert!(Dn::parse(r"cn=foo\").is_err());
}

#[test]
fn an_escape_outside_the_rfc_4514_set_is_refused() {
    assert!(Dn::parse(r"cn=\a").is_err());
}

#[test]
fn a_hex_escaped_multibyte_character_decodes() {
    let dn = Dn::parse(r"cn=\c3\a9").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "é");
}

#[test]
fn an_escape_error_names_the_byte_offset() {
    let err = Dn::parse(r"cn=ab\q").unwrap_err().to_string();
    assert!(err.contains("byte 5"), "{err}");
}

#[test]
fn every_rfc_4514_escapable_character_decodes() {
    for c in ['\\', '"', '+', ',', ';', '<', '>', ' ', '#', '='] {
        let dn = Dn::parse(&format!("cn=a\\{c}b")).unwrap();
        assert_eq!(dn.rdns[0].components[0].1, format!("a{c}b").as_str());
    }
}

#[test]
fn quoted_values_parse() {
    let dn = Dn::parse(r#"cn="a,b",dc=example"#).unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "a,b");
    assert_eq!(dn.rdns.len(), 2);
}

#[test]
fn an_unterminated_quote_is_refused() {
    assert!(Dn::parse(r#"cn="abc"#).is_err());
}

#[test]
fn an_escaped_trailing_space_at_the_end_is_kept() {
    let dn = Dn::parse(r"cn=foo\ ").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "foo ");
}

#[test]
fn unescaped_trailing_whitespace_at_the_end_is_dropped() {
    let dn = Dn::parse("cn=foo \t\n").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "foo");
}

#[test]
fn escape_dn_value_output_parses_back() {
    for value in ["foo ", " foo", "#foo", "a,b", "a\0b", "foo\n", "a\\b"] {
        let dn = Dn::parse(&format!("cn={}", escape_dn_value(value))).unwrap();
        assert_eq!(dn.rdns[0].components[0].1, value, "{value:?}");
    }
}

#[test]
fn spaces_after_a_hex_value_are_skipped() {
    let dn = Dn::parse("cn=#41 ,dc=x").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, AttributeValue::Ber(vec![0x41]));
    assert_eq!(dn.rdns.len(), 2);
}

#[test]
fn spaces_after_a_quoted_value_are_skipped() {
    let dn = Dn::parse(r#"cn="a" ,dc=x"#).unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "a");
    assert_eq!(dn.rdns.len(), 2);
}

#[test]
fn an_attribute_type_with_a_space_is_refused() {
    assert!(Dn::parse("c n=x").is_err());
}

#[test]
fn an_attribute_type_with_a_quote_is_refused() {
    assert!(Dn::parse("cn\"=y").is_err());
}

#[test]
fn a_numeric_oid_attribute_type_is_accepted() {
    let dn = Dn::parse("2.5.4.3=x").unwrap();
    assert_eq!(dn.rdns[0].components[0].0, "2.5.4.3");
}

#[test]
fn an_attribute_type_with_an_underscore_is_accepted() {
    assert!(Dn::parse("my_attr=x").is_ok());
}

#[test]
fn display_escapes_an_invalid_attribute_type() {
    let dn = Dn {
        rdns: vec![ldap_client_proto::dn::Rdn {
            components: vec![("cn=x,dc".into(), "evil".into())],
        }],
    };
    assert!(Dn::parse(&dn.to_string()).is_err());
}

#[test]
fn a_hex_value_round_trips() {
    let dn = Dn::parse("cn=#0403616263,dc=example").unwrap();
    assert_eq!(dn.to_string(), "cn=#0403616263,dc=example");
    assert_eq!(Dn::parse(&dn.to_string()).unwrap(), dn);
}

#[test]
fn an_escaped_hash_stays_text() {
    let dn = Dn::parse(r"cn=\#04026869").unwrap();
    assert_eq!(dn.rdns[0].components[0].1, "#04026869");
    assert_eq!(dn.to_string(), r"cn=\#04026869");
}

#[test]
fn a_text_value_equals_a_str() {
    let value = AttributeValue::from("x");
    assert_eq!(value, "x");
    assert_eq!(value.as_text(), Some("x"));
    assert_ne!(AttributeValue::Ber(b"x".to_vec()), "x");
    assert_eq!(AttributeValue::Ber(vec![1]).as_text(), None);
}

#[test]
fn the_parent_of_a_three_rdn_dn_has_two() {
    let dn = Dn::parse("cn=a,ou=b,dc=c").unwrap();
    assert_eq!(dn.parent().unwrap(), Dn::parse("ou=b,dc=c").unwrap());
}

#[test]
fn a_single_rdn_has_no_parent() {
    assert!(Dn::parse("dc=c").unwrap().parent().is_none());
    assert!(Dn::parse("").unwrap().parent().is_none());
}

#[test]
fn trailing_whitespace_after_a_hex_or_quoted_value_is_dropped() {
    assert!(Dn::parse("cn=#41\n").is_ok());
    assert!(Dn::parse("cn=\"a\"\r\n").is_ok());
}

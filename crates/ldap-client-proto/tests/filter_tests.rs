// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::{BerReader, BerWriter};
use ldap_client_proto::Filter;

#[test]
fn parse_equality() {
    let f = Filter::parse("(cn=John)").unwrap();
    assert_eq!(f, Filter::eq("cn", "John"));
}

#[test]
fn parse_present() {
    let f = Filter::parse("(objectClass=*)").unwrap();
    assert_eq!(f, Filter::present("objectClass"));
}

#[test]
fn parse_and() {
    let f = Filter::parse("(&(cn=John)(uid=jsmith))").unwrap();
    assert_eq!(
        f,
        Filter::and(vec![Filter::eq("cn", "John"), Filter::eq("uid", "jsmith")])
    );
}

#[test]
fn parse_or() {
    let f = Filter::parse("(|(cn=A)(cn=B))").unwrap();
    assert_eq!(
        f,
        Filter::or(vec![Filter::eq("cn", "A"), Filter::eq("cn", "B")])
    );
}

#[test]
fn parse_not() {
    let f = Filter::parse("(!(cn=test))").unwrap();
    assert_eq!(f, Filter::not(Filter::eq("cn", "test")));
}

#[test]
fn parse_gte() {
    let f = Filter::parse("(age>=18)").unwrap();
    assert_eq!(f, Filter::gte("age", "18"));
}

#[test]
fn parse_lte() {
    let f = Filter::parse("(age<=65)").unwrap();
    assert_eq!(f, Filter::lte("age", "65"));
}

#[test]
fn parse_approx() {
    let f = Filter::parse("(cn~=Jon)").unwrap();
    assert_eq!(f, Filter::approx("cn", "Jon"));
}

#[test]
fn parse_substring_initial() {
    let f = Filter::parse("(cn=Jo*)").unwrap();
    assert_eq!(f, Filter::substring("cn", Some("Jo".into()), vec![], None));
}

#[test]
fn parse_substring_final() {
    let f = Filter::parse("(cn=*son)").unwrap();
    assert_eq!(f, Filter::substring("cn", None, vec![], Some("son".into())));
}

#[test]
fn parse_substring_any() {
    let f = Filter::parse("(cn=*mid*)").unwrap();
    assert_eq!(f, Filter::substring("cn", None, vec!["mid".into()], None));
}

#[test]
fn parse_complex_nested() {
    let f = Filter::parse("(&(objectClass=inetOrgPerson)(|(uid=admin)(uid=root)))").unwrap();
    assert_eq!(
        f,
        Filter::and(vec![
            Filter::eq("objectClass", "inetOrgPerson"),
            Filter::or(vec![Filter::eq("uid", "admin"), Filter::eq("uid", "root")])
        ])
    );
}

#[test]
fn parse_escaped_value() {
    let f = Filter::parse("(cn=John \\28Jr\\29)").unwrap();
    assert_eq!(f, Filter::eq("cn", "John (Jr)"));
}

#[test]
fn filter_to_string_roundtrip() {
    let cases = [
        "(cn=John)",
        "(objectClass=*)",
        "(&(cn=A)(uid=B))",
        "(!(cn=test))",
        "(age>=18)",
        "(cn~=Jon)",
        "(cn=Jo*)",
        "(cn=*son)",
    ];
    for input in cases {
        let f = Filter::parse(input).unwrap();
        let serialized = f.to_filter_string();
        let reparsed = Filter::parse(&serialized).unwrap();
        assert_eq!(f, reparsed, "roundtrip failed for {input}");
    }
}

#[test]
fn escape_special_chars() {
    assert_eq!(Filter::escape_value("a*b"), "a\\2ab");
    assert_eq!(Filter::escape_value("a(b)"), "a\\28b\\29");
    assert_eq!(Filter::escape_value("a\\b"), "a\\5cb");
}

#[test]
fn ber_roundtrip_equality() {
    let f = Filter::eq("uid", "demo");
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_present() {
    let f = Filter::present("objectClass");
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_and() {
    let f = Filter::and(vec![
        Filter::eq("objectClass", "person"),
        Filter::eq("uid", "admin"),
    ]);
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_not() {
    let f = Filter::not(Filter::present("disabled"));
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_substring() {
    let f = Filter::substring(
        "cn",
        Some("Jo".into()),
        vec!["mid".into()],
        Some("end".into()),
    );
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_extensible_match() {
    let f = Filter::extensible_match(
        Some("1.2.840.113556.1.4.803"),
        Some("userAccountControl"),
        "2",
        false,
    );
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn parse_error_empty() {
    let result = Filter::parse("");
    assert!(result.is_err(), "empty string must be rejected");
}

#[test]
fn parse_error_no_parens() {
    let result = Filter::parse("cn=John");
    assert!(result.is_err(), "filter without parens must be rejected");
}

#[test]
fn parse_error_missing_operator() {
    let result = Filter::parse("(cn)");
    assert!(result.is_err(), "filter with no operator must be rejected");
}

#[test]
fn parse_extensible_match_string() {
    let input = "(cn:1.2.3.4:=value)";
    let f = Filter::parse(input).unwrap();
    assert_eq!(
        f,
        Filter::ExtensibleMatch {
            matching_rule: Some("1.2.3.4".into()),
            attr: Some("cn".into()),
            value: "value".into(),
            dn_attributes: false,
        }
    );
    // Roundtrip through to_filter_string and re-parse.
    let serialized = f.to_filter_string();
    let reparsed = Filter::parse(&serialized).unwrap();
    assert_eq!(f, reparsed, "extensible match roundtrip failed");
}

#[test]
fn ber_roundtrip_extensible_match_dn_attrs() {
    let f = Filter::extensible_match(Some("2.5.13.5"), Some("cn"), "test", true);
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn parse_deeply_nested_filter_rejected() {
    let mut s = String::new();
    for _ in 0..200 {
        s.push_str("(!");
    }
    s.push_str("(cn=x)");
    for _ in 0..200 {
        s.push(')');
    }
    let result = Filter::parse(&s);
    assert!(result.is_err(), "deeply nested filter must be rejected");
}

#[test]
fn an_incomplete_escape_is_refused() {
    assert!(Filter::parse("(cn=a\\2)").is_err());
}

#[test]
fn a_bare_backslash_is_refused() {
    assert!(Filter::parse("(cn=a\\b)").is_err());
}

#[test]
fn a_signed_escape_is_refused() {
    assert!(Filter::parse("(cn=\\+4)").is_err());
}

#[test]
fn an_uppercase_hex_escape_decodes() {
    assert_eq!(Filter::parse("(cn=\\2A)").unwrap(), Filter::eq("cn", "*"));
}

#[test]
fn an_escape_error_names_the_byte_offset() {
    let err = Filter::parse("(cn=ab\\q)").unwrap_err().to_string();
    assert!(err.contains("byte 6"), "{err}");
}

#[test]
fn extensible_match_dn_string_roundtrip() {
    let input = "(cn:dn:1.2.3:=test)";
    let f = Filter::parse(input).unwrap();
    assert_eq!(
        f,
        Filter::ExtensibleMatch {
            matching_rule: Some("1.2.3".into()),
            attr: Some("cn".into()),
            value: "test".into(),
            dn_attributes: true,
        }
    );
    let serialized = f.to_filter_string();
    let reparsed = Filter::parse(&serialized).unwrap();
    assert_eq!(f, reparsed);
}

#[test]
fn parse_extensible_match_attr_only() {
    let f = Filter::parse("(cn:=value)").unwrap();
    assert_eq!(
        f,
        Filter::ExtensibleMatch {
            matching_rule: None,
            attr: Some("cn".into()),
            value: "value".into(),
            dn_attributes: false,
        }
    );
    let serialized = f.to_filter_string();
    let reparsed = Filter::parse(&serialized).unwrap();
    assert_eq!(f, reparsed);
}

#[test]
fn parse_extensible_match_dn_only() {
    let f = Filter::parse("(cn:dn:=value)").unwrap();
    assert_eq!(
        f,
        Filter::ExtensibleMatch {
            matching_rule: None,
            attr: Some("cn".into()),
            value: "value".into(),
            dn_attributes: true,
        }
    );
}

#[test]
fn filter_from_str_trait() {
    let f: Filter = "(cn=test)".parse().unwrap();
    assert_eq!(f, Filter::eq("cn", "test"));
}

#[test]
fn filter_display_trait() {
    let f = Filter::eq("cn", "test");
    assert_eq!(format!("{f}"), "(cn=test)");
}

#[test]
fn ber_roundtrip_or() {
    let f = Filter::or(vec![Filter::present("mail"), Filter::gte("age", "21")]);
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_gte() {
    let f = Filter::gte("age", "18");
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_lte() {
    let f = Filter::lte("age", "65");
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn ber_roundtrip_approx() {
    let f = Filter::approx("cn", "John");
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let mut r = BerReader::new(w.as_bytes());
    let decoded = Filter::decode(&mut r).unwrap();
    assert_eq!(f, decoded);
}

#[test]
fn escape_null_char() {
    assert_eq!(Filter::escape_value("\0"), "\\00");
}

#[test]
fn parse_substring_initial_and_final() {
    let f = Filter::parse("(cn=Jo*son)").unwrap();
    assert_eq!(
        f,
        Filter::substring("cn", Some("Jo".into()), vec![], Some("son".into()))
    );
}

#[test]
fn parse_substring_all_parts() {
    let f = Filter::parse("(cn=Jo*mid*son)").unwrap();
    assert_eq!(
        f,
        Filter::substring(
            "cn",
            Some("Jo".into()),
            vec!["mid".into()],
            Some("son".into())
        )
    );
}

#[test]
fn degenerate_substring_rejected() {
    // "**" has no initial, any, or final assertions — should be rejected.
    assert!(Filter::parse("(cn=**)").is_err());
    assert!(Filter::parse("(cn=***)").is_err());
}

#[test]
fn single_star_is_present() {
    let f = Filter::parse("(cn=*)").unwrap();
    assert_eq!(f, Filter::present("cn"));
}

#[test]
fn extensible_match_no_attr_no_rule_no_dn_rejected() {
    // RFC 4515 §3: at least one of attr, matching rule, or :dn: is required.
    assert!(
        Filter::parse("(:=value)").is_err(),
        "extensible match with no attr, rule, or dn must be rejected"
    );
}

#[test]
fn an_attribute_with_a_parenthesis_is_refused() {
    assert!(Filter::parse("((cn=x)").is_err());
}

#[test]
fn an_empty_attribute_is_refused() {
    assert!(Filter::parse("(=x)").is_err());
}

#[test]
fn an_attribute_with_a_space_is_refused() {
    assert!(Filter::parse("(c n=x)").is_err());
}

#[test]
fn an_attribute_with_options_is_accepted() {
    assert_eq!(
        Filter::parse("(cn;lang-en=x)").unwrap(),
        Filter::eq("cn;lang-en", "x")
    );
}

#[test]
fn a_numeric_oid_attribute_is_accepted() {
    assert_eq!(
        Filter::parse("(2.5.4.3=x)").unwrap(),
        Filter::eq("2.5.4.3", "x")
    );
}

#[test]
fn an_attribute_with_an_underscore_is_accepted() {
    assert!(Filter::parse("(my_attr=x)").is_ok());
}

#[test]
fn an_empty_attribute_option_is_refused() {
    assert!(Filter::parse("(cn;=x)").is_err());
}

#[test]
fn an_invalid_matching_rule_is_refused() {
    assert!(Filter::parse("(cn:dn:bad rule:=x)").is_err());
}

#[test]
fn a_three_part_extensible_match_needs_dn_in_the_middle() {
    assert!(Filter::parse("(cn:foo:1.2.3:=x)").is_err());
}

#[test]
fn an_extensible_match_does_not_borrow_a_later_filter() {
    assert!(Filter::parse("(&(cn:dn:x=y)(uid:=a))").is_err());
}

#[test]
fn a_comparison_with_a_colon_attribute_is_refused() {
    assert!(Filter::parse("(cn:>=5)").is_err());
}

#[test]
fn display_of_an_injected_attribute_does_not_parse() {
    let f = Filter::eq("cn)(uid", "x");
    assert!(Filter::parse(&f.to_string()).is_err());
}

#[test]
fn display_escapes_an_injected_matching_rule() {
    let f = Filter::extensible_match(Some("1.2)(uid=*"), Some("cn"), "x", false);
    assert!(Filter::parse(&f.to_string()).is_err());
}

#[test]
fn every_variant_escapes_an_invalid_attribute() {
    let attr = "cn)(uid";
    let filters = [
        Filter::eq(attr, "x"),
        Filter::approx(attr, "x"),
        Filter::gte(attr, "x"),
        Filter::lte(attr, "x"),
        Filter::present(attr),
        Filter::substring(attr, Some("a".into()), vec![], None),
    ];
    for f in filters {
        assert!(Filter::parse(&f.to_string()).is_err(), "{f:?}");
    }
}

#[test]
fn a_binary_value_parses() {
    let f = Filter::parse("(objectGUID=\\a1\\b2)").unwrap();
    assert_eq!(f, Filter::eq("objectGUID", vec![0xA1, 0xB2]));
}

#[test]
fn a_binary_value_displays_with_hex_escapes() {
    let f = Filter::eq("objectGUID", vec![0xA1, b'a', 0xB2]);
    assert_eq!(f.to_string(), "(objectGUID=\\a1a\\b2)");
}

#[test]
fn invalid_utf8_survives_a_ber_round_trip() {
    let f = Filter::eq("objectGUID", vec![0xFF, 0xFE, 0x00]);
    let mut w = BerWriter::new();
    f.encode(&mut w);
    let decoded = Filter::decode(&mut BerReader::new(w.as_bytes())).unwrap();
    assert_eq!(decoded, f);
}

#[test]
fn a_binary_substring_part_round_trips_through_the_string_form() {
    let f = Filter::Substring {
        attr: "objectSid".into(),
        initial: Some(vec![0x01, 0xFF].into()),
        any: vec![],
        r#final: Some(vec![0x80].into()),
    };
    assert_eq!(Filter::parse(&f.to_string()).unwrap(), f);
}

#[test]
fn assertion_values_expose_their_bytes_and_text() {
    use ldap_client_proto::AssertionValue;
    let text = AssertionValue::from("abc");
    assert_eq!(text.as_bytes(), b"abc");
    assert_eq!(text.to_str(), Some("abc"));
    let binary = AssertionValue::from(&[0xFF][..]);
    assert_eq!(binary.to_str(), None);
    assert_eq!(binary.into_bytes(), vec![0xFF]);
}

#[test]
fn a_ber_attribute_that_is_not_utf8_is_refused() {
    let mut w = BerWriter::new();
    w.write_octet_string(ldap_client_ber::Tag::context(7), &[0xFF]);
    assert!(Filter::decode(&mut BerReader::new(w.as_bytes())).is_err());
}

#[test]
fn a_constructed_present_filter_is_refused() {
    let mut r = BerReader::new(&[0xA7, 0x00]);
    assert!(Filter::decode(&mut r).is_err());
}

#[test]
fn a_comparison_value_keeps_a_literal_star() {
    let f = Filter::parse("(cn>=a*b)").unwrap();
    assert_eq!(f, Filter::gte("cn", "a*b"));
}

#[test]
fn too_many_wildcard_parts_are_refused() {
    let value = "a*".repeat(100);
    assert!(Filter::parse(&format!("(cn={value})")).is_err());
}

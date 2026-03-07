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
fn find_value_end_invalid_escape_stops_at_paren() {
    let f = Filter::parse("(cn=a\\2)").unwrap();
    assert_eq!(f, Filter::eq("cn", "a\\2"));
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

// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::{BerReader, BerWriter};
use ldap_client_proto::{AssertionValue, Filter};
use proptest::prelude::*;

fn arb_attr() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z][a-zA-Z0-9_-]{0,15}",
        "[a-zA-Z][a-zA-Z0-9]{0,8};[a-z][a-z0-9-]{0,8}",
        "[0-9]{1,2}(\\.[0-9]{1,3}){1,4}",
    ]
}

fn arb_text() -> impl Strategy<Value = String> {
    any::<String>()
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn arb_leaf_filter() -> impl Strategy<Value = Filter> {
    prop_oneof![
        (arb_attr(), arb_text()).prop_map(|(a, v)| Filter::eq(a, v)),
        arb_attr().prop_map(Filter::present),
        (arb_attr(), arb_text()).prop_map(|(a, v)| Filter::gte(a, v)),
        (arb_attr(), arb_text()).prop_map(|(a, v)| Filter::lte(a, v)),
        (arb_attr(), arb_text()).prop_map(|(a, v)| Filter::approx(a, v)),
    ]
}

fn arb_filter() -> impl Strategy<Value = Filter> {
    arb_leaf_filter().prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..=4).prop_map(Filter::and),
            prop::collection::vec(inner.clone(), 1..=4).prop_map(Filter::or),
            inner.prop_map(Filter::not),
        ]
    })
}

fn nonempty_text() -> impl Strategy<Value = String> {
    "\\PC{1,8}"
}

/// Leaf filters of every variant over arbitrary attribute and rule strings.
/// Excludes the built forms that have no canonical string: a substring with
/// no non-empty part, a matching rule named `dn`, and an empty attribute or
/// matching rule in an extensible match, which reads back as an absent one.
fn arb_hostile_leaf() -> impl Strategy<Value = Filter> {
    let attr = || any::<String>();
    prop_oneof![
        (attr(), arb_bytes()).prop_map(|(a, v)| Filter::eq(a, v)),
        (attr(), arb_bytes()).prop_map(|(a, v)| Filter::approx(a, v)),
        (attr(), arb_bytes()).prop_map(|(a, v)| Filter::gte(a, v)),
        (attr(), arb_bytes()).prop_map(|(a, v)| Filter::lte(a, v)),
        attr().prop_map(Filter::present),
        (
            attr(),
            proptest::option::of(nonempty_text()),
            prop::collection::vec(nonempty_text(), 0..3),
            nonempty_text(),
        )
            .prop_map(|(a, i, any, f)| Filter::substring(a, i, any, Some(f))),
        (
            proptest::option::of(nonempty_text().prop_filter("not dn", |r| r != "dn")),
            proptest::option::of(nonempty_text()),
            arb_bytes(),
            any::<bool>(),
        )
            .prop_map(|(r, a, v, dn)| Filter::extensible_match(r, a, v, dn)),
    ]
}

proptest! {
    #[test]
    fn filter_string_roundtrip(f in arb_filter()) {
        let s = f.to_filter_string();
        let parsed = Filter::parse(&s).unwrap();
        prop_assert_eq!(&f, &parsed);
    }

    #[test]
    fn filter_ber_roundtrip(f in arb_filter()) {
        let mut w = BerWriter::new();
        f.encode(&mut w);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = Filter::decode(&mut r).unwrap();
        prop_assert_eq!(&f, &decoded);
    }

    #[test]
    fn escape_roundtrip(input in any::<String>()) {
        let escaped = Filter::escape_value(&input);
        prop_assert!(!escaped.contains('('));
        prop_assert!(!escaped.contains(')'));
        let parsed = Filter::parse(&format!("(cn={escaped})")).unwrap();
        prop_assert_eq!(parsed, Filter::eq("cn", AssertionValue::from(input)));
    }

    #[test]
    fn prop_any_byte_value_survives_the_string_form(value in arb_bytes()) {
        let f = Filter::eq("objectGUID", value);
        prop_assert_eq!(Filter::parse(&f.to_string()).unwrap(), f);
    }

    #[test]
    fn prop_any_byte_value_survives_the_ber_form(value in arb_bytes()) {
        let f = Filter::eq("objectGUID", value);
        let mut w = BerWriter::new();
        f.encode(&mut w);
        let decoded = Filter::decode(&mut BerReader::new(w.as_bytes())).unwrap();
        prop_assert_eq!(decoded, f);
    }

    #[test]
    fn filter_substring_ber_roundtrip(
        attr in arb_attr(),
        initial in proptest::option::of(arb_text()),
        any_parts in prop::collection::vec(arb_text(), 0..=3),
        final_part in proptest::option::of(arb_text()),
    ) {
        let f = Filter::substring(attr, initial, any_parts, final_part);
        let mut w = BerWriter::new();
        f.encode(&mut w);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = Filter::decode(&mut r).unwrap();
        prop_assert_eq!(&f, &decoded);
    }

    #[test]
    fn prop_parse_never_panics(input in any::<String>()) {
        let _ = Filter::parse(&input);
    }

    #[test]
    fn prop_parse_never_panics_near_syntax(input in "[()&|!=~<>*\\\\:a-f0-9é]{0,40}") {
        let _ = Filter::parse(&input);
    }

    #[test]
    fn prop_display_of_a_parsed_filter_parses_to_the_same_filter(
        input in "[()&|!=~<>*\\\\:a-f0-9]{0,40}"
    ) {
        if let Ok(f) = Filter::parse(&input) {
            prop_assert_eq!(Filter::parse(&f.to_string()).unwrap(), f);
        }
    }

    #[test]
    fn prop_display_of_any_built_filter_never_parses_to_a_different_filter(f in arb_hostile_leaf()) {
        if let Ok(parsed) = Filter::parse(&f.to_string()) {
            prop_assert_eq!(parsed, f);
        }
    }
}

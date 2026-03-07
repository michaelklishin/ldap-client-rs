// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::{BerReader, BerWriter};
use ldap_client_proto::Filter;
use proptest::prelude::*;

fn arb_attr() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9]{0,15}"
}

fn arb_safe_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,20}"
}

fn arb_leaf_filter() -> impl Strategy<Value = Filter> {
    prop_oneof![
        (arb_attr(), arb_safe_value()).prop_map(|(a, v)| Filter::eq(a, v)),
        arb_attr().prop_map(Filter::present),
        (arb_attr(), arb_safe_value()).prop_map(|(a, v)| Filter::gte(a, v)),
        (arb_attr(), arb_safe_value()).prop_map(|(a, v)| Filter::lte(a, v)),
        (arb_attr(), arb_safe_value()).prop_map(|(a, v)| Filter::approx(a, v)),
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
    fn escape_roundtrip(input in "[\\x00-\\x7f]{0,50}") {
        let escaped = Filter::escape_value(&input);
        assert!(!escaped.contains('('));
        assert!(!escaped.contains(')'));
        let filter_str = format!("(cn={escaped})");
        let parsed = Filter::parse(&filter_str).unwrap();
        match parsed {
            Filter::Eq(_, v) => prop_assert_eq!(v, input),
            other => panic!("unexpected filter type: {other:?}"),
        }
    }

    #[test]
    fn filter_substring_ber_roundtrip(
        attr in arb_attr(),
        initial in proptest::option::of(arb_safe_value()),
        any_parts in prop::collection::vec(arb_safe_value(), 0..=3),
        final_part in proptest::option::of(arb_safe_value()),
    ) {
        let f = Filter::substring(attr, initial, any_parts, final_part);
        let mut w = BerWriter::new();
        f.encode(&mut w);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = Filter::decode(&mut r).unwrap();
        prop_assert_eq!(&f, &decoded);
    }
}

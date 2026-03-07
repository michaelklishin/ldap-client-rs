// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::dn::{Dn, Rdn, escape_dn_value};
use proptest::prelude::*;

fn arb_attr() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9]{0,8}"
}

fn arb_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,16}"
        .prop_map(|s| s.trim().to_string())
        .prop_filter("non-empty", |s| !s.is_empty())
}

fn arb_rdn() -> impl Strategy<Value = Rdn> {
    prop::collection::vec((arb_attr(), arb_value()), 1..=2)
        .prop_map(|components| Rdn { components })
}

fn arb_dn() -> impl Strategy<Value = Dn> {
    prop::collection::vec(arb_rdn(), 1..=4).prop_map(|rdns| Dn { rdns })
}

proptest! {
    #[test]
    fn prop_escape_roundtrip(value in arb_value()) {
        let escaped = escape_dn_value(&value);
        // Escaped value should be parseable as part of a DN
        let dn_str = format!("cn={escaped}");
        let dn = Dn::parse(&dn_str).unwrap();
        assert_eq!(dn.rdns[0].components[0].1, value);
    }

    #[test]
    fn prop_dn_display_roundtrip(dn in arb_dn()) {
        let displayed = dn.to_string();
        let parsed = Dn::parse(&displayed).unwrap();
        assert_eq!(dn, parsed);
    }
}

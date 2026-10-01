// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::dn::{AttributeValue, Dn, Rdn, escape_dn_value};
use proptest::prelude::*;

fn arb_attr() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,8}"
}

fn arb_value() -> impl Strategy<Value = AttributeValue> {
    prop_oneof![
        any::<String>().prop_map(AttributeValue::Text),
        prop::collection::vec(any::<u8>(), 1..8).prop_map(AttributeValue::Ber),
    ]
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
    fn prop_escape_roundtrip(value in any::<String>()) {
        let dn = Dn::parse(&format!("cn={}", escape_dn_value(&value))).unwrap();
        prop_assert_eq!(&dn.rdns[0].components[0].1, &AttributeValue::Text(value));
    }

    #[test]
    fn prop_dn_display_roundtrip(dn in arb_dn()) {
        let parsed = Dn::parse(&dn.to_string()).unwrap();
        prop_assert_eq!(dn, parsed);
    }

    #[test]
    fn prop_parse_never_panics(input in any::<String>()) {
        let _ = Dn::parse(&input);
    }

    #[test]
    fn prop_parse_never_panics_near_escapes(input in "[\\\\\"#+,;=<> aé€]{0,32}") {
        let _ = Dn::parse(&input);
    }

    #[test]
    fn prop_display_of_a_parsed_dn_parses_to_the_same_dn(input in "[a-z=\\\\\"#+,;<> 0-9é]{0,32}") {
        if let Ok(dn) = Dn::parse(&input) {
            prop_assert_eq!(Dn::parse(&dn.to_string()).unwrap(), dn);
        }
    }
}

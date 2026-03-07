// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerReader, BerWriter};
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_integer_roundtrip(value in any::<i64>()) {
        let mut w = BerWriter::new();
        w.write_integer(value);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = r.read_integer().unwrap();
        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn prop_boolean_roundtrip(value in any::<bool>()) {
        let mut w = BerWriter::new();
        w.write_boolean(value);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = r.read_boolean().unwrap();
        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn prop_octet_string_roundtrip(value in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut w = BerWriter::new();
        w.write_bytes(&value);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = r.read_octet_string().unwrap();
        prop_assert_eq!(&value[..], decoded);
    }

    #[test]
    fn prop_enumerated_roundtrip(value in -1000i64..1000) {
        let mut w = BerWriter::new();
        w.write_enumerated(value);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = r.read_enumerated().unwrap();
        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn prop_nested_sequence_roundtrip(depth in 1u16..20, value in any::<i64>()) {
        fn nest(w: &mut BerWriter, depth: u16, value: i64) {
            if depth == 0 {
                w.write_integer(value);
            } else {
                w.write_sequence(Tag::sequence(), |inner| nest(inner, depth - 1, value));
            }
        }

        let mut w = BerWriter::new();
        nest(&mut w, depth, value);

        fn unnest(r: &mut BerReader<'_>, depth: u16) -> Result<i64, ldap_client_ber::BerError> {
            if depth == 0 {
                r.read_integer()
            } else {
                r.read_sequence(Tag::sequence(), |inner| unnest(inner, depth - 1))
            }
        }

        let mut r = BerReader::new(w.as_bytes());
        let decoded = unnest(&mut r, depth).unwrap();
        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn prop_context_tagged_roundtrip(tag_num in 0u32..10, value in proptest::collection::vec(any::<u8>(), 0..256)) {
        let mut w = BerWriter::new();
        w.write_octet_string(Tag::context(tag_num), &value);
        let mut r = BerReader::new(w.as_bytes());
        let decoded = r.read_tagged_implicit_octet_string(tag_num).unwrap();
        prop_assert_eq!(&value[..], decoded);
    }

    #[test]
    fn prop_sequence_of_integers_roundtrip(values in proptest::collection::vec(any::<i64>(), 1..20)) {
        let mut w = BerWriter::new();
        w.write_sequence(Tag::sequence(), |inner| {
            for &v in &values {
                inner.write_integer(v);
            }
        });

        let mut r = BerReader::new(w.as_bytes());
        r.read_sequence(Tag::sequence(), |inner| {
            for &expected in &values {
                let decoded = inner.read_integer()?;
                assert_eq!(expected, decoded);
            }
            Ok(())
        }).unwrap();
    }
}

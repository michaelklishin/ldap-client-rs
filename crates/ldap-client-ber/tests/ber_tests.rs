// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::tag::{INTEGER, OCTET_STRING, Tag};
use ldap_client_ber::{BerError, BerReader, BerWriter};

// ---------- Integer encoding/decoding ----------

#[test]
fn integer_zero() {
    let mut w = BerWriter::new();
    w.write_integer(0);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), 0);
}

#[test]
fn integer_positive_small() {
    let mut w = BerWriter::new();
    w.write_integer(127);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), 127);
}

#[test]
fn integer_positive_128() {
    let mut w = BerWriter::new();
    w.write_integer(128);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), 128);
}

#[test]
fn integer_negative() {
    let mut w = BerWriter::new();
    w.write_integer(-1);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), -1);
}

#[test]
fn integer_negative_128() {
    let mut w = BerWriter::new();
    w.write_integer(-128);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), -128);
}

#[test]
fn integer_negative_129() {
    let mut w = BerWriter::new();
    w.write_integer(-129);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), -129);
}

#[test]
fn integer_max() {
    let mut w = BerWriter::new();
    w.write_integer(i64::MAX);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), i64::MAX);
}

#[test]
fn integer_min() {
    let mut w = BerWriter::new();
    w.write_integer(i64::MIN);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), i64::MIN);
}

// ---------- Boolean encoding/decoding ----------

#[test]
fn boolean_true() {
    let mut w = BerWriter::new();
    w.write_boolean(true);
    let mut r = BerReader::new(w.as_bytes());
    assert!(r.read_boolean().unwrap());
}

#[test]
fn boolean_false() {
    let mut w = BerWriter::new();
    w.write_boolean(false);
    let mut r = BerReader::new(w.as_bytes());
    assert!(!r.read_boolean().unwrap());
}

// ---------- Octet string ----------

#[test]
fn octet_string_empty() {
    let mut w = BerWriter::new();
    w.write_bytes(&[]);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_octet_string().unwrap(), b"");
}

#[test]
fn octet_string_hello() {
    let mut w = BerWriter::new();
    w.write_bytes(b"hello");
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_octet_string().unwrap(), b"hello");
}

#[test]
fn octet_string_binary() {
    let data: Vec<u8> = (0..=255).collect();
    let mut w = BerWriter::new();
    w.write_bytes(&data);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_octet_string().unwrap(), &data[..]);
}

// ---------- Enumerated ----------

#[test]
fn enumerated_roundtrip() {
    for val in [0, 1, 2, 10, 49, 80, -1] {
        let mut w = BerWriter::new();
        w.write_enumerated(val);
        let mut r = BerReader::new(w.as_bytes());
        assert_eq!(r.read_enumerated().unwrap(), val);
    }
}

// ---------- Sequence ----------

#[test]
fn sequence_of_integers() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_integer(1);
        inner.write_integer(2);
        inner.write_integer(3);
    });

    let mut r = BerReader::new(w.as_bytes());
    r.read_sequence(Tag::sequence(), |inner| {
        assert_eq!(inner.read_integer()?, 1);
        assert_eq!(inner.read_integer()?, 2);
        assert_eq!(inner.read_integer()?, 3);
        Ok(())
    })
    .unwrap();
}

#[test]
fn nested_sequences() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |outer| {
        outer.write_integer(42);
        outer.write_sequence(Tag::sequence(), |inner| {
            inner.write_bytes(b"nested");
        });
    });

    let mut r = BerReader::new(w.as_bytes());
    r.read_sequence(Tag::sequence(), |outer| {
        assert_eq!(outer.read_integer()?, 42);
        outer.read_sequence(Tag::sequence(), |inner| {
            assert_eq!(inner.read_octet_string()?, b"nested");
            Ok(())
        })
    })
    .unwrap();
}

#[test]
fn empty_sequence() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |_| {});

    let mut r = BerReader::new(w.as_bytes());
    r.read_sequence(Tag::sequence(), |inner| {
        assert!(inner.is_empty());
        Ok(())
    })
    .unwrap();
}

// ---------- Context-tagged elements ----------

#[test]
fn context_tagged_octet_string() {
    let mut w = BerWriter::new();
    w.write_octet_string(Tag::context(0), b"password");

    let mut r = BerReader::new(w.as_bytes());
    let data = r.read_tagged_implicit_octet_string(0).unwrap();
    assert_eq!(data, b"password");
}

#[test]
fn context_constructed() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::context_constructed(3), |inner| {
        inner.write_string(Tag::universal(OCTET_STRING), "EXTERNAL");
    });

    let mut r = BerReader::new(w.as_bytes());
    r.read_sequence(Tag::context_constructed(3), |inner| {
        assert_eq!(inner.read_octet_string()?, b"EXTERNAL");
        Ok(())
    })
    .unwrap();
}

// ---------- Application-tagged elements ----------

#[test]
fn application_tagged_sequence() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::application(0), |inner| {
        inner.write_integer(3);
        inner.write_bytes(b"cn=admin");
        inner.write_octet_string(Tag::context(0), b"secret");
    });

    let mut r = BerReader::new(w.as_bytes());
    r.read_sequence(Tag::application(0), |inner| {
        assert_eq!(inner.read_integer()?, 3);
        assert_eq!(inner.read_octet_string()?, b"cn=admin");
        let pw = inner.read_tagged_implicit_octet_string(0)?;
        assert_eq!(pw, b"secret");
        Ok(())
    })
    .unwrap();
}

// ---------- Tag encoding ----------

#[test]
fn tag_encode_low_number() {
    let tag = Tag::universal(INTEGER);
    assert_eq!(tag.encode(), vec![0x02]);
}

#[test]
fn tag_encode_sequence() {
    let tag = Tag::sequence();
    assert_eq!(tag.encode(), vec![0x30]);
}

#[test]
fn tag_encode_context_0() {
    let tag = Tag::context(0);
    assert_eq!(tag.encode(), vec![0x80]);
}

#[test]
fn tag_encode_application_0_constructed() {
    let tag = Tag::application(0);
    assert_eq!(tag.encode(), vec![0x60]);
}

#[test]
fn tag_encode_high_number() {
    // Application tag 31+ uses high-tag-number form.
    let tag = Tag::application(31);
    assert_eq!(tag.encode(), vec![0x7F, 31]);
}

#[test]
fn tag_encode_application_23() {
    // Tag 23 fits in low 5 bits: class=01, constructed=1, tag=10111 = 0x77
    let tag = Tag::application(23);
    assert_eq!(tag.encode(), vec![0x77]);
}

// ---------- Error cases ----------

#[test]
fn truncated_input() {
    let r = BerReader::new(&[]).read_integer();
    assert!(matches!(r, Err(BerError::Truncated { .. })));
}

#[test]
fn wrong_tag() {
    let mut w = BerWriter::new();
    w.write_boolean(true);
    let mut r = BerReader::new(w.as_bytes());
    let err = r.read_integer().unwrap_err();
    assert!(matches!(err, BerError::UnexpectedTag { .. }));
}

#[test]
fn constructed_octet_string_rejected() {
    // Manually craft a constructed OCTET STRING: tag 0x24.
    let data = [0x24, 0x02, 0x04, 0x00];
    let mut r = BerReader::new(&data);
    let err = r.read_octet_string().unwrap_err();
    assert!(matches!(err, BerError::ConstructedPrimitive));
}

#[test]
fn indefinite_length_rejected() {
    let data = [0x30, 0x80]; // SEQUENCE with indefinite length
    let mut r = BerReader::new(&data);
    let err = r.read_sequence(Tag::sequence(), |_| Ok(())).unwrap_err();
    assert!(matches!(err, BerError::IndefiniteLength));
}

#[test]
fn recursion_limit_enforced() {
    // Build deeply nested sequences (35 levels).
    fn nest(w: &mut BerWriter, depth: u16) {
        if depth == 0 {
            w.write_integer(42);
        } else {
            w.write_sequence(Tag::sequence(), |inner| nest(inner, depth - 1));
        }
    }

    let mut w = BerWriter::new();
    nest(&mut w, 35);

    fn unnest(r: &mut BerReader<'_>, depth: u16) -> Result<i64, BerError> {
        if depth == 0 {
            r.read_integer()
        } else {
            r.read_sequence(Tag::sequence(), |inner| unnest(inner, depth - 1))
        }
    }

    let mut r = BerReader::new(w.as_bytes()).with_max_depth(32);
    let err = unnest(&mut r, 35).unwrap_err();
    assert!(matches!(err, BerError::RecursionLimit { max: 32 }));
}

#[test]
fn element_too_large_rejected() {
    // Craft a length field claiming 1 MiB, but with very little actual data.
    let data = [0x04, 0x83, 0x10, 0x00, 0x00, 0x00]; // OCTET STRING, length = 1048576
    let mut r = BerReader::new(&data).with_max_element_size(1024);
    let err = r.read_element().unwrap_err();
    assert!(matches!(err, BerError::ElementTooLarge { .. }));
}

#[test]
fn length_exceeds_buffer() {
    // Length field says 100 bytes, buffer has only 5.
    let data = [0x04, 0x64, 0x00, 0x00, 0x00];
    let mut r = BerReader::new(&data);
    let err = r.read_element().unwrap_err();
    assert!(matches!(err, BerError::Truncated { .. }));
}

#[test]
fn peek_tag_without_consuming() {
    let mut w = BerWriter::new();
    w.write_integer(99);
    let r = BerReader::new(w.as_bytes());
    let tag = r.peek_tag().unwrap();
    assert_eq!(tag, Tag::universal(INTEGER));
    // Reader state unchanged — can still read the integer.
    let mut r = r;
    assert_eq!(r.read_integer().unwrap(), 99);
}

// ---------- Writer reuse ----------

#[test]
fn writer_clear_reuse() {
    let mut w = BerWriter::with_capacity(64);
    w.write_integer(1);
    assert!(!w.as_bytes().is_empty());
    w.clear();
    assert!(w.as_bytes().is_empty());
    w.write_integer(2);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), 2);
}

// ---------- Multiple elements in sequence ----------

#[test]
fn multiple_elements() {
    let mut w = BerWriter::new();
    w.write_integer(1);
    w.write_boolean(true);
    w.write_bytes(b"test");

    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_integer().unwrap(), 1);
    assert!(r.read_boolean().unwrap());
    assert_eq!(r.read_octet_string().unwrap(), b"test");
    assert!(r.is_empty());
}

// ---------- Long-form lengths ----------

#[test]
fn long_form_length() {
    // Write a 200-byte octet string (length > 127 requires long form).
    let data = vec![0xAA; 200];
    let mut w = BerWriter::new();
    w.write_bytes(&data);
    let mut r = BerReader::new(w.as_bytes());
    assert_eq!(r.read_octet_string().unwrap(), &data[..]);
}

// ---------- read_sequence_lax ----------

#[test]
fn read_sequence_lax_allows_trailing_data() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_integer(1);
        inner.write_integer(2);
        inner.write_integer(3);
    });

    let mut r = BerReader::new(w.as_bytes());
    let val = r
        .read_sequence_lax(Tag::sequence(), |inner| {
            let first = inner.read_integer()?;
            Ok(first)
        })
        .unwrap();
    assert_eq!(val, 1);
}

#[test]
fn read_sequence_rejects_trailing_data() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_integer(1);
        inner.write_integer(2);
    });

    let mut r = BerReader::new(w.as_bytes());
    let err = r
        .read_sequence(Tag::sequence(), |inner| {
            inner.read_integer()?;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(err, BerError::TrailingData { .. }));
}

// ---------- High-tag-number roundtrip ----------

#[test]
fn high_tag_number_roundtrip() {
    let mut w = BerWriter::new();
    w.write_octet_string(Tag::context(128), b"high-tag");
    let mut r = BerReader::new(w.as_bytes());
    let data = r.read_tagged_implicit_octet_string(128).unwrap();
    assert_eq!(data, b"high-tag");
}

#[test]
fn tag_overflow_rejected() {
    // Craft a tag with too many continuation bytes: class=context, high-tag form
    // 0x9F = context(31+), then 6 continuation bytes (overflows u32).
    let data = [0x9F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x01, 0x00];
    let mut r = BerReader::new(&data);
    let err = r.read_element().unwrap_err();
    assert!(matches!(err, BerError::TagOverflow));
}

// ---------- Null ----------

#[test]
fn null_encoding() {
    let mut w = BerWriter::new();
    w.write_null();
    let bytes = w.as_bytes();
    assert_eq!(bytes, &[0x05, 0x00]);
}

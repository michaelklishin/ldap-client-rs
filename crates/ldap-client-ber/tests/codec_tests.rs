// SPDX-License-Identifier: MIT OR Apache-2.0

use bytes::BytesMut;
use ldap_client_ber::{BerWriter, LdapCodec};
use tokio_util::codec::{Decoder, Encoder};

/// An empty buffer should return `Ok(None)` (no frame available).
#[test]
fn empty_buffer_returns_none() {
    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::new();
    let result = codec.decode(&mut buf).unwrap();
    assert!(result.is_none());
}

/// Feeding a partial frame (incomplete TLV) returns `Ok(None)`, then
/// appending the remaining bytes yields the complete frame.
#[test]
fn partial_read_then_complete() {
    use ldap_client_ber::tag::Tag;

    // Build a valid LDAP-like SEQUENCE with BerWriter.
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_bytes(b"hello");
    });
    let full = w.into_bytes();
    assert!(full.len() > 4, "message must be long enough to split");

    let split = full.len() / 2;

    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::from(&full[..split]);

    // First decode: not enough data yet.
    let result = codec.decode(&mut buf).unwrap();
    assert!(result.is_none(), "partial frame must return None");

    // Append the rest.
    buf.extend_from_slice(&full[split..]);

    // Second decode: full frame is available.
    let frame = codec
        .decode(&mut buf)
        .unwrap()
        .expect("frame should be available");
    assert_eq!(&frame[..], &full[..]);
    assert!(buf.is_empty(), "buffer should be drained");
}

/// A message whose declared length exceeds `max_message_size` must be rejected.
#[test]
fn max_message_size_rejection() {
    use ldap_client_ber::tag::Tag;

    // Build a SEQUENCE containing a large payload.
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        // 256 bytes of payload -- small enough to actually allocate, but we
        // will set the codec limit very low (e.g. 64 bytes).
        msg.write_bytes(&[0xAA; 256]);
    });
    let full = w.into_bytes();

    let mut codec = LdapCodec::new().with_max_message_size(64);
    let mut buf = BytesMut::from(&full[..]);

    let err = codec.decode(&mut buf).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds maximum"),
        "expected ElementTooLarge error, got: {msg}"
    );
}

/// The first byte of any LDAP message must be 0x30 (SEQUENCE). Any other
/// byte must produce an `InvalidTag` error.
#[test]
fn invalid_first_byte_rejection() {
    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::from(&[0x02, 0x01, 0x05][..]); // INTEGER 5

    let err = codec.decode(&mut buf).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("0x02"),
        "expected InvalidTag mentioning 0x02, got: {msg}"
    );
}

/// When two complete messages are concatenated in a single buffer the codec
/// should return each one in turn.
#[test]
fn multiple_messages_in_one_buffer() {
    use ldap_client_ber::tag::Tag;

    let mut w1 = BerWriter::new();
    w1.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
    });
    let msg1 = w1.into_bytes();

    let mut w2 = BerWriter::new();
    w2.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(2);
    });
    let msg2 = w2.into_bytes();

    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&msg1);
    buf.extend_from_slice(&msg2);

    // First decode returns msg1.
    let frame1 = codec.decode(&mut buf).unwrap().expect("first frame");
    assert_eq!(&frame1[..], &msg1[..]);

    // Second decode returns msg2.
    let frame2 = codec.decode(&mut buf).unwrap().expect("second frame");
    assert_eq!(&frame2[..], &msg2[..]);

    // Buffer is now empty.
    assert!(buf.is_empty());
    assert!(codec.decode(&mut buf).unwrap().is_none());
}

#[test]
fn encoder_vec_u8() {
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
    });
    let data = w.into_bytes();

    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(data.clone(), &mut buf).unwrap();
    assert_eq!(&buf[..], &data[..]);
}

#[test]
fn encoder_slice() {
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(42);
    });
    let data = w.into_bytes();

    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(data.as_slice(), &mut buf).unwrap();
    assert_eq!(&buf[..], &data[..]);
}

#[test]
fn encode_then_decode() {
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(99);
        msg.write_bytes(b"test data");
    });
    let data = w.into_bytes();

    let mut codec = LdapCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(data.clone(), &mut buf).unwrap();

    let frame = codec.decode(&mut buf).unwrap().expect("should get frame");
    assert_eq!(&frame[..], &data[..]);
}

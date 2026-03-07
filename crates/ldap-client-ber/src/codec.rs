// SPDX-License-Identifier: MIT OR Apache-2.0

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::BerError;
use crate::length::decode_length;

/// BER-aware message framing codec for LDAP.
///
/// Reads the tag + length to determine message boundaries, then yields
/// the complete TLV as a frame.
///
/// Note that LDAP does not use length-prefix framing.
pub struct LdapCodec {
    max_message_size: u32,
}

impl LdapCodec {
    pub fn new() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024,
        }
    }

    pub fn with_max_message_size(mut self, max: u32) -> Self {
        self.max_message_size = max;
        self
    }
}

impl Default for LdapCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for LdapCodec {
    type Item = BytesMut;
    type Error = BerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Every LDAP message is a SEQUENCE (0x30).
        if src[0] != 0x30 {
            return Err(BerError::InvalidTag(src[0]));
        }

        // Try to read the length field (starts at byte 1).
        if src.len() < 2 {
            return Ok(None);
        }

        match decode_length(&src[1..])? {
            None => Ok(None),
            Some((length_field_size, value_length)) => {
                if value_length as u64 > self.max_message_size as u64 {
                    return Err(BerError::ElementTooLarge {
                        size: value_length as u64,
                        max: self.max_message_size,
                    });
                }

                let total = 1usize
                    .saturating_add(length_field_size)
                    .saturating_add(value_length);
                if src.len() < total {
                    src.reserve(total - src.len());
                    return Ok(None);
                }

                Ok(Some(src.split_to(total)))
            }
        }
    }
}

impl Encoder<Vec<u8>> for LdapCodec {
    type Error = BerError;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

impl Encoder<&[u8]> for LdapCodec {
    type Error = BerError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(item);
        Ok(())
    }
}

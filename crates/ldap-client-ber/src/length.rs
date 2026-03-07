// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::BerError;

/// Encode a definite length in minimal BER form.
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let num_bytes = be.len() - start;
    let mut result = Vec::with_capacity(1 + num_bytes);
    result.push(0x80 | num_bytes as u8);
    result.extend_from_slice(&be[start..]);
    result
}

/// Decode a BER length field. Returns `(length_field_size, value_length)`.
///
/// Returns `None` if more data is needed.
/// Returns `Err` for invalid encodings (indefinite length, overflow).
pub fn decode_length(input: &[u8]) -> Result<Option<(usize, usize)>, BerError> {
    if input.is_empty() {
        return Ok(None);
    }

    let first = input[0];
    if first == 0x80 {
        return Err(BerError::IndefiniteLength);
    }

    if first < 0x80 {
        return Ok(Some((1, first as usize)));
    }

    let num_bytes = (first & 0x7F) as usize;
    if num_bytes > 4 {
        return Err(BerError::InvalidLength);
    }
    if input.len() < 1 + num_bytes {
        return Ok(None);
    }

    let mut length: u64 = 0;
    for &b in &input[1..1 + num_bytes] {
        length = (length << 8) | b as u64;
    }

    // Guard against overflow before casting to usize.
    if length > usize::MAX as u64 {
        return Err(BerError::ElementTooLarge {
            size: length,
            max: u32::MAX,
        });
    }

    Ok(Some((1 + num_bytes, length as usize)))
}

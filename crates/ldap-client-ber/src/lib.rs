// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod codec;
pub mod length;
pub mod reader;
pub mod tag;
pub mod writer;

pub use codec::LdapCodec;
pub use reader::BerReader;
pub use tag::{Class, Tag};
pub use writer::BerWriter;

#[derive(Debug, thiserror::Error)]
pub enum BerError {
    #[error("unexpected tag: expected {expected:?}, got {actual:?}")]
    UnexpectedTag { expected: Tag, actual: Tag },

    #[error("truncated input: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },

    #[error("recursion depth exceeded (max {max})")]
    RecursionLimit { max: u16 },

    #[error("element size {size} exceeds maximum {max}")]
    ElementTooLarge { size: u64, max: u32 },

    #[error("invalid length encoding")]
    InvalidLength,

    #[error("invalid integer encoding")]
    InvalidInteger,

    #[error("invalid boolean encoding")]
    InvalidBoolean,

    #[error("indefinite length not supported")]
    IndefiniteLength,

    #[error("constructed OCTET STRING not supported")]
    ConstructedPrimitive,

    #[error("invalid tag byte: 0x{0:02x}")]
    InvalidTag(u8),

    #[error("tag number overflow")]
    TagOverflow,

    #[error("trailing data: {remaining} bytes unconsumed in constructed element")]
    TrailingData { remaining: usize },

    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

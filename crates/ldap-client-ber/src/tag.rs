// SPDX-License-Identifier: MIT OR Apache-2.0

/// BER tag class (top 2 bits of the identifier byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Class {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}

impl Class {
    pub fn from_byte(b: u8) -> Self {
        match b >> 6 {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::Context,
            3 => Self::Private,
            _ => unreachable!(),
        }
    }
}

/// Fully decoded BER tag: class + constructed flag + tag number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const fn universal(number: u32) -> Self {
        Self {
            class: Class::Universal,
            constructed: false,
            number,
        }
    }

    pub const fn sequence() -> Self {
        Self {
            class: Class::Universal,
            constructed: true,
            number: SEQUENCE,
        }
    }

    pub const fn set() -> Self {
        Self {
            class: Class::Universal,
            constructed: true,
            number: SET,
        }
    }

    pub const fn context(number: u32) -> Self {
        Self {
            class: Class::Context,
            constructed: false,
            number,
        }
    }

    pub const fn context_constructed(number: u32) -> Self {
        Self {
            class: Class::Context,
            constructed: true,
            number,
        }
    }

    pub const fn application(number: u32) -> Self {
        Self {
            class: Class::Application,
            constructed: true,
            number,
        }
    }

    pub const fn application_primitive(number: u32) -> Self {
        Self {
            class: Class::Application,
            constructed: false,
            number,
        }
    }

    pub fn with_constructed(self, constructed: bool) -> Self {
        Self {
            constructed,
            ..self
        }
    }

    /// Encode the identifier byte(s).
    pub fn encode(&self) -> Vec<u8> {
        let mut first = (self.class as u8) << 6;
        if self.constructed {
            first |= 0x20;
        }

        if self.number < 31 {
            first |= self.number as u8;
            vec![first]
        } else {
            first |= 0x1F;
            // Encode tag number in base-128. A u32 needs at most 5 base-128 digits.
            let mut buf = [0u8; 5];
            let mut pos = buf.len();
            let mut n = self.number;
            loop {
                pos -= 1;
                buf[pos] = (n & 0x7F) as u8;
                n >>= 7;
                if n == 0 {
                    break;
                }
            }
            // Set continuation bits on all but the last byte.
            let end = buf.len() - 1;
            for b in &mut buf[pos..end] {
                *b |= 0x80;
            }
            let mut result = Vec::with_capacity(1 + buf.len() - pos);
            result.push(first);
            result.extend_from_slice(&buf[pos..]);
            result
        }
    }
}

// Well-known universal tag numbers.
pub const BOOLEAN: u32 = 0x01;
pub const INTEGER: u32 = 0x02;
pub const OCTET_STRING: u32 = 0x04;
pub const NULL: u32 = 0x05;
pub const ENUMERATED: u32 = 0x0A;
pub const SEQUENCE: u32 = 0x10;
pub const SET: u32 = 0x11;

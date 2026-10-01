// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Assignment {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Removal {
    pub name: String,
    pub value: Option<Vec<u8>>,
}

impl FromStr for Assignment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once('=')
            .ok_or_else(|| format!("expected NAME=VALUE, got: {s}"))?;
        Ok(Self {
            name: name.to_owned(),
            value: value.as_bytes().to_vec(),
        })
    }
}

impl FromStr for Removal {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.split_once('=') {
            Some((name, value)) => Self {
                name: name.to_owned(),
                value: Some(value.as_bytes().to_vec()),
            },
            None => Self {
                name: s.to_owned(),
                value: None,
            },
        })
    }
}

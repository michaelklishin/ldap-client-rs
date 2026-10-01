// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

pub enum CliError {
    Usage(&'static str),
    Ldap(ldap_client::Error),
}

impl CliError {
    /// `clap` exits with 2 for its own usage errors.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Ldap(_) => 1,
        }
    }
}

impl From<ldap_client::Error> for CliError {
    fn from(e: ldap_client::Error) -> Self {
        Self::Ldap(e)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::Ldap(e) => e.fmt(f),
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultCode {
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongerAuthRequired,
    Referral,
    AdminLimitExceeded,
    SaslBindInProgress,
    NoSuchAttribute,
    UndefinedAttributeType,
    InappropriateMatching,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    NoSuchObject,
    InvalidDnSyntax,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    NotAllowedOnNonLeaf,
    EntryAlreadyExists,
    Other,
    Unknown(i32),
}

impl ResultCode {
    pub fn from_i64(code: i64) -> Self {
        let Ok(code) = i32::try_from(code) else {
            return Self::Unknown(i32::MAX);
        };
        match code {
            0 => Self::Success,
            1 => Self::OperationsError,
            2 => Self::ProtocolError,
            3 => Self::TimeLimitExceeded,
            4 => Self::SizeLimitExceeded,
            5 => Self::CompareFalse,
            6 => Self::CompareTrue,
            7 => Self::AuthMethodNotSupported,
            8 => Self::StrongerAuthRequired,
            10 => Self::Referral,
            11 => Self::AdminLimitExceeded,
            14 => Self::SaslBindInProgress,
            16 => Self::NoSuchAttribute,
            17 => Self::UndefinedAttributeType,
            18 => Self::InappropriateMatching,
            19 => Self::ConstraintViolation,
            20 => Self::AttributeOrValueExists,
            21 => Self::InvalidAttributeSyntax,
            32 => Self::NoSuchObject,
            34 => Self::InvalidDnSyntax,
            49 => Self::InvalidCredentials,
            50 => Self::InsufficientAccessRights,
            51 => Self::Busy,
            52 => Self::Unavailable,
            53 => Self::UnwillingToPerform,
            66 => Self::NotAllowedOnNonLeaf,
            68 => Self::EntryAlreadyExists,
            80 => Self::Other,
            n => Self::Unknown(n),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::CompareFalse | Self::CompareTrue)
    }

    pub fn is_credential_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidCredentials
                | Self::InsufficientAccessRights
                | Self::AuthMethodNotSupported
                | Self::StrongerAuthRequired
        )
    }

    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Busy | Self::Unavailable | Self::AdminLimitExceeded | Self::Other
        )
    }

    pub fn is_referral(&self) -> bool {
        matches!(self, Self::Referral)
    }

    pub fn is_configuration_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidDnSyntax
                | Self::NoSuchObject
                | Self::UndefinedAttributeType
                | Self::InappropriateMatching
        )
    }
}

impl std::fmt::Display for ResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

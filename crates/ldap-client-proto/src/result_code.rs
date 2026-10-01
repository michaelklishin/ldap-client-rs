// SPDX-License-Identifier: MIT OR Apache-2.0

/// One row per RFC 4511 appendix A result code: the variant, its number and
/// its RFC name. The enum, both conversions and `Display` come from the same rows.
macro_rules! result_codes {
    ($($variant:ident = $code:literal $name:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum ResultCode {
            $($variant,)*
            Unknown(i32),
        }

        impl ResultCode {
            pub fn from_i64(code: i64) -> Self {
                let Ok(code) = i32::try_from(code) else {
                    return Self::Unknown(i32::MAX);
                };
                match code {
                    $($code => Self::$variant,)*
                    n => Self::Unknown(n),
                }
            }

            pub fn code(self) -> i32 {
                match self {
                    $(Self::$variant => $code,)*
                    Self::Unknown(n) => n,
                }
            }

            fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                    Self::Unknown(_) => "unknown",
                }
            }
        }
    };
}

result_codes! {
    Success = 0 "success",
    OperationsError = 1 "operationsError",
    ProtocolError = 2 "protocolError",
    TimeLimitExceeded = 3 "timeLimitExceeded",
    SizeLimitExceeded = 4 "sizeLimitExceeded",
    CompareFalse = 5 "compareFalse",
    CompareTrue = 6 "compareTrue",
    AuthMethodNotSupported = 7 "authMethodNotSupported",
    StrongerAuthRequired = 8 "strongerAuthRequired",
    Referral = 10 "referral",
    AdminLimitExceeded = 11 "adminLimitExceeded",
    UnavailableCriticalExtension = 12 "unavailableCriticalExtension",
    ConfidentialityRequired = 13 "confidentialityRequired",
    SaslBindInProgress = 14 "saslBindInProgress",
    NoSuchAttribute = 16 "noSuchAttribute",
    UndefinedAttributeType = 17 "undefinedAttributeType",
    InappropriateMatching = 18 "inappropriateMatching",
    ConstraintViolation = 19 "constraintViolation",
    AttributeOrValueExists = 20 "attributeOrValueExists",
    InvalidAttributeSyntax = 21 "invalidAttributeSyntax",
    NoSuchObject = 32 "noSuchObject",
    AliasProblem = 33 "aliasProblem",
    InvalidDnSyntax = 34 "invalidDNSyntax",
    AliasDereferencingProblem = 36 "aliasDereferencingProblem",
    InappropriateAuthentication = 48 "inappropriateAuthentication",
    InvalidCredentials = 49 "invalidCredentials",
    InsufficientAccessRights = 50 "insufficientAccessRights",
    Busy = 51 "busy",
    Unavailable = 52 "unavailable",
    UnwillingToPerform = 53 "unwillingToPerform",
    LoopDetect = 54 "loopDetect",
    NamingViolation = 64 "namingViolation",
    ObjectClassViolation = 65 "objectClassViolation",
    NotAllowedOnNonLeaf = 66 "notAllowedOnNonLeaf",
    NotAllowedOnRdn = 67 "notAllowedOnRDN",
    EntryAlreadyExists = 68 "entryAlreadyExists",
    ObjectClassModsProhibited = 69 "objectClassModsProhibited",
    AffectsMultipleDsas = 71 "affectsMultipleDSAs",
    Other = 80 "other",
}

impl ResultCode {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::CompareFalse | Self::CompareTrue)
    }

    pub fn is_credential_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidCredentials
                | Self::InappropriateAuthentication
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
        write!(f, "{} ({})", self.name(), self.code())
    }
}

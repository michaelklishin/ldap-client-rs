// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::ResultCode;
use proptest::prelude::*;

const RFC_4511_CODES: [i32; 39] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 32, 33, 34, 36, 48, 49,
    50, 51, 52, 53, 54, 64, 65, 66, 67, 68, 69, 71, 80,
];

#[test]
fn every_code_in_the_table_round_trips_through_its_number() {
    for number in RFC_4511_CODES {
        let code = ResultCode::from_i64(i64::from(number));
        assert!(!matches!(code, ResultCode::Unknown(_)), "{number}");
        assert_eq!(code.code(), number);
    }
}

#[test]
fn the_codes_that_decoded_as_unknown_decode_as_their_variants() {
    assert_eq!(
        ResultCode::from_i64(12),
        ResultCode::UnavailableCriticalExtension
    );
    assert_eq!(
        ResultCode::from_i64(13),
        ResultCode::ConfidentialityRequired
    );
    assert_eq!(ResultCode::from_i64(33), ResultCode::AliasProblem);
    assert_eq!(
        ResultCode::from_i64(36),
        ResultCode::AliasDereferencingProblem
    );
    assert_eq!(
        ResultCode::from_i64(48),
        ResultCode::InappropriateAuthentication
    );
    assert_eq!(ResultCode::from_i64(54), ResultCode::LoopDetect);
    assert_eq!(ResultCode::from_i64(64), ResultCode::NamingViolation);
    assert_eq!(ResultCode::from_i64(65), ResultCode::ObjectClassViolation);
    assert_eq!(ResultCode::from_i64(67), ResultCode::NotAllowedOnRdn);
    assert_eq!(
        ResultCode::from_i64(69),
        ResultCode::ObjectClassModsProhibited
    );
    assert_eq!(ResultCode::from_i64(71), ResultCode::AffectsMultipleDsas);
}

#[test]
fn an_unlisted_number_is_unknown() {
    assert_eq!(ResultCode::from_i64(75), ResultCode::Unknown(75));
    assert_eq!(ResultCode::Unknown(75).code(), 75);
}

#[test]
fn a_number_beyond_i32_is_unknown() {
    assert_eq!(
        ResultCode::from_i64(i64::MAX),
        ResultCode::Unknown(i32::MAX)
    );
}

#[test]
fn display_names_the_rfc_name_and_number() {
    assert_eq!(
        ResultCode::InvalidCredentials.to_string(),
        "invalidCredentials (49)"
    );
    assert_eq!(
        ResultCode::InvalidDnSyntax.to_string(),
        "invalidDNSyntax (34)"
    );
    assert_eq!(
        ResultCode::NotAllowedOnRdn.to_string(),
        "notAllowedOnRDN (67)"
    );
    assert_eq!(ResultCode::Unknown(75).to_string(), "unknown (75)");
}

#[test]
fn inappropriate_authentication_is_a_credential_error() {
    assert!(ResultCode::InappropriateAuthentication.is_credential_error());
}

proptest! {
    #[test]
    fn prop_a_known_number_never_decodes_as_unknown(number in prop::sample::select(RFC_4511_CODES.to_vec())) {
        prop_assert!(!matches!(ResultCode::from_i64(i64::from(number)), ResultCode::Unknown(_)));
    }

    #[test]
    fn prop_any_number_survives_a_round_trip(number in any::<i32>()) {
        prop_assert_eq!(ResultCode::from_i64(i64::from(number)).code(), number);
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_ber::{BerWriter, Tag};
use ldap_client_proto::{
    Control, DomainScopeControl, MANAGE_DSA_IT_OID, ManageDsaItControl, PAGED_RESULTS_OID,
    PagedResultsControl, ResultCode, SERVER_SORT_RESPONSE_OID, SortKey, SortKeyList, SortResult,
};
use proptest::prelude::*;

fn paged_value(size: i64, cookie: &[u8]) -> Vec<u8> {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_integer(size);
        inner.write_bytes(cookie);
    });
    w.into_bytes()
}

#[test]
fn a_paged_control_round_trips_through_new_and_decode() {
    let paged = PagedResultsControl::new(50).with_cookie(b"abc".to_vec());
    let control = Control::new(&paged, false);
    assert_eq!(control.oid, PAGED_RESULTS_OID);
    let decoded: PagedResultsControl = control.decode().unwrap();
    assert_eq!(decoded.size, 50);
    assert_eq!(decoded.cookie, b"abc");
}

#[test]
fn decode_refuses_a_control_with_another_oid() {
    let control = Control {
        oid: MANAGE_DSA_IT_OID.into(),
        critical: false,
        value: Some(paged_value(10, b"")),
    };
    assert!(control.decode::<PagedResultsControl>().is_err());
    assert!(PagedResultsControl::from_control(&control).is_err());
}

#[test]
fn a_paged_size_out_of_range_is_refused() {
    let control = Control {
        oid: PAGED_RESULTS_OID.into(),
        critical: false,
        value: Some(paged_value(i64::from(i32::MAX) + 1, b"")),
    };
    assert!(control.decode::<PagedResultsControl>().is_err());
}

#[test]
fn a_paged_control_without_a_value_is_refused() {
    let control = Control {
        oid: PAGED_RESULTS_OID.into(),
        critical: false,
        value: None,
    };
    assert!(control.decode::<PagedResultsControl>().is_err());
}

#[test]
fn find_is_none_without_the_control() {
    let controls = vec![Control::new(&ManageDsaItControl::new(true), true)];
    assert!(
        Control::find::<PagedResultsControl>(&controls)
            .unwrap()
            .is_none()
    );
    assert!(Control::find::<PagedResultsControl>(&[]).unwrap().is_none());
}

#[test]
fn find_returns_the_decoded_control() {
    let controls = vec![
        Control::new(&ManageDsaItControl::new(false), false),
        Control::new(&PagedResultsControl::new(7).with_cookie(vec![1, 2]), false),
    ];
    let paged = Control::find::<PagedResultsControl>(&controls)
        .unwrap()
        .unwrap();
    assert_eq!((paged.size, paged.cookie), (7, vec![1, 2]));
}

#[test]
fn find_reports_an_undecodable_control() {
    let controls = vec![Control {
        oid: PAGED_RESULTS_OID.into(),
        critical: false,
        value: Some(vec![0xFF]),
    }];
    assert!(Control::find::<PagedResultsControl>(&controls).is_err());
}

#[test]
fn the_old_to_control_methods_produce_the_same_bytes() {
    let paged = PagedResultsControl::new(10).with_cookie(vec![9]);
    assert_eq!(paged.to_control(), Control::new(&paged, false));

    let manage = ManageDsaItControl::new(true);
    assert_eq!(manage.to_control(), Control::new(&manage, true));
    assert!(manage.to_control().value.is_none());

    let scope = DomainScopeControl::new(false);
    assert_eq!(scope.to_control(), Control::new(&scope, false));

    let sort = SortKeyList::new(vec![
        SortKey::new("cn")
            .reverse()
            .ordering_rule("caseIgnoreMatch"),
    ]);
    assert_eq!(sort.to_control(true), Control::new(&sort, true));
    assert!(sort.to_control(true).critical);
}

#[test]
fn a_sort_result_decodes_through_find() {
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_enumerated(0);
        inner.write_octet_string(Tag::context(0), b"cn");
    });
    let controls = vec![Control {
        oid: SERVER_SORT_RESPONSE_OID.into(),
        critical: false,
        value: Some(w.into_bytes()),
    }];
    let result = Control::find::<SortResult>(&controls).unwrap().unwrap();
    assert_eq!(result.result_code, ResultCode::Success);
    assert_eq!(result.attribute_type.as_deref(), Some("cn"));
}

#[test]
fn a_sort_result_refuses_another_oid() {
    let control = Control {
        oid: PAGED_RESULTS_OID.into(),
        critical: false,
        value: Some(vec![0x30, 0x03, 0x0A, 0x01, 0x00]),
    };
    assert!(SortResult::from_control(&control).is_err());
}

proptest! {
    #[test]
    fn prop_paged_control_round_trips(
        size in 0..=i32::MAX,
        cookie in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let paged = PagedResultsControl::new(size).with_cookie(cookie.clone());
        let decoded: PagedResultsControl = Control::new(&paged, false).decode().unwrap();
        prop_assert_eq!(decoded.size, size);
        prop_assert_eq!(decoded.cookie, cookie);
    }
}

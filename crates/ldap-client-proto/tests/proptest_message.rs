// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::{
    AddRequest, BindAuthentication, BindRequest, BindResponse, CompareRequest, Control,
    DerefAliases, ExtendedRequest, ExtendedResponse, Filter, IntermediateResponse, LdapMessage,
    LdapOperation, LdapResult, MessageId, Modification, ModifyDnRequest, ModifyOperation,
    ModifyRequest, PartialAttribute, ResultCode, SearchRequest, SearchResultEntry, SearchScope,
};
use proptest::prelude::*;
use zeroize::Zeroizing;

fn arb_text() -> impl Strategy<Value = String> {
    any::<String>()
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..32)
}

fn arb_message_id() -> impl Strategy<Value = MessageId> {
    (0..=i32::MAX).prop_map(MessageId)
}

fn arb_result() -> impl Strategy<Value = LdapResult> {
    (
        any::<i32>(),
        arb_text(),
        arb_text(),
        prop::collection::vec(arb_text(), 0..3),
    )
        .prop_map(
            |(code, matched_dn, diagnostic_message, referral)| LdapResult {
                code: ResultCode::from_i64(i64::from(code)),
                matched_dn,
                diagnostic_message,
                referral,
            },
        )
}

fn arb_attribute() -> impl Strategy<Value = PartialAttribute> {
    (arb_text(), prop::collection::vec(arb_bytes(), 0..3))
        .prop_map(|(name, values)| PartialAttribute { name, values })
}

fn arb_filter() -> impl Strategy<Value = Filter> {
    let leaf = prop_oneof![
        (arb_text(), arb_bytes()).prop_map(|(a, v)| Filter::eq(a, v)),
        arb_text().prop_map(Filter::present),
        (arb_text(), arb_bytes()).prop_map(|(a, v)| Filter::gte(a, v)),
    ];
    leaf.prop_recursive(2, 8, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..3).prop_map(Filter::and),
            inner.prop_map(Filter::not),
        ]
    })
}

fn arb_control() -> impl Strategy<Value = Control> {
    (arb_text(), any::<bool>(), proptest::option::of(arb_bytes())).prop_map(
        |(oid, critical, value)| Control {
            oid,
            critical,
            value,
        },
    )
}

fn arb_authentication() -> impl Strategy<Value = BindAuthentication> {
    prop_oneof![
        arb_bytes().prop_map(|pw| BindAuthentication::Simple(Zeroizing::new(pw))),
        (arb_text(), proptest::option::of(arb_bytes())).prop_map(|(mechanism, credentials)| {
            BindAuthentication::Sasl {
                mechanism,
                credentials: credentials.map(Zeroizing::new),
            }
        }),
    ]
}

fn arb_scope() -> impl Strategy<Value = SearchScope> {
    prop::sample::select(vec![
        SearchScope::BaseObject,
        SearchScope::SingleLevel,
        SearchScope::WholeSubtree,
    ])
}

fn arb_deref() -> impl Strategy<Value = DerefAliases> {
    prop::sample::select(vec![
        DerefAliases::NeverDerefAliases,
        DerefAliases::DerefInSearching,
        DerefAliases::DerefFindingBaseObj,
        DerefAliases::DerefAlways,
    ])
}

fn arb_modify_operation() -> impl Strategy<Value = ModifyOperation> {
    prop::sample::select(vec![
        ModifyOperation::Add,
        ModifyOperation::Delete,
        ModifyOperation::Replace,
        ModifyOperation::Increment,
    ])
}

fn arb_search_request() -> impl Strategy<Value = SearchRequest> {
    (
        arb_text(),
        arb_scope(),
        arb_deref(),
        any::<i32>(),
        any::<i32>(),
        any::<bool>(),
        arb_filter(),
        prop::collection::vec(arb_text(), 0..4),
    )
        .prop_map(
            |(
                base_dn,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            )| {
                SearchRequest {
                    base_dn,
                    scope,
                    deref_aliases,
                    size_limit,
                    time_limit,
                    types_only,
                    filter,
                    attributes,
                }
            },
        )
}

fn arb_request() -> impl Strategy<Value = LdapOperation> {
    prop_oneof![
        (any::<i64>(), arb_text(), arb_authentication()).prop_map(
            |(version, name, authentication)| LdapOperation::BindRequest(BindRequest {
                version,
                name,
                authentication,
            })
        ),
        Just(LdapOperation::UnbindRequest),
        arb_search_request().prop_map(LdapOperation::SearchRequest),
        (
            arb_text(),
            prop::collection::vec(
                (arb_modify_operation(), arb_attribute()).prop_map(|(operation, attribute)| {
                    Modification {
                        operation,
                        attribute,
                    }
                }),
                0..3,
            )
        )
            .prop_map(|(dn, changes)| LdapOperation::ModifyRequest(ModifyRequest { dn, changes })),
        (arb_text(), prop::collection::vec(arb_attribute(), 0..3))
            .prop_map(|(dn, attributes)| LdapOperation::AddRequest(AddRequest { dn, attributes })),
        arb_text().prop_map(LdapOperation::DeleteRequest),
        (
            arb_text(),
            arb_text(),
            any::<bool>(),
            proptest::option::of(arb_text())
        )
            .prop_map(|(dn, new_rdn, delete_old_rdn, new_superior)| {
                LdapOperation::ModifyDnRequest(ModifyDnRequest {
                    dn,
                    new_rdn,
                    delete_old_rdn,
                    new_superior,
                })
            }),
        (arb_text(), arb_text(), arb_bytes()).prop_map(|(dn, attr, value)| {
            LdapOperation::CompareRequest(CompareRequest { dn, attr, value })
        }),
        arb_message_id().prop_map(LdapOperation::AbandonRequest),
        (arb_text(), proptest::option::of(arb_bytes())).prop_map(|(oid, value)| {
            LdapOperation::ExtendedRequest(ExtendedRequest { oid, value })
        }),
    ]
}

fn arb_response() -> impl Strategy<Value = LdapOperation> {
    prop_oneof![
        (arb_result(), proptest::option::of(arb_bytes())).prop_map(
            |(result, server_sasl_creds)| {
                LdapOperation::BindResponse(BindResponse {
                    result,
                    server_sasl_creds,
                })
            }
        ),
        (arb_text(), prop::collection::vec(arb_attribute(), 0..3)).prop_map(|(dn, attributes)| {
            LdapOperation::SearchResultEntry(SearchResultEntry { dn, attributes })
        }),
        arb_result().prop_map(LdapOperation::SearchResultDone),
        prop::collection::vec(arb_text(), 0..3).prop_map(LdapOperation::SearchResultReference),
        arb_result().prop_map(LdapOperation::ModifyResponse),
        arb_result().prop_map(LdapOperation::AddResponse),
        arb_result().prop_map(LdapOperation::DeleteResponse),
        arb_result().prop_map(LdapOperation::ModifyDnResponse),
        arb_result().prop_map(LdapOperation::CompareResponse),
        (
            arb_result(),
            proptest::option::of(arb_text()),
            proptest::option::of(arb_bytes())
        )
            .prop_map(|(result, oid, value)| LdapOperation::ExtendedResponse(
                ExtendedResponse { result, oid, value }
            )),
        (
            proptest::option::of(arb_text()),
            proptest::option::of(arb_bytes())
        )
            .prop_map(|(oid, value)| LdapOperation::IntermediateResponse(
                IntermediateResponse { oid, value }
            )),
    ]
}

fn arb_message(
    operation: impl Strategy<Value = LdapOperation>,
) -> impl Strategy<Value = LdapMessage> {
    (
        arb_message_id(),
        operation,
        prop::collection::vec(arb_control(), 0..3),
    )
        .prop_map(|(message_id, operation, controls)| LdapMessage {
            message_id,
            operation,
            controls,
        })
}

/// A message header followed by an operation tag and arbitrary bytes, which
/// reaches the operation decoders far more often than uniform bytes do.
fn arb_message_shaped_bytes() -> impl Strategy<Value = Vec<u8>> {
    let tags = vec![
        0x60u8, 0x61, 0x42, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x4A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x50, 0x73, 0x77, 0x78, 0x79,
    ];
    (
        prop::sample::select(tags),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(tag, body)| {
            let mut bytes = vec![0x30, (body.len() + 6) as u8, 0x02, 0x01, 0x01, tag];
            bytes.push(body.len() as u8);
            bytes.extend(body);
            bytes
        })
}

proptest! {
    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = LdapMessage::decode(&bytes);
    }

    #[test]
    fn prop_decode_never_panics_on_message_shaped_bytes(bytes in arb_message_shaped_bytes()) {
        let _ = LdapMessage::decode(&bytes);
    }

    #[test]
    fn prop_every_request_round_trips(msg in arb_message(arb_request())) {
        prop_assert_eq!(LdapMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn prop_every_response_round_trips(msg in arb_message(arb_response())) {
        prop_assert_eq!(LdapMessage::decode(&msg.encode()).unwrap(), msg);
    }
}

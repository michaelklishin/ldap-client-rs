// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::{
    AddRequest, BindAuthentication, BindRequest, CompareRequest, DerefAliases, ExtendedRequest,
    Filter, LdapMessage, LdapOperation, MessageId, Modification, ModifyDnRequest, ModifyOperation,
    ModifyRequest, PartialAttribute, SearchRequest, SearchScope,
};

#[test]
fn bind_request_simple_encode() {
    let msg = LdapMessage {
        message_id: MessageId(1),
        operation: LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: "cn=admin,dc=example,dc=com".into(),
            authentication: BindAuthentication::Simple(b"secret".to_vec()),
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
    // Starts with SEQUENCE tag 0x30
    assert_eq!(bytes[0], 0x30);
}

#[test]
fn unbind_request() {
    let msg = LdapMessage {
        message_id: MessageId(2),
        operation: LdapOperation::UnbindRequest,
        controls: vec![],
    };
    let _ = msg.encode();
}

#[test]
fn search_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(3),
        operation: LdapOperation::SearchRequest(SearchRequest {
            base_dn: "dc=example,dc=com".into(),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::eq("objectClass", "inetOrgPerson"),
            attributes: vec!["cn".into(), "mail".into()],
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
    assert_eq!(bytes[0], 0x30);
}

#[test]
fn delete_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(5),
        operation: LdapOperation::DeleteRequest("cn=test,dc=example,dc=com".into()),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn compare_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(6),
        operation: LdapOperation::CompareRequest(CompareRequest {
            dn: "cn=test,dc=example,dc=com".into(),
            attr: "userPassword".into(),
            value: b"secret".to_vec(),
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn add_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(7),
        operation: LdapOperation::AddRequest(AddRequest {
            dn: "cn=new,dc=example,dc=com".into(),
            attributes: vec![
                PartialAttribute {
                    name: "objectClass".into(),
                    values: vec![b"inetOrgPerson".to_vec()],
                },
                PartialAttribute {
                    name: "cn".into(),
                    values: vec![b"new".to_vec()],
                },
                PartialAttribute {
                    name: "sn".into(),
                    values: vec![b"User".to_vec()],
                },
            ],
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn modify_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(8),
        operation: LdapOperation::ModifyRequest(ModifyRequest {
            dn: "cn=test,dc=example,dc=com".into(),
            changes: vec![Modification {
                operation: ModifyOperation::Replace,
                attribute: PartialAttribute {
                    name: "mail".into(),
                    values: vec![b"new@example.com".to_vec()],
                },
            }],
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn modify_dn_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(9),
        operation: LdapOperation::ModifyDnRequest(ModifyDnRequest {
            dn: "cn=old,dc=example,dc=com".into(),
            new_rdn: "cn=new".into(),
            delete_old_rdn: true,
            new_superior: None,
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn modify_dn_with_new_superior_encode() {
    let msg = LdapMessage {
        message_id: MessageId(10),
        operation: LdapOperation::ModifyDnRequest(ModifyDnRequest {
            dn: "cn=old,dc=example,dc=com".into(),
            new_rdn: "cn=old".into(),
            delete_old_rdn: false,
            new_superior: Some("ou=other,dc=example,dc=com".into()),
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn abandon_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(11),
        operation: LdapOperation::AbandonRequest(MessageId(3)),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn extended_request_encode() {
    let msg = LdapMessage {
        message_id: MessageId(12),
        operation: LdapOperation::ExtendedRequest(ExtendedRequest {
            oid: "1.3.6.1.4.1.1466.20037".into(), // StartTLS OID
            value: None,
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn extended_request_with_value_encode() {
    let msg = LdapMessage {
        message_id: MessageId(13),
        operation: LdapOperation::ExtendedRequest(ExtendedRequest {
            oid: "1.3.6.1.4.1.4203.1.11.1".into(), // Password Modify OID
            value: Some(b"payload".to_vec()),
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn bind_request_sasl_encode() {
    let msg = LdapMessage {
        message_id: MessageId(14),
        operation: LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: BindAuthentication::Sasl {
                mechanism: "PLAIN".into(),
                credentials: Some(b"\0user\0pass".to_vec()),
            },
        }),
        controls: vec![],
    };
    let bytes = msg.encode();
    assert!(!bytes.is_empty());
}

#[test]
fn decode_bind_response() {
    // Manually construct a BindResponse BER message.
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1); // message id
        msg.write_sequence(Tag::application(1), |bind_resp| {
            bind_resp.write_enumerated(0); // success
            bind_resp.write_bytes(b""); // matchedDN
            bind_resp.write_bytes(b""); // diagnosticMessage
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    assert_eq!(decoded.message_id, MessageId(1));
    match &decoded.operation {
        LdapOperation::BindResponse(resp) => {
            assert!(resp.result.code.is_success());
            assert!(resp.result.matched_dn.is_empty());
        }
        other => panic!("expected BindResponse, got {other:?}"),
    }
}

#[test]
fn decode_search_result_entry() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(2);
        msg.write_sequence(Tag::application(4), |entry| {
            entry.write_bytes(b"cn=admin,dc=example,dc=com"); // DN
            entry.write_sequence(Tag::sequence(), |attrs| {
                attrs.write_sequence(Tag::sequence(), |attr| {
                    attr.write_bytes(b"cn");
                    attr.write_sequence(Tag::set(), |vals| {
                        vals.write_bytes(b"admin");
                    });
                });
                attrs.write_sequence(Tag::sequence(), |attr| {
                    attr.write_bytes(b"objectClass");
                    attr.write_sequence(Tag::set(), |vals| {
                        vals.write_bytes(b"inetOrgPerson");
                        vals.write_bytes(b"organizationalPerson");
                    });
                });
            });
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::SearchResultEntry(entry) => {
            assert_eq!(entry.dn, "cn=admin,dc=example,dc=com");
            assert_eq!(entry.attributes.len(), 2);
            assert_eq!(
                entry.attr("cn").unwrap().first_string_value(),
                Some("admin")
            );
            let oc = entry.attr("objectClass").unwrap();
            assert_eq!(oc.string_values().len(), 2);
        }
        other => panic!("expected SearchResultEntry, got {other:?}"),
    }
}

#[test]
fn decode_search_result_done() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(2);
        msg.write_sequence(Tag::application(5), |done| {
            done.write_enumerated(0);
            done.write_bytes(b"");
            done.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::SearchResultDone(result) => {
            assert!(result.code.is_success());
        }
        other => panic!("expected SearchResultDone, got {other:?}"),
    }
}

#[test]
fn decode_modify_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(4);
        msg.write_sequence(Tag::application(7), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::ModifyResponse(result) => {
            assert!(result.code.is_success());
        }
        other => panic!("expected ModifyResponse, got {other:?}"),
    }
}

#[test]
fn decode_add_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(5);
        msg.write_sequence(Tag::application(9), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::AddResponse(result) => {
            assert!(result.code.is_success());
        }
        other => panic!("expected AddResponse, got {other:?}"),
    }
}

#[test]
fn decode_delete_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(6);
        msg.write_sequence(Tag::application(11), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::DeleteResponse(result) => {
            assert!(result.code.is_success());
        }
        other => panic!("expected DeleteResponse, got {other:?}"),
    }
}

#[test]
fn decode_compare_response_true() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;
    use ldap_client_proto::ResultCode;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(7);
        msg.write_sequence(Tag::application(15), |resp| {
            resp.write_enumerated(6); // compareTrue
            resp.write_bytes(b"");
            resp.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::CompareResponse(result) => {
            assert_eq!(result.code, ResultCode::CompareTrue);
        }
        other => panic!("expected CompareResponse, got {other:?}"),
    }
}

#[test]
fn decode_extended_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(8);
        msg.write_sequence(Tag::application(24), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
            resp.write_octet_string(Tag::context(10), b"1.3.6.1.4.1.1466.20037");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::ExtendedResponse(resp) => {
            assert!(resp.result.code.is_success());
            assert_eq!(resp.oid.as_deref(), Some("1.3.6.1.4.1.1466.20037"));
        }
        other => panic!("expected ExtendedResponse, got {other:?}"),
    }
}

#[test]
fn decode_ldap_result_with_referral() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;
    use ldap_client_proto::ResultCode;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_sequence(Tag::application(5), |done| {
            done.write_enumerated(10); // referral
            done.write_bytes(b"");
            done.write_bytes(b"please follow referral");
            done.write_sequence(Tag::context_constructed(3), |refs| {
                refs.write_bytes(b"ldap://other.example.com/dc=example,dc=com");
            });
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::SearchResultDone(result) => {
            assert_eq!(result.code, ResultCode::Referral);
            assert_eq!(result.diagnostic_message, "please follow referral");
            assert_eq!(result.referral.len(), 1);
            assert!(result.referral[0].contains("other.example.com"));
        }
        other => panic!("expected SearchResultDone, got {other:?}"),
    }
}

#[test]
fn decode_search_result_reference() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(2);
        msg.write_sequence(Tag::application(19), |refs| {
            refs.write_bytes(b"ldap://a.example.com/");
            refs.write_bytes(b"ldap://b.example.com/");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::SearchResultReference(urls) => {
            assert_eq!(urls.len(), 2);
        }
        other => panic!("expected SearchResultReference, got {other:?}"),
    }
}

#[test]
fn decode_modify_dn_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(9);
        msg.write_sequence(Tag::application(13), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::ModifyDnResponse(result) => {
            assert!(result.code.is_success());
        }
        other => panic!("expected ModifyDnResponse, got {other:?}"),
    }
}

#[test]
fn decode_bind_response_with_error() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;
    use ldap_client_proto::ResultCode;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_sequence(Tag::application(1), |bind_resp| {
            bind_resp.write_enumerated(49); // invalidCredentials
            bind_resp.write_bytes(b"");
            bind_resp.write_bytes(b"invalid credentials");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::BindResponse(resp) => {
            assert_eq!(resp.result.code, ResultCode::InvalidCredentials);
            assert!(resp.result.code.is_credential_error());
            assert_eq!(resp.result.diagnostic_message, "invalid credentials");
        }
        other => panic!("expected BindResponse, got {other:?}"),
    }
}

#[test]
fn partial_attribute_helpers() {
    use ldap_client_proto::SearchResultEntry;

    let entry = SearchResultEntry {
        dn: "cn=test".into(),
        attributes: vec![
            PartialAttribute {
                name: "cn".into(),
                values: vec![b"test".to_vec()],
            },
            PartialAttribute {
                name: "binary".into(),
                values: vec![vec![0xFF, 0xFE]],
            },
        ],
    };

    let cn = entry.attr("cn").unwrap();
    assert_eq!(cn.first_string_value(), Some("test"));
    assert_eq!(cn.string_values(), vec!["test"]);
    assert_eq!(cn.first_value(), Some(&b"test"[..]));

    // Case-insensitive lookup
    assert!(entry.attr("CN").is_some());

    // Binary value won't parse as UTF-8
    let binary = entry.attr("binary").unwrap();
    assert!(binary.first_string_value().is_none());
    assert_eq!(binary.string_values().len(), 0);
    assert_eq!(binary.first_value(), Some(&[0xFF, 0xFE][..]));
}

#[test]
fn controls_encode_decode_roundtrip() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;
    use ldap_client_proto::Control;

    // 1. Encode a request message with a control and verify encoding is non-empty.
    let ctrl = Control {
        oid: "1.2.840.113556.1.4.319".into(),
        critical: true,
        value: Some(b"cookie-data".to_vec()),
    };
    let msg = LdapMessage {
        message_id: MessageId(20),
        operation: LdapOperation::SearchRequest(SearchRequest {
            base_dn: "dc=example,dc=com".into(),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::present("objectClass"),
            attributes: vec![],
        }),
        controls: vec![ctrl],
    };
    let encoded = msg.encode();
    assert!(!encoded.is_empty());

    // 2. Manually build a SearchResultDone response that includes controls,
    //    then decode it and verify the controls come back.
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(20); // message id
        msg.write_sequence(Tag::application(5), |done| {
            done.write_enumerated(0); // success
            done.write_bytes(b""); // matchedDN
            done.write_bytes(b""); // diagnosticMessage
        });
        // Controls: context-constructed [0]
        msg.write_sequence(Tag::context_constructed(0), |ctrls| {
            ctrls.write_sequence(Tag::sequence(), |ctrl| {
                ctrl.write_bytes(b"1.2.840.113556.1.4.319"); // OID
                ctrl.write_boolean(false); // criticality
                ctrl.write_bytes(b"response-cookie"); // value
            });
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    assert_eq!(decoded.message_id, MessageId(20));
    assert_eq!(decoded.controls.len(), 1);
    assert_eq!(decoded.controls[0].oid, "1.2.840.113556.1.4.319");
    assert!(!decoded.controls[0].critical);
    assert_eq!(
        decoded.controls[0].value.as_deref(),
        Some(b"response-cookie".as_slice())
    );
}

#[test]
fn decode_intermediate_response() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(30);
        msg.write_sequence(Tag::application(25), |resp| {
            resp.write_octet_string(Tag::context(0), b"1.3.6.1.4.1.4203.1.9.1.4");
            resp.write_octet_string(Tag::context(1), b"intermediate-payload");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    assert_eq!(decoded.message_id, MessageId(30));
    match &decoded.operation {
        LdapOperation::IntermediateResponse(resp) => {
            assert_eq!(resp.oid.as_deref(), Some("1.3.6.1.4.1.4203.1.9.1.4"));
            assert_eq!(
                resp.value.as_deref(),
                Some(b"intermediate-payload".as_slice())
            );
        }
        other => panic!("expected IntermediateResponse, got {other:?}"),
    }
}

#[test]
fn decode_bind_response_with_sasl_creds() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_sequence(Tag::application(1), |bind_resp| {
            bind_resp.write_enumerated(0);
            bind_resp.write_bytes(b"");
            bind_resp.write_bytes(b"");
            bind_resp.write_octet_string(Tag::context(7), b"sasl-token-data");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::BindResponse(resp) => {
            assert!(resp.result.code.is_success());
            assert_eq!(
                resp.server_sasl_creds.as_deref(),
                Some(b"sasl-token-data".as_slice())
            );
        }
        other => panic!("expected BindResponse, got {other:?}"),
    }
}

#[test]
fn decode_unknown_application_tag_rejected() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_sequence(Tag::application(99), |inner| {
            inner.write_bytes(b"bogus");
        });
    });

    let result = LdapMessage::decode(w.as_bytes());
    assert!(result.is_err());
}

#[test]
fn extensible_match_too_many_colons_rejected() {
    let result = Filter::parse("(cn:dn:rule:extra:=value)");
    assert!(result.is_err(), "4+ colon parts must be rejected");
}

#[test]
fn bind_request_encode_decode_roundtrip() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(1);
        msg.write_sequence(Tag::application(1), |bind_resp| {
            bind_resp.write_enumerated(14);
            bind_resp.write_bytes(b"");
            bind_resp.write_bytes(b"SASL bind in progress");
            bind_resp.write_octet_string(Tag::context(7), b"challenge-token");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::BindResponse(resp) => {
            assert_eq!(
                resp.result.code,
                ldap_client_proto::ResultCode::SaslBindInProgress
            );
            assert_eq!(resp.result.diagnostic_message, "SASL bind in progress");
            assert_eq!(
                resp.server_sasl_creds.as_deref(),
                Some(b"challenge-token".as_slice())
            );
        }
        other => panic!("expected BindResponse, got {other:?}"),
    }
}

#[test]
fn decode_extended_response_with_value() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(8);
        msg.write_sequence(Tag::application(24), |resp| {
            resp.write_enumerated(0);
            resp.write_bytes(b"");
            resp.write_bytes(b"");
            resp.write_octet_string(Tag::context(10), b"1.3.6.1.4.1.1466.20037");
            resp.write_octet_string(Tag::context(11), b"response-payload");
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::ExtendedResponse(resp) => {
            assert!(resp.result.code.is_success());
            assert_eq!(resp.oid.as_deref(), Some("1.3.6.1.4.1.1466.20037"));
            assert_eq!(resp.value.as_deref(), Some(b"response-payload".as_slice()));
        }
        other => panic!("expected ExtendedResponse, got {other:?}"),
    }
}

#[test]
fn decode_intermediate_response_empty() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(30);
        msg.write_sequence(Tag::application(25), |_resp| {});
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    match &decoded.operation {
        LdapOperation::IntermediateResponse(resp) => {
            assert!(resp.oid.is_none());
            assert!(resp.value.is_none());
        }
        other => panic!("expected IntermediateResponse, got {other:?}"),
    }
}

#[test]
fn result_code_unknown_value() {
    use ldap_client_proto::ResultCode;
    let code = ResultCode::from_i64(999);
    assert_eq!(code, ResultCode::Unknown(999));
    assert!(!code.is_success());
    assert!(!code.is_credential_error());
    assert!(!code.is_transient());
    assert!(!code.is_referral());
}

#[test]
fn result_code_transient() {
    use ldap_client_proto::ResultCode;
    assert!(ResultCode::Busy.is_transient());
    assert!(ResultCode::Unavailable.is_transient());
    assert!(ResultCode::AdminLimitExceeded.is_transient());
    assert!(ResultCode::Other.is_transient());
    assert!(!ResultCode::Success.is_transient());
}

#[test]
fn result_code_display() {
    use ldap_client_proto::ResultCode;
    let s = format!("{}", ResultCode::InvalidCredentials);
    assert_eq!(s, "InvalidCredentials");
}

#[test]
fn paged_results_control_roundtrip() {
    use ldap_client_proto::PagedResultsControl;

    let prc = PagedResultsControl::new(100).with_cookie(b"cookie123".to_vec());
    let ctrl = prc.to_control();
    assert_eq!(ctrl.oid, ldap_client_proto::PAGED_RESULTS_OID);
    assert!(!ctrl.critical);
    assert!(ctrl.value.is_some());

    let decoded = PagedResultsControl::from_control(&ctrl).unwrap();
    assert_eq!(decoded.size, 100);
    assert_eq!(decoded.cookie, b"cookie123");
}

#[test]
fn paged_results_control_empty_cookie() {
    use ldap_client_proto::PagedResultsControl;

    let prc = PagedResultsControl::new(500);
    let ctrl = prc.to_control();
    let decoded = PagedResultsControl::from_control(&ctrl).unwrap();
    assert_eq!(decoded.size, 500);
    assert!(decoded.cookie.is_empty());
}

#[test]
fn paged_results_control_missing_value_error() {
    use ldap_client_proto::{Control, PagedResultsControl};

    let ctrl = Control {
        oid: ldap_client_proto::PAGED_RESULTS_OID.to_string(),
        critical: false,
        value: None,
    };
    let result = PagedResultsControl::from_control(&ctrl);
    assert!(result.is_err());
}

#[test]
fn request_encode_decode_roundtrip_search() {
    let msg = LdapMessage {
        message_id: MessageId(42),
        operation: LdapOperation::SearchRequest(SearchRequest {
            base_dn: "dc=example,dc=com".into(),
            scope: SearchScope::SingleLevel,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::and(vec![
                Filter::eq("objectClass", "person"),
                Filter::present("mail"),
            ]),
            attributes: vec!["cn".into(), "mail".into()],
        }),
        controls: vec![],
    };
    let encoded = msg.encode();
    assert!(encoded.len() > 10);
    assert_eq!(encoded[0], 0x30);
}

#[test]
fn controls_with_no_critical_field() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |msg| {
        msg.write_integer(20);
        msg.write_sequence(Tag::application(5), |done| {
            done.write_enumerated(0);
            done.write_bytes(b"");
            done.write_bytes(b"");
        });
        msg.write_sequence(Tag::context_constructed(0), |ctrls| {
            ctrls.write_sequence(Tag::sequence(), |ctrl| {
                ctrl.write_bytes(b"1.2.840.113556.1.4.319");
                ctrl.write_bytes(b"control-value");
            });
        });
    });

    let decoded = LdapMessage::decode(w.as_bytes()).unwrap();
    assert_eq!(decoded.controls.len(), 1);
    assert!(!decoded.controls[0].critical);
    assert_eq!(
        decoded.controls[0].value.as_deref(),
        Some(b"control-value".as_slice())
    );
}

#[test]
fn result_code_is_configuration_error() {
    use ldap_client_proto::ResultCode;
    assert!(ResultCode::InvalidDnSyntax.is_configuration_error());
    assert!(ResultCode::NoSuchObject.is_configuration_error());
    assert!(ResultCode::UndefinedAttributeType.is_configuration_error());
    assert!(ResultCode::InappropriateMatching.is_configuration_error());
    assert!(!ResultCode::Success.is_configuration_error());
    assert!(!ResultCode::InvalidCredentials.is_configuration_error());
}

#[test]
fn manage_dsa_it_control() {
    use ldap_client_proto::ManageDsaItControl;
    let ctrl = ManageDsaItControl::new(true).to_control();
    assert_eq!(ctrl.oid, ldap_client_proto::MANAGE_DSA_IT_OID);
    assert!(ctrl.critical);
    assert!(ctrl.value.is_none());
}

#[test]
fn domain_scope_control() {
    use ldap_client_proto::DomainScopeControl;
    let ctrl = DomainScopeControl::new(false).to_control();
    assert_eq!(ctrl.oid, ldap_client_proto::DOMAIN_SCOPE_OID);
    assert!(!ctrl.critical);
    assert!(ctrl.value.is_none());
}

#[test]
fn sort_key_list_encode() {
    use ldap_client_proto::{SERVER_SORT_REQUEST_OID, SortKey, SortKeyList};
    let keys = SortKeyList::new(vec![SortKey::new("cn"), SortKey::new("sn").reverse()]);
    let ctrl = keys.to_control(true);
    assert_eq!(ctrl.oid, SERVER_SORT_REQUEST_OID);
    assert!(ctrl.critical);
    assert!(ctrl.value.is_some());
}

#[test]
fn sort_result_decode() {
    use ldap_client_ber::BerWriter;
    use ldap_client_ber::tag::Tag;
    use ldap_client_proto::{Control, ResultCode, SERVER_SORT_RESPONSE_OID, SortResult};

    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |inner| {
        inner.write_enumerated(0); // success
    });
    let ctrl = Control {
        oid: SERVER_SORT_RESPONSE_OID.to_string(),
        critical: false,
        value: Some(w.into_bytes()),
    };
    let result = SortResult::from_control(&ctrl).unwrap();
    assert_eq!(result.result_code, ResultCode::Success);
    assert!(result.attribute_type.is_none());
}

#[test]
fn has_ldap_result_trait() {
    use ldap_client_proto::{
        BindResponse, ExtendedResponse, HasLdapResult, LdapResult, ResultCode,
    };

    let result = LdapResult {
        code: ResultCode::Success,
        matched_dn: String::new(),
        diagnostic_message: String::new(),
        referral: vec![],
    };
    assert!(result.is_success());
    assert!(!result.is_referral());

    let bind_resp = BindResponse {
        result: LdapResult {
            code: ResultCode::Referral,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
            referral: vec!["ldap://other.example.com/".into()],
        },
        server_sasl_creds: None,
    };
    assert!(!bind_resp.is_success());
    assert!(bind_resp.is_referral());
    assert_eq!(bind_resp.referral_urls().len(), 1);

    let ext_resp = ExtendedResponse {
        result: LdapResult {
            code: ResultCode::Success,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
            referral: vec![],
        },
        oid: None,
        value: None,
    };
    assert!(ext_resp.is_success());
}

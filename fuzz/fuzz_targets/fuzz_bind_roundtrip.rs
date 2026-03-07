// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use ldap_client_proto::{
    BindAuthentication, BindRequest, LdapMessage, LdapOperation, MessageId,
};

fuzz_target!(|data: &[u8]| {
    // Split fuzzer input into DN and password portions.
    let split = data.len() / 2;
    let dn_bytes = &data[..split];
    let pw_bytes = &data[split..];

    let dn = String::from_utf8_lossy(dn_bytes).into_owned();

    // Simple bind roundtrip.
    let msg = LdapMessage {
        message_id: MessageId(1),
        operation: LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: dn.clone(),
            authentication: BindAuthentication::Simple(
                zeroize::Zeroizing::new(pw_bytes.to_vec()),
            ),
        }),
        controls: vec![],
    };
    let encoded = msg.encode();
    let _ = LdapMessage::decode(&encoded);

    // SASL bind roundtrip.
    let msg = LdapMessage {
        message_id: MessageId(2),
        operation: LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: dn,
            authentication: BindAuthentication::Sasl {
                mechanism: String::from_utf8_lossy(&pw_bytes[..pw_bytes.len().min(16)])
                    .into_owned(),
                credentials: if pw_bytes.is_empty() {
                    None
                } else {
                    Some(zeroize::Zeroizing::new(pw_bytes.to_vec()))
                },
            },
        }),
        controls: vec![],
    };
    let encoded = msg.encode();
    let _ = LdapMessage::decode(&encoded);
});

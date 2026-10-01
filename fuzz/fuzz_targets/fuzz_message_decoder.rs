// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use ldap_client_proto::LdapMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decode should not panic regardless of input.
    let _ = LdapMessage::decode(data);
});

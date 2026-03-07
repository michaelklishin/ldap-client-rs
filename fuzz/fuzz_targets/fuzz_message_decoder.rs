// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use ldap_client_proto::LdapMessage;

fuzz_target!(|data: &[u8]| {
    // Decode should not panic regardless of input.
    let _ = LdapMessage::decode(data);
});

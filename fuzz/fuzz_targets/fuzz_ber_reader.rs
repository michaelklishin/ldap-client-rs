// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use ldap_client_ber::BerReader;

fuzz_target!(|data: &[u8]| {
    let mut r = BerReader::new(data);
    // Try reading various element types; we don't care if they fail,
    // only that they don't panic or hang.
    let _ = r.read_element();

    let mut r = BerReader::new(data);
    let _ = r.read_integer();

    let mut r = BerReader::new(data);
    let _ = r.read_octet_string();

    let mut r = BerReader::new(data);
    let _ = r.read_boolean();
});

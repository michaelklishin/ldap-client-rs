// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use ldap_client_proto::Dn;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(dn) = Dn::parse(s)
    {
        assert_eq!(Dn::parse(&dn.to_string()).unwrap(), dn);
    }
});

// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::url::LdapUrl;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_parse_never_panics(input in any::<String>()) {
        let _ = LdapUrl::parse(&input);
    }

    #[test]
    fn prop_parse_never_panics_near_syntax(
        input in "ldaps?://[a-z.:\\[\\]0-9]{0,12}/[%?,=!a-z0-9+]{0,40}"
    ) {
        let _ = LdapUrl::parse(&input);
    }

    #[test]
    fn prop_display_of_a_parsed_url_parses_to_the_same_url(
        input in "ldaps?://[a-z.:\\[\\]0-9]{0,12}/[%?,=!a-z0-9+]{0,40}"
    ) {
        if let Ok(url) = LdapUrl::parse(&input) {
            prop_assert_eq!(LdapUrl::parse(&url.to_string()).unwrap(), url);
        }
    }
}

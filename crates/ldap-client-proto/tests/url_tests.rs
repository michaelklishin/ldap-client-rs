// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client_proto::SearchScope;
use ldap_client_proto::url::{LdapScheme, LdapUrl};

#[test]
fn parse_simple() {
    let url = LdapUrl::parse("ldap://localhost").unwrap();
    assert_eq!(url.scheme, LdapScheme::Ldap);
    assert_eq!(url.host, "localhost");
    assert_eq!(url.port, None);
    assert_eq!(url.effective_port(), 389);
    assert!(url.base_dn.is_none());
}

#[test]
fn parse_with_port() {
    let url = LdapUrl::parse("ldap://localhost:1389").unwrap();
    assert_eq!(url.port, Some(1389));
    assert_eq!(url.effective_port(), 1389);
}

#[test]
fn parse_ldaps() {
    let url = LdapUrl::parse("ldaps://ldap.example.com").unwrap();
    assert_eq!(url.scheme, LdapScheme::Ldaps);
    assert_eq!(url.effective_port(), 636);
}

#[test]
fn parse_with_base_dn() {
    let url = LdapUrl::parse("ldap://localhost/dc=example,dc=com").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("dc=example,dc=com"));
}

#[test]
fn parse_with_attributes() {
    let url = LdapUrl::parse("ldap://localhost/dc=example,dc=com?cn,mail").unwrap();
    assert_eq!(url.attributes, vec!["cn", "mail"]);
}

#[test]
fn parse_with_scope() {
    let url = LdapUrl::parse("ldap://localhost/dc=example,dc=com??sub").unwrap();
    assert_eq!(url.scope, Some(SearchScope::WholeSubtree));
}

#[test]
fn parse_with_filter() {
    let url = LdapUrl::parse("ldap://localhost/dc=example,dc=com???%28cn%3Dadmin%29").unwrap();
    assert_eq!(url.filter.as_deref(), Some("(cn=admin)"));
}

#[test]
fn parse_full() {
    let url = LdapUrl::parse("ldap://host:389/dc=example,dc=com?cn,sn?sub?%28objectClass%3D%2A%29")
        .unwrap();
    assert_eq!(url.host, "host");
    assert_eq!(url.port, Some(389));
    assert_eq!(url.base_dn.as_deref(), Some("dc=example,dc=com"));
    assert_eq!(url.attributes, vec!["cn", "sn"]);
    assert_eq!(url.scope, Some(SearchScope::WholeSubtree));
    assert_eq!(url.filter.as_deref(), Some("(objectClass=*)"));
}

#[test]
fn parse_scope_base() {
    let url = LdapUrl::parse("ldap://localhost/??base").unwrap();
    assert_eq!(url.scope, Some(SearchScope::BaseObject));
}

#[test]
fn parse_scope_one() {
    let url = LdapUrl::parse("ldap://localhost/??one").unwrap();
    assert_eq!(url.scope, Some(SearchScope::SingleLevel));
}

#[test]
fn invalid_scheme_rejected() {
    assert!(LdapUrl::parse("http://localhost").is_err());
}

#[test]
fn invalid_scope_rejected() {
    assert!(LdapUrl::parse("ldap://localhost/??children").is_err());
}

#[test]
fn display_simple() {
    let url = LdapUrl::parse("ldap://localhost:1389/dc=example,dc=com").unwrap();
    let s = url.to_string();
    assert!(s.starts_with("ldap://localhost:1389/"));
    assert!(s.contains("dc"));
}

#[test]
fn display_roundtrip() {
    let input = "ldap://localhost:1389/dc=example,dc=com?cn,sn?sub";
    let url = LdapUrl::parse(input).unwrap();
    let displayed = url.to_string();
    let reparsed = LdapUrl::parse(&displayed).unwrap();
    assert_eq!(url, reparsed);
}

#[test]
fn fromstr_impl() {
    let url: LdapUrl = "ldap://localhost:389".parse().unwrap();
    assert_eq!(url.host, "localhost");
}

#[test]
fn ipv6_host() {
    let url = LdapUrl::parse("ldap://[::1]:389/dc=example,dc=com").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, Some(389));
}

#[test]
fn percent_encoded_dn() {
    let url = LdapUrl::parse("ldap://localhost/dc%3Dexample%2Cdc%3Dcom").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("dc=example,dc=com"));
}

#[test]
fn empty_host_rejected() {
    assert!(LdapUrl::parse("ldap:///dc=example,dc=com").is_err());
}

#[test]
fn display_roundtrip_with_filter() {
    let input = "ldap://localhost:389/dc=example,dc=com?cn?sub?%28objectClass%3D%2A%29";
    let url = LdapUrl::parse(input).unwrap();
    let displayed = url.to_string();
    let reparsed = LdapUrl::parse(&displayed).unwrap();
    assert_eq!(url, reparsed);
}

#[test]
fn the_extensions_field_is_not_part_of_the_filter() {
    let url = LdapUrl::parse("ldap://h/dc=x?cn?sub?(a=b)?e-bindname=x").unwrap();
    assert_eq!(url.filter.as_deref(), Some("(a=b)"));
}

#[test]
fn a_critical_extension_is_refused() {
    assert!(LdapUrl::parse("ldap://h/dc=x?cn?sub?(a=b)?!e-bindname=x").is_err());
}

#[test]
fn a_critical_extension_after_an_ordinary_one_is_refused() {
    assert!(LdapUrl::parse("ldap://h/dc=x????x-one,!x-two").is_err());
}

#[test]
fn a_noncritical_extension_is_ignored() {
    let url = LdapUrl::parse("ldap://h/dc=x????e-bindname=x").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("dc=x"));
    assert_eq!(url.filter, None);
}

#[test]
fn a_sixth_field_is_refused() {
    assert!(LdapUrl::parse("ldap://h/dc=x?cn?sub?(a=b)?x?y").is_err());
}

#[test]
fn a_signed_percent_escape_stays_text() {
    let url = LdapUrl::parse("ldap://h/dc=%+4").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("dc=%+4"));
}

#[test]
fn a_stray_percent_sign_stays_text() {
    let url = LdapUrl::parse("ldap://h/dc=a%zz%4").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("dc=a%zz%4"));
}

#[test]
fn an_invalid_utf8_escape_is_refused() {
    assert!(LdapUrl::parse("ldap://h/dc=%ff").is_err());
}

#[test]
fn a_utf8_escape_decodes() {
    let url = LdapUrl::parse("ldap://h/cn=caf%c3%a9").unwrap();
    assert_eq!(url.base_dn.as_deref(), Some("cn=café"));
}

#[test]
fn an_encoded_comma_in_an_attribute_survives_display() {
    let url = LdapUrl::parse("ldap://h/dc=x?a%2Cb").unwrap();
    assert_eq!(url.attributes, vec!["a,b"]);
    assert_eq!(LdapUrl::parse(&url.to_string()).unwrap(), url);
}

#[test]
fn scope_names_parse_case_insensitively() {
    assert_eq!(
        "BASE".parse::<SearchScope>().unwrap(),
        SearchScope::BaseObject
    );
    assert_eq!(
        "One".parse::<SearchScope>().unwrap(),
        SearchScope::SingleLevel
    );
    assert_eq!(
        "sUb".parse::<SearchScope>().unwrap(),
        SearchScope::WholeSubtree
    );
    assert!("subtree".parse::<SearchScope>().is_err());
}

#[test]
fn every_scope_displays_as_the_name_it_parses_from() {
    for scope in SearchScope::ALL {
        assert_eq!(scope.to_string().parse::<SearchScope>().unwrap(), scope);
        assert_eq!(scope.to_string(), scope.as_str());
    }
}

#[test]
fn default_ports_follow_the_scheme() {
    assert_eq!(LdapScheme::Ldap.default_port(), 389);
    assert_eq!(LdapScheme::Ldaps.default_port(), 636);
}

#[test]
fn a_host_starting_with_a_bracket_displays_in_brackets() {
    let url = LdapUrl::parse("ldap://[[]/").unwrap();
    assert_eq!(url.host, "[");
    assert_eq!(LdapUrl::parse(&url.to_string()).unwrap(), url);
}

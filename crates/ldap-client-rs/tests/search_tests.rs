// SPDX-License-Identifier: MIT OR Apache-2.0

mod common;

use std::num::NonZeroU32;
use std::time::Duration;

use common::{MockServer, Step, entry, referral, search_done, search_reference};
use ldap_client::{
    Client, ClientBuilder, Control, DerefAliases, Error, Filter, PagedResultsControl, ResultCode,
    SearchParams, SearchScope,
};
use ldap_client_proto::{LdapOperation, SearchRequest};

fn present() -> Filter {
    Filter::present("objectClass")
}

async fn connect_with_base(server: &MockServer) -> Client {
    ClientBuilder::new(server.host(), server.port())
        .base_dn("dc=example,dc=com")
        .connect()
        .await
        .unwrap()
}

async fn the_search_request(server: &MockServer) -> SearchRequest {
    match server.received_operations().await.remove(0) {
        LdapOperation::SearchRequest(request) => request,
        other => panic!("expected a search request, got {other:?}"),
    }
}

fn done() -> Step {
    Step::respond(search_done(ResultCode::Success))
}

fn paged_done(cookie: &[u8]) -> Vec<Control> {
    vec![
        PagedResultsControl::new(0)
            .with_cookie(cookie.to_vec())
            .to_control(),
    ]
}

fn page(dn: &str, cookie: &[u8]) -> Step {
    Step::respond(entry(dn)).and_with_controls(search_done(ResultCode::Success), paged_done(cookie))
}

#[tokio::test]
async fn search_with_sends_the_requested_limits_and_deref_policy() {
    let server = MockServer::start(vec![done()]).await;
    let client = common::connect_plain(&server).await;

    let params = SearchParams::new("dc=x", SearchScope::SingleLevel, present())
        .attributes(["cn", "mail"])
        .deref_aliases(DerefAliases::DerefAlways)
        .size_limit(NonZeroU32::new(5).unwrap())
        .time_limit(Duration::from_secs(7))
        .types_only();
    client.search_with(params).await.unwrap();

    let request = the_search_request(&server).await;
    assert_eq!(request.base_dn, "dc=x");
    assert_eq!(request.scope, SearchScope::SingleLevel);
    assert_eq!(request.deref_aliases, DerefAliases::DerefAlways);
    assert_eq!(request.size_limit, 5);
    assert_eq!(request.time_limit, 7);
    assert!(request.types_only);
    assert_eq!(request.attributes, ["cn", "mail"]);
    assert_eq!(request.filter, present());
}

#[tokio::test]
async fn a_search_without_limits_sends_zero() {
    let server = MockServer::start(vec![done()]).await;
    let client = common::connect_plain(&server).await;

    client
        .search_with(SearchParams::new(
            "dc=x",
            SearchScope::BaseObject,
            present(),
        ))
        .await
        .unwrap();

    let request = the_search_request(&server).await;
    assert_eq!((request.size_limit, request.time_limit), (0, 0));
    assert_eq!(request.deref_aliases, DerefAliases::NeverDerefAliases);
    assert!(!request.types_only);
}

#[tokio::test]
async fn limits_beyond_what_the_wire_carries_are_clamped() {
    let server = MockServer::start(vec![done()]).await;
    let client = common::connect_plain(&server).await;

    let params = SearchParams::new("dc=x", SearchScope::BaseObject, present())
        .size_limit(NonZeroU32::MAX)
        .time_limit(Duration::MAX);
    client.search_with(params).await.unwrap();

    let request = the_search_request(&server).await;
    assert_eq!(request.size_limit, i32::MAX);
    assert_eq!(request.time_limit, i32::MAX);
}

#[tokio::test]
async fn a_sub_second_time_limit_is_sent_as_one_second() {
    let server = MockServer::start(vec![done()]).await;
    let client = common::connect_plain(&server).await;

    let params = SearchParams::new("dc=x", SearchScope::BaseObject, present())
        .time_limit(Duration::from_millis(1));
    client.search_with(params).await.unwrap();

    assert_eq!(the_search_request(&server).await.time_limit, 1);
}

#[tokio::test]
async fn search_full_returns_entries_references_and_controls() {
    let control = Control {
        oid: "1.2.3".into(),
        critical: false,
        value: Some(vec![1]),
    };
    let server = MockServer::start(vec![
        Step::respond(entry("cn=a"))
            .and(search_reference(&["ldap://ref/"]))
            .and(entry("cn=b"))
            .and_with_controls(search_done(ResultCode::Success), vec![control.clone()]),
    ])
    .await;
    let client = common::connect_plain(&server).await;

    let result = client
        .search_full("dc=x", SearchScope::WholeSubtree, present(), vec![], vec![])
        .await
        .unwrap();
    let dns: Vec<_> = result.entries.iter().map(|e| e.dn.as_str()).collect();
    assert_eq!(dns, ["cn=a", "cn=b"]);
    assert_eq!(result.referrals, ["ldap://ref/"]);
    assert_eq!(result.controls, [control]);
}

#[tokio::test]
async fn a_search_ending_in_an_error_code_is_an_error() {
    let server = MockServer::start(vec![
        Step::respond(entry("cn=a")).and(search_done(ResultCode::NoSuchObject)),
        Step::respond(search_done(ResultCode::Success)),
    ])
    .await;
    let client = common::connect_plain(&server).await;

    let err = client
        .search("dc=x", SearchScope::WholeSubtree, present(), vec![])
        .await
        .unwrap_err();
    assert_eq!(err.result_code(), Some(ResultCode::NoSuchObject));
    assert!(client.is_connected());
}

#[tokio::test]
async fn root_dse_ignores_the_default_base() {
    let server = MockServer::start(vec![
        Step::respond(entry("")).and(search_done(ResultCode::Success)),
    ])
    .await;
    let client = connect_with_base(&server).await;

    let dse = client.root_dse().await.unwrap();
    assert_eq!(dse.dn, "");

    let request = the_search_request(&server).await;
    assert_eq!(request.base_dn, "");
    assert_eq!(request.scope, SearchScope::BaseObject);
    assert_eq!(request.attributes, ["*", "+"]);
}

#[tokio::test]
async fn an_empty_base_in_search_means_the_default_base() {
    let server = MockServer::start(vec![done()]).await;
    let client = connect_with_base(&server).await;

    client
        .search("", SearchScope::WholeSubtree, present(), vec![])
        .await
        .unwrap();

    assert_eq!(
        the_search_request(&server).await.base_dn,
        "dc=example,dc=com"
    );
}

#[tokio::test]
async fn under_default_base_resolves_to_the_client_base_or_to_the_empty_dn() {
    let server = MockServer::start(vec![done()]).await;
    let client = connect_with_base(&server).await;
    client
        .search_with(SearchParams::under_default_base(
            SearchScope::BaseObject,
            present(),
        ))
        .await
        .unwrap();
    assert_eq!(
        the_search_request(&server).await.base_dn,
        "dc=example,dc=com"
    );

    let server = MockServer::start(vec![done()]).await;
    let client = common::connect_plain(&server).await;
    client
        .search_with(SearchParams::under_default_base(
            SearchScope::BaseObject,
            present(),
        ))
        .await
        .unwrap();
    assert_eq!(the_search_request(&server).await.base_dn, "");
}

#[tokio::test]
async fn search_one_sends_a_size_limit_of_two_and_the_request_timeout() {
    let server = MockServer::start(vec![
        Step::respond(entry("cn=a")).and(search_done(ResultCode::Success)),
    ])
    .await;
    let client = ClientBuilder::new(server.host(), server.port())
        .request_timeout(Duration::from_millis(500))
        .connect()
        .await
        .unwrap();

    let found = client
        .search_one("dc=x", SearchScope::WholeSubtree, present(), vec![])
        .await
        .unwrap();
    assert_eq!(found.unwrap().dn, "cn=a");

    let request = the_search_request(&server).await;
    assert_eq!(request.size_limit, 2);
    assert_eq!(request.time_limit, 1);
}

#[tokio::test]
async fn search_one_reports_none_and_multiple() {
    let server = MockServer::start(vec![
        done(),
        Step::respond(entry("cn=a"))
            .and(entry("cn=b"))
            .and(search_done(ResultCode::Success)),
        Step::respond(entry("cn=a")).and(search_done(ResultCode::SizeLimitExceeded)),
    ])
    .await;
    let client = common::connect_plain(&server).await;
    let search = || client.search_one("dc=x", SearchScope::WholeSubtree, present(), vec![]);

    assert!(search().await.unwrap().is_none());
    assert!(matches!(search().await, Err(Error::MultipleResults)));
    assert!(matches!(search().await, Err(Error::MultipleResults)));
}

#[tokio::test]
async fn search_paged_collects_every_page() {
    let server = MockServer::start(vec![
        page("cn=1", b"one"),
        page("cn=2", b"two"),
        page("cn=3", b""),
    ])
    .await;
    let client = common::connect_plain(&server).await;

    let entries = client
        .search_paged("dc=x", SearchScope::WholeSubtree, present(), vec![], 1)
        .await
        .unwrap();
    let dns: Vec<_> = entries.iter().map(|e| e.dn.as_str()).collect();
    assert_eq!(dns, ["cn=1", "cn=2", "cn=3"]);

    let cookies: Vec<Vec<u8>> = server
        .received()
        .await
        .iter()
        .map(|m| {
            Control::find::<PagedResultsControl>(&m.controls)
                .unwrap()
                .unwrap()
                .cookie
        })
        .collect();
    assert_eq!(cookies, [b"".to_vec(), b"one".to_vec(), b"two".to_vec()]);
}

#[tokio::test]
async fn a_response_without_the_paged_control_ends_the_search() {
    let server = MockServer::start(vec![
        Step::respond(entry("cn=1")).and(search_done(ResultCode::Success)),
    ])
    .await;
    let client = common::connect_plain(&server).await;
    let mut pages =
        client.search_paged_stream("dc=x", SearchScope::WholeSubtree, present(), vec![], 10);

    assert_eq!(pages.next_page().await.unwrap().unwrap().len(), 1);
    assert!(pages.is_done());
    assert!(pages.next_page().await.unwrap().is_none());
}

#[tokio::test]
async fn next_page_after_an_error_does_not_restart_the_search() {
    let server = MockServer::start(vec![
        page("cn=1", b"one"),
        Step::respond(search_done(ResultCode::Busy)),
        page("cn=restart", b""),
    ])
    .await;
    let client = common::connect_plain(&server).await;
    let mut pages =
        client.search_paged_stream("dc=x", SearchScope::WholeSubtree, present(), vec![], 1);

    assert!(pages.next_page().await.unwrap().is_some());
    assert!(pages.next_page().await.is_err());
    assert!(pages.is_done());
    assert!(pages.next_page().await.unwrap().is_none());
    assert_eq!(server.received().await.len(), 2);
}

#[tokio::test]
async fn a_repeated_cookie_is_an_error() {
    let server = MockServer::start(vec![page("cn=1", b"same"), page("cn=2", b"same")]).await;
    let client = common::connect_plain(&server).await;

    let err = client
        .search_paged("dc=x", SearchScope::WholeSubtree, present(), vec![], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Proto(_)), "{err:?}");
}

#[tokio::test]
async fn alternating_cookies_are_an_error() {
    let server = MockServer::start(vec![
        page("cn=1", b"a"),
        page("cn=2", b"b"),
        page("cn=3", b"a"),
    ])
    .await;
    let client = common::connect_plain(&server).await;

    let err = client
        .search_paged("dc=x", SearchScope::WholeSubtree, present(), vec![], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Proto(_)), "{err:?}");
}

#[tokio::test]
async fn an_undecodable_paged_control_is_an_error() {
    let broken = Control {
        oid: ldap_client::PAGED_RESULTS_OID.into(),
        critical: false,
        value: Some(vec![0xFF]),
    };
    let server = MockServer::start(vec![
        Step::respond(entry("cn=1"))
            .and_with_controls(search_done(ResultCode::Success), vec![broken]),
    ])
    .await;
    let client = common::connect_plain(&server).await;

    let err = client
        .search_paged("dc=x", SearchScope::WholeSubtree, present(), vec![], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Proto(_)), "{err:?}");
}

#[tokio::test]
async fn cancel_sends_the_abandon_page_only_from_a_continuing_search() {
    let server = MockServer::start(vec![page("cn=1", b"one"), done()]).await;
    let client = common::connect_plain(&server).await;
    let mut pages =
        client.search_paged_stream("dc=x", SearchScope::WholeSubtree, present(), vec![], 5);

    pages.cancel().await.unwrap();
    assert!(pages.is_done());
    assert!(server.received().await.is_empty());

    let mut pages =
        client.search_paged_stream("dc=x", SearchScope::WholeSubtree, present(), vec![], 5);
    pages.next_page().await.unwrap();
    pages.cancel().await.unwrap();
    assert!(pages.is_done());

    let received = server.received().await;
    let last = Control::find::<PagedResultsControl>(&received[1].controls)
        .unwrap()
        .unwrap();
    assert_eq!((last.size, last.cookie), (0, b"one".to_vec()));
}

#[tokio::test]
async fn a_referral_in_a_paged_search_is_an_error_under_return() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::SearchResultDone(
        referral(&["ldap://elsewhere/"]),
    ))])
    .await;
    let client = ClientBuilder::new(server.host(), server.port())
        .referral_policy(ldap_client::ReferralPolicy::Return)
        .connect()
        .await
        .unwrap();

    let err = client
        .search_paged("dc=x", SearchScope::WholeSubtree, present(), vec![], 1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Referral { .. }), "{err:?}");
}

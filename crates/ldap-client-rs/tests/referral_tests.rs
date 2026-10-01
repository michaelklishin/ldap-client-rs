// SPDX-License-Identifier: MIT OR Apache-2.0

mod common;

use common::{MockServer, Step, bind_referral, bind_response, entry, referral, result, url_of};
use ldap_client::{
    Client, ClientBuilder, Error, Filter, ReferralPolicy, ResultCode, SearchScope, SecretString,
};
use ldap_client_proto::{LdapOperation, Modification, ModifyOperation, PartialAttribute};

const REFERRED: &str = "ldap://elsewhere.example/";

async fn connect(server: &MockServer, policy: ReferralPolicy) -> Client {
    ClientBuilder::new(server.host(), server.port())
        .referral_policy(policy)
        .connect()
        .await
        .unwrap()
}

fn policies() -> [ReferralPolicy; 3] {
    [
        ReferralPolicy::Ignore,
        ReferralPolicy::Return,
        ReferralPolicy::follow(),
    ]
}

fn assert_referral(err: Error) {
    assert!(
        matches!(&err, Error::Referral { urls, .. } if urls == &[REFERRED]),
        "{err:?}"
    );
    assert_eq!(err.result_code(), Some(ResultCode::Referral));
}

#[tokio::test]
async fn a_referred_bind_is_an_error_under_every_policy() {
    for policy in policies() {
        let server = MockServer::start(vec![Step::respond(bind_referral(&[REFERRED]))]).await;
        let client = connect(&server, policy).await;

        let err = client
            .simple_bind("cn=a", &SecretString::from("pw"))
            .await
            .unwrap_err();
        assert_referral(err);
    }
}

#[tokio::test]
async fn a_referred_write_is_an_error_under_ignore() {
    let responses = [
        LdapOperation::AddResponse(referral(&[REFERRED])),
        LdapOperation::ModifyResponse(referral(&[REFERRED])),
        LdapOperation::DeleteResponse(referral(&[REFERRED])),
        LdapOperation::ModifyDnResponse(referral(&[REFERRED])),
        common::extended_response_with(referral(&[REFERRED])),
    ];
    for (i, response) in responses.into_iter().enumerate() {
        let server = MockServer::start(vec![Step::respond(response)]).await;
        let client = connect(&server, ReferralPolicy::Ignore).await;

        let err = match i {
            0 => client.add("cn=a", vec![]).await.unwrap_err(),
            1 => client
                .modify(
                    "cn=a",
                    vec![Modification {
                        operation: ModifyOperation::Replace,
                        attribute: PartialAttribute {
                            name: "sn".into(),
                            values: vec![],
                        },
                    }],
                )
                .await
                .unwrap_err(),
            2 => client.delete("cn=a").await.unwrap_err(),
            3 => client
                .modify_dn("cn=a", "cn=b", true, None)
                .await
                .unwrap_err(),
            _ => client.extended("1.2.3", None).await.unwrap_err(),
        };
        assert_referral(err);
    }
}

#[tokio::test]
async fn a_referred_compare_is_a_referral_error() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::CompareResponse(
        referral(&[REFERRED]),
    ))])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    assert_referral(client.compare("cn=a", "sn", "x").await.unwrap_err());
}

#[tokio::test]
async fn follow_runs_the_operation_on_the_referred_server() {
    let second = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(result(
        ResultCode::Success,
    )))])
    .await;
    let first = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(
        referral(&[&url_of(&second)]),
    ))])
    .await;
    let client = connect(&first, ReferralPolicy::follow()).await;

    client.delete("cn=a,dc=x").await.unwrap();

    assert_eq!(
        second.received_operations().await,
        vec![LdapOperation::DeleteRequest("cn=a,dc=x".into())]
    );
}

#[tokio::test]
async fn follow_stops_at_the_hop_limit() {
    let hop_limit = 2;
    let server = MockServer::start_with(
        |addr| {
            let url = format!("ldap://{addr}/");
            (0..=hop_limit)
                .map(|_| {
                    vec![Step::respond(LdapOperation::DeleteResponse(referral(&[
                        url.as_str(),
                    ])))]
                })
                .collect()
        },
        None,
    )
    .await;
    let client = connect(&server, ReferralPolicy::Follow { hop_limit }).await;

    let err = client.delete("cn=a").await.unwrap_err();
    assert!(matches!(err, Error::ReferralHopLimitExceeded), "{err:?}");
    // The original request, and one more for each hop.
    assert_eq!(server.received().await.len(), usize::from(hop_limit) + 1);
}

#[tokio::test]
async fn follow_with_a_hop_limit_of_zero_does_not_follow() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(
        referral(&[REFERRED]),
    ))])
    .await;
    let client = connect(&server, ReferralPolicy::Follow { hop_limit: 0 }).await;

    let err = client.delete("cn=a").await.unwrap_err();
    assert!(matches!(err, Error::ReferralHopLimitExceeded), "{err:?}");
}

#[tokio::test]
async fn follow_skips_a_referral_url_that_does_not_parse() {
    let second = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(result(
        ResultCode::Success,
    )))])
    .await;
    let first = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(
        referral(&["not a url", &url_of(&second)]),
    ))])
    .await;
    let client = connect(&first, ReferralPolicy::follow()).await;

    client.delete("cn=a").await.unwrap();
}

#[tokio::test]
async fn a_search_referral_under_ignore_is_listed_in_the_result() {
    let server = MockServer::start(vec![
        Step::respond(entry("cn=a"))
            .and(common::search_reference(&["ldap://ref1/"]))
            .and(LdapOperation::SearchResultDone(referral(&[REFERRED]))),
    ])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    let result = client
        .search_full(
            "dc=x",
            SearchScope::WholeSubtree,
            Filter::present("cn"),
            vec![],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.referrals, ["ldap://ref1/", REFERRED]);
}

#[tokio::test]
async fn a_search_referral_under_return_is_an_error() {
    for policy in [ReferralPolicy::Return, ReferralPolicy::follow()] {
        let server = MockServer::start(vec![Step::respond(LdapOperation::SearchResultDone(
            referral(&[REFERRED]),
        ))])
        .await;
        let client = connect(&server, policy).await;

        let err = client
            .search(
                "dc=x",
                SearchScope::WholeSubtree,
                Filter::present("cn"),
                vec![],
            )
            .await
            .unwrap_err();
        assert_referral(err);
    }
}

#[tokio::test]
async fn an_answer_of_the_wrong_kind_is_a_protocol_error() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::ModifyResponse(result(
        ResultCode::Success,
    )))])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    let err = client.delete("cn=a").await.unwrap_err();
    assert!(
        matches!(&err, Error::Proto(_)) && err.to_string().contains("DeleteResponse"),
        "{err:?}"
    );
    assert!(!client.is_connected());
}

#[tokio::test]
async fn compare_answers_true_and_false() {
    let server = MockServer::start(vec![
        Step::respond(LdapOperation::CompareResponse(result(
            ResultCode::CompareTrue,
        ))),
        Step::respond(LdapOperation::CompareResponse(result(
            ResultCode::CompareFalse,
        ))),
        Step::respond(LdapOperation::CompareResponse(result(
            ResultCode::NoSuchAttribute,
        ))),
    ])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    assert!(client.compare("cn=a", "sn", "x").await.unwrap());
    assert!(!client.compare("cn=a", "sn", "y").await.unwrap());
    let err = client.compare("cn=a", "nope", "y").await.unwrap_err();
    assert_eq!(err.result_code(), Some(ResultCode::NoSuchAttribute));
}

#[tokio::test]
async fn a_write_answered_with_a_compare_code_is_an_error() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(result(
        ResultCode::CompareTrue,
    )))])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    assert!(client.delete("cn=a").await.is_err());
}

#[tokio::test]
async fn extended_refuses_the_starttls_oid() {
    let server = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(result(
        ResultCode::Success,
    )))])
    .await;
    let client = connect(&server, ReferralPolicy::Ignore).await;

    let err = client
        .extended(ldap_client::STARTTLS_OID, None)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::StartTls(_)), "{err:?}");
    assert!(server.received().await.is_empty());

    client.delete("cn=a").await.unwrap();
}

#[tokio::test]
async fn a_followed_referral_binds_anonymously_by_default() {
    let second = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(result(
        ResultCode::Success,
    )))])
    .await;
    let first = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(
        referral(&[&url_of(&second)]),
    ))])
    .await;
    let client = ClientBuilder::new(first.host(), first.port())
        .referral_policy(ReferralPolicy::follow())
        .service_account("cn=svc,dc=x", SecretString::from("pw"))
        .connect()
        .await
        .unwrap();

    client.delete("cn=a").await.unwrap();

    let operations = second.received_operations().await;
    assert!(
        matches!(&operations[..], [LdapOperation::DeleteRequest(_)]),
        "{operations:?}"
    );
}

#[tokio::test]
async fn referral_credentials_service_account_binds_the_referral_connection() {
    let second = MockServer::start(vec![
        Step::respond(bind_response(ResultCode::Success)),
        Step::respond(LdapOperation::DeleteResponse(result(ResultCode::Success))),
    ])
    .await;
    let first = MockServer::start(vec![Step::respond(LdapOperation::DeleteResponse(
        referral(&[&url_of(&second)]),
    ))])
    .await;
    let client = ClientBuilder::new(first.host(), first.port())
        .referral_policy(ReferralPolicy::follow())
        .referral_credentials(ldap_client::ReferralCredentials::ServiceAccount)
        .service_account("cn=svc,dc=x", SecretString::from("pw"))
        .connect()
        .await
        .unwrap();

    client.delete("cn=a").await.unwrap();

    let operations = second.received_operations().await;
    assert!(
        matches!(
            &operations[..],
            [LdapOperation::BindRequest(bind), LdapOperation::DeleteRequest(_)]
                if bind.name == "cn=svc,dc=x"
        ),
        "{operations:?}"
    );
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;
use std::num::NonZeroU32;
use std::time::Duration;

use ldap_client_proto::{
    Control, DerefAliases, Filter, LdapOperation, LdapResult, MessageId, PagedResultsControl,
    ProtoError, ResultCode, SearchRequest, SearchResultEntry, SearchScope,
};

use super::session::{Session, TransportError};
use super::{Client, MAX_SEARCH_ENTRIES, ReferralPolicy, SearchResult};
use crate::Error;

#[derive(Clone, Debug)]
enum SearchBase {
    ClientDefault,
    Dn(String),
}

impl SearchBase {
    /// The existing search methods take an empty base to mean the client's
    /// default base.
    fn from_legacy(base: String) -> Self {
        if base.is_empty() {
            Self::ClientDefault
        } else {
            Self::Dn(base)
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchParams {
    base: SearchBase,
    scope: SearchScope,
    filter: Filter,
    attributes: Vec<String>,
    deref_aliases: DerefAliases,
    size_limit: Option<NonZeroU32>,
    time_limit: Option<Duration>,
    types_only: bool,
    controls: Vec<Control>,
}

impl SearchParams {
    /// A search under `base`. The empty DN is the root DSE, not the client's
    /// default base.
    pub fn new(base: impl Into<String>, scope: SearchScope, filter: Filter) -> Self {
        Self::with_base(SearchBase::Dn(base.into()), scope, filter)
    }

    /// A search under the base DN the client was configured with, or under
    /// the empty DN when it has none.
    pub fn under_default_base(scope: SearchScope, filter: Filter) -> Self {
        Self::with_base(SearchBase::ClientDefault, scope, filter)
    }

    fn with_base(base: SearchBase, scope: SearchScope, filter: Filter) -> Self {
        Self {
            base,
            scope,
            filter,
            attributes: Vec::new(),
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: None,
            time_limit: None,
            types_only: false,
            controls: Vec::new(),
        }
    }

    pub(super) fn from_legacy(
        base: String,
        scope: SearchScope,
        filter: Filter,
        attributes: Vec<String>,
    ) -> Self {
        Self::with_base(SearchBase::from_legacy(base), scope, filter).attributes(attributes)
    }

    pub fn attributes(mut self, attributes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.attributes = attributes.into_iter().map(Into::into).collect();
        self
    }

    pub fn deref_aliases(mut self, deref: DerefAliases) -> Self {
        self.deref_aliases = deref;
        self
    }

    pub fn size_limit(mut self, limit: NonZeroU32) -> Self {
        self.size_limit = Some(limit);
        self
    }

    pub fn time_limit(mut self, limit: Duration) -> Self {
        self.time_limit = Some(limit);
        self
    }

    pub fn types_only(mut self) -> Self {
        self.types_only = true;
        self
    }

    pub fn controls(mut self, controls: Vec<Control>) -> Self {
        self.controls = controls;
        self
    }

    fn request(self, default_base: Option<&str>) -> (SearchRequest, Vec<Control>) {
        let base_dn = match self.base {
            SearchBase::Dn(dn) => dn,
            SearchBase::ClientDefault => default_base.unwrap_or_default().to_owned(),
        };
        let request = SearchRequest {
            base_dn,
            scope: self.scope,
            deref_aliases: self.deref_aliases,
            size_limit: self.size_limit.map_or(0, wire_size_limit),
            time_limit: self.time_limit.map_or(0, wire_time_limit),
            types_only: self.types_only,
            filter: self.filter,
            attributes: self.attributes,
        };
        (request, self.controls)
    }
}

/// The wire's limit is an `i32`, and no server can count higher.
fn wire_size_limit(limit: NonZeroU32) -> i32 {
    i32::try_from(limit.get()).unwrap_or(i32::MAX)
}

/// Whole seconds rounded up, so that a sub-second limit does not become the
/// wire's 0, which means no limit.
fn wire_time_limit(limit: Duration) -> i32 {
    let seconds = limit
        .as_secs()
        .saturating_add(u64::from(limit.subsec_nanos() > 0));
    i32::try_from(seconds.max(1)).unwrap_or(i32::MAX)
}

struct Collected {
    entries: Vec<SearchResultEntry>,
    references: Vec<String>,
    done: LdapResult,
    controls: Vec<Control>,
}

async fn collect(session: &mut Session, id: MessageId) -> Result<Collected, TransportError> {
    let mut entries = Vec::new();
    let mut references = Vec::new();
    loop {
        let message = session.receive(id).await?;
        match message.operation {
            LdapOperation::SearchResultEntry(entry) => {
                if entries.len() >= MAX_SEARCH_ENTRIES {
                    return Err(TransportError::entry_limit(MAX_SEARCH_ENTRIES));
                }
                entries.push(entry);
            }
            LdapOperation::SearchResultReference(urls) => references.extend(urls),
            LdapOperation::SearchResultDone(done) => {
                return Ok(Collected {
                    entries,
                    references,
                    done,
                    controls: message.controls,
                });
            }
            _ => {
                return Err(ProtoError::Protocol(
                    "unexpected response, expected SearchResult*".into(),
                )
                .into());
            }
        }
    }
}

impl Client {
    pub async fn search_with(&self, params: SearchParams) -> Result<SearchResult, Error> {
        let (request, controls) = params.request(self.settings.base_dn.as_deref());
        let collected = self
            .with_session(async |session| {
                let id = session
                    .send(LdapOperation::SearchRequest(request), controls)
                    .await?;
                collect(session, id).await
            })
            .await?;

        let Collected {
            entries,
            references: mut referrals,
            done,
            controls,
        } = collected;
        match done.code {
            ResultCode::Success => {}
            ResultCode::Referral if self.settings.referral_policy == ReferralPolicy::Ignore => {
                referrals.extend(done.referral);
            }
            _ => return Err(Error::from_failed_result(&done)),
        }
        Ok(SearchResult {
            entries,
            referrals,
            controls,
        })
    }
}

#[derive(Debug)]
enum PageState {
    Start,
    Continue(Vec<u8>),
    Done,
}

/// Incremental paged search that yields one page of results at a time.
///
/// Created via [`Client::search_paged_stream`]. Call [`next_page`](PagedSearch::next_page)
/// repeatedly to fetch pages. If you stop before exhausting results, call
/// [`cancel`](PagedSearch::cancel) to release the server-side cookie.
pub struct PagedSearch<'a> {
    client: &'a Client,
    params: SearchParams,
    page_size: i32,
    state: PageState,
    cookies_seen: HashSet<Vec<u8>>,
}

impl<'a> PagedSearch<'a> {
    pub(super) fn new(client: &'a Client, params: SearchParams, page_size: i32) -> Self {
        Self {
            client,
            params,
            page_size,
            state: PageState::Start,
            cookies_seen: HashSet::new(),
        }
    }

    /// Fetch the next page of results.
    ///
    /// Returns `Ok(Some(entries))` for each page, `Ok(None)` when all pages
    /// have been consumed. After an error the search is over: later calls
    /// return `Ok(None)`.
    pub async fn next_page(&mut self) -> Result<Option<Vec<SearchResultEntry>>, Error> {
        let cookie = match std::mem::replace(&mut self.state, PageState::Done) {
            PageState::Done => return Ok(None),
            PageState::Start => Vec::new(),
            PageState::Continue(cookie) => cookie,
        };

        let result = self.page(self.page_size, cookie.clone()).await?;
        self.state = match Control::find::<PagedResultsControl>(&result.controls)? {
            Some(paged)
                if !paged.cookie.is_empty() && !self.cookies_seen.insert(paged.cookie.clone()) =>
            {
                return Err(Error::Proto(ProtoError::Protocol(
                    "server repeated a paged results cookie".into(),
                )));
            }
            Some(paged) if !paged.cookie.is_empty() => PageState::Continue(paged.cookie),
            _ => PageState::Done,
        };
        Ok(Some(result.entries))
    }

    /// Send an abandon request (page size 0) to release the server cookie.
    ///
    /// Call this if you stop iterating before all pages are consumed. If you
    /// don't, the server cookie will eventually time out on its own (~120 s).
    pub async fn cancel(&mut self) -> Result<(), Error> {
        if let PageState::Continue(cookie) = std::mem::replace(&mut self.state, PageState::Done) {
            self.page(0, cookie).await?;
        }
        Ok(())
    }

    /// Returns `true` once all pages have been consumed or `cancel` was called.
    pub fn is_done(&self) -> bool {
        matches!(self.state, PageState::Done)
    }

    async fn page(&self, size: i32, cookie: Vec<u8>) -> Result<SearchResult, Error> {
        let paged = PagedResultsControl::new(size).with_cookie(cookie);
        let params = self.params.clone().controls(vec![paged.to_control()]);
        self.client.search_with(params).await
    }
}

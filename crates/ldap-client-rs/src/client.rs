// SPDX-License-Identifier: MIT OR Apache-2.0

mod operation;
mod search;
mod session;

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;
use tracing::debug;
use zeroize::Zeroizing;

use ldap_client_proto::{
    AddRequest, BindAuthentication, BindRequest, CompareRequest, Control, ExtendedRequest,
    ExtendedResponse, Filter, HasLdapResult, LdapScheme, LdapUrl, ModifyDnRequest, ModifyRequest,
    ProtoError, STARTTLS_OID, SearchResultEntry, SearchScope, WHO_AM_I_OID,
};

use crate::Error;
use crate::tls_config::default_client_config;
use operation::{Delete, Operation};
pub use search::{PagedSearch, SearchParams};
use session::{ConnectParams, Security, Session, TransportError};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;
const MAX_SEARCH_ENTRIES: usize = 500_000;
const SEARCH_ONE_SIZE_LIMIT: NonZeroU32 = NonZeroU32::new(2).unwrap();

/// Handler for unsolicited notifications other than Notice of Disconnection.
pub type UnsolicitedHandler = Arc<dyn Fn(&ExtendedResponse) + Send + Sync>;

fn default_unsolicited_handler() -> UnsolicitedHandler {
    Arc::new(|resp| {
        tracing::debug!(
            oid = resp.oid.as_deref().unwrap_or("<none>"),
            "received unsolicited notification from server"
        );
    })
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub entries: Vec<SearchResultEntry>,
    pub referrals: Vec<String>,
    pub controls: Vec<Control>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Plain,
    Tls,
    StartTls,
}

impl Transport {
    /// StartTLS runs on the plain port.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Plain | Self::StartTls => LdapScheme::Ldap.default_port(),
            Self::Tls => LdapScheme::Ldaps.default_port(),
        }
    }
}

impl From<LdapScheme> for Transport {
    fn from(scheme: LdapScheme) -> Self {
        match scheme {
            LdapScheme::Ldap => Self::Plain,
            LdapScheme::Ldaps => Self::Tls,
        }
    }
}

/// Controls how the server's referral responses are handled.
///
/// In a search, a referral is listed in `SearchResult::referrals` under
/// `Ignore` and returned as `Error::Referral` under the other two policies;
/// it is never followed. For any other operation, a referral means the
/// server did not perform it, so it is returned as `Error::Referral` unless
/// the policy is `Follow`. A bind is never followed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReferralPolicy {
    /// List referrals in search results and return them as errors otherwise.
    #[default]
    Ignore,
    /// Return referrals as `Error::Referral` to the caller.
    Return,
    /// Automatically chase referrals up to `hop_limit` hops.
    Follow { hop_limit: u8 },
}

impl ReferralPolicy {
    /// Create a `Follow` policy with the default hop limit of 10.
    pub fn follow() -> Self {
        Self::Follow { hop_limit: 10 }
    }
}

/// What a connection opened to follow a referral binds as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferralCredentials {
    /// No bind: the referred operation is the first request.
    #[default]
    Anonymous,
    /// Bind with the client's service account. The referral names the host,
    /// so this sends the service account's password where the server says.
    ServiceAccount,
}

/// Credentials for [`Client::bind`].
pub enum BindCredentials<'a> {
    /// Simple bind with a DN and password.
    Simple {
        dn: &'a str,
        password: &'a SecretString,
    },
    /// Re-bind using the pre-configured service account.
    ServiceAccount,
    /// SASL EXTERNAL bind (client certificate authentication).
    SaslExternal,
}

#[derive(Clone)]
struct ServiceAccount {
    dn: String,
    password: SecretString,
}

/// What a client does with a connection, as opposed to how it connects.
struct Settings {
    base_dn: Option<String>,
    service_account: Option<ServiceAccount>,
    referral_policy: ReferralPolicy,
    referral_credentials: ReferralCredentials,
    unsolicited_handler: UnsolicitedHandler,
}

pub struct ClientBuilder {
    host: String,
    port: u16,
    transport: Transport,
    tls_config: Option<Arc<ClientConfig>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    max_message_size: u32,
    settings: Settings,
}

impl ClientBuilder {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            transport: Transport::Plain,
            tls_config: None,
            connect_timeout: DEFAULT_TIMEOUT,
            request_timeout: DEFAULT_TIMEOUT,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            settings: Settings {
                base_dn: None,
                service_account: None,
                referral_policy: ReferralPolicy::default(),
                referral_credentials: ReferralCredentials::default(),
                unsolicited_handler: default_unsolicited_handler(),
            },
        }
    }

    pub fn from_url(url: &str) -> Result<Self, Error> {
        let parsed = LdapUrl::parse(url).map_err(|e| Error::InvalidUrl(format!("{e}")))?;

        let port = parsed.effective_port();
        let mut builder = Self::new(parsed.host, port).transport(Transport::from(parsed.scheme));
        builder.settings.base_dn = parsed.base_dn;
        Ok(builder)
    }

    pub fn transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Set the TLS configuration from a pre-built [`rustls::ClientConfig`].
    ///
    /// For a higher-level API, see [`tls`](Self::tls).
    pub fn tls_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Build and set the TLS configuration from a [`TlsConfig`](crate::tls_config::TlsConfig).
    ///
    /// Returns `Err` if certificate loading fails.
    pub fn tls(mut self, config: crate::tls_config::TlsConfig) -> Result<Self, Error> {
        self.tls_config = Some(config.build()?);
        Ok(self)
    }

    /// Set both connect and request timeouts.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self.request_timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn base_dn(mut self, base_dn: impl Into<String>) -> Self {
        self.settings.base_dn = Some(base_dn.into());
        self
    }

    /// Set the service account that [`Client::rebind_service_account`] and
    /// [`Client::reconnect`] bind with. A DN with an empty password is refused
    /// by [`connect`](Self::connect) as `Error::UnauthenticatedBind`.
    pub fn service_account(mut self, dn: impl Into<String>, password: SecretString) -> Self {
        self.settings.service_account = Some(ServiceAccount {
            dn: dn.into(),
            password,
        });
        self
    }

    pub fn referral_policy(mut self, policy: ReferralPolicy) -> Self {
        self.settings.referral_policy = policy;
        self
    }

    /// Choose what a connection opened to follow a referral binds as
    /// (anonymous by default).
    pub fn referral_credentials(mut self, credentials: ReferralCredentials) -> Self {
        self.settings.referral_credentials = credentials;
        self
    }

    /// Set the maximum accepted LDAP message size (10 MiB by default).
    pub fn max_message_size(mut self, max: u32) -> Self {
        self.max_message_size = max;
        self
    }

    /// Register a callback for unsolicited notifications (message-id 0) other
    /// than the Notice of Disconnection. The default handler logs the event at
    /// `debug` level.
    pub fn on_unsolicited_notification(
        mut self,
        handler: impl Fn(&ExtendedResponse) + Send + Sync + 'static,
    ) -> Self {
        self.settings.unsolicited_handler = Arc::new(handler);
        self
    }

    pub async fn connect(self) -> Result<Client, Error> {
        if let Some(account) = &self.settings.service_account {
            simple_bind_request(account.dn.clone(), &account.password)?;
        }

        let params = ConnectParams {
            security: Security::new(self.transport, &self.host)?,
            host: self.host,
            port: self.port,
            tls_config: self
                .tls_config
                .unwrap_or_else(|| Arc::new(default_client_config())),
            connect_timeout: self.connect_timeout,
            request_timeout: self.request_timeout,
            max_message_size: self.max_message_size,
        };
        let session = Session::open(&params, &self.settings.unsolicited_handler).await?;
        Ok(Client::new(session, params, self.settings))
    }
}

const MIN_RECONNECT_INTERVAL: Duration = Duration::from_secs(1);

pub struct Client {
    /// `None` is a connection that cannot be used: a request that did not
    /// read its whole answer, for any reason, leaves it empty.
    session: Mutex<Option<Session>>,
    params: ConnectParams,
    settings: Settings,
    last_reconnect: Mutex<Option<tokio::time::Instant>>,
}

fn simple_bind_request(dn: String, password: &SecretString) -> Result<BindRequest, Error> {
    if !dn.is_empty() && password.expose_secret().is_empty() {
        return Err(Error::UnauthenticatedBind);
    }
    Ok(BindRequest {
        version: 3,
        name: dn,
        authentication: BindAuthentication::Simple(Zeroizing::new(
            password.expose_secret().as_bytes().to_vec(),
        )),
    })
}

impl Client {
    fn new(session: Session, params: ConnectParams, settings: Settings) -> Self {
        Self {
            session: Mutex::new(Some(session)),
            params,
            settings,
            last_reconnect: Mutex::new(None),
        }
    }

    /// Runs `run` on the session, and puts the session back only if it
    /// returns `Ok`. A timeout, an I/O or decode error, an answer for the
    /// wrong request, and a dropped future all leave the slot empty, so the
    /// next request cannot read this one's late answer.
    async fn with_session<T>(
        &self,
        run: impl AsyncFnOnce(&mut Session) -> Result<T, TransportError>,
    ) -> Result<T, Error> {
        let mut slot = self.session.lock().await;
        let mut session = slot.take().ok_or(Error::ConnectionClosed)?;
        let value = run(&mut session).await?;
        *slot = Some(session);
        Ok(value)
    }

    async fn exchange<O: Operation>(
        &self,
        operation: &O,
        controls: Vec<Control>,
    ) -> Result<O::Output, Error> {
        let response = self
            .with_session(async |session| {
                let id = session.send(operation.to_protocol(), controls).await?;
                let message = session.receive(id).await?;
                O::response(message.operation).ok_or_else(|| {
                    ProtoError::Protocol(format!("unexpected response, expected {}", O::RESPONSE))
                        .into()
                })
            })
            .await?;
        O::output(response).map_err(|response| Error::from_failed_result(response.result()))
    }

    /// `exchange`, following referrals under `ReferralPolicy::Follow`. Each
    /// referral opens a connection whose own policy is `Return`, so this loop
    /// counts the hops.
    async fn execute<O: Operation>(
        &self,
        operation: O,
        controls: Vec<Control>,
    ) -> Result<O::Output, Error> {
        let ReferralPolicy::Follow { hop_limit } = self.settings.referral_policy else {
            return self.exchange(&operation, controls).await;
        };

        let mut hops = 0;
        let mut referred: Option<Client> = None;
        loop {
            let client = referred.as_ref().unwrap_or(self);
            match client.exchange(&operation, controls.clone()).await {
                Err(Error::Referral { urls, .. }) => {
                    if hops >= hop_limit {
                        return Err(Error::ReferralHopLimitExceeded);
                    }
                    hops += 1;
                    referred = Some(self.connect_referral(&urls).await?);
                }
                other => return other,
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.session
            .try_lock()
            .map_or(true, |session| session.is_some())
    }

    /// Open a new connection and, when a service account is configured,
    /// bind with it. Any other identity is not restored: a caller that
    /// bound with its own credentials binds again.
    pub async fn reconnect(&self) -> Result<(), Error> {
        {
            let mut last = self.last_reconnect.lock().await;
            if let Some(prev) = *last {
                let elapsed = prev.elapsed();
                if elapsed < MIN_RECONNECT_INTERVAL {
                    tokio::time::sleep(MIN_RECONNECT_INTERVAL - elapsed).await;
                }
            }
            *last = Some(tokio::time::Instant::now());
        }

        let session = Session::open(&self.params, &self.settings.unsolicited_handler).await?;
        *self.session.lock().await = Some(session);

        if self.settings.service_account.is_some()
            && let Err(e) = self.rebind_service_account().await
        {
            self.session.lock().await.take();
            return Err(e);
        }
        Ok(())
    }

    pub async fn rebind_service_account(&self) -> Result<(), Error> {
        let account = self.settings.service_account.as_ref().ok_or_else(|| {
            Error::Proto(ProtoError::Protocol("no service account configured".into()))
        })?;
        self.simple_bind(&account.dn, &account.password).await
    }

    pub async fn simple_bind(
        &self,
        dn: impl Into<String>,
        password: &SecretString,
    ) -> Result<(), Error> {
        let request = simple_bind_request(dn.into(), password)?;
        if self.params.security.transport() == Transport::Plain {
            tracing::warn!(
                "simple bind over plain (unencrypted) connection; credentials are sent in cleartext"
            );
        }
        self.exchange(&request, Vec::new()).await
    }

    pub async fn sasl_external_bind(&self) -> Result<(), Error> {
        let request = BindRequest {
            version: 3,
            name: String::new(),
            authentication: BindAuthentication::Sasl {
                mechanism: "EXTERNAL".into(),
                credentials: None,
            },
        };
        self.exchange(&request, Vec::new()).await
    }

    /// Bind using one of the supported credential types.
    pub async fn bind(&self, credentials: BindCredentials<'_>) -> Result<(), Error> {
        match credentials {
            BindCredentials::Simple { dn, password } => self.simple_bind(dn, password).await,
            BindCredentials::ServiceAccount => self.rebind_service_account().await,
            BindCredentials::SaslExternal => self.sasl_external_bind().await,
        }
    }

    /// Send an unbind request. The connection is closed afterwards.
    pub async fn unbind(&self) -> Result<(), Error> {
        let mut slot = self.session.lock().await;
        let mut session = slot.take().ok_or(Error::ConnectionClosed)?;
        session
            .send(ldap_client_proto::LdapOperation::UnbindRequest, Vec::new())
            .await?;
        Ok(())
    }

    /// An empty `base_dn` means the base DN the client was configured with.
    pub async fn search(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
    ) -> Result<Vec<SearchResultEntry>, Error> {
        let params = SearchParams::from_legacy(base_dn.into(), scope, filter, attrs);
        Ok(self.search_with(params).await?.entries)
    }

    pub async fn search_with_controls(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        controls: Vec<Control>,
    ) -> Result<(Vec<SearchResultEntry>, Vec<Control>), Error> {
        let result = self
            .search_full(base_dn, scope, filter, attrs, controls)
            .await?;
        Ok((result.entries, result.controls))
    }

    pub async fn search_full(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        controls: Vec<Control>,
    ) -> Result<SearchResult, Error> {
        let params =
            SearchParams::from_legacy(base_dn.into(), scope, filter, attrs).controls(controls);
        self.search_with(params).await
    }

    pub async fn search_paged(
        &self,
        base_dn: &str,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        page_size: i32,
    ) -> Result<Vec<SearchResultEntry>, Error> {
        let mut pages = self.search_paged_stream(base_dn, scope, filter, attrs, page_size);
        let mut entries = Vec::new();
        while let Some(page) = pages.next_page().await? {
            entries.extend(page);
            if entries.len() > MAX_SEARCH_ENTRIES {
                return Err(Error::SearchEntryLimitExceeded(MAX_SEARCH_ENTRIES));
            }
        }
        Ok(entries)
    }

    pub fn search_paged_stream(
        &self,
        base_dn: &str,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        page_size: i32,
    ) -> PagedSearch<'_> {
        let params = SearchParams::from_legacy(base_dn.to_owned(), scope, filter, attrs);
        PagedSearch::new(self, params, page_size)
    }

    pub async fn search_one(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
    ) -> Result<Option<SearchResultEntry>, Error> {
        let params = SearchParams::from_legacy(base_dn.into(), scope, filter, attrs)
            .size_limit(SEARCH_ONE_SIZE_LIMIT)
            .time_limit(self.params.request_timeout);

        // SizeLimitExceeded means the server stopped because of our size
        // limit, which indicates multiple results exist.
        let entries = match self.search_with(params).await {
            Ok(result) => result.entries,
            Err(Error::Ldap {
                code: ldap_client_proto::ResultCode::SizeLimitExceeded,
                ..
            }) => {
                return Err(Error::MultipleResults);
            }
            Err(e) => return Err(e),
        };

        let mut entries = entries.into_iter();
        match (entries.next(), entries.next()) {
            (None, _) => Ok(None),
            (Some(entry), None) => Ok(Some(entry)),
            (Some(_), Some(_)) => Err(Error::MultipleResults),
        }
    }

    pub async fn root_dse(&self) -> Result<SearchResultEntry, Error> {
        let params = SearchParams::new("", SearchScope::BaseObject, Filter::present("objectClass"))
            .attributes(["*", "+"]);
        let result = self.search_with(params).await?;
        result
            .entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::Proto(ProtoError::Protocol("root DSE not found".into())))
    }

    /// Retrieve all values of a multi-valued attribute using Active Directory
    /// range retrieval.
    ///
    /// AD limits the number of values returned per request (typically 1500).
    /// This method loops, requesting `attr;range=N-*` with `BaseObject` scope
    /// until all values are collected.
    pub async fn search_range(
        &self,
        base_dn: &str,
        filter: Filter,
        attr: &str,
    ) -> Result<Vec<Vec<u8>>, Error> {
        const MAX_RANGE_ROUNDS: usize = 100_000;
        let mut all_values: Vec<Vec<u8>> = Vec::new();
        let mut range_start: u32 = 0;

        for _ in 0..MAX_RANGE_ROUNDS {
            let range_attr = format!("{attr};range={range_start}-*");
            let entries = self
                .search(
                    base_dn,
                    SearchScope::BaseObject,
                    filter.clone(),
                    vec![range_attr],
                )
                .await?;

            let entry = match entries.into_iter().next() {
                Some(e) => e,
                None => break,
            };

            // Find the response attribute that has range info.
            let mut found = false;
            for pa in &entry.attributes {
                if let Some((base, _start, end)) = parse_range_option(&pa.name)
                    && base.eq_ignore_ascii_case(attr)
                {
                    all_values.extend(pa.values.iter().cloned());
                    found = true;
                    match end {
                        None => {
                            // `*` means this is the last chunk.
                            return Ok(all_values);
                        }
                        Some(e) => {
                            let next = e.saturating_add(1);
                            if next <= range_start {
                                // No progress — avoid infinite loop.
                                return Ok(all_values);
                            }
                            range_start = next;
                        }
                    }
                }
            }
            if !found {
                // No range option in response — the attribute may be small enough
                // to be returned entirely.
                for pa in entry.attributes {
                    let base = pa.name.split(';').next().unwrap_or(&pa.name);
                    if base.eq_ignore_ascii_case(attr) {
                        all_values.extend(pa.values);
                    }
                }
                break;
            }
        }

        Ok(all_values)
    }

    pub async fn add(
        &self,
        dn: impl Into<String>,
        attrs: Vec<ldap_client_proto::PartialAttribute>,
    ) -> Result<(), Error> {
        let request = AddRequest {
            dn: dn.into(),
            attributes: attrs,
        };
        self.execute(request, Vec::new()).await
    }

    pub async fn modify(
        &self,
        dn: impl Into<String>,
        changes: Vec<ldap_client_proto::Modification>,
    ) -> Result<(), Error> {
        let request = ModifyRequest {
            dn: dn.into(),
            changes,
        };
        self.execute(request, Vec::new()).await
    }

    pub async fn delete(&self, dn: impl Into<String>) -> Result<(), Error> {
        self.execute(Delete(dn.into()), Vec::new()).await
    }

    pub async fn compare(
        &self,
        dn: impl Into<String>,
        attr: impl Into<String>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let request = CompareRequest {
            dn: dn.into(),
            attr: attr.into(),
            value: value.as_ref().to_vec(),
        };
        self.execute(request, Vec::new()).await
    }

    pub async fn modify_dn(
        &self,
        dn: impl Into<String>,
        new_rdn: impl Into<String>,
        delete_old_rdn: bool,
        new_superior: Option<String>,
    ) -> Result<(), Error> {
        let request = ModifyDnRequest {
            dn: dn.into(),
            new_rdn: new_rdn.into(),
            delete_old_rdn,
            new_superior,
        };
        self.execute(request, Vec::new()).await
    }

    /// Send an extended request. StartTLS is refused: it is negotiated when
    /// the connection opens, with [`Transport::StartTls`].
    pub async fn extended(
        &self,
        oid: impl Into<String>,
        value: Option<Vec<u8>>,
    ) -> Result<ExtendedResponse, Error> {
        let oid = oid.into();
        if oid == STARTTLS_OID {
            return Err(Error::StartTls(
                "StartTLS is negotiated at connect time; use Transport::StartTls".into(),
            ));
        }
        self.execute(ExtendedRequest { oid, value }, Vec::new())
            .await
    }

    pub async fn who_am_i(&self) -> Result<Option<String>, Error> {
        let resp = self.extended(WHO_AM_I_OID, None).await?;
        Ok(resp.value.map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    /// Connect to a referral server, binding with the service account if
    /// [`ReferralCredentials::ServiceAccount`] is chosen.
    ///
    /// Tries each URL in order, returning the first successful connection.
    /// The returned client's policy is `ReferralPolicy::Return`: the caller
    /// counts hops.
    async fn connect_referral(&self, urls: &[String]) -> Result<Client, Error> {
        let mut last_err = None;
        for raw_url in urls {
            let Ok(url) = LdapUrl::parse(raw_url) else {
                continue;
            };
            let transport = Transport::from(url.scheme);
            if self.params.security.transport() != Transport::Plain && transport == Transport::Plain
            {
                debug!(url = %raw_url, "skipping referral that would downgrade from TLS to plain");
                continue;
            }
            match self.open_referral(&url, transport).await {
                Ok(client) => return Ok(client),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or(Error::InvalidUrl("no valid referral URLs".into())))
    }

    async fn open_referral(&self, url: &LdapUrl, transport: Transport) -> Result<Client, Error> {
        let params = ConnectParams {
            host: url.host.clone(),
            port: url.effective_port(),
            security: Security::new(transport, &url.host)?,
            ..self.params.clone()
        };
        let session = Session::open(&params, &self.settings.unsolicited_handler).await?;
        let settings = Settings {
            base_dn: None,
            service_account: match self.settings.referral_credentials {
                ReferralCredentials::ServiceAccount => self.settings.service_account.clone(),
                ReferralCredentials::Anonymous => None,
            },
            referral_policy: ReferralPolicy::Return,
            referral_credentials: ReferralCredentials::Anonymous,
            unsolicited_handler: self.settings.unsolicited_handler.clone(),
        };
        let client = Client::new(session, params, settings);
        if client.settings.service_account.is_some() {
            client.rebind_service_account().await?;
        }
        Ok(client)
    }
}

/// Parse an AD range option from an attribute name.
///
/// `"member;range=0-1499"` → `Some(("member", 0, Some(1499)))`
/// `"member;range=1500-*"` → `Some(("member", 1500, None))`
pub fn parse_range_option(attr_name: &str) -> Option<(&str, u32, Option<u32>)> {
    let base = attr_name.split(';').next().unwrap_or(attr_name);
    let range_part = attr_name
        .split(';')
        .find_map(|part| part.strip_prefix("range="))?;
    let (start_s, end_s) = range_part.split_once('-')?;
    let start: u32 = start_s.parse().ok()?;
    let end = if end_s == "*" {
        None
    } else {
        Some(end_s.parse().ok()?)
    };
    Some((base, start, end))
}

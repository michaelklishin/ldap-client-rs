// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::codec::Framed;
use tracing::debug;

use ldap_client_ber::LdapCodec;
use ldap_client_proto::{
    AddRequest, BindAuthentication, BindRequest, CompareRequest, Control, DerefAliases,
    ExtendedRequest, Filter, LdapMessage, LdapOperation, LdapResult as ProtoLdapResult, LdapScheme,
    LdapUrl, MessageId, ModifyDnRequest, ModifyRequest, PAGED_RESULTS_OID, PagedResultsControl,
    ResultCode, SearchRequest, SearchResultEntry, SearchScope,
};

use crate::Error;
use crate::conn::{self, LdapStream};

const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";
const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Controls how the server's referral responses are handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReferralPolicy {
    /// Silently ignore referrals (treat as success).
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

pub struct ClientBuilder {
    host: String,
    port: u16,
    transport: Transport,
    tls_config: Option<Arc<ClientConfig>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    base_dn: Option<String>,
    service_account_dn: Option<String>,
    service_account_password: Option<SecretString>,
    referral_policy: ReferralPolicy,
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
            base_dn: None,
            service_account_dn: None,
            service_account_password: None,
            referral_policy: ReferralPolicy::default(),
        }
    }

    pub fn from_url(url: &str) -> Result<Self, Error> {
        let parsed = LdapUrl::parse(url).map_err(|e| Error::InvalidUrl(format!("{e}")))?;

        let transport = match parsed.scheme {
            LdapScheme::Ldap => Transport::Plain,
            LdapScheme::Ldaps => Transport::Tls,
        };

        let port = parsed.effective_port();
        Ok(Self {
            host: parsed.host,
            port,
            transport,
            tls_config: None,
            connect_timeout: DEFAULT_TIMEOUT,
            request_timeout: DEFAULT_TIMEOUT,
            base_dn: parsed.base_dn,
            service_account_dn: None,
            service_account_password: None,
            referral_policy: ReferralPolicy::default(),
        })
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
        self.base_dn = Some(base_dn.into());
        self
    }

    pub fn service_account(mut self, dn: impl Into<String>, password: SecretString) -> Self {
        self.service_account_dn = Some(dn.into());
        self.service_account_password = Some(password);
        self
    }

    pub fn referral_policy(mut self, policy: ReferralPolicy) -> Self {
        self.referral_policy = policy;
        self
    }

    pub async fn connect(self) -> Result<Client, Error> {
        let addr = format_addr(&self.host, self.port);
        debug!(addr = %addr, transport = ?self.transport, "connecting");

        let tcp = match tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr)).await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => return Err(Error::Timeout),
        };
        tcp.set_nodelay(true)?;

        let tls_config = self
            .tls_config
            .clone()
            .unwrap_or_else(|| Arc::new(conn::default_tls_config()));

        let stream = match self.transport {
            Transport::Plain => LdapStream::Plain(tcp),
            Transport::Tls | Transport::StartTls => {
                let server_name = ServerName::try_from(self.host.clone())
                    .map_err(|e| Error::InvalidUrl(format!("invalid server name: {e}")))?;

                if self.transport == Transport::Tls {
                    conn::upgrade_to_tls(tcp, server_name, tls_config.clone()).await?
                } else {
                    perform_start_tls(tcp, server_name, tls_config.clone(), self.request_timeout)
                        .await?
                }
            }
        };

        let start_id = if self.transport == Transport::StartTls {
            2
        } else {
            1
        };
        Ok(Client {
            framed: Mutex::new(Framed::new(stream, LdapCodec::default())),
            next_id: AtomicI32::new(start_id),
            connected: AtomicBool::new(true),
            request_timeout: self.request_timeout,
            base_dn: self.base_dn,
            referral_policy: self.referral_policy,
            host: self.host,
            port: self.port,
            transport: self.transport,
            tls_config,
            connect_timeout: self.connect_timeout,
            service_account_dn: self.service_account_dn,
            service_account_password: self.service_account_password,
        })
    }
}

async fn perform_start_tls(
    tcp: TcpStream,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<LdapStream, Error> {
    let mut framed = Framed::new(tcp, LdapCodec::default());

    let msg = LdapMessage {
        message_id: MessageId(1),
        operation: LdapOperation::ExtendedRequest(ExtendedRequest {
            oid: STARTTLS_OID.to_string(),
            value: None,
        }),
        controls: vec![],
    };
    framed.send(msg.encode()).await.map_err(ber_to_io)?;

    let response = match tokio::time::timeout(timeout, framed.next()).await {
        Ok(Some(Ok(frame))) => LdapMessage::decode(&frame).map_err(Error::Proto)?,
        Ok(Some(Err(e))) => return Err(ber_to_io(e)),
        Ok(None) => return Err(Error::ConnectionClosed),
        Err(_) => return Err(Error::Timeout),
    };

    match response.operation {
        LdapOperation::ExtendedResponse(resp) if resp.result.code.is_success() => {}
        LdapOperation::ExtendedResponse(resp) => {
            return Err(Error::StartTls(resp.result.diagnostic_message));
        }
        _ => return Err(Error::StartTls("unexpected response".into())),
    }

    let parts = framed.into_parts();
    if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
        return Err(Error::StartTls(
            "unexpected buffered data before TLS handshake".into(),
        ));
    }
    let tcp = parts.io;
    conn::upgrade_to_tls(tcp, server_name, tls_config).await
}

type FramedLdap = Framed<LdapStream, LdapCodec>;

pub struct Client {
    framed: Mutex<FramedLdap>,
    next_id: AtomicI32,
    connected: AtomicBool,
    request_timeout: Duration,
    base_dn: Option<String>,
    referral_policy: ReferralPolicy,
    // Fields stored for reconnect.
    host: String,
    port: u16,
    transport: Transport,
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    service_account_dn: Option<String>,
    service_account_password: Option<SecretString>,
}

fn format_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Client {
    fn next_message_id(&self) -> MessageId {
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n > 0 && n < i32::MAX - 1 {
                    Some(n + 1)
                } else {
                    Some(2) // wrap-around: store 2, current caller keeps n
                }
            });
        // fetch_update with an always-Some closure never fails.
        MessageId(id.unwrap())
    }

    fn resolve_base_dn(&self, base_dn: String) -> String {
        if base_dn.is_empty()
            && let Some(default) = &self.base_dn
        {
            return default.clone();
        }
        base_dn
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn reconnect(&self) -> Result<(), Error> {
        let addr = format_addr(&self.host, self.port);
        debug!(addr = %addr, transport = ?self.transport, "reconnecting");

        let tcp = match tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr)).await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => return Err(Error::Timeout),
        };
        tcp.set_nodelay(true)?;

        let stream = match self.transport {
            Transport::Plain => LdapStream::Plain(tcp),
            Transport::Tls | Transport::StartTls => {
                let server_name = ServerName::try_from(self.host.clone())
                    .map_err(|e| Error::InvalidUrl(format!("invalid server name: {e}")))?;

                if self.transport == Transport::Tls {
                    conn::upgrade_to_tls(tcp, server_name, self.tls_config.clone()).await?
                } else {
                    perform_start_tls(
                        tcp,
                        server_name,
                        self.tls_config.clone(),
                        self.request_timeout,
                    )
                    .await?
                }
            }
        };

        let start_id = if self.transport == Transport::StartTls {
            2
        } else {
            1
        };

        let mut framed = self.framed.lock().await;
        *framed = Framed::new(stream, LdapCodec::default());
        self.next_id.store(start_id, Ordering::Relaxed);
        self.connected.store(true, Ordering::Relaxed);
        drop(framed);

        if self.service_account_dn.is_some()
            && let Err(e) = self.rebind_service_account().await
        {
            self.connected.store(false, Ordering::Relaxed);
            return Err(e);
        }
        Ok(())
    }

    pub async fn rebind_service_account(&self) -> Result<(), Error> {
        let dn = self.service_account_dn.as_deref().ok_or_else(|| {
            Error::Proto(ldap_client_proto::ProtoError::Protocol(
                "no service account configured".into(),
            ))
        })?;
        let password = self.service_account_password.as_ref().ok_or_else(|| {
            Error::Proto(ldap_client_proto::ProtoError::Protocol(
                "no service account password configured".into(),
            ))
        })?;
        self.simple_bind(dn, password).await
    }

    async fn request(&self, operation: LdapOperation) -> Result<LdapMessage, Error> {
        self.request_with_controls(operation, vec![]).await
    }

    async fn request_with_controls(
        &self,
        operation: LdapOperation,
        controls: Vec<Control>,
    ) -> Result<LdapMessage, Error> {
        let message_id = self.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation,
            controls,
        };
        let data = msg.encode();

        let mut framed = self.framed.lock().await;
        send_msg(&mut framed, data, &self.connected).await?;
        recv_msg(&mut framed, self.request_timeout, &self.connected).await
    }

    pub async fn simple_bind(
        &self,
        dn: impl Into<String>,
        password: &SecretString,
    ) -> Result<(), Error> {
        let op = LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: dn.into(),
            authentication: BindAuthentication::Simple(zeroize::Zeroizing::new(
                password.expose_secret().as_bytes().to_vec(),
            )),
        });

        let response = self.request(op).await?;
        match response.operation {
            LdapOperation::BindResponse(resp) => check_result(&resp.result, self.referral_policy),
            _ => Err(unexpected_response("BindResponse")),
        }
    }

    pub async fn search(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
    ) -> Result<Vec<SearchResultEntry>, Error> {
        let (entries, _controls) = self
            .search_with_controls(base_dn, scope, filter, attrs, vec![])
            .await?;
        Ok(entries)
    }

    pub async fn search_with_controls(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        controls: Vec<Control>,
    ) -> Result<(Vec<SearchResultEntry>, Vec<Control>), Error> {
        let message_id = self.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::SearchRequest(SearchRequest {
                base_dn: self.resolve_base_dn(base_dn.into()),
                scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter,
                attributes: attrs,
            }),
            controls,
        };
        let data = msg.encode();

        let mut framed = self.framed.lock().await;
        send_msg(&mut framed, data, &self.connected).await?;

        let mut entries = Vec::new();
        let collected = collect_search_results(
            &mut framed,
            self.request_timeout,
            &self.connected,
            &mut entries,
            self.referral_policy,
        )
        .await?;

        Ok((entries, collected.controls))
    }

    pub async fn search_full(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        controls: Vec<Control>,
    ) -> Result<SearchResult, Error> {
        let message_id = self.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::SearchRequest(SearchRequest {
                base_dn: self.resolve_base_dn(base_dn.into()),
                scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter,
                attributes: attrs,
            }),
            controls,
        };
        let data = msg.encode();

        let mut framed = self.framed.lock().await;
        send_msg(&mut framed, data, &self.connected).await?;

        let mut entries = Vec::new();
        let collected = collect_search_results(
            &mut framed,
            self.request_timeout,
            &self.connected,
            &mut entries,
            self.referral_policy,
        )
        .await?;

        Ok(SearchResult {
            entries,
            referrals: collected.referral_urls,
            controls: collected.controls,
        })
    }

    pub async fn search_paged(
        &self,
        base_dn: &str,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        page_size: i32,
    ) -> Result<Vec<SearchResultEntry>, Error> {
        const MAX_PAGED_ROUNDS: usize = 100_000;
        let resolved_base = self.resolve_base_dn(base_dn.to_string());
        let mut all_entries = Vec::new();
        let mut cookie = Vec::new();
        let mut prev_cookie = Vec::new();

        for _ in 0..MAX_PAGED_ROUNDS {
            let paged =
                PagedResultsControl::new(page_size).with_cookie(std::mem::take(&mut cookie));
            let controls = vec![paged.to_control()];

            let message_id = self.next_message_id();
            let msg = LdapMessage {
                message_id,
                operation: LdapOperation::SearchRequest(SearchRequest {
                    base_dn: resolved_base.clone(),
                    scope,
                    deref_aliases: DerefAliases::NeverDerefAliases,
                    size_limit: 0,
                    time_limit: 0,
                    types_only: false,
                    filter: filter.clone(),
                    attributes: attrs.clone(),
                }),
                controls,
            };
            let data = msg.encode();

            let mut framed = self.framed.lock().await;
            send_msg(&mut framed, data, &self.connected).await?;

            let collected = collect_search_results(
                &mut framed,
                self.request_timeout,
                &self.connected,
                &mut all_entries,
                self.referral_policy,
            )
            .await?;

            let new_cookie = collected
                .controls
                .iter()
                .find(|c| c.oid == PAGED_RESULTS_OID)
                .and_then(|c| PagedResultsControl::from_control(c).ok())
                .map(|p| p.cookie);

            match new_cookie {
                Some(c) if !c.is_empty() => {
                    if c == prev_cookie {
                        // Server returned the same cookie twice. Abort to prevent an infinite loop.
                        break;
                    }
                    prev_cookie = c.clone();
                    cookie = c;
                }
                _ => break,
            }
        }

        Ok(all_entries)
    }

    pub fn search_paged_stream(
        &self,
        base_dn: &str,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
        page_size: i32,
    ) -> PagedSearch<'_> {
        PagedSearch {
            client: self,
            base_dn: self.resolve_base_dn(base_dn.to_string()),
            scope,
            filter,
            attrs,
            page_size,
            cookie: Vec::new(),
            done: false,
        }
    }

    pub async fn add(
        &self,
        dn: impl Into<String>,
        attrs: Vec<ldap_client_proto::PartialAttribute>,
    ) -> Result<(), Error> {
        let dn = dn.into();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::AddRequest(AddRequest {
                dn: dn.clone(),
                attributes: attrs.clone(),
            });
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::AddResponse(result) => match try_chase(client, &result).await {
                    Chase::Ok => return Ok(()),
                    Chase::Follow(c) => {
                        chased = Some(*c);
                        continue;
                    }
                    Chase::Err(e) => return Err(e),
                },
                _ => return Err(unexpected_response("AddResponse")),
            }
        }
    }

    pub async fn modify(
        &self,
        dn: impl Into<String>,
        changes: Vec<ldap_client_proto::Modification>,
    ) -> Result<(), Error> {
        let dn = dn.into();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::ModifyRequest(ModifyRequest {
                dn: dn.clone(),
                changes: changes.clone(),
            });
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::ModifyResponse(result) => match try_chase(client, &result).await {
                    Chase::Ok => return Ok(()),
                    Chase::Follow(c) => {
                        chased = Some(*c);
                        continue;
                    }
                    Chase::Err(e) => return Err(e),
                },
                _ => return Err(unexpected_response("ModifyResponse")),
            }
        }
    }

    pub async fn delete(&self, dn: impl Into<String>) -> Result<(), Error> {
        let dn = dn.into();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::DeleteRequest(dn.clone());
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::DeleteResponse(result) => match try_chase(client, &result).await {
                    Chase::Ok => return Ok(()),
                    Chase::Follow(c) => {
                        chased = Some(*c);
                        continue;
                    }
                    Chase::Err(e) => return Err(e),
                },
                _ => return Err(unexpected_response("DeleteResponse")),
            }
        }
    }

    pub async fn compare(
        &self,
        dn: impl Into<String>,
        attr: impl Into<String>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let dn = dn.into();
        let attr = attr.into();
        let value = value.as_ref().to_vec();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::CompareRequest(CompareRequest {
                dn: dn.clone(),
                attr: attr.clone(),
                value: value.clone(),
            });
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::CompareResponse(result) => {
                    use ldap_client_proto::ResultCode;
                    match result.code {
                        ResultCode::CompareTrue => return Ok(true),
                        ResultCode::CompareFalse => return Ok(false),
                        _ => match try_chase(client, &result).await {
                            Chase::Ok => return Err(Error::ldap(&result)),
                            Chase::Follow(c) => {
                                chased = Some(*c);
                                continue;
                            }
                            Chase::Err(e) => return Err(e),
                        },
                    }
                }
                _ => return Err(unexpected_response("CompareResponse")),
            }
        }
    }

    pub async fn modify_dn(
        &self,
        dn: impl Into<String>,
        new_rdn: impl Into<String>,
        delete_old_rdn: bool,
        new_superior: Option<String>,
    ) -> Result<(), Error> {
        let dn = dn.into();
        let new_rdn = new_rdn.into();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::ModifyDnRequest(ModifyDnRequest {
                dn: dn.clone(),
                new_rdn: new_rdn.clone(),
                delete_old_rdn,
                new_superior: new_superior.clone(),
            });
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::ModifyDnResponse(result) => match try_chase(client, &result).await {
                    Chase::Ok => return Ok(()),
                    Chase::Follow(c) => {
                        chased = Some(*c);
                        continue;
                    }
                    Chase::Err(e) => return Err(e),
                },
                _ => return Err(unexpected_response("ModifyDnResponse")),
            }
        }
    }

    pub async fn extended(
        &self,
        oid: impl Into<String>,
        value: Option<Vec<u8>>,
    ) -> Result<ldap_client_proto::ExtendedResponse, Error> {
        let oid = oid.into();
        let mut chased: Option<Client> = None;
        loop {
            let client = chased.as_ref().unwrap_or(self);
            let op = LdapOperation::ExtendedRequest(ExtendedRequest {
                oid: oid.clone(),
                value: value.clone(),
            });
            let response = client.request(op).await?;
            match response.operation {
                LdapOperation::ExtendedResponse(resp) => {
                    match try_chase(client, &resp.result).await {
                        Chase::Ok => return Ok(resp),
                        Chase::Follow(c) => {
                            chased = Some(*c);
                            continue;
                        }
                        Chase::Err(e) => return Err(e),
                    }
                }
                _ => return Err(unexpected_response("ExtendedResponse")),
            }
        }
    }

    pub async fn who_am_i(&self) -> Result<Option<String>, Error> {
        let resp = self.extended("1.3.6.1.4.1.4203.1.11.3", None).await?;
        Ok(resp.value.map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    pub async fn search_one(
        &self,
        base_dn: impl Into<String>,
        scope: SearchScope,
        filter: Filter,
        attrs: Vec<String>,
    ) -> Result<Option<SearchResultEntry>, Error> {
        let message_id = self.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::SearchRequest(SearchRequest {
                base_dn: self.resolve_base_dn(base_dn.into()),
                scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 2,
                time_limit: 0,
                types_only: false,
                filter,
                attributes: attrs,
            }),
            controls: vec![],
        };
        let data = msg.encode();

        let mut framed = self.framed.lock().await;
        send_msg(&mut framed, data, &self.connected).await?;

        let mut entries = Vec::new();
        let result = collect_search_results(
            &mut framed,
            self.request_timeout,
            &self.connected,
            &mut entries,
            self.referral_policy,
        )
        .await;

        // SizeLimitExceeded means the server stopped because of our size_limit=2,
        // which indicates multiple results exist.
        if let Err(Error::Ldap { code, .. }) = &result
            && *code == ResultCode::SizeLimitExceeded
        {
            return Err(Error::MultipleResults);
        }
        result?;

        match entries.len() {
            0 => Ok(None),
            1 => Ok(Some(entries.into_iter().next().unwrap())),
            _ => Err(Error::MultipleResults),
        }
    }

    pub async fn root_dse(&self) -> Result<SearchResultEntry, Error> {
        let entries = self
            .search(
                "",
                SearchScope::BaseObject,
                Filter::present("objectClass"),
                vec!["*".into(), "+".into()],
            )
            .await?;
        entries.into_iter().next().ok_or_else(|| {
            Error::Proto(ldap_client_proto::ProtoError::Protocol(
                "root DSE not found".into(),
            ))
        })
    }

    pub async fn sasl_external_bind(&self) -> Result<(), Error> {
        let op = LdapOperation::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: BindAuthentication::Sasl {
                mechanism: "EXTERNAL".into(),
                credentials: None,
            },
        });
        let response = self.request(op).await?;
        match response.operation {
            LdapOperation::BindResponse(resp) => check_result(&resp.result, self.referral_policy),
            _ => Err(unexpected_response("BindResponse")),
        }
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
        let resolved_base = self.resolve_base_dn(base_dn.to_string());
        let mut all_values: Vec<Vec<u8>> = Vec::new();
        let mut range_start: u32 = 0;

        loop {
            let range_attr = format!("{attr};range={range_start}-*");
            let entries = self
                .search(
                    resolved_base.clone(),
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

    /// Connect to a referral server, optionally binding with the service account.
    ///
    /// Tries each URL in order, returning the first successful connection.
    /// The returned client has its hop limit decremented by one.
    async fn connect_referral(&self, urls: &[String], hop_limit: u8) -> Result<Client, Error> {
        if hop_limit == 0 {
            return Err(Error::ReferralHopLimitExceeded);
        }

        let mut last_err = None;
        for raw_url in urls {
            let referral_url = match LdapUrl::parse(raw_url) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let transport = match referral_url.scheme {
                LdapScheme::Ldap => Transport::Plain,
                LdapScheme::Ldaps => Transport::Tls,
            };
            let mut builder =
                ClientBuilder::new(referral_url.host.clone(), referral_url.effective_port())
                    .transport(transport)
                    .tls_config(self.tls_config.clone())
                    .connect_timeout(self.connect_timeout)
                    .request_timeout(self.request_timeout)
                    .referral_policy(ReferralPolicy::Follow {
                        hop_limit: hop_limit - 1,
                    });
            if let Some(dn) = &self.service_account_dn
                && let Some(pw) = &self.service_account_password
            {
                builder = builder.service_account(dn.clone(), pw.clone());
            }
            match builder.connect().await {
                Ok(client) => {
                    // Bind with service account if configured.
                    if client.service_account_dn.is_some()
                        && let Err(e) = client.rebind_service_account().await
                    {
                        last_err = Some(e);
                        continue;
                    }
                    return Ok(client);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(Error::InvalidUrl("no valid referral URLs".into())))
    }

    /// Bind using one of the supported credential types.
    pub async fn bind(&self, credentials: BindCredentials<'_>) -> Result<(), Error> {
        match credentials {
            BindCredentials::Simple { dn, password } => self.simple_bind(dn, password).await,
            BindCredentials::ServiceAccount => self.rebind_service_account().await,
            BindCredentials::SaslExternal => self.sasl_external_bind().await,
        }
    }

    pub async fn unbind(&self) -> Result<(), Error> {
        let message_id = self.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::UnbindRequest,
            controls: vec![],
        };
        let data = msg.encode();
        let mut framed = self.framed.lock().await;
        send_msg(&mut framed, data, &self.connected).await
    }
}

/// Incremental paged search that yields one page of results at a time.
///
/// Created via [`Client::search_paged_stream`]. Call [`next_page`](PagedSearch::next_page)
/// repeatedly to fetch pages. If you stop before exhausting results, call
/// [`cancel`](PagedSearch::cancel) to release the server-side cookie.
pub struct PagedSearch<'a> {
    client: &'a Client,
    base_dn: String,
    scope: SearchScope,
    filter: Filter,
    attrs: Vec<String>,
    page_size: i32,
    cookie: Vec<u8>,
    done: bool,
}

impl<'a> PagedSearch<'a> {
    /// Fetch the next page of results.
    ///
    /// Returns `Ok(Some(entries))` for each page, `Ok(None)` when all pages
    /// have been consumed.
    pub async fn next_page(&mut self) -> Result<Option<Vec<SearchResultEntry>>, Error> {
        if self.done {
            return Ok(None);
        }

        let paged =
            PagedResultsControl::new(self.page_size).with_cookie(std::mem::take(&mut self.cookie));
        let controls = vec![paged.to_control()];

        let message_id = self.client.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::SearchRequest(SearchRequest {
                base_dn: self.base_dn.clone(),
                scope: self.scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: self.filter.clone(),
                attributes: self.attrs.clone(),
            }),
            controls,
        };
        let data = msg.encode();

        let mut framed = self.client.framed.lock().await;
        send_msg(&mut framed, data, &self.client.connected).await?;

        let mut entries = Vec::new();
        let collected = collect_search_results(
            &mut framed,
            self.client.request_timeout,
            &self.client.connected,
            &mut entries,
            self.client.referral_policy,
        )
        .await?;

        let new_cookie = collected
            .controls
            .iter()
            .find(|c| c.oid == PAGED_RESULTS_OID)
            .and_then(|c| PagedResultsControl::from_control(c).ok())
            .map(|p| p.cookie);

        match new_cookie {
            Some(c) if !c.is_empty() => self.cookie = c,
            _ => self.done = true,
        }

        Ok(Some(entries))
    }

    /// Send an abandon request (page size 0) to release the server cookie.
    ///
    /// Call this if you stop iterating before all pages are consumed. If you
    /// don't, the server cookie will eventually time out on its own (~120 s).
    pub async fn cancel(&mut self) -> Result<(), Error> {
        if self.done {
            return Ok(());
        }
        self.done = true;

        let paged = PagedResultsControl::new(0).with_cookie(std::mem::take(&mut self.cookie));
        let controls = vec![paged.to_control()];

        let message_id = self.client.next_message_id();
        let msg = LdapMessage {
            message_id,
            operation: LdapOperation::SearchRequest(SearchRequest {
                base_dn: self.base_dn.clone(),
                scope: self.scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: self.filter.clone(),
                attributes: self.attrs.clone(),
            }),
            controls,
        };
        let data = msg.encode();

        let mut framed = self.client.framed.lock().await;
        send_msg(&mut framed, data, &self.client.connected).await?;

        let mut entries = Vec::new();
        collect_search_results(
            &mut framed,
            self.client.request_timeout,
            &self.client.connected,
            &mut entries,
            self.client.referral_policy,
        )
        .await?;

        Ok(())
    }

    /// Returns `true` once all pages have been consumed or `cancel` was called.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// Result of collecting search response messages.
struct CollectedSearch {
    controls: Vec<Control>,
    referral_urls: Vec<String>,
}

async fn collect_search_results(
    framed: &mut FramedLdap,
    timeout: Duration,
    connected: &AtomicBool,
    entries: &mut Vec<SearchResultEntry>,
    referral_policy: ReferralPolicy,
) -> Result<CollectedSearch, Error> {
    let mut referral_urls = Vec::new();
    loop {
        let response = recv_msg(framed, timeout, connected).await?;
        match response.operation {
            LdapOperation::SearchResultEntry(entry) => {
                entries.push(entry);
            }
            LdapOperation::SearchResultDone(result) => {
                // Collect referral URLs from the Done result before checking.
                if result.code.is_referral() {
                    referral_urls.extend(result.referral.iter().cloned());
                }
                check_result(&result, referral_policy)?;
                return Ok(CollectedSearch {
                    controls: response.controls,
                    referral_urls,
                });
            }
            LdapOperation::SearchResultReference(urls) => {
                referral_urls.extend(urls);
            }
            _ => return Err(unexpected_response("SearchResult*")),
        }
    }
}

async fn send_msg(
    framed: &mut FramedLdap,
    data: Vec<u8>,
    connected: &AtomicBool,
) -> Result<(), Error> {
    framed.send(data).await.map_err(|e| {
        connected.store(false, Ordering::Relaxed);
        ber_to_io(e)
    })
}

async fn recv_msg(
    framed: &mut FramedLdap,
    timeout: Duration,
    connected: &AtomicBool,
) -> Result<LdapMessage, Error> {
    loop {
        let msg = match tokio::time::timeout(timeout, framed.next()).await {
            Ok(Some(Ok(frame))) => LdapMessage::decode(&frame).map_err(Error::Proto)?,
            Ok(Some(Err(e))) => {
                connected.store(false, Ordering::Relaxed);
                return Err(ber_to_io(e));
            }
            Ok(None) => {
                connected.store(false, Ordering::Relaxed);
                return Err(Error::ConnectionClosed);
            }
            Err(_) => {
                // After a timeout the connection is desynchronized: the server
                // may still send the response later. Force a reconnect.
                connected.store(false, Ordering::Relaxed);
                return Err(Error::Timeout);
            }
        };

        // Skip unsolicited notifications (message_id == 0).
        if msg.message_id == MessageId(0) {
            if let LdapOperation::ExtendedResponse(ref resp) = msg.operation
                && resp.oid.as_deref() == Some(NOTICE_OF_DISCONNECTION_OID)
            {
                connected.store(false, Ordering::Relaxed);
                return Err(Error::ConnectionClosed);
            }
            // Other unsolicited notifications are silently skipped.
            continue;
        }

        return Ok(msg);
    }
}

fn ber_to_io(e: ldap_client_ber::BerError) -> Error {
    match e {
        ldap_client_ber::BerError::Io(io) => Error::Io(io),
        other => Error::Ber(other),
    }
}

fn check_result(result: &ProtoLdapResult, referral_policy: ReferralPolicy) -> Result<(), Error> {
    if result.code.is_success() {
        return Ok(());
    }
    if result.code.is_referral() {
        return match referral_policy {
            ReferralPolicy::Ignore => Ok(()),
            ReferralPolicy::Return | ReferralPolicy::Follow { .. } => Err(Error::Referral {
                urls: result.referral.clone(),
                result: result.clone(),
            }),
        };
    }
    Err(Error::ldap(result))
}

/// Outcome of checking an LDAP result and potentially chasing a referral.
enum Chase {
    Ok,
    Follow(Box<Client>),
    Err(Error),
}

/// Check the LDAP result: if success, return `Chase::Ok`. If a referral
/// and the client's policy is `Follow`, connect to the referral and return
/// `Chase::Follow`. Otherwise return `Chase::Err`.
async fn try_chase(client: &Client, result: &ProtoLdapResult) -> Chase {
    if result.code.is_success() {
        return Chase::Ok;
    }
    if result.code.is_referral() {
        return match client.referral_policy {
            ReferralPolicy::Ignore => Chase::Ok,
            ReferralPolicy::Return => Chase::Err(Error::Referral {
                urls: result.referral.clone(),
                result: result.clone(),
            }),
            ReferralPolicy::Follow { hop_limit } => {
                match client.connect_referral(&result.referral, hop_limit).await {
                    Ok(c) => Chase::Follow(Box::new(c)),
                    Err(e) => Chase::Err(e),
                }
            }
        };
    }
    Chase::Err(Error::ldap(result))
}

fn unexpected_response(expected: &str) -> Error {
    Error::Proto(ldap_client_proto::ProtoError::Protocol(format!(
        "unexpected response, expected {expected}"
    )))
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

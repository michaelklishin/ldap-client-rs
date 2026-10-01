// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(dead_code)]

//! A scripted LDAP server for client tests. It reads each request with
//! `LdapMessage::decode`, records it, and answers with the next step of the
//! script, written with `LdapMessage::encode`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use ldap_client_ber::LdapCodec;
use ldap_client_proto::{
    BindResponse, Control, ExtendedResponse, LdapMessage, LdapOperation, LdapResult, MessageId,
    ResultCode, SearchResultEntry,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Clone, Copy)]
pub enum Id {
    SameAsRequest,
    Fixed(i32),
}

pub enum Reply {
    Message {
        id: Id,
        operation: LdapOperation,
        controls: Vec<Control>,
    },
    Raw(Vec<u8>),
}

#[derive(Default)]
pub struct Step {
    pub replies: Vec<Reply>,
    pub delay: Duration,
    /// Run a TLS handshake as the server once the replies are written.
    pub then_tls: Option<Arc<ServerConfig>>,
}

impl Step {
    pub fn respond(operation: LdapOperation) -> Self {
        Self::default().and(operation)
    }

    pub fn silent() -> Self {
        Self::default()
    }

    pub fn raw(bytes: Vec<u8>) -> Self {
        Self {
            replies: vec![Reply::Raw(bytes)],
            ..Self::default()
        }
    }

    pub fn and(mut self, operation: LdapOperation) -> Self {
        self.replies.push(Reply::Message {
            id: Id::SameAsRequest,
            operation,
            controls: Vec::new(),
        });
        self
    }

    pub fn and_with_controls(mut self, operation: LdapOperation, controls: Vec<Control>) -> Self {
        self.replies.push(Reply::Message {
            id: Id::SameAsRequest,
            operation,
            controls,
        });
        self
    }

    pub fn with_id(mut self, id: i32) -> Self {
        for reply in &mut self.replies {
            if let Reply::Message { id: reply_id, .. } = reply {
                *reply_id = Id::Fixed(id);
            }
        }
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn then_tls(mut self, config: Arc<ServerConfig>) -> Self {
        self.then_tls = Some(config);
        self
    }
}

pub fn result(code: ResultCode) -> LdapResult {
    LdapResult {
        code,
        matched_dn: String::new(),
        diagnostic_message: String::new(),
        referral: Vec::new(),
    }
}

pub fn referral(urls: &[&str]) -> LdapResult {
    LdapResult {
        referral: urls.iter().map(|u| u.to_string()).collect(),
        ..result(ResultCode::Referral)
    }
}

pub fn bind_response(code: ResultCode) -> LdapOperation {
    LdapOperation::BindResponse(BindResponse {
        result: result(code),
        server_sasl_creds: None,
    })
}

pub fn extended_response(code: ResultCode, oid: Option<&str>) -> LdapOperation {
    LdapOperation::ExtendedResponse(ExtendedResponse {
        result: result(code),
        oid: oid.map(str::to_owned),
        value: None,
    })
}

pub fn extended_response_with(result: LdapResult) -> LdapOperation {
    LdapOperation::ExtendedResponse(ExtendedResponse {
        result,
        oid: None,
        value: None,
    })
}

pub fn search_reference(urls: &[&str]) -> LdapOperation {
    LdapOperation::SearchResultReference(urls.iter().map(|u| u.to_string()).collect())
}

pub fn search_done(code: ResultCode) -> LdapOperation {
    LdapOperation::SearchResultDone(result(code))
}

pub fn entry(dn: &str) -> LdapOperation {
    LdapOperation::SearchResultEntry(SearchResultEntry {
        dn: dn.to_owned(),
        attributes: Vec::new(),
    })
}

pub struct MockServer {
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<LdapMessage>>>,
    task: JoinHandle<()>,
}

impl MockServer {
    pub async fn start(script: Vec<Step>) -> Self {
        Self::start_connections(vec![script], None).await
    }

    /// Serves one script per accepted connection, in order. Connections are
    /// served concurrently.
    pub async fn start_connections(
        scripts: Vec<Vec<Step>>,
        tls: Option<Arc<ServerConfig>>,
    ) -> Self {
        Self::start_with(|_| scripts, tls).await
    }

    /// Like `start_connections`, with the scripts built from the address the
    /// server listens on, for a script that refers to its own server.
    pub async fn start_with(
        scripts: impl FnOnce(SocketAddr) -> Vec<Vec<Step>>,
        tls: Option<Arc<ServerConfig>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let scripts = scripts(addr);
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = received.clone();
        let task = tokio::spawn(async move {
            for script in scripts {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let tls = tls.clone();
                let log = log.clone();
                tokio::spawn(async move {
                    let stream: Box<dyn Stream> = match tls {
                        Some(config) => match TlsAcceptor::from(config).accept(tcp).await {
                            Ok(stream) => Box::new(stream),
                            Err(_) => return,
                        },
                        None => Box::new(tcp),
                    };
                    serve(stream, script, log).await;
                });
            }
        });
        Self {
            addr,
            received,
            task,
        }
    }

    pub fn host(&self) -> String {
        self.addr.ip().to_string()
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The requests read so far. Waits briefly first, so that a request the
    /// client sent just before is recorded.
    pub async fn received(&self) -> Vec<LdapMessage> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.received.lock().unwrap().clone()
    }

    pub async fn received_operations(&self) -> Vec<LdapOperation> {
        self.received()
            .await
            .into_iter()
            .map(|m| m.operation)
            .collect()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(stream: Box<dyn Stream>, script: Vec<Step>, log: Arc<Mutex<Vec<LdapMessage>>>) {
    let mut framed = Framed::new(stream, LdapCodec::new());
    let mut script = script.into_iter();
    while let Some(Ok(frame)) = framed.next().await {
        let request = LdapMessage::decode(&frame).expect("the client sent an undecodable request");
        log.lock().unwrap().push(request.clone());
        let Some(step) = script.next() else {
            continue;
        };

        tokio::time::sleep(step.delay).await;
        let mut bytes = Vec::new();
        for reply in step.replies {
            match reply {
                Reply::Message {
                    id,
                    operation,
                    controls,
                } => {
                    let message_id = match id {
                        Id::SameAsRequest => request.message_id,
                        Id::Fixed(n) => MessageId(n),
                    };
                    bytes.extend(
                        LdapMessage {
                            message_id,
                            operation,
                            controls,
                        }
                        .encode(),
                    );
                }
                Reply::Raw(raw) => bytes.extend(raw),
            }
        }
        if framed.get_mut().write_all(&bytes).await.is_err() {
            return;
        }

        if let Some(config) = step.then_tls {
            let parts = framed.into_parts();
            let Ok(tls) = TlsAcceptor::from(config).accept(parts.io).await else {
                return;
            };
            framed = Framed::new(Box::new(tls) as Box<dyn Stream>, LdapCodec::new());
        }
    }
}

pub struct TestCertificate {
    pub der: CertificateDer<'static>,
    key: Vec<u8>,
}

impl TestCertificate {
    pub fn new() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        Self {
            der: certified.cert.der().clone(),
            key: certified.signing_key.serialize_der(),
        }
    }

    pub fn server_config(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()));
        Arc::new(
            ServerConfig::builder_with_protocol_versions(versions)
                .with_no_client_auth()
                .with_single_cert(vec![self.der.clone()], key)
                .unwrap(),
        )
    }
}

pub fn bind_referral(urls: &[&str]) -> LdapOperation {
    LdapOperation::BindResponse(BindResponse {
        result: referral(urls),
        server_sasl_creds: None,
    })
}

pub fn url_of(server: &MockServer) -> String {
    format!("ldap://{}:{}/", server.host(), server.port())
}

pub async fn connect_plain(server: &MockServer) -> ldap_client::Client {
    ldap_client::ClientBuilder::new(server.host(), server.port())
        .connect()
        .await
        .unwrap()
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::debug;

use ldap_client_ber::{BerError, LdapCodec};
use ldap_client_proto::{
    Control, ExtendedRequest, LdapMessage, LdapOperation, MessageId, NOTICE_OF_DISCONNECTION_OID,
    ProtoError, ResultCode, STARTTLS_OID,
};

use super::{Transport, UnsolicitedHandler};
use crate::Error;
use crate::conn::{self, LdapStream};

/// What a session method fails with. An LDAP result code is not one: the
/// caller reads that from the message after the session is back in place.
pub(super) struct TransportError(Error);

impl TransportError {
    pub(super) fn timeout() -> Self {
        Self(Error::Timeout)
    }

    pub(super) fn closed() -> Self {
        Self(Error::ConnectionClosed)
    }

    pub(super) fn entry_limit(limit: usize) -> Self {
        Self(Error::SearchEntryLimitExceeded(limit))
    }
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self(Error::Io(e))
    }
}

impl From<BerError> for TransportError {
    fn from(e: BerError) -> Self {
        match e {
            BerError::Io(io) => Self(Error::Io(io)),
            other => Self(Error::Ber(other)),
        }
    }
}

impl From<ProtoError> for TransportError {
    fn from(e: ProtoError) -> Self {
        Self(Error::Proto(e))
    }
}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        e.0
    }
}

#[derive(Clone)]
pub(super) enum Security {
    Plain,
    Tls(ServerName<'static>),
    StartTls(ServerName<'static>),
}

impl Security {
    pub(super) fn new(transport: Transport, host: &str) -> Result<Self, Error> {
        let server_name = || {
            ServerName::try_from(host.to_owned())
                .map_err(|e| Error::InvalidUrl(format!("invalid server name: {e}")))
        };
        match transport {
            Transport::Plain => Ok(Self::Plain),
            Transport::Tls => Ok(Self::Tls(server_name()?)),
            Transport::StartTls => Ok(Self::StartTls(server_name()?)),
        }
    }

    pub(super) fn transport(&self) -> Transport {
        match self {
            Self::Plain => Transport::Plain,
            Self::Tls(_) => Transport::Tls,
            Self::StartTls(_) => Transport::StartTls,
        }
    }
}

/// The TLS configuration is not part of `Security`: a plain client that
/// follows a referral to an `ldaps://` URL uses it.
#[derive(Clone)]
pub(super) struct ConnectParams {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) security: Security,
    pub(super) tls_config: Arc<ClientConfig>,
    pub(super) connect_timeout: Duration,
    pub(super) request_timeout: Duration,
    pub(super) max_message_size: u32,
}

impl ConnectParams {
    fn codec(&self) -> LdapCodec {
        LdapCodec::new().with_max_message_size(self.max_message_size)
    }
}

pub(super) struct Session {
    framed: Framed<LdapStream, LdapCodec>,
    next_id: MessageId,
    request_timeout: Duration,
    unsolicited: UnsolicitedHandler,
}

impl Session {
    pub(super) async fn open(
        params: &ConnectParams,
        unsolicited: &UnsolicitedHandler,
    ) -> Result<Session, Error> {
        let addr = format_addr(&params.host, params.port);
        debug!(addr = %addr, transport = ?params.security.transport(), "connecting");

        let tcp =
            match tokio::time::timeout(params.connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_) => return Err(Error::Timeout),
            };
        tcp.set_nodelay(true)?;

        let new_session = |stream| Session {
            framed: Framed::new(stream, params.codec()),
            next_id: MessageId::FIRST,
            request_timeout: params.request_timeout,
            unsolicited: unsolicited.clone(),
        };

        match &params.security {
            Security::Plain => Ok(new_session(LdapStream::Plain(tcp))),
            Security::Tls(server_name) => {
                let stream = conn::upgrade_to_tls(
                    tcp,
                    server_name.clone(),
                    params.tls_config.clone(),
                    params.connect_timeout,
                )
                .await?;
                Ok(new_session(stream))
            }
            Security::StartTls(server_name) => {
                new_session(LdapStream::Plain(tcp))
                    .start_tls(server_name.clone(), params)
                    .await
            }
        }
    }

    pub(super) async fn send(
        &mut self,
        operation: LdapOperation,
        controls: Vec<Control>,
    ) -> Result<MessageId, TransportError> {
        let message_id = self.next_id;
        self.next_id = message_id.next();
        let message = LdapMessage {
            message_id,
            operation,
            controls,
        };
        self.framed.send(message.encode()).await?;
        Ok(message_id)
    }

    /// Reads the answer to the request with this id. A message for any other
    /// id means the stream is out of step with the requests, which ends the
    /// session.
    pub(super) async fn receive(&mut self, id: MessageId) -> Result<LdapMessage, TransportError> {
        loop {
            let frame = match tokio::time::timeout(self.request_timeout, self.framed.next()).await {
                Ok(Some(frame)) => frame?,
                Ok(None) => return Err(TransportError::closed()),
                Err(_) => return Err(TransportError::timeout()),
            };
            let message = LdapMessage::decode(&frame)?;

            if message.message_id == MessageId::UNSOLICITED {
                if let LdapOperation::ExtendedResponse(resp) = &message.operation {
                    if resp.oid.as_deref() == Some(NOTICE_OF_DISCONNECTION_OID) {
                        return Err(TransportError::closed());
                    }
                    (self.unsolicited)(resp);
                }
                continue;
            }

            if message.message_id != id {
                return Err(ProtoError::Protocol(format!(
                    "expected a response to message {}, got one for message {}",
                    id.get(),
                    message.message_id.get()
                ))
                .into());
            }
            return Ok(message);
        }
    }

    async fn start_tls(
        mut self,
        server_name: ServerName<'static>,
        params: &ConnectParams,
    ) -> Result<Session, Error> {
        let request = LdapOperation::ExtendedRequest(ExtendedRequest {
            oid: STARTTLS_OID.to_string(),
            value: None,
        });
        let id = self.send(request, Vec::new()).await?;
        match self.receive(id).await?.operation {
            LdapOperation::ExtendedResponse(resp) if resp.result.code == ResultCode::Success => {}
            LdapOperation::ExtendedResponse(resp) => {
                return Err(Error::StartTls(resp.result.diagnostic_message));
            }
            _ => return Err(Error::StartTls("unexpected response".into())),
        }

        let parts = self.framed.into_parts();
        if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
            return Err(Error::StartTls(
                "unexpected buffered data before TLS handshake".into(),
            ));
        }
        let LdapStream::Plain(tcp) = parts.io else {
            return Err(Error::StartTls("connection is already encrypted".into()));
        };
        let stream = conn::upgrade_to_tls(
            tcp,
            server_name,
            params.tls_config.clone(),
            params.connect_timeout,
        )
        .await?;

        Ok(Session {
            framed: Framed::new(stream, params.codec()),
            next_id: self.next_id,
            request_timeout: self.request_timeout,
            unsolicited: self.unsolicited,
        })
    }
}

fn format_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

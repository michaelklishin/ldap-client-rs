// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use clap::{Parser, Subcommand};
use ldap_client::{Client, ClientBuilder, SecretString, Transport};

use crate::commands;
use crate::error::CliError;

pub enum Credentials {
    Anonymous,
    Simple { dn: String, password: SecretString },
}

impl Credentials {
    fn from_args(dn: Option<String>, password: Option<SecretString>) -> Result<Self, CliError> {
        match (dn, password) {
            (Some(dn), Some(password)) => Ok(Self::Simple { dn, password }),
            (None, None) => Ok(Self::Anonymous),
            (Some(_), None) => Err(CliError::Usage("--bind-dn needs --password")),
            (None, Some(_)) => Err(CliError::Usage("--password needs --bind-dn")),
        }
    }
}

fn parse_secret(value: &str) -> Result<SecretString, std::convert::Infallible> {
    Ok(SecretString::from(value))
}

#[derive(Parser)]
#[command(name = "ldap-client", about = "Command-line LDAP client", version)]
pub struct Cli {
    /// LDAP URL (ldap:// or ldaps://)
    #[arg(long, env = "LDAP_URL", conflicts_with_all = ["tls", "starttls"])]
    url: Option<String>,

    /// LDAP server host
    #[arg(long, env = "LDAP_HOST", default_value = "localhost")]
    host: String,

    /// LDAP server port (636 with --tls, 389 otherwise)
    #[arg(long, env = "LDAP_PORT")]
    port: Option<u16>,

    /// Bind DN
    #[arg(long, env = "LDAP_BIND_DN")]
    bind_dn: Option<String>,

    /// Bind password (prefer LDAP_PASSWORD env var to avoid shell history exposure)
    #[arg(long, env = "LDAP_PASSWORD", hide_env_values = true, value_parser = parse_secret)]
    password: Option<SecretString>,

    /// Use TLS (ldaps)
    #[arg(long, conflicts_with = "starttls")]
    tls: bool,

    /// Use STARTTLS
    #[arg(long, conflicts_with = "tls")]
    starttls: bool,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Default base DN for operations
    #[arg(long, env = "LDAP_BASE_DN")]
    base_dn: Option<String>,

    /// Skip TLS certificate verification (dangerous!)
    #[arg(long)]
    insecure: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Search for entries
    Search(commands::search::SearchArgs),
    /// Test bind credentials
    Bind,
    /// Compare an attribute value
    Compare(commands::compare::CompareArgs),
    /// Run Who Am I extended operation
    Whoami,
    /// Print root DSE attributes
    RootDse,
    /// Add an entry
    Add(commands::add::AddArgs),
    /// Modify an entry
    Modify(commands::modify::ModifyArgs),
    /// Delete an entry
    Delete(commands::delete::DeleteArgs),
    /// Rename / move an entry
    Rename(commands::rename::RenameArgs),
}

impl Cli {
    pub async fn run(self) -> Result<(), CliError> {
        let credentials = Credentials::from_args(self.bind_dn.clone(), self.password.clone())?;
        if matches!(self.command, Command::Bind) && matches!(credentials, Credentials::Anonymous) {
            return Err(CliError::Usage("`bind` needs --bind-dn"));
        }

        let client = self.connect(credentials).await?;

        match self.command {
            Command::Search(args) => commands::search::run(&client, args).await,
            Command::Bind => commands::bind::run(&client).await,
            Command::Compare(args) => commands::compare::run(&client, args).await,
            Command::Whoami => commands::whoami::run(&client).await,
            Command::RootDse => commands::root_dse::run(&client).await,
            Command::Add(args) => commands::add::run(&client, args).await,
            Command::Modify(args) => commands::modify::run(&client, args).await,
            Command::Delete(args) => commands::delete::run(&client, args).await,
            Command::Rename(args) => commands::rename::run(&client, args).await,
        }
    }

    fn transport(&self) -> Transport {
        if self.tls {
            Transport::Tls
        } else if self.starttls {
            Transport::StartTls
        } else {
            Transport::Plain
        }
    }

    async fn connect(&self, credentials: Credentials) -> Result<Client, ldap_client::Error> {
        let mut builder = match &self.url {
            Some(url) => ClientBuilder::from_url(url)?,
            None => {
                let transport = self.transport();
                let port = self.port.unwrap_or_else(|| transport.default_port());
                ClientBuilder::new(&self.host, port).transport(transport)
            }
        };

        builder = builder.timeout(Duration::from_secs(self.timeout));

        if let Some(base) = &self.base_dn {
            builder = builder.base_dn(base);
        }

        if self.insecure {
            if !self.tls
                && !self.starttls
                && self
                    .url
                    .as_deref()
                    .is_none_or(|u| !u.starts_with("ldaps://"))
            {
                tracing::warn!("--insecure has no effect on plain (non-TLS) connections");
            }
            let config = std::sync::Arc::new(ldap_client::danger_no_verify_tls_config());
            builder = builder.tls_config(config);
        }

        let client = builder.connect().await?;

        if let Credentials::Simple { dn, password } = credentials {
            client.simple_bind(&dn, &password).await?;
            tracing::debug!(bind_dn = %dn, "bound successfully");
        }

        Ok(client)
    }
}

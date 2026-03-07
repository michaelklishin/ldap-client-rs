// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use clap::{Parser, Subcommand};
use ldap_client::{Client, ClientBuilder, SecretString, Transport};
use zeroize::Zeroize;

use crate::commands;

#[derive(Parser)]
#[command(name = "ldap-client", about = "Command-line LDAP client", version)]
pub struct Cli {
    /// LDAP URL (ldap:// or ldaps://)
    #[arg(long, env = "LDAP_URL")]
    url: Option<String>,

    /// LDAP server host
    #[arg(long, env = "LDAP_HOST", default_value = "localhost")]
    host: String,

    /// LDAP server port
    #[arg(long, env = "LDAP_PORT", default_value_t = 389)]
    port: u16,

    /// Bind DN
    #[arg(long, env = "LDAP_BIND_DN")]
    bind_dn: Option<String>,

    /// Bind password (prefer LDAP_PASSWORD env var to avoid shell history exposure)
    #[arg(long, env = "LDAP_PASSWORD", hide_env_values = true)]
    password: Option<String>,

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
    pub async fn run(mut self) -> Result<(), ldap_client::Error> {
        let client = self.connect().await?;

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

    async fn connect(&mut self) -> Result<Client, ldap_client::Error> {
        let mut builder = if let Some(url) = &self.url {
            if self.tls || self.starttls {
                return Err(ldap_client::Error::InvalidUrl(
                    "--tls / --starttls cannot be combined with --url".into(),
                ));
            }
            ClientBuilder::from_url(url)?
        } else {
            let mut b = ClientBuilder::new(&self.host, self.port);
            if self.tls {
                b = b.transport(Transport::Tls);
            } else if self.starttls {
                b = b.transport(Transport::StartTls);
            }
            b
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

        if let Some(dn) = &self.bind_dn {
            if self.password.is_none() {
                tracing::warn!("--bind-dn set without --password; binding with empty password");
            }
            let mut raw = self.password.take().unwrap_or_default();
            let secret = SecretString::from(raw.clone());
            raw.zeroize();
            client.simple_bind(dn, &secret).await?;
            tracing::debug!(bind_dn = %dn, "bound successfully");
        }

        Ok(client)
    }
}

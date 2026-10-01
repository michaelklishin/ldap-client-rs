// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Dn};

use crate::error::CliError;

#[derive(Args)]
pub struct RenameArgs {
    /// DN of the entry to rename
    #[arg(long)]
    dn: String,

    /// New RDN (e.g. "cn=NewName")
    #[arg(long)]
    new_rdn: String,

    /// Keep the old RDN value as an attribute
    #[arg(long)]
    keep_old_rdn: bool,

    /// New superior DN (to move the entry)
    #[arg(long)]
    new_superior: Option<String>,
}

pub async fn run(client: &Client, args: RenameArgs) -> Result<(), CliError> {
    let parent = match &args.new_superior {
        Some(sup) => Some(sup.clone()),
        None => Dn::parse(&args.dn)
            .ok()
            .and_then(|dn| dn.parent())
            .map(|dn| dn.to_string()),
    };
    client
        .modify_dn(
            &args.dn,
            &args.new_rdn,
            !args.keep_old_rdn,
            args.new_superior,
        )
        .await?;
    let new_dn = match parent {
        Some(parent) => format!("{},{}", args.new_rdn, parent),
        None => args.new_rdn,
    };
    println!("entry renamed: {} -> {new_dn}", args.dn);
    Ok(())
}

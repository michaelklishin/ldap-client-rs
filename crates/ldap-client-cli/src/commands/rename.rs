// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Dn};

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

pub async fn run(client: &Client, args: RenameArgs) -> Result<(), ldap_client::Error> {
    let parent = match &args.new_superior {
        Some(sup) => sup.clone(),
        None => {
            // Parse the DN properly to handle escaped commas.
            let parsed = Dn::parse(&args.dn).unwrap_or_else(|_| Dn { rdns: Vec::new() });
            if parsed.rdns.len() > 1 {
                let parent_dn = Dn {
                    rdns: parsed.rdns[1..].to_vec(),
                };
                parent_dn.to_string()
            } else {
                String::new()
            }
        }
    };
    client
        .modify_dn(
            &args.dn,
            &args.new_rdn,
            !args.keep_old_rdn,
            args.new_superior,
        )
        .await?;
    let new_dn = if parent.is_empty() {
        args.new_rdn
    } else {
        format!("{},{}", args.new_rdn, parent)
    };
    println!("entry renamed: {} -> {new_dn}", args.dn);
    Ok(())
}

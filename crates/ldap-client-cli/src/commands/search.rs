// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Filter, SearchScope};

use super::output::print_entry;
use crate::error::CliError;

#[derive(Args)]
pub struct SearchArgs {
    /// Search base DN (overrides --base-dn)
    #[arg(short, long)]
    base: Option<String>,

    /// Search scope: base, one, sub
    #[arg(short, long, default_value = "sub", value_parser = str::parse::<SearchScope>)]
    scope: SearchScope,

    /// LDAP filter (RFC 4515)
    #[arg(short, long, default_value = "(objectClass=*)", value_parser = str::parse::<Filter>)]
    filter: Filter,

    /// Attributes to return
    #[arg(trailing_var_arg = true)]
    attrs: Vec<String>,
}

pub async fn run(client: &Client, args: SearchArgs) -> Result<(), CliError> {
    let base = args.base.unwrap_or_default();
    let entries = client
        .search(base, args.scope, args.filter, args.attrs)
        .await?;

    for entry in &entries {
        print_entry(entry);
        println!();
    }

    println!("# {} entries returned", entries.len());
    Ok(())
}

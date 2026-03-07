// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Filter, SearchScope};

#[derive(Args)]
pub struct SearchArgs {
    /// Search base DN (overrides --base-dn)
    #[arg(short, long)]
    base: Option<String>,

    /// Search scope: base, one, sub
    #[arg(short, long, default_value = "sub")]
    scope: String,

    /// LDAP filter (RFC 4515)
    #[arg(short, long, default_value = "(objectClass=*)")]
    filter: String,

    /// Attributes to return
    #[arg(trailing_var_arg = true)]
    attrs: Vec<String>,
}

pub async fn run(client: &Client, args: SearchArgs) -> Result<(), ldap_client::Error> {
    let scope = match args.scope.as_str() {
        "base" => SearchScope::BaseObject,
        "one" => SearchScope::SingleLevel,
        "sub" => SearchScope::WholeSubtree,
        other => {
            return Err(ldap_client::Error::InvalidUrl(format!(
                "unknown scope: {other}"
            )));
        }
    };

    let filter = Filter::parse(&args.filter)
        .map_err(|e| ldap_client::Error::InvalidUrl(format!("bad filter: {e}")))?;

    let base = args.base.unwrap_or_default();
    let entries = client.search(base, scope, filter, args.attrs).await?;

    for entry in &entries {
        println!("dn: {}", entry.dn);
        for attr in &entry.attributes {
            for val in &attr.values {
                match std::str::from_utf8(val) {
                    Ok(s) => println!("{}: {s}", attr.name),
                    Err(_) => println!("{}: <binary {} bytes>", attr.name, val.len()),
                }
            }
        }
        println!();
    }

    println!("# {} entries returned", entries.len());
    Ok(())
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::Client;

#[derive(Args)]
pub struct CompareArgs {
    /// DN of the entry
    #[arg(long)]
    dn: String,

    /// Attribute name
    #[arg(long)]
    attr: String,

    /// Value to compare
    #[arg(long)]
    value: String,
}

pub async fn run(client: &Client, args: CompareArgs) -> Result<(), ldap_client::Error> {
    let result = client
        .compare(&args.dn, &args.attr, args.value.as_bytes())
        .await?;
    if result {
        println!("TRUE");
    } else {
        println!("FALSE");
    }
    Ok(())
}

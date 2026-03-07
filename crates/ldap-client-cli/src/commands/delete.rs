// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::Client;

#[derive(Args)]
pub struct DeleteArgs {
    /// DN of the entry to delete
    #[arg(long)]
    dn: String,
}

pub async fn run(client: &Client, args: DeleteArgs) -> Result<(), ldap_client::Error> {
    client.delete(&args.dn).await?;
    println!("entry deleted: {}", args.dn);
    Ok(())
}

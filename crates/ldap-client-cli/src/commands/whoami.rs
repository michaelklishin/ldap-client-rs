// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::Client;

use crate::error::CliError;

pub async fn run(client: &Client) -> Result<(), CliError> {
    match client.who_am_i().await? {
        Some(id) => println!("{id}"),
        None => println!("(anonymous)"),
    }
    Ok(())
}

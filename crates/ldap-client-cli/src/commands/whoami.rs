// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::Client;

pub async fn run(client: &Client) -> Result<(), ldap_client::Error> {
    match client.who_am_i().await? {
        Some(id) => println!("{id}"),
        None => println!("(anonymous)"),
    }
    Ok(())
}

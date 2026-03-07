// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::Client;

pub async fn run(client: &Client) -> Result<(), ldap_client::Error> {
    // If we got here, the bind in connect() already succeeded.
    match client.who_am_i().await {
        Ok(Some(id)) => println!("bind successful: {id}"),
        Ok(None) => println!("bind successful"),
        Err(ldap_client::Error::Ldap { .. }) => {
            println!("bind successful (Who Am I not supported)");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

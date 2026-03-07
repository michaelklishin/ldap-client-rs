// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::Client;

pub async fn run(client: &Client) -> Result<(), ldap_client::Error> {
    let entry = client.root_dse().await?;

    println!("dn: {}", entry.dn);
    for attr in &entry.attributes {
        for val in &attr.values {
            match std::str::from_utf8(val) {
                Ok(s) => println!("{}: {s}", attr.name),
                Err(_) => println!("{}: <binary {} bytes>", attr.name, val.len()),
            }
        }
    }

    Ok(())
}

// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, PartialAttribute};

#[derive(Args)]
pub struct AddArgs {
    /// DN of the new entry
    #[arg(long)]
    dn: String,

    /// Attributes in NAME=VALUE format (repeatable)
    #[arg(long = "attr", value_name = "NAME=VALUE")]
    attrs: Vec<String>,
}

pub async fn run(client: &Client, args: AddArgs) -> Result<(), ldap_client::Error> {
    let mut attr_map: Vec<(&str, Vec<Vec<u8>>)> = Vec::new();

    for kv in &args.attrs {
        let (name, value) = kv.split_once('=').ok_or_else(|| {
            ldap_client::Error::InvalidUrl(format!("invalid attribute format: {kv}"))
        })?;
        if let Some(existing) = attr_map.iter_mut().find(|(n, _)| *n == name) {
            existing.1.push(value.as_bytes().to_vec());
        } else {
            attr_map.push((name, vec![value.as_bytes().to_vec()]));
        }
    }

    let partial_attrs: Vec<PartialAttribute> = attr_map
        .into_iter()
        .map(|(name, values)| PartialAttribute {
            name: name.to_string(),
            values,
        })
        .collect();

    client.add(&args.dn, partial_attrs).await?;
    println!("entry added: {}", args.dn);
    Ok(())
}

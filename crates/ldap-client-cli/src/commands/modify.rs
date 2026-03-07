// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Modification, ModifyOperation, PartialAttribute};

#[derive(Args)]
pub struct ModifyArgs {
    /// DN of the entry to modify
    #[arg(long)]
    dn: String,

    /// Add attribute values (NAME=VALUE, repeatable)
    #[arg(long = "add", value_name = "NAME=VALUE")]
    adds: Vec<String>,

    /// Replace attribute values (NAME=VALUE, repeatable)
    #[arg(long = "replace", value_name = "NAME=VALUE")]
    replaces: Vec<String>,

    /// Delete attribute values (NAME or NAME=VALUE, repeatable)
    #[arg(long = "delete", value_name = "NAME[=VALUE]")]
    deletes: Vec<String>,
}

pub async fn run(client: &Client, args: ModifyArgs) -> Result<(), ldap_client::Error> {
    let mut changes = Vec::new();

    for kv in &args.adds {
        let (name, value) = parse_kv(kv)?;
        changes.push(Modification {
            operation: ModifyOperation::Add,
            attribute: PartialAttribute {
                name: name.to_string(),
                values: vec![value.as_bytes().to_vec()],
            },
        });
    }

    for kv in &args.replaces {
        let (name, value) = parse_kv(kv)?;
        changes.push(Modification {
            operation: ModifyOperation::Replace,
            attribute: PartialAttribute {
                name: name.to_string(),
                values: vec![value.as_bytes().to_vec()],
            },
        });
    }

    for kv in &args.deletes {
        if let Some((name, value)) = kv.split_once('=') {
            changes.push(Modification {
                operation: ModifyOperation::Delete,
                attribute: PartialAttribute {
                    name: name.to_string(),
                    values: vec![value.as_bytes().to_vec()],
                },
            });
        } else {
            changes.push(Modification {
                operation: ModifyOperation::Delete,
                attribute: PartialAttribute {
                    name: kv.to_string(),
                    values: vec![],
                },
            });
        }
    }

    client.modify(&args.dn, changes).await?;
    println!("entry modified: {}", args.dn);
    Ok(())
}

fn parse_kv(kv: &str) -> Result<(&str, &str), ldap_client::Error> {
    kv.split_once('=')
        .ok_or_else(|| ldap_client::Error::InvalidUrl(format!("expected NAME=VALUE, got: {kv}")))
}

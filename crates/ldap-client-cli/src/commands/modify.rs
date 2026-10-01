// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, Modification, ModifyOperation, PartialAttribute};

use super::assignment::{Assignment, Removal};
use crate::error::CliError;

#[derive(Args)]
pub struct ModifyArgs {
    /// DN of the entry to modify
    #[arg(long)]
    dn: String,

    /// Add attribute values (NAME=VALUE, repeatable)
    #[arg(long = "add", value_name = "NAME=VALUE")]
    adds: Vec<Assignment>,

    /// Replace attribute values (NAME=VALUE, repeatable)
    #[arg(long = "replace", value_name = "NAME=VALUE")]
    replaces: Vec<Assignment>,

    /// Delete attribute values (NAME or NAME=VALUE, repeatable)
    #[arg(long = "delete", value_name = "NAME[=VALUE]")]
    deletes: Vec<Removal>,
}

fn modification(operation: ModifyOperation, name: String, value: Option<Vec<u8>>) -> Modification {
    Modification {
        operation,
        attribute: PartialAttribute {
            name,
            values: value.into_iter().collect(),
        },
    }
}

pub async fn run(client: &Client, args: ModifyArgs) -> Result<(), CliError> {
    let adds = args
        .adds
        .into_iter()
        .map(|a| modification(ModifyOperation::Add, a.name, Some(a.value)));
    let replaces = args
        .replaces
        .into_iter()
        .map(|a| modification(ModifyOperation::Replace, a.name, Some(a.value)));
    let deletes = args
        .deletes
        .into_iter()
        .map(|r| modification(ModifyOperation::Delete, r.name, r.value));
    let changes: Vec<Modification> = adds.chain(replaces).chain(deletes).collect();

    client.modify(&args.dn, changes).await?;
    println!("entry modified: {}", args.dn);
    Ok(())
}

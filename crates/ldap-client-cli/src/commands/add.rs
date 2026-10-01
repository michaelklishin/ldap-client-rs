// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Args;
use ldap_client::{Client, PartialAttribute};

use super::assignment::Assignment;
use crate::error::CliError;

#[derive(Args)]
pub struct AddArgs {
    /// DN of the new entry
    #[arg(long)]
    dn: String,

    /// Attributes in NAME=VALUE format (repeatable)
    #[arg(long = "attr", value_name = "NAME=VALUE")]
    attrs: Vec<Assignment>,
}

pub async fn run(client: &Client, args: AddArgs) -> Result<(), CliError> {
    let mut attributes: Vec<PartialAttribute> = Vec::new();

    for Assignment { name, value } in args.attrs {
        match attributes
            .iter_mut()
            .find(|a| a.name.eq_ignore_ascii_case(&name))
        {
            Some(existing) => existing.values.push(value),
            None => attributes.push(PartialAttribute {
                name,
                values: vec![value],
            }),
        }
    }

    client.add(&args.dn, attributes).await?;
    println!("entry added: {}", args.dn);
    Ok(())
}

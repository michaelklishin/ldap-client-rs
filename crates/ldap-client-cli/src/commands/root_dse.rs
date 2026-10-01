// SPDX-License-Identifier: MIT OR Apache-2.0

use ldap_client::Client;

use super::output::print_entry;
use crate::error::CliError;

pub async fn run(client: &Client) -> Result<(), CliError> {
    print_entry(&client.root_dse().await?);
    Ok(())
}

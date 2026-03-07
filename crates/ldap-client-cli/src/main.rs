// SPDX-License-Identifier: MIT OR Apache-2.0

mod cli;
mod commands;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::Cli;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if let Err(e) = cli.run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

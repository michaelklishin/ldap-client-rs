# Contributing

See also [AGENTS.md](./AGENTS.md) for a high-level codebase overview and conventions.

## Prerequisites

 * Rust toolchain >= 1.93 (MSRV) and stable
 * Docker, Podman or Rancher for integration tests
 * Nushell (for running development scripts)

## Running Tests

While tests support the standard `cargo test` option, another option
for running tests is [cargo-nextest](https://nexte.st/).

### Run Unit Tests Only (No Container Needed)

``` bash
cargo nextest run
```

### Run All Tests Including Integration Tests

Start the OpenLDAP test container first:

``` bash
nu bin/containers/start-openldap.nu
```

Then run the full suite:

``` bash
cargo nextest run --all-features
```

Stop the container when done:

``` bash
nu bin/containers/stop-openldap.nu
```

## Running the Fuzzer

``` bash
cargo +nightly fuzz run fuzz_ber_reader
cargo +nightly fuzz run fuzz_filter_parser
cargo +nightly fuzz run fuzz_message_decoder
```

## Adding a New Operation

 * Define the request/response types in `crates/ldap-client-proto/src/{operation}.rs`
 * Add variants to `LdapOperation` in `message.rs`
 * Implement BER encode/decode (use `encode_dn_operation` helper for write ops)
 * Implement `HasLdapResult` for the response type
 * Add proptest roundtrip test for the message type
 * Add a `Client` method in `crates/ldap-client-rs/src/client.rs`
 * Add integration test in `crates/ldap-client-rs/tests/integration/`

## Adding a Dependency

All new direct dependencies must be audited before being accepted:

``` bash
cargo vet inspect <crate>
cargo vet certify <crate> <version> <criteria>
```

Do not suppress advisories. If a dependency has a known advisory, upgrade, patch, or replace it.

## Code Style

 * `cargo clippy` must pass with no warnings (`-D warnings`)
 * `cargo fmt` with default settings
 * No `unsafe` code in the BER codec or the protocol crate

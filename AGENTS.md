# Instructions for AI Agents

## What is This Codebase?

A modern Rust client for LDAPv3 targeting Rust `1.93+`.

## Build System

All the standard Cargo commands apply but with one important detail: make sure to add `--all-features` so that
all feature-gated code (vendor TLV parsing, axum integration) is included.

 * `cargo build --all-features` to build
 * `cargo nextest run --all-features` to run tests
 * `cargo clippy --all-features` to lint
 * `cargo fmt` to reformat
 * `cargo publish` to publish the crate

Always run `cargo check --all-features` before making changes to verify the codebase compiles cleanly.
If compilation fails, investigate and fix compilation errors before proceeding with any modifications.


## Key Files

 * `crates/ldap-client-rs/src/client.rs`: a `Client`, a `ClientBuilder`, implementations of individual LDAP operations
 * `crates/ldap-client-rs/src/conn.rs`: LDAP connection, TLS and STARTTLS-related parts
 * `crates/ldap-client-rs/src/error.rs`: error types
 * `crates/ldap-client-proto/src/message.rs`: LDAPv3 PDU types
 * `crates/ldap-client-proto/src/filter.rs`: RFC 4515 filter parser
 * `crates/ldap-client-ber/src/reader.rs`: BER deserializer
 * `crates/ldap-client-ber/src/writer.rs`: BER serializer

## Test Suite Layout

 * `crates/ldap-client-ber/tests/`: property-based tests for BER encoding
 * `crates/ldap-client-proto/tests/`: property-based tests for protocol types
 * `crates/ldap-client-rs/tests/integration_tests.rs`: integration tests with an OpenLDAP container, gated by the `integration-tests` feature

Use `cargo nextest run --profile default --all-features '--' --exact [test module name]` to run
all tests in a specific module.

### Property-based Tests

Property-based tests are written using [proptest](https://docs.rs/proptest/latest/proptest/) and
use a naming convention: they begin with `prop_`.

To run the property-based tests specifically, use `cargo nextest run --all-features 'prop_'`.

## Source of Domain Knowledge

[LDAP-related RFCs](https://ldap.com/ldap-related-rfcs/)

## Comments, Writing Style and Voice

Keep comments short and to the point. Avoid filler words like "This function does X" when the
function name already says it. Don't add doc comments to obvious methods. Match the existing
comment density — the codebase is deliberately light on comments.

### Voice

Write like an engineer who values clarity and simplicity. This applies
to all prose: design docs, analyses, notes, and commit messages.

 * Plain and factual: state the why in one line, never narrate the what
 * Literal mechanism over metaphor: name the actual thing, not an image of it
 * Prefer the plainest word. No coined verbs, no jargon for its own sake
 * No flourish, no editorializing, no imagery. Real domain terms are fine
 * If a sentence needs a second clause to justify itself, it is probably too clever

### Writing and Markdown Style

 * Never add full stops to Markdown list items
 * Use "X and Y" in prose, not "X / Y" slash-shorthand. Exceptions: unit
   fractions (`bytes/sec`), single-concept abbreviations (`I/O`), and paths
   or code (`tests/unit/`, `src/lib.rs`)
 * Wrap code identifiers in backticks in prose: types like `Vec<T>`, traits
   like `Display`, functions like `Iterator::next`, modules, file names, and paths
 * Avoid robotic labels such as `**Thing / other:**`; write a plain sentence or a simple label
 * Match the existing conventions of the file and subdirectory you are
   editing — bullet character, heading depth, ID schemes, and table shape
   vary by project, and the local choice wins

## Change Log

If asked to perform change log updates, consult and modify `CHANGELOG.md` and stick to its
existing writing style.

## Releases

### How to Roll (Produce) a New Release

Suppose the current development version in `Cargo.toml` is `0.N.0` and `CHANGELOG.md` has
a `## v0.N.0 (in development)` section at the top.

To produce a new release:

 1. Update the changelog: replace `(in development)` with today's date, e.g. `(Feb 20, 2026)`. Make sure all notable changes since the previous release are listed
 2. Commit with the message `0.N.0` (just the version number, nothing else)
 3. Tag the commit: `git tag v0.N.0`
 4. Bump the dev version: back on `main`, set `Cargo.toml` workspace version to `0.(N+1).0` and update the version in `[workspace.dependencies]` and `crates/ldap-client-cli/Cargo.toml`
 5. Add a new `## v0.(N+1).0 (in development)` section to `CHANGELOG.md` with `No changes yet.` underneath
 6. Commit with the message `Bump dev version`
 7. Push: `git push && git push --tags`

The tag push triggers `.github/workflows/release.yml`, which publishes the crates to crates.io
via Trusted Publishing (OIDC) and creates a GitHub Release with changelog notes. No manual
`cargo publish` needed.

## Git Commits

 * Do not commit changes automatically without an explicit permission to do so
 * Never add yourself as a git commit coauthor
 * Never mention yourself in commit messages in any way (no "Generated by", no AI tool links, etc)

## Iterative Post-Implementation Review (IPIR)

Review the changes very carefully and holistically for correctness and safety,
opportunities to meaningfully simplify the implementation without losing
fidelity and effectiveness, the use of Rust idioms, the rich type system
patterns, meaningful test coverage, API usability and whether the changes are
worth adopting to begin with.

Look hard for ways to meaningfully improve both the tests and the implementation.

Perform 5 such iterations (holistic analysis runs).

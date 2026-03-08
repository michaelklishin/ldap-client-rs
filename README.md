# An LDAP Client for Rust and Tokio

An async LDAPv3 client built on Tokio and Rustls.

Covers Bind (simple and SASL EXTERNAL), Search (including paged results), Compare, Add, Delete,
Modify, ModifyDN, Extended operations, and Who Am I. Supports LDAPS, StartTLS, reconnection,
referral policies, and server-side controls (paged results, server-side sort, ManageDsaIT, domain scope).

The BER codec and protocol layer are separate crates (`ldap-client-ber`, `ldap-client-proto`)
with no `unsafe` code, property-based testing, and fuzzing targets.


## Project Maturity

This library is young. Before `1.0`, breaking API changes are possible.


## Requirements

 * Rust 1.93+ (edition 2024)
 * Tokio runtime


## Dependency

```toml
ldap-client = "0.5"
```


## Usage

### Connect and Bind

```rust
use ldap_client::{ClientBuilder, SecretString};

let client = ClientBuilder::new("ldap.example.com", 389)
    .connect().await?;

client.simple_bind("cn=admin,dc=example,dc=com", &SecretString::from("password")).await?;
```

### Connect via URL

```rust
use ldap_client::ClientBuilder;

// LDAPS on port 636
let client = ClientBuilder::from_url("ldaps://ldap.example.com")?
    .connect().await?;
```

### Search

```rust
use ldap_client::{Filter, SearchScope};

let entries = client.search(
    "dc=example,dc=com",
    SearchScope::WholeSubtree,
    Filter::eq("uid", "alice"),
    vec!["cn".into(), "mail".into()],
).await?;

for entry in &entries {
    println!("{}", entry.dn);
}
```

### Search One

```rust
use ldap_client::{Filter, SearchScope};

let entry = client.search_one(
    "dc=example,dc=com",
    SearchScope::WholeSubtree,
    Filter::eq("uid", "alice"),
    vec!["cn".into(), "mail".into()],
).await?;

if let Some(entry) = entry {
    println!("{}", entry.dn);
}
```

### Paged Search (Collect All)

```rust
use ldap_client::{Filter, SearchScope};

let all_entries = client.search_paged(
    "dc=example,dc=com",
    SearchScope::WholeSubtree,
    Filter::present("objectClass"),
    vec!["dn".into()],
    100, // page size
).await?;
```

### Paged Search (Stream)

```rust
use ldap_client::{Filter, SearchScope};

let mut stream = client.search_paged_stream(
    "dc=example,dc=com",
    SearchScope::WholeSubtree,
    Filter::present("objectClass"),
    vec!["dn".into()],
    100,
);

while let Some(page) = stream.next_page().await? {
    println!("got {} entries", page.len());
}
```

### Add, Modify, Delete

```rust
use ldap_client::{Modification, ModifyOperation, PartialAttribute};

// Add
client.add("cn=new,dc=example,dc=com", vec![
    PartialAttribute::new("objectClass", vec!["inetOrgPerson"]),
    PartialAttribute::new("cn", vec!["new"]),
    PartialAttribute::new("sn", vec!["User"]),
]).await?;

// Modify
client.modify("cn=new,dc=example,dc=com", vec![
    Modification {
        operation: ModifyOperation::Replace,
        attribute: PartialAttribute::new("sn", vec!["Updated"]),
    },
]).await?;

// Delete
client.delete("cn=new,dc=example,dc=com").await?;
```

### Compare

```rust
let is_member = client.compare(
    "cn=alice,dc=example,dc=com",
    "memberOf",
    b"cn=admins,dc=example,dc=com",
).await?;
```

### Referral Policy

```rust
use ldap_client::{ClientBuilder, ReferralPolicy};

let client = ClientBuilder::new("ldap.example.com", 389)
    .referral_policy(ReferralPolicy::Return)
    .connect().await?;

// Operations that trigger a referral will return Error::Referral
// with the referral URLs instead of Error::Ldap
```

### Reconnect

```rust
if !client.is_connected() {
    client.reconnect().await?;
    client.rebind_service_account().await?;
}
```

### StartTLS

```rust
use ldap_client::{ClientBuilder, Transport};

let client = ClientBuilder::new("ldap.example.com", 389)
    .transport(Transport::StartTls)
    .connect().await?;
```

### Custom TLS Configuration

```rust
use ldap_client::{ClientBuilder, TlsConfig, TlsVersion, Transport};

let client = ClientBuilder::new("ldap.example.com", 636)
    .transport(Transport::Tls)
    .tls(TlsConfig {
        min_tls_version: TlsVersion::Tls12,
        ..Default::default()
    })?
    .connect().await?;
```

### Who Am I

```rust
if let Some(authz_id) = client.who_am_i().await? {
    println!("bound as {authz_id}");
}
```

### Unsolicited Notification Handler

```rust
use ldap_client::ClientBuilder;

let client = ClientBuilder::new("ldap.example.com", 389)
    .on_unsolicited_notification(|resp| {
        eprintln!("server notification: {:?}", resp.oid);
    })
    .connect().await?;
```


## Crate Layout

| Crate | Description |
|---|---|
| `ldap-client-ber` | Hand-written ASN.1 BER codec with recursion limits and size enforcement |
| `ldap-client-proto` | LDAPv3 wire types, filter parser, DN parser, URL parser, controls |
| `ldap-client` | Async `Client` with TLS, paging, reconnect, and referral support |


## Copyright

(c) 2025-2026 Michael S. Klishin and Contributors.


## License

This crate, `ldap-client-rs`, is dual-licensed under
the Apache Software License 2.0 and the MIT license.

SPDX-License-Identifier: Apache-2.0 OR MIT

# ldap-client-rs Change Log

## v0.8.0 (Sep 30, 2026)

This release focuses on refactoring, subtle bug fixes and small behavior nuances that
turned out to be suboptimal in the original implementation.

To reflect that in a pre-`1.0.0` codebase, the minor is bumped by two.

### Breaking Changes

 * `Filter` values are bytes: `Filter::Eq`, `Approx`, `Gte`, `Lte`, the `Substring` parts and the `ExtensibleMatch` value hold an `AssertionValue` instead of a `String`. Constructors still accept `&str` and `String`; code that matches those variants uses `AssertionValue::to_str` or `as_bytes`
 * `Rdn::components` values are an `AttributeValue`, either `Text` or `Ber` (a `#` hex value), instead of a `String`. `"x".into()` and comparison with `&str` still work; use `AttributeValue::as_text` where a `&str` is needed
 * `TlsConfig` is built with `TlsConfig::default()` and its methods (`trust_anchors`, `client_certificate`, `min_tls_version`, `danger_disable_verification`) instead of a struct literal. `TrustAnchors` is `#[non_exhaustive]`
 * `Error`, `ProtoError`, `BerError` and `Filter` are `#[non_exhaustive]`: a `match` on them needs a `_` arm
 * `ResultCode` displays as the RFC name and number (`invalidCredentials (49)`), and decodes the eleven RFC 4511 codes it lacked (12, 13, 33, 36, 48, 54, 64, 65, 67, 69, 71) as variants instead of `Unknown`
 * `TlsVersion::default()` is `Tls12`, so `TlsConfig::default()` accepts TLS 1.2 and 1.3, as a client with no `.tls()` call already did. Use `min_tls_version(TlsVersion::Tls13)` for TLS 1.3 only

## v0.6.0 (Mar 7, 2026)

### Enhancements

 * Publishing to `crates.io` now uses [Trusted Publishing](https://crates.io/docs/trusted-publishing)


## v0.5.0 (Mar 7, 2026)

Initial release.

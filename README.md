# Keychain Services for Rust 🔐 <a href="https://www.iqlusion.io"><img src="https://storage.googleapis.com/iqlusion-prod-web-assets/img/logo/iqlusion-rings-sm.png" alt="iqlusion" width="24" height="24"></a>

[![Crate][crate-image]][crate-link]
[![Build Status][build-image]][build-link]
[![Apache 2.0 Licensed][license-image]][license-link]

[crate-image]: https://img.shields.io/crates/v/keychain-services.svg
[crate-link]: https://crates.io/crates/keychain-services
[build-image]: https://travis-ci.org/iqlusioninc/keychain-services-rs.svg?branch=master
[build-link]: https://travis-ci.org/iqlusioninc/keychain-services-rs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[license-link]: https://github.com/iqlusioninc/keychain-services-rs/blob/master/LICENSE-APACHE

Rust binding for macOS Keychain Services, including TouchID-guarded access to
cryptographic keys stored in the Secure Enclave Processor (SEP).

This binding aims to provide a thin wrapper using largely the same type names
as Keychain Services itself, but also provide a safe, mostly idiomatic API
which does not rely on e.g. Core Foundation types.

**NOTE:** This is an unofficial binding which is in no way affiliated with Apple!

## Status

This crate only wraps a small part of the Keychain Services API, and presently
only supports interacting with the default keychain (i.e. `login`). Below is a
rough outline of the Keychain Service API and what is supported.

- [ ] Keychains (`SecKeychain`)
  - [ ] Creating keychains
  - [ ] Deleting keychains
- [ ] Keychain Items (`SecKeychainItem`)
  - [ ] Creating keychain item attributes
  - [ ] Fetching keychain items
  - [ ] Getting keychain item attributes
  - [ ] Deleting keychain items
- [ ] Certificates / Identities (`SecCertificate`)
  - [ ] Creating certificates
  - [ ] Deleting certificates
  - [ ] Querying certificates
  - [ ] Signing certificates
- [ ] Cryptographic keys (`SecKey`)
  - [x] Generating cryptographic keys
  - [ ] Importing cryptographic keys
  - [x] Exporting cryptographic keys
  - [ ] Deleting cryptographic keys
  - [x] Querying cryptographic keys
  - [x] Querying cryptographic key attributes
  - [x] Digital signatures (ECDSA/RSA)
  - [ ] Encryption
- [ ] Passwords
  - [ ] Creating passwords
  - [ ] Querying passwords
  - [ ] Deleting passwords

## Tests

This crate has two suites of tests:

- Core: `cargo test` - run a minimal set of tests (e.g. in CI) that work
  everywhere, but don't cover all functionality.
- Interactive: `cargo test --features=interactive-tests --no-run`
  compile tests which require user interactions, and additionally must be
  signed by macOS's code signing in order to work. See code signing notes.

## Code Signing

The Keychain Service API requires signed code to access much of its
functionality. Accessing many APIs from an unsigned app will return
an `ErrorKind::MissingEntitlement`.

Follow the instructions here to create a self-signed code signing certificate:
<https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>

You will need to use the [codesign] command-line utility (or XCode) to sign
your code before it will be able to access most Keychain Services API
functionality.

[codesign]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW4

## License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.

//! macOS Keychain Services wrapper for accessing the system and user's
//! cryptographic keychains, as well as keys stored in the Secure Enclave
//! Processor (SEP).
//!
//! This crate provides a thin, low-level binding with a safe, mostly idiomatic
//! Rust API. Ideally however, it should be wrapped up in higher level, easy-to-use
//! libraries, as the API it presents is rather complicated and arcane.
//!
//! For more information on Keychain Services`, see:
//! <https://developer.apple.com/documentation/security/keychain_services/keychains>
//!
//! ## Code Signing
//!
//! The Keychain Service API requires signed code to access much of its
//! functionality. Accessing many APIs from an unsigned app will return
//! an error with a kind of `ErrorKind::MissingEntitlement`.
//!
//! Follow the instructions here to create a self-signed code signing certificate:
//! <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>
//!
//! You will need to use the [codesign] command-line utility (or XCode) to sign
//! your code before it will be able to access most Keychain Services API
//! functionality. When you sign, you will need an entitlements file which
//! grants access to the Keychain Services API. Below is an example:
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
//! <plist version="1.0">
//! <dict>
//!	<key>keychain-access-groups</key>
//!	<array>
//!		<string>$(AppIdentifierPrefix)com.example.MyApplication</string>
//!	</array>
//! </dict>
//! </plist>
//! ```
//!
//! [codesign]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW4

#![crate_name = "keychain_services"]
#![crate_type = "rlib"]
#![allow(
    unknown_lints,
    suspicious_arithmetic_impl,
    non_snake_case,
    non_upper_case_globals
)]
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications
)]

#[cfg(not(target_os = "macos"))]
compile_error!("This crate presently only compiles on macOS.");

#[macro_use]
extern crate core_foundation;
extern crate failure;
#[macro_use]
extern crate failure_derive;

mod access;
mod attr;
mod dictionary;
mod error;
mod ffi;
pub mod key;
pub mod keychain;
mod signature;

pub use access::*;
pub use attr::*;
pub use error::*;
pub use key::*;
pub use keychain::*;
pub use signature::*;

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
//! TODO: merge this into the `security-framework` crate:
//! <https://crates.io/crates/security-framework>

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
mod algorithm;
mod attr;
mod error;
mod ffi;
mod item;
mod key;
mod query;
mod signature;

pub use access::*;
pub use algorithm::*;
pub use attr::*;
pub use error::*;
pub use item::*;
pub use key::*;
pub use query::*;
pub use signature::*;

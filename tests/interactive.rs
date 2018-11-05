#![cfg(feature = "interactive-tests")]

//! Interactive tests intended to be manually run by a person.
//!
//! These tests require a signed `target/debug/interactive-*` executable in
//! order to pass. To sign the test executable, you'll first need to
//! create a self-signed code signing certificate, see the
//! "To obtain a self-signed certificate using Certificate Assistant"
//! section of:
//!
//! <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>

extern crate keychain_services;
use keychain_services::*;

/// Generate a `SecKeyPair` for testing purposes
fn generate_keypair(tag: &str, label: &str) -> KeyPair {
    let acl = SecAccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default())
        .unwrap();

    let generate_params = KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256)
        .access_control(acl)
        .application_tag(tag)
        .label(label)
        .permanent(true);

    KeyPair::generate(generate_params).unwrap()
}

/// `SecKey` query
#[test]
fn seckey_query() {
    let keypair = generate_keypair(
        "rs.keychain-services.test.integration.query",
        "keychain-services.rs integration test query key",
    );

    let private_key_query = ItemQuery::new()
        .key_class(AttrKeyClass::Private)
        .key_type(AttrKeyType::EcSecPrimeRandom)
        .application_label(keypair.public_key.application_label().unwrap());

    let private_key = SecKey::find(private_key_query).unwrap();
    assert_eq!(
        keypair.private_key.application_label(),
        private_key.application_label()
    );
}

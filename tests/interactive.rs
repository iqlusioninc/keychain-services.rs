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

// TODO: these tests presently fail (possibly due to a codesigning issue?)

use keychain_services::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test password. do not really use";

/// Creates a temporary keychain in a temporary directory
struct TempKeychain {
    pub dir: TempDir,
    pub keychain: Keychain,
}

/// Create a temporary keychain we can use for testing
fn temp_keychain() -> TempKeychain {
    let dir = tempfile::tempdir().unwrap();
    let keychain =
        Keychain::create(&dir.path().join("test-keychain"), Some(TEST_PASSWORD)).unwrap();

    TempKeychain { dir, keychain }
}

/// Generate a `key::Pair` for testing purposes
fn generate_keypair(tag: &str, label: &str) -> KeyPair {
    let acl =
        AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default()).unwrap();

    let generate_params = KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256)
        .access_control(&acl)
        .application_tag(tag)
        .label(label)
        .permanent(true);

    KeyPair::generate(generate_params).unwrap()
}

/// Queries for secret keys
#[test]
fn key_query() {
    let keypair = generate_keypair(
        "rs.keychain-services.test.integration.query",
        "keychain-services.rs integration test query key",
    );

    let private_key_query = keychain::item::Query::new()
        .key_class(AttrKeyClass::Private)
        .key_type(AttrKeyType::EcSecPrimeRandom)
        .application_label(keypair.public_key.application_label().unwrap());

    let private_key = Key::find(private_key_query).unwrap();

    assert_eq!(
        keypair.private_key.application_label(),
        private_key.application_label()
    );
}

/// Passwords
#[test]
fn store_and_retrieve_passwords() {
    let tmp = temp_keychain();
    let service = "example.com";
    let account = "example";

    let keychain_item =
        keychain::item::GenericPassword::create(&tmp.keychain, service, account, TEST_PASSWORD)
            .unwrap();

    assert_eq!(keychain_item.service().unwrap(), service);
    assert_eq!(keychain_item.account().unwrap(), account);
    assert_eq!(keychain_item.password().unwrap().as_str(), TEST_PASSWORD);
}

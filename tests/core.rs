//! Core suite of tests which should work on all supported macOS platforms.
//!
//! This suite is mainly intended to run in CI. See `tests/interactive.rs`
//! for notes on how to run the full test suite.

use keychain_services::*;

const TEST_MESSAGE: &[u8] = b"Embed confidential information in items that you store in a keychain";

/// Soft ECDSA key support
#[test]
fn generate_and_sign_with_ecdsa_keys() {
    let acl =
        AccessControl::create_with_flags(AttrAccessible::WhenUnlocked, Default::default()).unwrap();

    let generate_params =
        KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256).access_control(&acl);

    let keypair = KeyPair::generate(generate_params).unwrap();

    let public_key_bytes = keypair.public_key.to_external_representation().unwrap();

    let signature = keypair
        .private_key
        .sign(KeyAlgorithm::ECDSASignatureMessageX962SHA256, TEST_MESSAGE)
        .unwrap();

    ring::signature::verify(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        untrusted::Input::from(&public_key_bytes),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    )
    .unwrap();

    let res = keypair.public_key.verify(KeyAlgorithm::ECDSASignatureMessageX962SHA256, TEST_MESSAGE, &signature);
    assert!(res.is_ok());
    assert!(res.unwrap());
    let res = keypair.public_key.verify(KeyAlgorithm::ECDSASignatureMessageX962SHA256, &[0u8, 0u8], &signature);
    assert!(res.is_err());
}

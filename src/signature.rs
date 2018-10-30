//! Signatures produced by this library.
//!
//! This type doesn't map directly to any type in the Keychain Services API,
//! but instead provides a newtype for signatures this binding produces.

use algorithm::SecKeyAlgorithm;

/// Cryptographic signatures
#[derive(Clone, Debug)]
pub struct SecSignature {
    alg: SecKeyAlgorithm,
    bytes: Vec<u8>,
}

impl SecSignature {
    /// Create a new `Signature`
    pub(crate) fn new(alg: SecKeyAlgorithm, bytes: Vec<u8>) -> Self {
        // TODO: restrict valid algorithms to signature algorithms?
        Self { alg, bytes }
    }

    /// Get the algorithm which produced this signature
    pub fn algorithm(&self) -> SecKeyAlgorithm {
        self.alg
    }

    /// Borrow the signature data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert into a byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for SecSignature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<SecSignature> for Vec<u8> {
    fn from(sig: SecSignature) -> Vec<u8> {
        sig.into_vec()
    }
}

//! Ciphertext produced by this library.
//!
//! This type doesn't map directly to any type in the Keychain Services API,
//! but instead provides a newtype for signatures this binding produces.

use crate::key::KeyAlgorithm;

/// Cryptographic signatures
#[derive(Clone, Debug)]
pub struct Ciphertext {
    alg: KeyAlgorithm,
    bytes: Vec<u8>,
}

impl Ciphertext {
    /// Create a new `Ciphertext`
    pub fn new(alg: KeyAlgorithm, bytes: Vec<u8>) -> Self {
        // TODO: restrict valid algorithms to encryption algorithms?
        Self { alg, bytes }
    }

    /// Get the algorithm which produced this signature
    pub fn algorithm(&self) -> KeyAlgorithm {
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

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Ciphertext> for Vec<u8> {
    fn from(ciphertext: Ciphertext) -> Vec<u8> {
        ciphertext.into_vec()
    }
}

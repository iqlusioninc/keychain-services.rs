use core_foundation::{base::TCFType, string::CFString};

use ffi::*;

/// Cryptographic algorithms for use with keys stored in the keychain.
///
/// For more information on `SecKeyAlgorithm`, see:
/// <https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecKeyAlgorithm {
    /// Elliptic Curve Encryption Standard X963
    ECIESEncryptionStandardX963SHA1AESGCM,

    /// Elliptic Curve Encryption Standard X963
    ECIESEncryptionStandardX963SHA224AESGCM,

    /// Elliptic Curve Encryption Standard X963
    ECIESEncryptionStandardX963SHA256AESGCM,

    /// Elliptic Curve Encryption Standard X963
    ECIESEncryptionStandardX963SHA384AESGCM,

    /// Elliptic Curve Encryption Standard X963
    ECIESEncryptionStandardX963SHA512AESGCM,

    /// Elliptic Curve Encryption Standard Variable IVX963
    ECIESEncryptionStandardVariableIVX963SHA224AESGCM,

    /// Elliptic Curve Encryption Standard Variable IVX963
    ECIESEncryptionStandardVariableIVX963SHA256AESGCM,

    /// Elliptic Curve Encryption Standard Variable IVX963
    ECIESEncryptionStandardVariableIVX963SHA384AESGCM,

    /// Elliptic Curve Encryption Standard Variable IVX963
    ECIESEncryptionStandardVariableIVX963SHA512AESGCM,

    /// Elliptic Curve Encryption Cofactor Variable IVX963
    ECIESEncryptionCofactorVariableIVX963SHA224AESGCM,

    /// Elliptic Curve Encryption Cofactor Variable IVX963
    ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,

    /// Elliptic Curve Encryption Cofactor Variable IVX963
    ECIESEncryptionCofactorVariableIVX963SHA384AESGCM,

    /// Elliptic Curve Encryption Cofactor Variable IVX963
    ECIESEncryptionCofactorVariableIVX963SHA512AESGCM,

    /// Elliptic Curve Encryption Cofactor X963
    ECIESEncryptionCofactorX963SHA1AESGCM,

    /// Elliptic Curve Encryption Cofactor X963
    ECIESEncryptionCofactorX963SHA224AESGCM,

    /// Elliptic Curve Encryption Cofactor X963
    ECIESEncryptionCofactorX963SHA256AESGCM,

    /// Elliptic Curve Encryption Cofactor X963
    ECIESEncryptionCofactorX963SHA384AESGCM,

    /// Elliptic Curve Encryption Cofactor X963
    ECIESEncryptionCofactorX963SHA512AESGCM,

    /// Elliptic Curve Signature RFC4754
    ECDSASignatureRFC4754,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962SHA1,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962SHA224,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962SHA256,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962SHA384,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureDigestX962SHA512,

    /// Elliptic Curve Signature Message X962
    ECDSASignatureMessageX962SHA1,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureMessageX962SHA224,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureMessageX962SHA256,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureMessageX962SHA384,

    /// Elliptic Curve Signature Digest X962
    ECDSASignatureMessageX962SHA512,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactor,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandard,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactorX963SHA1,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandardX963SHA1,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactorX963SHA224,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactorX963SHA256,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactorX963SHA384,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeCofactorX963SHA512,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandardX963SHA224,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandardX963SHA256,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandardX963SHA384,

    /// Elliptic Curve Key Exchange
    ECDHKeyExchangeStandardX963SHA512,

    /// RSA Encryption
    RSAEncryptionRaw,

    /// RSA Encryption
    RSAEncryptionPKCS1,
    /// RSA Encryption OAEP
    RSAEncryptionOAEPSHA1,

    /// RSA Encryption OAEP
    RSAEncryptionOAEPSHA224,

    /// RSA Encryption OAEP
    RSAEncryptionOAEPSHA256,

    /// RSA Encryption OAEP
    RSAEncryptionOAEPSHA384,

    /// RSA Encryption OAEP
    RSAEncryptionOAEPSHA512,

    /// RSA Encryption OAEP AES-GCM
    RSAEncryptionOAEPSHA1AESGCM,

    /// RSA Encryption OAEP AES-GCM
    RSAEncryptionOAEPSHA224AESGCM,

    /// RSA Encryption OAEP AES-GCM
    RSAEncryptionOAEPSHA256AESGCM,

    /// RSA Encryption OAEP AES-GCM
    RSAEncryptionOAEPSHA384AESGCM,

    /// RSA Encryption OAEP AES-GCM
    RSAEncryptionOAEPSHA512AESGCM,

    /// RSA Signature Raw
    RSASignatureRaw,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15Raw,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15SHA1,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15SHA224,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15SHA256,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15SHA384,

    /// RSA Signature Digest PKCS1v15
    RSASignatureDigestPKCS1v15SHA512,

    /// RSA Signature Message PKCS1v15
    RSASignatureMessagePKCS1v15SHA1,

    /// RSA Signature Digest PKCS1v15
    RSASignatureMessagePKCS1v15SHA224,

    /// RSA Signature Digest PKCS1v15
    RSASignatureMessagePKCS1v15SHA256,

    /// RSA Signature Digest PKCS1v15
    RSASignatureMessagePKCS1v15SHA384,

    /// RSA Signature Digest PKCS1v15
    RSASignatureMessagePKCS1v15SHA512,

    /// RSA Signature Digest PSS
    RSASignatureDigestPSSSHA1,

    /// RSA Signature Digest PSS
    RSASignatureDigestPSSSHA224,

    /// RSA Signature Digest PSS
    RSASignatureDigestPSSSHA256,

    /// RSA Signature Digest PSS
    RSASignatureDigestPSSSHA384,

    /// RSA Signature Digest PSS
    RSASignatureDigestPSSSHA512,

    /// RSA Signature Message PSS
    RSASignatureMessagePSSSHA1,

    /// RSA Signature Message PSS
    RSASignatureMessagePSSSHA224,

    /// RSA Signature Message PSS
    RSASignatureMessagePSSSHA256,

    /// RSA Signature Message PSS
    RSASignatureMessagePSSSHA384,

    /// RSA Signature Message PSS
    RSASignatureMessagePSSSHA512,
}

impl SecKeyAlgorithm {
    /// Get `CFString` containing the `kSecKeyAlgorithm` dictionary value for
    /// a particular cryptographic algorithm.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecKeyAlgorithm::ECIESEncryptionStandardX963SHA1AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorX963SHA1AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM
                }
                SecKeyAlgorithm::ECIESEncryptionCofactorX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM
                }
                SecKeyAlgorithm::ECDSASignatureRFC4754 => kSecKeyAlgorithmECDSASignatureRFC4754,
                SecKeyAlgorithm::ECDSASignatureDigestX962 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962
                }
                SecKeyAlgorithm::ECDSASignatureDigestX962SHA1 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA1
                }
                SecKeyAlgorithm::ECDSASignatureDigestX962SHA224 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA224
                }
                SecKeyAlgorithm::ECDSASignatureDigestX962SHA256 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA256
                }
                SecKeyAlgorithm::ECDSASignatureDigestX962SHA384 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA384
                }
                SecKeyAlgorithm::ECDSASignatureDigestX962SHA512 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA512
                }
                SecKeyAlgorithm::ECDSASignatureMessageX962SHA1 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA1
                }
                SecKeyAlgorithm::ECDSASignatureMessageX962SHA224 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA224
                }
                SecKeyAlgorithm::ECDSASignatureMessageX962SHA256 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA256
                }
                SecKeyAlgorithm::ECDSASignatureMessageX962SHA384 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA384
                }
                SecKeyAlgorithm::ECDSASignatureMessageX962SHA512 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA512
                }
                SecKeyAlgorithm::ECDHKeyExchangeCofactor => kSecKeyAlgorithmECDHKeyExchangeCofactor,
                SecKeyAlgorithm::ECDHKeyExchangeStandard => kSecKeyAlgorithmECDHKeyExchangeStandard,
                SecKeyAlgorithm::ECDHKeyExchangeCofactorX963SHA1 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1
                }
                SecKeyAlgorithm::ECDHKeyExchangeStandardX963SHA1 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1
                }
                SecKeyAlgorithm::ECDHKeyExchangeCofactorX963SHA224 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224
                }
                SecKeyAlgorithm::ECDHKeyExchangeCofactorX963SHA256 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256
                }
                SecKeyAlgorithm::ECDHKeyExchangeCofactorX963SHA384 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384
                }
                SecKeyAlgorithm::ECDHKeyExchangeCofactorX963SHA512 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512
                }
                SecKeyAlgorithm::ECDHKeyExchangeStandardX963SHA224 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224
                }
                SecKeyAlgorithm::ECDHKeyExchangeStandardX963SHA256 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256
                }
                SecKeyAlgorithm::ECDHKeyExchangeStandardX963SHA384 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384
                }
                SecKeyAlgorithm::ECDHKeyExchangeStandardX963SHA512 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512
                }
                SecKeyAlgorithm::RSAEncryptionRaw => kSecKeyAlgorithmRSAEncryptionRaw,
                SecKeyAlgorithm::RSAEncryptionPKCS1 => kSecKeyAlgorithmRSAEncryptionPKCS1,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA1 => kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA224 => kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA256 => kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA384 => kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA512 => kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
                SecKeyAlgorithm::RSAEncryptionOAEPSHA1AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM
                }
                SecKeyAlgorithm::RSAEncryptionOAEPSHA224AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM
                }
                SecKeyAlgorithm::RSAEncryptionOAEPSHA256AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM
                }
                SecKeyAlgorithm::RSAEncryptionOAEPSHA384AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM
                }
                SecKeyAlgorithm::RSAEncryptionOAEPSHA512AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM
                }
                SecKeyAlgorithm::RSASignatureRaw => kSecKeyAlgorithmRSASignatureRaw,
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15Raw => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw
                }
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15SHA1 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                }
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15SHA224 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224
                }
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15SHA256 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                }
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15SHA384 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                }
                SecKeyAlgorithm::RSASignatureDigestPKCS1v15SHA512 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
                }
                SecKeyAlgorithm::RSASignatureMessagePKCS1v15SHA1 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                }
                SecKeyAlgorithm::RSASignatureMessagePKCS1v15SHA224 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224
                }
                SecKeyAlgorithm::RSASignatureMessagePKCS1v15SHA256 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                }
                SecKeyAlgorithm::RSASignatureMessagePKCS1v15SHA384 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                }
                SecKeyAlgorithm::RSASignatureMessagePKCS1v15SHA512 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
                }
                SecKeyAlgorithm::RSASignatureDigestPSSSHA1 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                }
                SecKeyAlgorithm::RSASignatureDigestPSSSHA224 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA224
                }
                SecKeyAlgorithm::RSASignatureDigestPSSSHA256 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                }
                SecKeyAlgorithm::RSASignatureDigestPSSSHA384 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                }
                SecKeyAlgorithm::RSASignatureDigestPSSSHA512 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA512
                }
                SecKeyAlgorithm::RSASignatureMessagePSSSHA1 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                }
                SecKeyAlgorithm::RSASignatureMessagePSSSHA224 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA224
                }
                SecKeyAlgorithm::RSASignatureMessagePSSSHA256 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                }
                SecKeyAlgorithm::RSASignatureMessagePSSSHA384 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                }
                SecKeyAlgorithm::RSASignatureMessagePSSSHA512 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA512
                }
            })
        }
    }
}

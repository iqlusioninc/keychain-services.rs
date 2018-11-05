use core_foundation::{base::TCFType, string::CFString};

use ffi::*;

/// Cryptographic algorithms for use with keys stored in the keychain.
///
/// Wrapper for `SecKeyAlgorithm`. See:
/// <https://developer.apple.com/documentation/security/seckeyalgorithm>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
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

impl KeyAlgorithm {
    /// Get `CFString` containing the `kSecKeyAlgorithm` dictionary value for
    /// a particular cryptographic algorithm.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                KeyAlgorithm::ECIESEncryptionStandardX963SHA1AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM
                }
                KeyAlgorithm::ECIESEncryptionStandardVariableIVX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorX963SHA1AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorX963SHA224AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorX963SHA256AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorX963SHA384AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM
                }
                KeyAlgorithm::ECIESEncryptionCofactorX963SHA512AESGCM => {
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM
                }
                KeyAlgorithm::ECDSASignatureRFC4754 => kSecKeyAlgorithmECDSASignatureRFC4754,
                KeyAlgorithm::ECDSASignatureDigestX962 => kSecKeyAlgorithmECDSASignatureDigestX962,
                KeyAlgorithm::ECDSASignatureDigestX962SHA1 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA1
                }
                KeyAlgorithm::ECDSASignatureDigestX962SHA224 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA224
                }
                KeyAlgorithm::ECDSASignatureDigestX962SHA256 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA256
                }
                KeyAlgorithm::ECDSASignatureDigestX962SHA384 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA384
                }
                KeyAlgorithm::ECDSASignatureDigestX962SHA512 => {
                    kSecKeyAlgorithmECDSASignatureDigestX962SHA512
                }
                KeyAlgorithm::ECDSASignatureMessageX962SHA1 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA1
                }
                KeyAlgorithm::ECDSASignatureMessageX962SHA224 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA224
                }
                KeyAlgorithm::ECDSASignatureMessageX962SHA256 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA256
                }
                KeyAlgorithm::ECDSASignatureMessageX962SHA384 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA384
                }
                KeyAlgorithm::ECDSASignatureMessageX962SHA512 => {
                    kSecKeyAlgorithmECDSASignatureMessageX962SHA512
                }
                KeyAlgorithm::ECDHKeyExchangeCofactor => kSecKeyAlgorithmECDHKeyExchangeCofactor,
                KeyAlgorithm::ECDHKeyExchangeStandard => kSecKeyAlgorithmECDHKeyExchangeStandard,
                KeyAlgorithm::ECDHKeyExchangeCofactorX963SHA1 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1
                }
                KeyAlgorithm::ECDHKeyExchangeStandardX963SHA1 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1
                }
                KeyAlgorithm::ECDHKeyExchangeCofactorX963SHA224 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224
                }
                KeyAlgorithm::ECDHKeyExchangeCofactorX963SHA256 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256
                }
                KeyAlgorithm::ECDHKeyExchangeCofactorX963SHA384 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384
                }
                KeyAlgorithm::ECDHKeyExchangeCofactorX963SHA512 => {
                    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512
                }
                KeyAlgorithm::ECDHKeyExchangeStandardX963SHA224 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224
                }
                KeyAlgorithm::ECDHKeyExchangeStandardX963SHA256 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256
                }
                KeyAlgorithm::ECDHKeyExchangeStandardX963SHA384 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384
                }
                KeyAlgorithm::ECDHKeyExchangeStandardX963SHA512 => {
                    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512
                }
                KeyAlgorithm::RSAEncryptionRaw => kSecKeyAlgorithmRSAEncryptionRaw,
                KeyAlgorithm::RSAEncryptionPKCS1 => kSecKeyAlgorithmRSAEncryptionPKCS1,
                KeyAlgorithm::RSAEncryptionOAEPSHA1 => kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
                KeyAlgorithm::RSAEncryptionOAEPSHA224 => kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
                KeyAlgorithm::RSAEncryptionOAEPSHA256 => kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                KeyAlgorithm::RSAEncryptionOAEPSHA384 => kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
                KeyAlgorithm::RSAEncryptionOAEPSHA512 => kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
                KeyAlgorithm::RSAEncryptionOAEPSHA1AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM
                }
                KeyAlgorithm::RSAEncryptionOAEPSHA224AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM
                }
                KeyAlgorithm::RSAEncryptionOAEPSHA256AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM
                }
                KeyAlgorithm::RSAEncryptionOAEPSHA384AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM
                }
                KeyAlgorithm::RSAEncryptionOAEPSHA512AESGCM => {
                    kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM
                }
                KeyAlgorithm::RSASignatureRaw => kSecKeyAlgorithmRSASignatureRaw,
                KeyAlgorithm::RSASignatureDigestPKCS1v15Raw => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw
                }
                KeyAlgorithm::RSASignatureDigestPKCS1v15SHA1 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
                }
                KeyAlgorithm::RSASignatureDigestPKCS1v15SHA224 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224
                }
                KeyAlgorithm::RSASignatureDigestPKCS1v15SHA256 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
                }
                KeyAlgorithm::RSASignatureDigestPKCS1v15SHA384 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
                }
                KeyAlgorithm::RSASignatureDigestPKCS1v15SHA512 => {
                    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
                }
                KeyAlgorithm::RSASignatureMessagePKCS1v15SHA1 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                }
                KeyAlgorithm::RSASignatureMessagePKCS1v15SHA224 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224
                }
                KeyAlgorithm::RSASignatureMessagePKCS1v15SHA256 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                }
                KeyAlgorithm::RSASignatureMessagePKCS1v15SHA384 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                }
                KeyAlgorithm::RSASignatureMessagePKCS1v15SHA512 => {
                    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
                }
                KeyAlgorithm::RSASignatureDigestPSSSHA1 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA1
                }
                KeyAlgorithm::RSASignatureDigestPSSSHA224 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA224
                }
                KeyAlgorithm::RSASignatureDigestPSSSHA256 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA256
                }
                KeyAlgorithm::RSASignatureDigestPSSSHA384 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA384
                }
                KeyAlgorithm::RSASignatureDigestPSSSHA512 => {
                    kSecKeyAlgorithmRSASignatureDigestPSSSHA512
                }
                KeyAlgorithm::RSASignatureMessagePSSSHA1 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                }
                KeyAlgorithm::RSASignatureMessagePSSSHA224 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA224
                }
                KeyAlgorithm::RSASignatureMessagePSSSHA256 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                }
                KeyAlgorithm::RSASignatureMessagePSSSHA384 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                }
                KeyAlgorithm::RSASignatureMessagePSSSHA512 => {
                    kSecKeyAlgorithmRSASignatureMessagePSSSHA512
                }
            })
        }
    }
}

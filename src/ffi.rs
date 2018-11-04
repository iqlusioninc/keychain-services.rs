use core_foundation::{
    base::{CFAllocatorRef, CFOptionFlags, CFTypeID, CFTypeRef, OSStatus},
    data::CFDataRef,
    dictionary::CFDictionaryRef,
    error::CFErrorRef,
    string::CFStringRef,
};
use std::os::raw::{c_char, c_void};

/// Reference to an access control policy.
///
/// See `SecAccessControlRef` documentation:
/// <https://developer.apple.com/documentation/security/secaccesscontrolref>
pub(crate) type SecAccessControlRef = CFTypeRef;

/// Reference to a `SecKey`
///
/// See `SecKeyRef` documentation:
/// <https://developer.apple.com/documentation/security/seckeyref>
pub(crate) type SecKeyRef = CFTypeRef;

/// Reference to a `SecKeychain`
///
/// See `SecKeychainRef` documentation:
/// <https://developer.apple.com/documentation/security/seckeychainref>
pub(crate) type SecKeychainRef = CFTypeRef;

/// Reference to a `SecKeychainItem`
///
/// See `SecKeychainItemRef` documentation:
/// <https://developer.apple.com/documentation/security/seckeychainitemref>
pub(crate) type SecKeychainItemRef = CFTypeRef;

#[link(name = "Security", kind = "framework")]
extern "C" {
    pub(crate) static kSecAttrAccessControl: CFStringRef;
    pub(crate) static kSecAttrAccessible: CFStringRef;
    pub(crate) static kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: CFStringRef;
    pub(crate) static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    pub(crate) static kSecAttrAccessibleWhenUnlocked: CFStringRef;
    pub(crate) static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
    pub(crate) static kSecAttrAccessibleAfterFirstUnlock: CFStringRef;
    pub(crate) static kSecAttrAccessibleAlwaysThisDeviceOnly: CFStringRef;
    pub(crate) static kSecAttrAccessibleAlways: CFStringRef;
    pub(crate) static kSecAttrAccount: CFStringRef;
    pub(crate) static kSecAttrApplicationLabel: CFStringRef;
    pub(crate) static kSecAttrApplicationTag: CFStringRef;
    pub(crate) static kSecAttrIsPermanent: CFStringRef;
    pub(crate) static kSecAttrKeyClass: CFStringRef;
    pub(crate) static kSecAttrKeyClassPublic: CFStringRef;
    pub(crate) static kSecAttrKeyClassPrivate: CFStringRef;
    pub(crate) static kSecAttrKeyClassSymmetric: CFStringRef;
    pub(crate) static kSecAttrKeyType: CFStringRef;
    pub(crate) static kSecAttrKeyTypeAES: CFStringRef;
    pub(crate) static kSecAttrKeyTypeRSA: CFStringRef;
    pub(crate) static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    pub(crate) static kSecAttrKeySizeInBits: CFStringRef;
    pub(crate) static kSecAttrLabel: CFStringRef;
    pub(crate) static kSecAttrProtocol: CFStringRef;
    pub(crate) static kSecAttrProtocolFTP: CFStringRef;
    pub(crate) static kSecAttrProtocolFTPAccount: CFStringRef;
    pub(crate) static kSecAttrProtocolHTTP: CFStringRef;
    pub(crate) static kSecAttrProtocolIRC: CFStringRef;
    pub(crate) static kSecAttrProtocolNNTP: CFStringRef;
    pub(crate) static kSecAttrProtocolPOP3: CFStringRef;
    pub(crate) static kSecAttrProtocolSMTP: CFStringRef;
    pub(crate) static kSecAttrProtocolSOCKS: CFStringRef;
    pub(crate) static kSecAttrProtocolIMAP: CFStringRef;
    pub(crate) static kSecAttrProtocolLDAP: CFStringRef;
    pub(crate) static kSecAttrProtocolAppleTalk: CFStringRef;
    pub(crate) static kSecAttrProtocolAFP: CFStringRef;
    pub(crate) static kSecAttrProtocolTelnet: CFStringRef;
    pub(crate) static kSecAttrProtocolSSH: CFStringRef;
    pub(crate) static kSecAttrProtocolFTPS: CFStringRef;
    pub(crate) static kSecAttrProtocolHTTPS: CFStringRef;
    pub(crate) static kSecAttrProtocolHTTPProxy: CFStringRef;
    pub(crate) static kSecAttrProtocolHTTPSProxy: CFStringRef;
    pub(crate) static kSecAttrProtocolFTPProxy: CFStringRef;
    pub(crate) static kSecAttrProtocolSMB: CFStringRef;
    pub(crate) static kSecAttrProtocolRTSP: CFStringRef;
    pub(crate) static kSecAttrProtocolRTSPProxy: CFStringRef;
    pub(crate) static kSecAttrProtocolDAAP: CFStringRef;
    pub(crate) static kSecAttrProtocolEPPC: CFStringRef;
    pub(crate) static kSecAttrProtocolIPP: CFStringRef;
    pub(crate) static kSecAttrProtocolNNTPS: CFStringRef;
    pub(crate) static kSecAttrProtocolLDAPS: CFStringRef;
    pub(crate) static kSecAttrProtocolTelnetS: CFStringRef;
    pub(crate) static kSecAttrProtocolIMAPS: CFStringRef;
    pub(crate) static kSecAttrProtocolIRCS: CFStringRef;
    pub(crate) static kSecAttrProtocolPOP3S: CFStringRef;
    pub(crate) static kSecAttrServer: CFStringRef;
    pub(crate) static kSecAttrService: CFStringRef;
    pub(crate) static kSecAttrSynchronizable: CFStringRef;
    pub(crate) static kSecAttrTokenID: CFStringRef;
    pub(crate) static kSecAttrTokenIDSecureEnclave: CFStringRef;
    pub(crate) static kSecClass: CFStringRef;
    pub(crate) static kSecClassGenericPassword: CFStringRef;
    pub(crate) static kSecClassInternetPassword: CFStringRef;
    pub(crate) static kSecClassCertificate: CFStringRef;
    pub(crate) static kSecClassKey: CFStringRef;
    pub(crate) static kSecClassIdentity: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM:
        CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureRFC4754: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureDigestX962SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureMessageX962SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureMessageX962SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureMessageX962SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDSASignatureMessageX962SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactor: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandard: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionRaw: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionPKCS1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureRaw: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPSSSHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPSSSHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPSSSHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPSSSHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureDigestPSSSHA512: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePSSSHA1: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePSSSHA224: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePSSSHA256: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePSSSHA384: CFStringRef;
    pub(crate) static kSecKeyAlgorithmRSASignatureMessagePSSSHA512: CFStringRef;
    pub(crate) static kSecMatchLimit: CFStringRef;
    pub(crate) static kSecMatchLimitOne: CFStringRef;
    pub(crate) static kSecMatchLimitAll: CFStringRef;
    pub(crate) static kSecPrivateKeyAttrs: CFStringRef;
    pub(crate) static kSecReturnRef: CFStringRef;
    pub(crate) static kSecUseOperationPrompt: CFStringRef;

    pub(crate) fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: CFOptionFlags,
        error: *mut CFErrorRef,
    ) -> CFTypeRef;
    pub(crate) fn SecAccessControlGetTypeID() -> CFTypeID;
    pub(crate) fn SecCopyErrorMessageString(
        status: OSStatus,
        reserved: *const c_void,
    ) -> CFStringRef;
    pub(crate) fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    pub(crate) fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
    pub(crate) fn SecKeyCopyExternalRepresentation(
        key: SecKeyRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub(crate) fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: CFTypeRef,
        data_to_sign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    pub(crate) fn SecKeyGeneratePair(
        parameters: CFDictionaryRef,
        publicKey: *mut SecKeyRef,
        privateKey: *mut SecKeyRef,
    ) -> OSStatus;
    pub(crate) fn SecKeyGetTypeID() -> CFTypeID;
    pub(crate) fn SecKeychainCopyDefault(keychain: *mut SecKeychainRef) -> OSStatus;
    pub(crate) fn SecKeychainCreate(
        path_name: *const c_char,
        password_length: u32,
        password: *const c_char,
        prompt_user: bool,
        initial_access: CFTypeRef,
        keychain: *mut SecKeychainRef,
    ) -> OSStatus;
    pub(crate) fn SecKeychainDelete(keychain_or_array: SecKeychainRef) -> OSStatus;
    pub(crate) fn SecKeychainGetTypeID() -> CFTypeID;
    pub(crate) fn SecKeychainItemGetTypeID() -> CFTypeID;
}

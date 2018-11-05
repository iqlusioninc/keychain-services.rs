use core_foundation::{base::TCFType, string::CFString};

use ffi::*;

/// Classes of keychain items supported by Keychain Services
/// (not to be confused with `SecAttrClass` or `SecType`)
///
/// Wrapper for the `kSecClass` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecclass>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ItemClass {
    /// Generic password items.
    ///
    /// Wrapper for the `kSecClassGenericPassword` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecclassgenericpassword>
    GenericPassword,

    /// Internet passwords.
    ///
    /// Wrapper for the `kSecClassInternetPassword` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecclassinternetpassword>
    InternetPassword,

    /// Certificates.
    ///
    /// Wrapper for the `kSecClassCertificate` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecclasscertificate>
    Certificate,

    /// Cryptographic keys.
    ///
    /// Wrapper for the `kSecClassKey` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecclasskey>
    Key,

    /// Identities.
    ///
    /// Wrapper for the `kSecClassIdentity` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecclassidentity>
    Identity,
}

impl ItemClass {
    /// Get `CFString` containing the `kSecClass` dictionary value for
    /// this particular `SecClass`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                ItemClass::GenericPassword => kSecClassGenericPassword,
                ItemClass::InternetPassword => kSecClassInternetPassword,
                ItemClass::Certificate => kSecClassCertificate,
                ItemClass::Key => kSecClassKey,
                ItemClass::Identity => kSecClassIdentity,
            })
        }
    }
}

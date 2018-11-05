use core_foundation::{base::TCFType, string::CFString};

use ffi::*;

/// Classes of keychain items supported by Keychain Services
/// (not to be confused with `SecAttrClass` or `SecType`)
///
/// Wrapper for the `kSecClass` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecclass>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Class {
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

impl Class {
    /// Attempt to look up an attribute kind by its `FourCharacterCode`.
    // TODO: cache `FourCharacterCodes`? e.g. as `lazy_static`
    pub(crate) fn from_tag(tag: FourCharacterCode) -> Option<Self> {
        let result = unsafe {
            if tag == FourCharacterCode::from(kSecClassGenericPassword) {
                Class::GenericPassword
            } else if tag == FourCharacterCode::from(kSecClassInternetPassword) {
                Class::InternetPassword
            } else if tag == FourCharacterCode::from(kSecClassCertificate) {
                Class::Certificate
            } else if tag == FourCharacterCode::from(kSecClassKey) {
                Class::Key
            } else if tag == FourCharacterCode::from(kSecClassIdentity) {
                Class::Identity
            } else {
                return None;
            }
        };

        Some(result)
    }
    /// Get `CFString` containing the `kSecClass` dictionary value for
    /// this particular `SecClass`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                Class::GenericPassword => kSecClassGenericPassword,
                Class::InternetPassword => kSecClassInternetPassword,
                Class::Certificate => kSecClassCertificate,
                Class::Key => kSecClassKey,
                Class::Identity => kSecClassIdentity,
            })
        }
    }
}

impl From<FourCharacterCode> for Class {
    fn from(tag: FourCharacterCode) -> Self {
        Self::from_tag(tag).unwrap_or_else(|| panic!("invalid SecItemClass tag: {:?}", tag))
    }
}

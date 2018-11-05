use core_foundation::base::TCFType;

use ffi::*;

pub(super) mod class;
pub(super) mod query;

declare_TCFType!{
    /// Items stored in the keychain.
    ///
    /// Wrapper for the `SecKeychainItem`/`SecKeychainItemRef` types:
    /// <https://developer.apple.com/documentation/security/seckeychainitemref>
    KeychainItem, KeychainItemRef
}

impl_TCFType!(KeychainItem, KeychainItemRef, SecKeychainItemGetTypeID);

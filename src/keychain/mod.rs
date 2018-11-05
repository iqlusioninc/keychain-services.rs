//! Keychains

use core_foundation::base::{CFTypeRef, TCFType};
use std::{ffi::CString, os::raw::c_char, os::unix::ffi::OsStrExt, path::Path, ptr};

use dictionary::*;
use error::Error;
use ffi::*;

pub mod item;
pub mod key;

use self::item::MatchLimit;
pub use self::{item::Item, key::Key};

declare_TCFType!{
    /// Keychains which store cryptographic keys, passwords, and other secrets.
    ///
    /// Wrapper for the `SecKeychain`/`SecKeychainRef` types:
    /// <https://developer.apple.com/documentation/security/seckeychainref>
    Keychain, KeychainRef
}

impl_TCFType!(Keychain, KeychainRef, SecKeychainGetTypeID);

impl Keychain {
    /// Find the default keychain. Returns an `Error` result with a kind of
    /// `ErrorKind::NoDefaultKeychain` if there is no default keychain.
    ///
    /// This is a non-panicking alternative to `Keychain::default()`.
    ///
    /// Wrapper for the `SecKeychainCopyDefault` function. See:
    /// <https://developer.apple.com/documentation/security/1400743-seckeychaincopydefault>
    pub fn find_default() -> Result<Keychain, Error> {
        let mut result: KeychainRef = ptr::null_mut();
        let status = unsafe { SecKeychainCopyDefault(&mut result) };

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(unsafe { Keychain::wrap_under_create_rule(result) })
        }
    }

    /// Create a new keychain. Accepts a path where the new keychain will be
    /// located along with an optional password. If no password is given, the
    /// user will be prompted for a password.
    ///
    /// Wrapper for the `SecKeychainCreate` function. See:
    /// <https://developer.apple.com/documentation/security/1401214-seckeychaincreate>
    pub fn create(path: &Path, password: Option<&str>) -> Result<Keychain, Error> {
        let path_cstring = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut result: KeychainRef = ptr::null_mut();

        let status = match password {
            Some(pw) => unsafe {
                SecKeychainCreate(
                    path_cstring.as_ptr() as *const c_char,
                    pw.len() as u32,
                    pw.as_bytes().as_ptr() as *const c_char,
                    false,
                    ptr::null(),
                    &mut result,
                )
            },
            None => unsafe {
                SecKeychainCreate(
                    path_cstring.as_ptr() as *const c_char,
                    0,
                    ptr::null(),
                    true,
                    ptr::null(),
                    &mut result,
                )
            },
        };

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(unsafe { Keychain::wrap_under_create_rule(result) })
        }
    }

    /// Delete this keychain.
    ///
    /// Wrapper for the `SecKeychainDelete` function. See:
    /// <https://developer.apple.com/documentation/security/1395206-seckeychaindelete>
    pub fn delete(self) -> Result<(), Error> {
        let status = unsafe { SecKeychainDelete(self.as_concrete_TypeRef()) };

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Find an item in this keychain.
    ///
    /// This is a private method we wrap using builders for querying various
    /// keychain item types.
    ///
    /// Wrapper for `SecItemCopyMatching`. See:
    /// <https://developer.apple.com/documentation/security/1398306-secitemcopymatching>
    fn find_item(&self, mut attrs: DictionaryBuilder) -> Result<Item, Error> {
        attrs.add(unsafe { kSecMatchLimit }, &MatchLimit::One.as_CFType());
        attrs.add_boolean(unsafe { kSecReturnRef }, true);

        let mut result: ItemRef = ptr::null_mut();
        let status = unsafe {
            SecItemCopyMatching(
                Dictionary::from(attrs).as_concrete_TypeRef(),
                &mut result as &mut CFTypeRef,
            )
        };

        // Return an error if the status was unsuccessful
        if let Some(e) = Error::maybe_from_OSStatus(status) {
            return Err(e);
        }

        Ok(unsafe { Item::wrap_under_create_rule(result) })
    }

    /// Add an item to this keychain.
    ///
    /// This is a private method we wrap using builders for various keychain
    /// item types.
    ///
    /// Wrapper for the `SecItemAdd` function. See:
    /// <https://developer.apple.com/documentation/security/1401659-secitemadd>
    fn add_item(&self, mut attrs: DictionaryBuilder) -> Result<Item, Error> {
        attrs.add(unsafe { kSecUseKeychain }, self);
        attrs.add_boolean(unsafe { kSecReturnRef }, true);

        let mut result: ItemRef = ptr::null_mut();
        let status =
            unsafe { SecItemAdd(Dictionary::from(attrs).as_concrete_TypeRef(), &mut result) };

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(unsafe { Item::wrap_under_create_rule(result) })
        }
    }
}

impl Default for Keychain {
    fn default() -> Keychain {
        Self::find_default().expect("no default keychain available")
    }
}

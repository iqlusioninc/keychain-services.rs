//! Keychains

use core_foundation::base::TCFType;
use std::{ffi::CString, os::raw::c_char, os::unix::ffi::OsStrExt, path::Path, ptr};

use error::Error;
use ffi::*;

declare_TCFType!{
    /// Object which represents a keychain.
    ///
    /// Wrapper for the `SecKeychain`/`SecKeychainRef` types:
    /// <https://developer.apple.com/documentation/security/seckeychainref>
    SecKeychain, SecKeychainRef
}

impl_TCFType!(SecKeychain, SecKeychainRef, SecKeychainGetTypeID);

impl SecKeychain {
    /// Create a new keychain. Accepts a path where the new keychain will be
    /// located along with an optional password. If no password is given, the
    /// user will be prompted for a password.
    ///
    /// Wrapper for the `SecKeychainCreate` function. See:
    /// <https://developer.apple.com/documentation/security/1401214-seckeychaincreate>
    pub fn create(path: &Path, password: Option<&str>) -> Result<SecKeychain, Error> {
        let path_cstring = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut result: SecKeychainRef = ptr::null_mut();

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
            return Err(e);
        }

        Ok(unsafe { SecKeychain::wrap_under_create_rule(result) })
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
}

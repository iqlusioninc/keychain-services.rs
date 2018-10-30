//! Error types

use core_foundation::{
    base::{CFRelease, CFTypeRef, OSStatus, TCFType},
    error::{CFErrorCopyDescription, CFErrorGetCode, CFErrorGetDomain, CFErrorRef},
    string::CFString,
};
use failure::{Backtrace, Fail};
use std::{
    fmt::{self, Display},
    ptr,
};

use ffi::*;

/// No error occurred.
/// <https://developer.apple.com/documentation/security/errsecsuccess>
const errSecSuccess: OSStatus = 0;

/// Authentication and/or authorization failed.
/// <https://developer.apple.com/documentation/security/errsecauthfailed>
const errSecAuthFailed: OSStatus = -25293;

/// Buffer is too small.
/// <https://developer.apple.com/documentation/security/errsecbuffertoosmall>
const errSecBufferTooSmall: OSStatus = -25301;

/// Certificate chain creation attempt failed.
/// <https://developer.apple.com/documentation/security/errseccreatechainfailed>
const errSecCreateChainFailed: OSStatus = -25318;

/// Data too large for the given data type.
/// <https://developer.apple.com/documentation/security/errsecdatatoolarge>
const errSecDataTooLarge: OSStatus = -25302;

/// Data is not available.
/// <https://developer.apple.com/documentation/security/errsecdatanotavailable>
const errSecDataNotAvailable: OSStatus = -25316;

/// Data cannot be modified.
/// <https://developer.apple.com/documentation/security/errsecdatanotmodifiable>
const errSecDataNotModifiable: OSStatus = -25317;

/// Callback with the same name already exists.
/// <https://developer.apple.com/documentation/security/errsecduplicatecallback>
const errSecDuplicateCallback: OSStatus = -25297;

/// Item already exists.
/// <https://developer.apple.com/documentation/security/errsecduplicateitem>
const errSecDuplicateItem: OSStatus = -25299;

/// Keychain with the same name already exists.
/// <https://developer.apple.com/documentation/security/errsecduplicatekeychain>
const errSecDuplicateKeychain: OSStatus = -25296;

/// System is in a dark wake state - user interface cannot be displayed.
/// <https://developer.apple.com/documentation/security/errsecindarkwake>
const errSecInDarkWake: OSStatus = -25320;

/// Security Server interactions not allowed in this context.
/// <https://developer.apple.com/documentation/security/errsecinteractionnotallowed>
const errSecInteractionNotAllowed: OSStatus = -25308;

/// User interaction required.
/// <https://developer.apple.com/documentation/security/errsecinteractionrequired>
const errSecInteractionRequired: OSStatus = -25315;

/// Callback is invalid.
/// <https://developer.apple.com/documentation/security/errsecinvalidcallback>
const errSecInvalidCallback: OSStatus = -25298;

/// Item reference is invalid.
/// <https://developer.apple.com/documentation/security/errsecinvaliditemref>
const errSecInvalidItemRef: OSStatus = -25304;

/// Keychain is invalid.
/// <https://developer.apple.com/documentation/security/errsecinvalidkeychain>
const errSecInvalidKeychain: OSStatus = -25295;

/// Specified preference domain is not valid.
/// <https://developer.apple.com/documentation/security/errsecinvalidprefsdomain>
const errSecInvalidPrefsDomain: OSStatus = -25319;

/// Search reference is invalid.
/// <https://developer.apple.com/documentation/security/errsecinvalidsearchref>
const errSecInvalidSearchRef: OSStatus = -25305;

/// Item could not be found.
/// <https://developer.apple.com/documentation/security/errsecitemnotfound>
const errSecItemNotFound: OSStatus = -25300;

/// Invalid key size.
/// <https://developer.apple.com/documentation/security/errseckeysizenotallowed>
const errSecKeySizeNotAllowed: OSStatus = -25311;

/// Missing entitlement: keychain access disallowed because app is unsigned.
/// <https://developer.apple.com/documentation/security/errsecmissingentitlement>
const errSecMissingEntitlement: OSStatus = -34018;

/// Certificate module unavailable.
/// <https://developer.apple.com/documentation/security/errsecnocertificatemodule>
const errSecNoCertificateModule: OSStatus = -25313;

/// Default keychain does not exist.
/// <https://developer.apple.com/documentation/security/errsecnodefaultkeychain>
const errSecNoDefaultKeychain: OSStatus = -25307;

/// Policy module unavailable.
/// <https://developer.apple.com/documentation/security/errsecnopolicymodule>
const errSecNoPolicyModule: OSStatus = -25314;

/// Storage module unavailable.
/// <https://developer.apple.com/documentation/security/errsecnostoragemodule>
const errSecNoStorageModule: OSStatus = -25312;

/// Specified attribute does not exist.
/// <https://developer.apple.com/documentation/security/errsecnosuchattr>
const errSecNoSuchAttr: OSStatus = -25303;

/// Specified keychain item class does not exist.
/// <https://developer.apple.com/documentation/security/errsecnosuchclass>
const errSecNoSuchClass: OSStatus = -25306;

/// Specified keychain does not exist.
/// <https://developer.apple.com/documentation/security/errsecnosuchkeychain>
const errSecNoSuchKeychain: OSStatus = -25294;

/// Trust results not available.
/// <https://developer.apple.com/documentation/security/errsecnotavailable>
const errSecNotAvailable: OSStatus = -25291;

/// Can't perform given action on read-only item.
/// <https://developer.apple.com/documentation/security/errsecreadonly>
const errSecReadOnly: OSStatus = -25292;

/// Can't perform action on read-only attribute
/// <https://developer.apple.com/documentation/security/errsecreadonlyattr>
const errSecReadOnlyAttr: OSStatus = -25309;

/// Invalid version.
/// <https://developer.apple.com/documentation/security/errsecwrongversion>
const errSecWrongSecVersion: OSStatus = -25310;

/// Error type.
///
/// Wrapper for the `CFError` type:
/// <https://developer.apple.com/documentation/corefoundation/cferror>
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    backtrace: Backtrace,
    description: String,
}

impl Error {
    /// Create an error from an `OSStatus` if the status is not success
    pub fn maybe_from_OSStatus(status: OSStatus) -> Option<Self> {
        if status == errSecSuccess {
            None
        } else {
            let kind = ErrorKind::from(status);
            let backtrace = Backtrace::new();
            let description = unsafe {
                CFString::wrap_under_create_rule(SecCopyErrorMessageString(status, ptr::null()))
            }.to_string();

            Some(Error {
                kind,
                backtrace,
                description,
            })
        }
    }

    /// Get the `ErrorKind` for this error
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", &self.description, &self.kind)
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        None
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        Some(&self.backtrace)
    }
}

impl From<CFErrorRef> for Error {
    /// Creates an `Error` with copies of all error data on the Rust heap.
    ///
    /// Calls `CFRelease` on the provided `CFErrorRef`.
    fn from(error_ref: CFErrorRef) -> Error {
        let kind = ErrorKind::from(error_ref);
        let backtrace = Backtrace::new();
        let description =
            unsafe { CFString::wrap_under_create_rule(CFErrorCopyDescription(error_ref)) }
                .to_string();

        // Free the error reference
        unsafe {
            CFRelease(error_ref as CFTypeRef);
        }

        Error {
            kind,
            backtrace,
            description,
        }
    }
}

/// Kinds of errors.
#[derive(Clone, Debug, Fail)]
pub enum ErrorKind {
    /// Authentication and/or authorization failed.
    ///
    /// Wrapper for the `errSecAuthFailed` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecauthfailed>
    #[fail(display = "authentication failed")]
    AuthFailed,

    /// Buffer is too small.
    ///
    /// Wrapper for the `errSecBufferTooSmall` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecbuffertoosmall>
    #[fail(display = "buffer too small")]
    BufferTooSmall,

    /// Certificate chain creation attempt failed.
    ///
    /// Wrapper for the `errSecCreateChainFailed` status code. See:
    /// <https://developer.apple.com/documentation/security/errseccreatechainfailed>
    #[fail(display = "certificate chain creation attempt failed")]
    CreateChainFailed,

    /// Data too large for the given data type.
    ///
    /// Wrapper for the `errSecDataTooLarge` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecdatatoolarge>
    #[fail(display = "data too large")]
    DataTooLarge,

    /// Data is not available.
    ///
    /// Wrapper for the `errSecDataNotAvailable` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecdatanotavailable>
    #[fail(display = "data not available")]
    DataNotAvailable,

    /// Data cannot be modified.
    ///
    /// Wrapper for the `errSecDataNotModifiable` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecdatanotmodifiable>
    #[fail(display = "data not modifiable")]
    DataNotModifiable,

    /// Callback with the same name already exists.
    ///
    /// Wrapper for the `errSecDuplicateCallback` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecduplicatecallback>
    #[fail(display = "duplicate callback")]
    DuplicateCallback,

    /// Item already exists.
    ///
    /// Wrapper for the `errSecDuplicateItem` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecduplicateitem>
    #[fail(display = "duplicate item")]
    DuplicateItem,

    /// Keychain with the same name already exists.
    ///
    /// Wrapper for the `errSecDuplicateKeychain` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecduplicatekeychain>
    #[fail(display = "duplicate keychain")]
    DuplicateKeychain,

    /// System is in a dark wake state - user interface cannot be displayed.
    ///
    /// Wrapper for the `errSecInDarkWake` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecindarkwake>
    #[fail(display = "in dark wake")]
    InDarkWake,

    /// Security Server interactions not allowed in this context.
    ///
    /// Wrapper for the `errSecInteractionNotAllowed` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinteractionnotallowed>
    #[fail(display = "interaction not allowed")]
    InteractionNotAllowed,

    /// User interaction required.
    ///
    /// Wrapper for the `errSecInteractionRequired` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinteractionrequired>
    #[fail(display = "user interaction required")]
    InteractionRequired,

    /// Callback is invalid.
    ///
    /// Wrapper for the `errSecInvalidCallback` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinvalidcallback>
    #[fail(display = "invalid callback")]
    InvalidCallback,

    /// Item reference is invalid.
    ///
    /// Wrapper for the `errSecInvalidItemRef` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinvaliditemref>
    #[fail(display = "invalid item ref")]
    InvalidItemRef,

    /// Keychain is invalid.
    ///
    /// Wrapper for the `errSecInvalidKeychain` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinvalidkeychain>
    #[fail(display = "invalid keychain")]
    InvalidKeychain,

    /// Specified preference domain is not valid.
    ///
    /// Wrapper for the `errSecInvalidPrefsDomain` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinvalidprefsdomain>
    #[fail(display = "invalid preference domain")]
    InvalidPrefsDomain,

    /// Search reference is invalid.
    ///
    /// Wrapper for the `errSecInvalidSearchRef` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecinvalidsearchref>
    #[fail(display = "search ref is invalid")]
    InvalidSearchRef,

    /// Item could not be found.
    ///
    /// Wrapper for the `errSecItemNotFound` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecitemnotfound>
    #[fail(display = "item not found")]
    ItemNotFound,

    /// Invalid key size.
    ///
    /// Wrapper for the `errSecKeySizeNotAllowed` status code. See:
    /// <https://developer.apple.com/documentation/security/errseckeysizenotallowed>
    #[fail(display = "key size not allowed")]
    KeySizeNotAllowed,

    /// Required entitlement for accessing the keychain is missing. This error
    /// occurs when attempting to access certain keychain functionality from an
    /// application which is either unsigned or missing a required entitlement.
    ///
    /// Wrapper for the `errSecMissingEntitlement` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecmissingentitlement>
    #[fail(display = "missing application entitlement (errSecMissingEntitlement)")]
    MissingEntitlement,

    /// Certificate module unavailable.
    ///
    /// Wrapper for the `errSecNoCertificateModule` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnocertificatemodule>
    #[fail(display = "no certificate module")]
    NoCertificateModule,

    /// Default keychain does not exist.
    ///
    /// Wrapper for the `errSecNoDefaultKeychain` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnodefaultkeychain>
    #[fail(display = "no default keychain")]
    NoDefaultKeychain,

    /// Policy module unavailable.
    ///
    /// Wrapper for the `errSecNoPolicyModule` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnopolicymodule>
    #[fail(display = "no policy module")]
    NoPolicyModule,

    /// Storage module unavailable.
    ///
    /// Wrapper for the `errSecNoStorageModule` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnostoragemodule>
    #[fail(display = "no storage module")]
    NoStorageModule,

    /// Specified attribute does not exist.
    ///
    /// Wrapper for the `errSecNoSuchAttr` status code. See:;
    /// <https://developer.apple.com/documentation/security/errsecnosuchattr>
    #[fail(display = "no such attr")]
    NoSuchAttr,

    /// Specified keychain item class does not exist.
    ///
    /// Wrapper for the `errSecNoSuchClass` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnosuchclass>
    #[fail(display = "no such class")]
    NoSuchClass,

    /// Specified keychain does not exist.
    ///
    /// Wrapper for the `errSecNoSuchKeychain` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnosuchkeychain>
    #[fail(display = "no such keychain")]
    NoSuchKeychain,

    /// Trust results not available.
    ///
    /// Wrapper for the `errSecNotAvailable` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecnotavailable>
    #[fail(display = "not available")]
    NotAvailable,

    /// Can't perform given action on read-only item.
    ///
    /// Wrapper for the `errSecReadOnly` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecreadonly>
    #[fail(display = "read-only")]
    ReadOnly,

    /// Can't perform action on read-only attribute
    ///
    /// Wrapper for the `errSecReadOnlyAttr` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecreadonlyattr>
    #[fail(display = "read-only attr")]
    ReadOnlyAttr,

    /// Invalid version.
    ///
    /// Wrapper for the `errSecWrongSecVersion` status code. See:
    /// <https://developer.apple.com/documentation/security/errsecwrongversion>
    #[fail(display = "wrong version")]
    WrongSecVersion,

    /// Errors returned from CoreFoundation.
    ///
    /// Codes correspond to the return value of the `CFErrorGetCode` function.
    ///
    /// For more information, see:
    /// <https://developer.apple.com/documentation/corefoundation/1494656-cferrorgetcode?language=objc>
    #[fail(
        display = "Core Foundation error (code: {}, domain: {})",
        code,
        domain
    )]
    CFError {
        /// Code identifying this type of `CFError`.
        ///
        /// See `CFErrorGetCode()` for more information:
        /// <https://developer.apple.com/documentation/corefoundation/1494656-cferrorgetcode>
        code: i64,

        /// Domain associated with this error.
        ///
        /// See `CFErrorGetDomain()` for more information:
        /// <https://developer.apple.com/documentation/corefoundation/1494657-cferrorgetdomain>
        domain: String,
    },

    /// `OSStatus` codes which we can't otherwise decode.
    #[fail(display = "unknown OS error (code: {})", code)]
    OSError {
        /// OS error code
        code: i64,
    },
}

impl From<CFErrorRef> for ErrorKind {
    fn from(error_ref: CFErrorRef) -> ErrorKind {
        ErrorKind::CFError {
            code: unsafe { CFErrorGetCode(error_ref) } as i64,
            domain: unsafe { CFString::wrap_under_get_rule(CFErrorGetDomain(error_ref)) }
                .to_string(),
        }
    }
}

impl From<OSStatus> for ErrorKind {
    fn from(status: OSStatus) -> ErrorKind {
        match status {
            errSecAuthFailed => ErrorKind::AuthFailed,
            errSecBufferTooSmall => ErrorKind::BufferTooSmall,
            errSecCreateChainFailed => ErrorKind::CreateChainFailed,
            errSecDataTooLarge => ErrorKind::DataTooLarge,
            errSecDataNotAvailable => ErrorKind::DataNotAvailable,
            errSecDataNotModifiable => ErrorKind::DataNotModifiable,
            errSecDuplicateCallback => ErrorKind::DuplicateCallback,
            errSecDuplicateItem => ErrorKind::DuplicateItem,
            errSecDuplicateKeychain => ErrorKind::DuplicateKeychain,
            errSecInDarkWake => ErrorKind::InDarkWake,
            errSecInteractionNotAllowed => ErrorKind::InteractionNotAllowed,
            errSecInteractionRequired => ErrorKind::InteractionRequired,
            errSecInvalidCallback => ErrorKind::InvalidCallback,
            errSecInvalidItemRef => ErrorKind::InvalidItemRef,
            errSecInvalidKeychain => ErrorKind::InvalidKeychain,
            errSecInvalidPrefsDomain => ErrorKind::InvalidPrefsDomain,
            errSecInvalidSearchRef => ErrorKind::InvalidSearchRef,
            errSecItemNotFound => ErrorKind::ItemNotFound,
            errSecKeySizeNotAllowed => ErrorKind::KeySizeNotAllowed,
            errSecMissingEntitlement => ErrorKind::MissingEntitlement,
            errSecNoCertificateModule => ErrorKind::NoCertificateModule,
            errSecNoDefaultKeychain => ErrorKind::NoDefaultKeychain,
            errSecNoPolicyModule => ErrorKind::NoPolicyModule,
            errSecNoStorageModule => ErrorKind::NoStorageModule,
            errSecNoSuchAttr => ErrorKind::NoSuchAttr,
            errSecNoSuchClass => ErrorKind::NoSuchClass,
            errSecNoSuchKeychain => ErrorKind::NoSuchKeychain,
            errSecNotAvailable => ErrorKind::NotAvailable,
            errSecReadOnly => ErrorKind::ReadOnly,
            errSecReadOnlyAttr => ErrorKind::ReadOnlyAttr,
            errSecWrongSecVersion => ErrorKind::WrongSecVersion,
            _ => ErrorKind::OSError {
                code: i64::from(status),
            },
        }
    }
}

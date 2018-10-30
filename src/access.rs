//! Keychain item access control types: ACLs and policies around usage of
//! private keys stored in the keychain.

use core_foundation::{
    base::{kCFAllocatorDefault, CFOptionFlags, CFTypeRef, TCFType},
    error::CFErrorRef,
};
use std::{
    fmt::{self, Debug},
    ptr,
};

use attr::SecAttrAccessible;
use error::Error;
use ffi::*;

/// Marker trait for types which can be used as `SecAccessControlFlags`.
pub trait SecAccessControlFlag: Copy + Clone + Sized + Into<CFOptionFlags> {}

/// Constraints on keychain item access.
///
/// See "Constraints" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum SecAccessConstraint {
    /// Require either passcode or biometric auth (TouchID/FaceID).
    ///
    /// Wrapper for `kSecAccessControlUserPresence`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontroluserpresence>
    UserPresence,

    /// Require biometric auth (TouchID/FaceID) from any enrolled user for this device.
    ///
    /// Wrapper for `kSecAccessControlBiometryAny`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolbiometryany>
    BiometryAny,

    /// Require biometric auth (TouchID/FaceID) from the current user.
    ///
    /// Wrapper for `kSecAccessControlBiometryCurrentSet`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolbiometrycurrentset>
    BiometryCurrentSet,

    /// Require device passcode.
    ///
    /// Wrapper for `kSecAccessControlDevicePasscode`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontroldevicepasscode>
    DevicePasscode,
}

impl SecAccessControlFlag for SecAccessConstraint {}

impl From<SecAccessConstraint> for CFOptionFlags {
    fn from(constraint: SecAccessConstraint) -> CFOptionFlags {
        match constraint {
            SecAccessConstraint::UserPresence => 1,
            SecAccessConstraint::BiometryAny => 1 << 1,
            SecAccessConstraint::BiometryCurrentSet => 1 << 3,
            SecAccessConstraint::DevicePasscode => 1 << 4,
        }
    }
}

/// Conjunctions (and/or) on keychain item access.
///
/// See "Conjunctions" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum SecAccessConjunction {
    /// Require *all* constraints be satisfied.
    ///
    /// Wrapper for `kSecAccessControlAnd`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontroland>
    And,

    /// Require *at least one* constraint must be satisfied.
    ///
    /// Wrapper for `kSecAccessControlOr`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolor>
    Or,
}

impl SecAccessControlFlag for SecAccessConjunction {}

impl From<SecAccessConjunction> for CFOptionFlags {
    fn from(conjunction: SecAccessConjunction) -> CFOptionFlags {
        match conjunction {
            SecAccessConjunction::Or => 1 << 14,
            SecAccessConjunction::And => 1 << 15,
        }
    }
}

/// Options for keychain item access.
///
/// See "Additional Options" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum SecAccessOption {
    /// Require private key be stored in the device's Secure Enclave.
    ///
    /// Wrapper for `kSecAccessControlApplicationPassword`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolprivatekeyusage>
    PrivateKeyUsage,

    /// Generate encryption-key from an application-provided password.
    ///
    /// Wrapper for `kSecAccessControlPrivateKeyUsage`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolapplicationpassword>
    ApplicationPassword,
}

impl SecAccessControlFlag for SecAccessOption {}

impl From<SecAccessOption> for CFOptionFlags {
    fn from(option: SecAccessOption) -> CFOptionFlags {
        match option {
            SecAccessOption::PrivateKeyUsage => 1 << 30,
            SecAccessOption::ApplicationPassword => 1 << 31,
        }
    }
}

/// Access control restrictions for a particular keychain item.
///
/// More information about restricting keychain items can be found at:
/// <https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility>
///
/// Wrapper for the `SecAccessControlCreateFlags` type:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SecAccessControlFlags(CFOptionFlags);

impl SecAccessControlFlags {
    /// Create `SecAccessControlFlags` with no policy set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an `SecAccessControlFlag` to this set of flags.
    // TODO: handle illegal combinations of flags?
    pub fn add<F: SecAccessControlFlag>(&mut self, flag: F) {
        self.0 |= flag.into();
    }
}

/// Shorthand syntax for when flags are all of the same type
impl<'a, F> From<&'a [F]> for SecAccessControlFlags
where
    F: SecAccessControlFlag,
{
    fn from(flags: &[F]) -> SecAccessControlFlags {
        let mut result = SecAccessControlFlags::new();

        for flag in flags {
            result.add(*flag)
        }

        result
    }
}

/// Reference to an access control policy.
///
/// See `SecAccessControlRef` documentation:
/// <https://developer.apple.com/documentation/security/secaccesscontrolref>
type SecAccessControlRef = CFTypeRef;

declare_TCFType!{
    /// Access control policy (a.k.a. ACL) for a keychain item, combining both a
    /// set of `SecAccessControlFlags` and a `SecAttrAccessible` restriction.
    ///
    /// Wrapper for the `SecAccessControl`/`SecAccessControlRef` types:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolref>
    SecAccessControl, SecAccessControlRef
}

impl_TCFType!(
    SecAccessControl,
    SecAccessControlRef,
    SecAccessControlGetTypeID
);

impl SecAccessControl {
    /// Create a new `AccessControl` policy/ACL.
    ///
    /// Wrapper for the `SecAccessControlCreateWithFlags()` function:
    /// <https://developer.apple.com/documentation/security/1394452-secaccesscontrolcreatewithflags>
    pub fn create_with_flags(
        protection: SecAttrAccessible,
        flags: SecAccessControlFlags,
    ) -> Result<Self, Error> {
        let mut error: CFErrorRef = ptr::null_mut();

        let result = unsafe {
            SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                protection.as_CFString().as_CFTypeRef(),
                flags.0,
                &mut error,
            )
        };

        if error.is_null() {
            Ok(unsafe { Self::wrap_under_create_rule(result) })
        } else {
            Err(error.into())
        }
    }
}

impl Debug for SecAccessControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: display more information about `SecAccessControl`s
        write!(f, "SecAccessControl {{ ... }}")
    }
}

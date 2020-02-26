//! Keychain item access control types: ACLs and policies around usage of
//! private keys stored in the keychain.

use crate::{attr::AttrAccessible, error::Error, ffi::*};
use core_foundation::{
    base::{kCFAllocatorDefault, CFOptionFlags, TCFType},
    error::CFErrorRef,
};
use std::{
    fmt::{self, Debug},
    ptr,
};

/// Marker trait for types which can be used as `AccessControlFlags`.
pub trait AccessControlFlag: Copy + Clone + Sized + Into<CFOptionFlags> {}

/// Constraints on keychain item access.
///
/// See "Constraints" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum AccessConstraint {
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

impl AccessControlFlag for AccessConstraint {}

impl From<AccessConstraint> for CFOptionFlags {
    fn from(constraint: AccessConstraint) -> CFOptionFlags {
        match constraint {
            AccessConstraint::UserPresence => 1,
            AccessConstraint::BiometryAny => 1 << 1,
            AccessConstraint::BiometryCurrentSet => 1 << 3,
            AccessConstraint::DevicePasscode => 1 << 4,
        }
    }
}

/// Conjunctions (and/or) on keychain item access.
///
/// See "Conjunctions" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum AccessConjunction {
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

impl AccessControlFlag for AccessConjunction {}

impl From<AccessConjunction> for CFOptionFlags {
    fn from(conjunction: AccessConjunction) -> CFOptionFlags {
        match conjunction {
            AccessConjunction::Or => 1 << 14,
            AccessConjunction::And => 1 << 15,
        }
    }
}

/// Options for keychain item access.
///
/// See "Additional Options" topic under the "Topics" section of the
/// `SecAccessControlCreateFlags` documentation at:
/// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum AccessOption {
    /// Require private key be stored in the device's Secure Enclave.
    ///
    /// Wrapper for `kSecAccessControlPrivateKeyUsage`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolprivatekeyusage>
    PrivateKeyUsage,

    /// Generate encryption-key from an application-provided password.
    ///
    /// Wrapper for `kSecAccessControlApplicationPassword`. See:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontrolapplicationpassword>
    ApplicationPassword,
}

impl AccessControlFlag for AccessOption {}

impl From<AccessOption> for CFOptionFlags {
    fn from(option: AccessOption) -> CFOptionFlags {
        match option {
            AccessOption::PrivateKeyUsage => 1 << 30,
            AccessOption::ApplicationPassword => 1 << 31,
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
pub struct AccessControlFlags(CFOptionFlags);

impl AccessControlFlags {
    /// Create `SecAccessControlFlags` with no policy set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an `AccessControlFlag` to this set of flags.
    // TODO: handle illegal combinations of flags?
    pub fn add<F: AccessControlFlag>(&mut self, flag: F) {
        self.0 |= flag.into();
    }
}

/// Shorthand syntax for when flags are all of the same type
impl<'a, F> From<&'a [F]> for AccessControlFlags
where
    F: AccessControlFlag,
{
    fn from(flags: &[F]) -> AccessControlFlags {
        let mut result = AccessControlFlags::new();

        for flag in flags {
            result.add(*flag)
        }

        result
    }
}

declare_TCFType! {
    /// Access control policy (a.k.a. ACL) for a keychain item, combining both a
    /// set of `AccessControlFlags` and a `AttrAccessible` restriction.
    ///
    /// Wrapper for the `SecAccessControl`/`SecAccessControlRef` types:
    /// <https://developer.apple.com/documentation/security/secaccesscontrolref>
    AccessControl, AccessControlRef
}

impl_TCFType!(AccessControl, AccessControlRef, SecAccessControlGetTypeID);

impl AccessControl {
    /// Create a new `AccessControl` policy/ACL.
    ///
    /// Wrapper for the `SecAccessControlCreateWithFlags()` function:
    /// <https://developer.apple.com/documentation/security/1394452-secaccesscontrolcreatewithflags>
    pub fn create_with_flags(
        protection: AttrAccessible,
        flags: AccessControlFlags,
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

impl Debug for AccessControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: display more information about `AccessControl`s
        write!(f, "SecAccessControl {{ ... }}")
    }
}

use core_foundation::base::{CFIndex, CFIndexConvertible};

use self::KeyOperation::*;
/// Types of operations that a cryptographic key can perform
///
/// Wrapper for `SecKeyOperationType`. See:
/// <https://developer.apple.com/documentation/security/seckeyoperationtype>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyOperation {
    /// Decrypt operation
    Decrypt,
    /// Encrypt operation
    Encrypt,
    /// KeyExchange operation
    KeyExchange,
    /// Sign operation
    Sign,
    /// Verify operation
    Verify,
}

impl CFIndexConvertible for KeyOperation {
    fn to_CFIndex(self) -> CFIndex {
        let i = match self {
            Decrypt => 3,
            Encrypt => 2,
            KeyExchange => 4,
            Sign => 0,
            Verify => 1,
        };
        i as CFIndex
    }
}

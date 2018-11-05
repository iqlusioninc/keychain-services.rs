//! Keychain item attributes (i.e. `SecAttr*`)

use core_foundation::{
    base::{CFType, TCFType, ToVoid},
    data::CFData,
    string::{CFString, CFStringRef},
};
use std::{
    ffi::c_void,
    fmt::{self, Debug, Display},
    str::{self, Utf8Error},
};

use ffi::*;

/// Trait implemented by all `SecAttr*` types to simplify adding them to
/// attribute dictionaries.
pub(crate) trait TSecAttr {
    /// Get the attribute kind (i.e. `SecAttr` enum variant) for this attribute
    fn kind(&self) -> SecAttr;

    /// Get a `CFType` object representing this attribute.
    fn as_CFType(&self) -> CFType;
}

/// Enum of attribute types passed in parameter dictionaries. This wraps up
/// access to framework constants which would otherwise be unsafe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SecAttr {
    /// Wrapper for the `kSecAttrAccessControl` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattraccesscontrol>
    AccessControl,

    /// Wrapper for the `kSecAttrAccessible` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattraccessible>
    Accessible,

    /// Wrapper for the `kSecAttrAccount` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattraccount>
    Account,

    /// Wrapper for the `kSecAttrApplicationLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    ApplicationLabel,

    /// Wrapper for the `kSecAttrApplicationTag` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrapplicationtag>
    ApplicationTag,

    /// Wrapper for the `kSecAttrKeyClass` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclass>
    KeyClass,

    /// Wrapper for the `kSecAttrKeySizeInBits` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeysizeinbits>
    KeySizeInBits,

    /// Wrapper for the `kSecAttrKeyType` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeytype>
    KeyType,

    /// Wrapper for the `kSecAttrIsPermanent` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrispermanent>
    IsPermanent,

    /// Wrapper for the `kSecAttrLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    Label,

    /// Wrapper for the `kSecAttrProtocol` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrprotocol>
    Protocol,

    /// Wrapper for the `kSecAttrServer` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrserver>
    Server,

    /// Wrapper for the `kSecAttrService` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrservice>
    Service,

    /// Wrapper for the `kSecAttrSynchronizable` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrsynchronizable>
    Synchronizable,

    /// Wrapper for the `kSecAttrTokenID` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenid>
    TokenId,
}

impl From<SecAttr> for CFStringRef {
    fn from(attr: SecAttr) -> CFStringRef {
        unsafe {
            match attr {
                SecAttr::AccessControl => kSecAttrAccessControl,
                SecAttr::Accessible => kSecAttrAccessible,
                SecAttr::Account => kSecAttrAccount,
                SecAttr::ApplicationLabel => kSecAttrApplicationLabel,
                SecAttr::ApplicationTag => kSecAttrApplicationTag,
                SecAttr::KeyClass => kSecAttrKeyClass,
                SecAttr::KeySizeInBits => kSecAttrKeySizeInBits,
                SecAttr::KeyType => kSecAttrKeyType,
                SecAttr::IsPermanent => kSecAttrIsPermanent,
                SecAttr::Label => kSecAttrLabel,
                SecAttr::Protocol => kSecAttrProtocol,
                SecAttr::Server => kSecAttrServer,
                SecAttr::Service => kSecAttrService,
                SecAttr::Synchronizable => kSecAttrSynchronizable,
                SecAttr::TokenId => kSecAttrTokenID,
            }
        }
    }
}

unsafe impl ToVoid<CFType> for SecAttr {
    fn to_void(&self) -> *const c_void {
        CFStringRef::from(*self).to_void()
    }
}

/// Keychain item accessibility restrictions (from most to least restrictive).
///
/// More information about restricting keychain items can be found at:
/// <https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility>
///
/// Wrapper for the `kSecAttrAccessible` attribute key. See
/// "Accessibility Values" section of "Item Attribute Keys and Values":
/// <https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecAttrAccessible {
    /// Device is unlocked and a passcode has been set on the device.
    /// <https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly>
    WhenPasscodeSetThisDeviceOnly,

    /// The device is unlocked (no passcode mandatory). Non-exportable.
    /// <https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly>
    WhenUnlockedThisDeviceOnly,

    /// The device is unlocked (no passcode mandatory).
    /// <https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked>
    WhenUnlocked,

    /// Permanently accessible after the device is first unlocked after boot.
    /// Non-exportable.
    /// <https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlockthisdeviceonly>
    AfterFirstUnlockThisDeviceOnly,

    /// Permanently accessible after the device is first unlocked after boot.
    /// <https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock>
    AfterFirstUnlock,

    /// Item is always accessible on this device. Non-exportable.
    /// <https://developer.apple.com/documentation/security/ksecattraccessiblealwaysthisdeviceonly>
    AlwaysThisDeviceOnly,

    /// Item is always accessible.
    /// <https://developer.apple.com/documentation/security/ksecattraccessiblealways>
    Always,
}

impl SecAttrAccessible {
    /// Get pointer to an accessibility value to associate with the
    /// `kSecAttrAccessible` key for a keychain item
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecAttrAccessible::WhenPasscodeSetThisDeviceOnly => {
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                }
                SecAttrAccessible::WhenUnlockedThisDeviceOnly => {
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                }
                SecAttrAccessible::WhenUnlocked => kSecAttrAccessibleWhenUnlocked,
                SecAttrAccessible::AfterFirstUnlockThisDeviceOnly => {
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                }
                SecAttrAccessible::AfterFirstUnlock => kSecAttrAccessibleAfterFirstUnlock,
                SecAttrAccessible::AlwaysThisDeviceOnly => kSecAttrAccessibleAlwaysThisDeviceOnly,
                SecAttrAccessible::Always => kSecAttrAccessibleAlways,
            })
        }
    }
}

impl TSecAttr for SecAttrAccessible {
    fn kind(&self) -> SecAttr {
        SecAttr::Accessible
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

/// Application-specific key labels, i.e. key fingerprints.
///
/// Not to be confused with `SecAttrApplicationTag` or `SecAttrLabel`, the
/// `SecAttrApplicationLabel` value is useful for programatically looking up
/// public/private key pairs, and is set to the hash of the public key, a.k.a.
/// the public key fingerprint.
///
/// Wrapper for the `kSecAttrApplicationLabel` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrapplicationlabel>
#[derive(Clone, Eq, PartialEq)]
pub struct SecAttrApplicationLabel(pub(crate) CFData);

impl SecAttrApplicationLabel {
    /// Create a new application label from a byte slice
    pub fn new(bytes: &[u8]) -> Self {
        SecAttrApplicationLabel(CFData::from_buffer(bytes))
    }

    /// Borrow this value as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecAttrApplicationLabel {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Debug for SecAttrApplicationLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = Vec::from(self.as_bytes());
        write!(f, "SecAttrApplicationLabel({:?})", bytes)
    }
}

impl<'a> From<&'a [u8]> for SecAttrApplicationLabel {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl TSecAttr for SecAttrApplicationLabel {
    fn kind(&self) -> SecAttr {
        SecAttr::ApplicationLabel
    }

    fn as_CFType(&self) -> CFType {
        self.0.as_CFType()
    }
}

/// Application-specific tags for keychain items.
///
/// These should be unique for a specific item (i.e. named after its purpose
/// and used as the "primary key" for locating a particular keychain item),
/// and often use a reversed domain name-like syntax, e.g.
/// `io.crates.PackageSigning`
///
/// Wrapper for the `kSecAttrApplicationTag` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrapplicationtag>
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecAttrApplicationTag(pub(crate) CFData);

impl SecAttrApplicationTag {
    /// Create a new application tag from a byte slice
    pub fn new(bytes: &[u8]) -> Self {
        SecAttrApplicationTag(CFData::from_buffer(bytes))
    }

    /// Borrow the tag data as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the tag data as a `str` (if it is valid UTF-8)
    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(self.as_bytes())
    }
}

impl AsRef<[u8]> for SecAttrApplicationTag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Display for SecAttrApplicationTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl<'a> From<&'a [u8]> for SecAttrApplicationTag {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl<'a> From<&'a str> for SecAttrApplicationTag {
    fn from(string: &str) -> Self {
        Self::new(string.as_bytes())
    }
}

impl TSecAttr for SecAttrApplicationTag {
    fn kind(&self) -> SecAttr {
        SecAttr::ApplicationTag
    }

    fn as_CFType(&self) -> CFType {
        self.0.as_CFType()
    }
}

/// Human readable/meaningful labels for keychain items.
///
/// Wrapper for the `kSecAttrLabel` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrlabel>
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecAttrLabel(pub(crate) CFString);

impl SecAttrLabel {
    /// Create a new label from a `&str`
    pub fn new(label: &str) -> Self {
        SecAttrLabel(CFString::new(label))
    }
}

impl Display for SecAttrLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl<'a> From<&'a str> for SecAttrLabel {
    fn from(label: &str) -> Self {
        Self::new(label)
    }
}

impl TSecAttr for SecAttrLabel {
    fn kind(&self) -> SecAttr {
        SecAttr::Label
    }

    fn as_CFType(&self) -> CFType {
        self.0.as_CFType()
    }
}

/// Classes of keys supported by Keychain Services (not to be confused with
/// `SecClass`, `SecAttrClass` or `SecAttrKeyType`)
///
/// Wrapper for the `kSecAttrKeyClass` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrkeyclass>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecAttrKeyClass {
    /// Public keys.
    ///
    /// Wrapper for the `kSecAttrKeyClassPublic` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclasspublic>
    Public,

    /// Private keys.
    ///
    /// Wrapper for the `kSecAttrKeyClassPrivate` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclassprivate>
    Private,

    /// Symmetric keys
    ///
    /// Wrapper for the `kSecAttrKeyClassSymmetric` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclasssymmetric>
    // TODO: support for symmetric encryption
    Symmetric,
}

impl SecAttrKeyClass {
    /// Get `CFString` containing the `kSecAttrKeyClass` dictionary value for
    /// this particular `SecAttrKeyClass`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecAttrKeyClass::Public => kSecAttrKeyClassPublic,
                SecAttrKeyClass::Private => kSecAttrKeyClassPrivate,
                SecAttrKeyClass::Symmetric => kSecAttrKeyClassSymmetric,
            })
        }
    }
}

impl TSecAttr for SecAttrKeyClass {
    fn kind(&self) -> SecAttr {
        SecAttr::KeyClass
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

/// Types of keys supported by Keychain Services (not to be confused with
/// `SecAttrKeyClass`)
///
/// Wrapper for the `kSecAttrKeyType` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrkeytype>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecAttrKeyType {
    /// AES algorithm.
    ///
    /// Wrapper for the `kSecAttrKeyTypeAES` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeytypeaes>
    // TODO: support for AES encryption
    Aes,

    /// RSA algorithm.
    ///
    /// Wrapper for the `kSecAttrKeyTypeRSA` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeytypersa>
    Rsa,

    /// Elliptic curve cryptography over the NIST curves (e.g. P-256)
    ///
    /// Wrapper for the `kSecAttrKeyTypeECSECPrimeRandom` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeytypeecsecprimerandom>
    EcSecPrimeRandom,
}

impl SecAttrKeyType {
    /// Get `CFString` containing the `kSecAttrKeyType` dictionary value for
    /// this particular `SecAttrKeyType`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecAttrKeyType::Aes => kSecAttrKeyTypeAES,
                SecAttrKeyType::Rsa => kSecAttrKeyTypeRSA,
                SecAttrKeyType::EcSecPrimeRandom => kSecAttrKeyTypeECSECPrimeRandom,
            })
        }
    }
}

impl TSecAttr for SecAttrKeyType {
    fn kind(&self) -> SecAttr {
        SecAttr::KeyType
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

/// Internet protocols optionally associated with `SecClass::InternetPassword`
/// keychain items.
///
/// Wrapper for the `kSecAttrProtocol` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrprotocol>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecAttrProtocol {
    /// File Transfer Protocol
    FTP,

    /// Client-side FTP account.
    FTPAccount,

    /// Hypertext Transfer Protocol.
    HTTP,

    /// Internet Relay Chat.
    IRC,

    /// Network News Transfer Protocol.
    NNTP,

    /// Post Office Protocol v3.
    POP3,

    /// Simple Mail Transfer Protocol.
    SMTP,

    /// SOCKS protocol.
    SOCKS,

    /// Internet Message Access Protocol.
    IMAP,

    /// Lightweight Directory Access Protocol.
    LDAP,

    /// AFP over AppleTalk.
    AppleTalk,

    /// AFP over TCP.
    AFP,

    /// Telnet protocol.
    Telnet,

    /// Secure Shell Protocol.
    SSH,

    /// FTP over TLS/SSL.
    FTPS,

    /// HTTP over TLS/SSL.
    HTTPS,

    /// HTTP proxy.
    HTTPProxy,

    /// HTTPS proxy.
    HTTPSProxy,

    /// FTP proxy.
    FTPProxy,

    /// Server Message Block protocol.
    SMB,

    /// Real Time Streaming Protocol
    RTSP,

    /// RTSP proxy.
    RTSPProxy,

    /// DAAP protocol.
    DAAP,

    /// Remote Apple Events.
    EPPC,

    /// IPP protocol.
    IPP,

    /// NNTP over TLS/SSL.
    NNTPS,

    /// LDAP over TLS/SSL.
    LDAPS,

    /// Telnet over TLS/SSL.
    TelnetS,

    /// IMAP over TLS/SSL.
    IMAPS,

    /// IRC over TLS/SSL.
    IRCS,

    /// POP3 over TLS/SSL.
    POP3S,
}

impl SecAttrProtocol {
    /// Get `CFString` containing the `kSecAttrProtocol` dictionary value for
    /// this particular `SecAttrProtocol`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecAttrProtocol::FTP => kSecAttrProtocolFTP,
                SecAttrProtocol::FTPAccount => kSecAttrProtocolFTPAccount,
                SecAttrProtocol::HTTP => kSecAttrProtocolHTTP,
                SecAttrProtocol::IRC => kSecAttrProtocolIRC,
                SecAttrProtocol::NNTP => kSecAttrProtocolNNTP,
                SecAttrProtocol::POP3 => kSecAttrProtocolPOP3,
                SecAttrProtocol::SMTP => kSecAttrProtocolSMTP,
                SecAttrProtocol::SOCKS => kSecAttrProtocolSOCKS,
                SecAttrProtocol::IMAP => kSecAttrProtocolIMAP,
                SecAttrProtocol::LDAP => kSecAttrProtocolLDAP,
                SecAttrProtocol::AppleTalk => kSecAttrProtocolAppleTalk,
                SecAttrProtocol::AFP => kSecAttrProtocolAFP,
                SecAttrProtocol::Telnet => kSecAttrProtocolTelnet,
                SecAttrProtocol::SSH => kSecAttrProtocolSSH,
                SecAttrProtocol::FTPS => kSecAttrProtocolFTPS,
                SecAttrProtocol::HTTPS => kSecAttrProtocolHTTPS,
                SecAttrProtocol::HTTPProxy => kSecAttrProtocolHTTPProxy,
                SecAttrProtocol::HTTPSProxy => kSecAttrProtocolHTTPSProxy,
                SecAttrProtocol::FTPProxy => kSecAttrProtocolFTPProxy,
                SecAttrProtocol::SMB => kSecAttrProtocolSMB,
                SecAttrProtocol::RTSP => kSecAttrProtocolRTSP,
                SecAttrProtocol::RTSPProxy => kSecAttrProtocolRTSPProxy,
                SecAttrProtocol::DAAP => kSecAttrProtocolDAAP,
                SecAttrProtocol::EPPC => kSecAttrProtocolEPPC,
                SecAttrProtocol::IPP => kSecAttrProtocolIPP,
                SecAttrProtocol::NNTPS => kSecAttrProtocolNNTPS,
                SecAttrProtocol::LDAPS => kSecAttrProtocolLDAPS,
                SecAttrProtocol::TelnetS => kSecAttrProtocolTelnetS,
                SecAttrProtocol::IMAPS => kSecAttrProtocolIMAPS,
                SecAttrProtocol::IRCS => kSecAttrProtocolIRCS,
                SecAttrProtocol::POP3S => kSecAttrProtocolPOP3S,
            })
        }
    }
}

impl TSecAttr for SecAttrProtocol {
    fn kind(&self) -> SecAttr {
        SecAttr::Protocol
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

/// Identifiers for external storage tokens for cryptographic keys
/// (i.e. Secure Enclave).
///
/// Wrapper for the `kSecAttrTokenID` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrtokenid>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecAttrTokenId {
    /// Secure Enclave Processor (SEP), e.g. T1/T2 chip.
    ///
    /// Wrapper for the `kSecAttrTokenIDSecureEnclave` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave>
    SecureEnclave,
}

impl SecAttrTokenId {
    /// Get `CFString` containing the `kSecAttrTokenID` dictionary value for
    /// this particular `SecAttrTokenId`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                SecAttrTokenId::SecureEnclave => kSecAttrTokenIDSecureEnclave,
            })
        }
    }
}

impl TSecAttr for SecAttrTokenId {
    fn kind(&self) -> SecAttr {
        SecAttr::TokenId
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

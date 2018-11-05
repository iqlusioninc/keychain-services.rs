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

/// Trait implemented by all `Attr*` types to simplify adding them to
/// attribute dictionaries.
pub(crate) trait TAttr {
    /// Get the attribute kind (i.e. `SecAttr` enum variant) for this attribute
    fn kind(&self) -> Attr;

    /// Get a `CFType` object representing this attribute.
    fn as_CFType(&self) -> CFType;
}

/// Enum of attribute types passed in parameter dictionaries. This wraps up
/// access to framework constants which would otherwise be unsafe.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Attr {
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

impl From<Attr> for CFStringRef {
    fn from(attr: Attr) -> CFStringRef {
        unsafe {
            match attr {
                Attr::AccessControl => kSecAttrAccessControl,
                Attr::Accessible => kSecAttrAccessible,
                Attr::Account => kSecAttrAccount,
                Attr::ApplicationLabel => kSecAttrApplicationLabel,
                Attr::ApplicationTag => kSecAttrApplicationTag,
                Attr::KeyClass => kSecAttrKeyClass,
                Attr::KeySizeInBits => kSecAttrKeySizeInBits,
                Attr::KeyType => kSecAttrKeyType,
                Attr::IsPermanent => kSecAttrIsPermanent,
                Attr::Label => kSecAttrLabel,
                Attr::Protocol => kSecAttrProtocol,
                Attr::Server => kSecAttrServer,
                Attr::Service => kSecAttrService,
                Attr::Synchronizable => kSecAttrSynchronizable,
                Attr::TokenId => kSecAttrTokenID,
            }
        }
    }
}

unsafe impl ToVoid<CFType> for Attr {
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
pub enum AttrAccessible {
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

impl AttrAccessible {
    /// Get pointer to an accessibility value to associate with the
    /// `kSecAttrAccessible` key for a keychain item
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                AttrAccessible::WhenPasscodeSetThisDeviceOnly => {
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                }
                AttrAccessible::WhenUnlockedThisDeviceOnly => {
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                }
                AttrAccessible::WhenUnlocked => kSecAttrAccessibleWhenUnlocked,
                AttrAccessible::AfterFirstUnlockThisDeviceOnly => {
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                }
                AttrAccessible::AfterFirstUnlock => kSecAttrAccessibleAfterFirstUnlock,
                AttrAccessible::AlwaysThisDeviceOnly => kSecAttrAccessibleAlwaysThisDeviceOnly,
                AttrAccessible::Always => kSecAttrAccessibleAlways,
            })
        }
    }
}

impl TAttr for AttrAccessible {
    fn kind(&self) -> Attr {
        Attr::Accessible
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
pub struct AttrApplicationLabel(pub(crate) CFData);

impl AttrApplicationLabel {
    /// Create a new application label from a byte slice
    pub fn new(bytes: &[u8]) -> Self {
        AttrApplicationLabel(CFData::from_buffer(bytes))
    }

    /// Borrow this value as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for AttrApplicationLabel {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Debug for AttrApplicationLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = Vec::from(self.as_bytes());
        write!(f, "SecAttrApplicationLabel({:?})", bytes)
    }
}

impl<'a> From<&'a [u8]> for AttrApplicationLabel {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl TAttr for AttrApplicationLabel {
    fn kind(&self) -> Attr {
        Attr::ApplicationLabel
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
pub struct AttrApplicationTag(pub(crate) CFData);

impl AttrApplicationTag {
    /// Create a new application tag from a byte slice
    pub fn new(bytes: &[u8]) -> Self {
        AttrApplicationTag(CFData::from_buffer(bytes))
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

impl AsRef<[u8]> for AttrApplicationTag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Display for AttrApplicationTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl<'a> From<&'a [u8]> for AttrApplicationTag {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl<'a> From<&'a str> for AttrApplicationTag {
    fn from(string: &str) -> Self {
        Self::new(string.as_bytes())
    }
}

impl TAttr for AttrApplicationTag {
    fn kind(&self) -> Attr {
        Attr::ApplicationTag
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
pub struct AttrLabel(pub(crate) CFString);

impl AttrLabel {
    /// Create a new label from a `&str`
    pub fn new(label: &str) -> Self {
        AttrLabel(CFString::new(label))
    }
}

impl Display for AttrLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl<'a> From<&'a str> for AttrLabel {
    fn from(label: &str) -> Self {
        Self::new(label)
    }
}

impl TAttr for AttrLabel {
    fn kind(&self) -> Attr {
        Attr::Label
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
pub enum AttrKeyClass {
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

impl AttrKeyClass {
    /// Get `CFString` containing the `kSecAttrKeyClass` dictionary value for
    /// this particular `SecAttrKeyClass`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                AttrKeyClass::Public => kSecAttrKeyClassPublic,
                AttrKeyClass::Private => kSecAttrKeyClassPrivate,
                AttrKeyClass::Symmetric => kSecAttrKeyClassSymmetric,
            })
        }
    }
}

impl TAttr for AttrKeyClass {
    fn kind(&self) -> Attr {
        Attr::KeyClass
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

/// Types of keys supported by Keychain Services (not to be confused with
/// `AttrKeyClass`)
///
/// Wrapper for the `kSecAttrKeyType` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecattrkeytype>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttrKeyType {
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

impl AttrKeyType {
    /// Get `CFString` containing the `kSecAttrKeyType` dictionary value for
    /// this particular `SecAttrKeyType`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                AttrKeyType::Aes => kSecAttrKeyTypeAES,
                AttrKeyType::Rsa => kSecAttrKeyTypeRSA,
                AttrKeyType::EcSecPrimeRandom => kSecAttrKeyTypeECSECPrimeRandom,
            })
        }
    }
}

impl TAttr for AttrKeyType {
    fn kind(&self) -> Attr {
        Attr::KeyType
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
pub enum AttrProtocol {
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

impl AttrProtocol {
    /// Get `CFString` containing the `kSecAttrProtocol` dictionary value for
    /// this particular `SecAttrProtocol`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                AttrProtocol::FTP => kSecAttrProtocolFTP,
                AttrProtocol::FTPAccount => kSecAttrProtocolFTPAccount,
                AttrProtocol::HTTP => kSecAttrProtocolHTTP,
                AttrProtocol::IRC => kSecAttrProtocolIRC,
                AttrProtocol::NNTP => kSecAttrProtocolNNTP,
                AttrProtocol::POP3 => kSecAttrProtocolPOP3,
                AttrProtocol::SMTP => kSecAttrProtocolSMTP,
                AttrProtocol::SOCKS => kSecAttrProtocolSOCKS,
                AttrProtocol::IMAP => kSecAttrProtocolIMAP,
                AttrProtocol::LDAP => kSecAttrProtocolLDAP,
                AttrProtocol::AppleTalk => kSecAttrProtocolAppleTalk,
                AttrProtocol::AFP => kSecAttrProtocolAFP,
                AttrProtocol::Telnet => kSecAttrProtocolTelnet,
                AttrProtocol::SSH => kSecAttrProtocolSSH,
                AttrProtocol::FTPS => kSecAttrProtocolFTPS,
                AttrProtocol::HTTPS => kSecAttrProtocolHTTPS,
                AttrProtocol::HTTPProxy => kSecAttrProtocolHTTPProxy,
                AttrProtocol::HTTPSProxy => kSecAttrProtocolHTTPSProxy,
                AttrProtocol::FTPProxy => kSecAttrProtocolFTPProxy,
                AttrProtocol::SMB => kSecAttrProtocolSMB,
                AttrProtocol::RTSP => kSecAttrProtocolRTSP,
                AttrProtocol::RTSPProxy => kSecAttrProtocolRTSPProxy,
                AttrProtocol::DAAP => kSecAttrProtocolDAAP,
                AttrProtocol::EPPC => kSecAttrProtocolEPPC,
                AttrProtocol::IPP => kSecAttrProtocolIPP,
                AttrProtocol::NNTPS => kSecAttrProtocolNNTPS,
                AttrProtocol::LDAPS => kSecAttrProtocolLDAPS,
                AttrProtocol::TelnetS => kSecAttrProtocolTelnetS,
                AttrProtocol::IMAPS => kSecAttrProtocolIMAPS,
                AttrProtocol::IRCS => kSecAttrProtocolIRCS,
                AttrProtocol::POP3S => kSecAttrProtocolPOP3S,
            })
        }
    }
}

impl TAttr for AttrProtocol {
    fn kind(&self) -> Attr {
        Attr::Protocol
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
pub enum AttrTokenId {
    /// Secure Enclave Processor (SEP), e.g. T1/T2 chip.
    ///
    /// Wrapper for the `kSecAttrTokenIDSecureEnclave` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave>
    SecureEnclave,
}

impl AttrTokenId {
    /// Get `CFString` containing the `kSecAttrTokenID` dictionary value for
    /// this particular `SecAttrTokenId`.
    pub fn as_CFString(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                AttrTokenId::SecureEnclave => kSecAttrTokenIDSecureEnclave,
            })
        }
    }
}

impl TAttr for AttrTokenId {
    fn kind(&self) -> Attr {
        Attr::TokenId
    }

    fn as_CFType(&self) -> CFType {
        self.as_CFString().as_CFType()
    }
}

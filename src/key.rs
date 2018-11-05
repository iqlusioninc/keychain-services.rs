//! Keys stored in macOS Keychain Services.

use core_foundation::{
    base::{CFTypeRef, TCFType},
    data::{CFData, CFDataRef},
    error::CFErrorRef,
    string::{CFString, CFStringRef},
};
use std::{
    fmt::{self, Debug},
    ptr,
};

use access::AccessControl;
use algorithm::KeyAlgorithm;
use attr::*;
use dictionary::{Dictionary, DictionaryBuilder};
use error::Error;
use ffi::*;
use item::Class;
use query::{ItemQuery, MatchLimit};
use signature::Signature;

declare_TCFType!{
    /// Object which represents a cryptographic key.
    ///
    /// Wrapper for the `SecKey`/`SecKeyRef` types:
    /// <https://developer.apple.com/documentation/security/seckeyref>
    Key, KeyRef
}

impl_TCFType!(Key, KeyRef, SecKeyGetTypeID);

impl Key {
    /// Find a `Key` in the keyring using the given `ItemQuery`.
    ///
    /// Wrapper for `SecItemCopyMatching`. See:
    /// <https://developer.apple.com/documentation/security/1398306-secitemcopymatching>
    pub fn find(query: ItemQuery) -> Result<Self, Error> {
        let mut params = DictionaryBuilder::from(query);
        params.add(unsafe { kSecClass }, &Class::Key.as_CFString());
        params.add(unsafe { kSecMatchLimit }, &MatchLimit::One.as_CFType());
        params.add_boolean(unsafe { kSecReturnRef }, true);

        let mut result: KeyRef = ptr::null_mut();
        let status = unsafe {
            SecItemCopyMatching(
                Dictionary::from(params).as_concrete_TypeRef(),
                &mut result as &mut CFTypeRef,
            )
        };

        // Return an error if the status was unsuccessful
        if let Some(e) = Error::maybe_from_OSStatus(status) {
            return Err(e);
        }

        Ok(unsafe { Key::wrap_under_create_rule(result) })
    }

    /// Get the `AttrApplicationLabel` for this `Key`.
    pub fn application_label(&self) -> Option<AttrApplicationLabel> {
        self.attributes().find(Attr::ApplicationLabel).map(|tag| {
            AttrApplicationLabel(unsafe {
                CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
            })
        })
    }

    /// Get the `AttrApplicationTag` for this `Key`.
    pub fn application_tag(&self) -> Option<AttrApplicationTag> {
        self.attributes().find(Attr::ApplicationTag).map(|tag| {
            AttrApplicationTag(unsafe {
                CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
            })
        })
    }

    /// Get the `AttrLabel` for this `Key`.
    pub fn label(&self) -> Option<AttrLabel> {
        self.attributes().find(Attr::Label).map(|label| {
            AttrLabel(unsafe { CFString::wrap_under_get_rule(label.as_CFTypeRef() as CFStringRef) })
        })
    }

    /// Create a cryptographic signature of the given data using this key.
    ///
    /// Wrapper for the `SecKeyCreateSignature` function. See:
    /// <https://developer.apple.com/documentation/security/1643916-seckeycreatesignature>
    pub fn sign(&self, alg: KeyAlgorithm, data: &[u8]) -> Result<Signature, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let signature = unsafe {
            SecKeyCreateSignature(
                self.as_concrete_TypeRef(),
                alg.as_CFString().as_CFTypeRef(),
                CFData::from_buffer(data).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            let bytes = unsafe { CFData::wrap_under_create_rule(signature) }.to_vec();
            Ok(Signature::new(alg, bytes))
        } else {
            Err(error.into())
        }
    }

    /// Export this key as an external representation.
    ///
    /// If the key is not exportable the operation will fail (e.g. if it
    /// was generated inside of the Secure Enclave, or if the "Extractable"
    /// flag is set to NO).
    ///
    /// The data returned depends on the key type:
    ///
    /// - RSA: PKCS#1 format
    /// - EC: ANSI X9.63 bytestring:
    ///   - Public key: `04 || X || Y`
    ///   - Private key: Concatenation of public key with big endian encoding
    ///     of the secret scalar, i.e. `04 || X || Y || K`
    ///
    /// All representations use fixed-size integers with leading zeroes.
    ///
    /// Wrapper for the `SecKeyCopyExternalRepresentation` function. See:
    /// <https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation>
    pub fn to_external_representation(&self) -> Result<Vec<u8>, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let data =
            unsafe { SecKeyCopyExternalRepresentation(self.as_concrete_TypeRef(), &mut error) };

        if error.is_null() {
            Ok(unsafe { CFData::wrap_under_create_rule(data) }.to_vec())
        } else {
            Err(error.into())
        }
    }

    /// Fetch attributes for this `Key`.
    ///
    /// Wrapper for `SecKeyCopyAttributes`. See:
    /// <https://developer.apple.com/documentation/security/1643699-seckeycopyattributes>
    fn attributes(&self) -> Dictionary {
        unsafe { Dictionary::wrap_under_get_rule(SecKeyCopyAttributes(self.as_concrete_TypeRef())) }
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SecKey {{ application_label: {:?}, application_tag: {:?}, label: {:?} }}",
            self.application_label(),
            self.application_tag(),
            self.label()
        )
    }
}

/// Public key pairs (i.e. public and private key) stored in the keychain.
#[derive(Debug)]
pub struct KeyPair {
    /// Public key
    pub public_key: Key,

    /// Private key
    pub private_key: Key,
}

impl KeyPair {
    /// Generate a public/private `KeyPair` using the given
    /// `GeneratePairParams`.
    ///
    /// Wrapper for the `SecKeyGeneratePair` function. See:
    /// <https://developer.apple.com/documentation/security/1395339-seckeygeneratepair>
    pub fn generate(params: GeneratePairParams) -> Result<KeyPair, Error> {
        let mut public_key_ref: KeyRef = ptr::null_mut();
        let mut private_key_ref: KeyRef = ptr::null_mut();

        let status = unsafe {
            SecKeyGeneratePair(
                Dictionary::from(params).as_concrete_TypeRef(),
                &mut public_key_ref,
                &mut private_key_ref,
            )
        };

        // Return an error if the status was unsuccessful
        if let Some(e) = Error::maybe_from_OSStatus(status) {
            return Err(e);
        }

        assert!(!public_key_ref.is_null());
        assert!(!private_key_ref.is_null());

        Ok(unsafe {
            KeyPair {
                public_key: Key::wrap_under_create_rule(public_key_ref),
                private_key: Key::wrap_under_create_rule(private_key_ref),
            }
        })
    }
}

/// Builder for key generation parameters (passed to the underlying
/// `SecKeyGeneratePair` function)
///
/// For more information on generating cryptographic keys in a keychain, see:
/// <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys>
#[derive(Clone, Debug)]
pub struct GeneratePairParams {
    key_type: AttrKeyType,
    key_size: usize,
    attrs: DictionaryBuilder,
}

impl GeneratePairParams {
    /// Create a new `GeneratePairParams`
    pub fn new(key_type: AttrKeyType, key_size: usize) -> Self {
        Self {
            key_type,
            key_size,
            attrs: <_>::default(),
        }
    }

    /// Set the access control policy (a.k.a. ACL) for the `Key`.
    ///
    /// Wrapper for the `kSecAttrAccessControl` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattraccesscontrol>
    pub fn access_control(mut self, access_control: &AccessControl) -> Self {
        self.attrs
            .add(Attr::AccessControl, &access_control.as_CFType());
        self
    }

    /// Set a tag (private, application-specific identifier) on this key.
    /// Tags are useful as the "primary key" for looking up keychain items.
    ///
    /// Wrapper for `kSecAttrApplicationTag` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrapplicationtag>
    pub fn application_tag<T>(mut self, tag: T) -> Self
    where
        T: Into<AttrApplicationTag>,
    {
        self.attrs.add_attr(&tag.into());
        self
    }

    /// Set whether this key is stored permanently in the keychain (default: false).
    ///
    /// Wrapper for the `kSecAttrIsPermanent` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrispermanent>
    pub fn permanent(mut self, value: bool) -> Self {
        self.attrs.add_boolean(Attr::IsPermanent, value);
        self
    }

    /// Set a string label on this key. SecAttrLabels are useful for providing
    /// additional descriptions or context on keys.
    ///
    /// Wrapper for the `kSecAttrLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    pub fn label<L: Into<AttrLabel>>(mut self, label: L) -> Self {
        self.attrs.add_attr(&label.into());
        self
    }

    /// Set whether this key can be synchronized with other devices owned by
    /// the same account (default: false).
    ///
    /// Wrapper for the `kSecAttrSynchronizable` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrsynchronizable>
    pub fn synchronizable(mut self, value: bool) -> Self {
        self.attrs.add_boolean(Attr::Synchronizable, value);
        self
    }

    /// Store this key in an external token i.e. Secure Enclave Processor (SEP).
    ///
    /// Wrapper for the `kSecAttrTokenID` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenid>
    pub fn token_id(mut self, value: AttrTokenId) -> Self {
        self.attrs.add_attr(&value);
        self
    }
}

impl From<GeneratePairParams> for Dictionary {
    fn from(params: GeneratePairParams) -> Dictionary {
        let mut result = DictionaryBuilder::new();
        result.add_attr(&params.key_type);
        result.add_number(Attr::KeySizeInBits, params.key_size as i64);
        result.add(
            unsafe { kSecPrivateKeyAttrs },
            &Dictionary::from(params.attrs),
        );
        result.into()
    }
}

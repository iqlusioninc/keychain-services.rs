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

use access::SecAccessControl;
use algorithm::SecKeyAlgorithm;
use attr::*;
use dictionary::{CFDictionary, CFDictionaryBuilder};
use error::Error;
use ffi::*;
use item::SecClass;
use query::{SecItemQueryParams, SecMatchLimit};
use signature::SecSignature;

declare_TCFType!{
    /// Object which represents a cryptographic key.
    ///
    /// Wrapper for the `SecKey`/`SecKeyRef` types:
    /// <https://developer.apple.com/documentation/security/seckeyref>
    SecKey, SecKeyRef
}

impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

impl SecKey {
    /// Find a `SecKey` in the keyring using the given `SecItemQuery`.
    ///
    /// Wrapper for `SecItemCopyMatching`. See:
    /// <https://developer.apple.com/documentation/security/1398306-secitemcopymatching>
    pub fn find(query: SecItemQueryParams) -> Result<Self, Error> {
        let mut params = CFDictionaryBuilder::from(query);
        params.add(unsafe { kSecClass }, &SecClass::Key.as_CFString());
        params.add(unsafe { kSecMatchLimit }, &SecMatchLimit::One.as_CFType());
        params.add_boolean(unsafe { kSecReturnRef }, true);

        let mut result: SecKeyRef = ptr::null_mut();
        let status = unsafe {
            SecItemCopyMatching(
                CFDictionary::from(params).as_concrete_TypeRef(),
                &mut result as &mut CFTypeRef,
            )
        };

        // Return an error if the status was unsuccessful
        if let Some(e) = Error::maybe_from_OSStatus(status) {
            return Err(e);
        }

        // TODO: is this a create or a get?
        Ok(unsafe { SecKey::wrap_under_create_rule(result) })
    }

    /// Get the `SecAttrApplicationLabel` for this `SecKey`.
    pub fn application_label(&self) -> Option<SecAttrApplicationLabel> {
        self.attributes()
            .find(SecAttr::ApplicationLabel)
            .map(|tag| {
                SecAttrApplicationLabel(unsafe {
                    CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
                })
            })
    }

    /// Get the `SecAttrApplicationTag` for this `SecKey`.
    pub fn application_tag(&self) -> Option<SecAttrApplicationTag> {
        self.attributes().find(SecAttr::ApplicationTag).map(|tag| {
            SecAttrApplicationTag(unsafe {
                CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
            })
        })
    }

    /// Get the `SecAttrLabel` for this `SecKey`.
    pub fn label(&self) -> Option<SecAttrLabel> {
        self.attributes().find(SecAttr::Label).map(|label| {
            SecAttrLabel(unsafe {
                CFString::wrap_under_get_rule(label.as_CFTypeRef() as CFStringRef)
            })
        })
    }

    /// Create a cryptographic signature of the given data using this key.
    ///
    /// Wrapper for the `SecKeyCreateSignature` function. See:
    /// <https://developer.apple.com/documentation/security/1643916-seckeycreatesignature>
    pub fn sign(&self, alg: SecKeyAlgorithm, data: &[u8]) -> Result<SecSignature, Error> {
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
            Ok(SecSignature::new(alg, bytes))
        } else {
            Err(error.into())
        }
    }

    /// Export this key as an external representation.
    ///
    /// If the key is not exportable the operation will fail (e.g. if it
    /// was generated inside of the Secure Enclave, or if `kSecKeyExtractable`
    /// is set to NO).
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

    /// Fetch attributes for this `SecKey`.
    ///
    /// Wrapper for `SecKeyCopyAttributes`. See:
    /// <https://developer.apple.com/documentation/security/1643699-seckeycopyattributes>
    fn attributes(&self) -> CFDictionary {
        unsafe {
            CFDictionary::wrap_under_get_rule(SecKeyCopyAttributes(self.as_concrete_TypeRef()))
        }
    }
}

impl Debug for SecKey {
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
pub struct SecKeyPair {
    /// Public key
    pub public_key: SecKey,

    /// Private key
    pub private_key: SecKey,
}

impl SecKeyPair {
    /// Generate a public/private `SecKey` pair using the given
    /// `SecKeyGeneratePairParams`.
    ///
    /// Wrapper for the `SecKeyGeneratePair` function. See:
    /// <https://developer.apple.com/documentation/security/1395339-seckeygeneratepair>
    pub fn generate(params: SecKeyGeneratePairParams) -> Result<SecKeyPair, Error> {
        let mut public_key_ref: SecKeyRef = ptr::null_mut();
        let mut private_key_ref: SecKeyRef = ptr::null_mut();

        let status = unsafe {
            SecKeyGeneratePair(
                CFDictionary::from(params).as_concrete_TypeRef(),
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

        // TODO: check status to ensure success
        let public_key = unsafe { SecKey::wrap_under_create_rule(public_key_ref) };
        let private_key = unsafe { SecKey::wrap_under_create_rule(private_key_ref) };

        Ok(SecKeyPair {
            public_key,
            private_key,
        })
    }
}

/// Builder for key generation parameters (passed to the underlying
/// `SecKeyGeneratePair` function)
///
/// For more information on generating cryptographic keys in a keychain, see:
/// <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys>
#[derive(Clone, Debug)]
pub struct SecKeyGeneratePairParams {
    key_type: SecAttrKeyType,
    key_size: usize,
    attrs: CFDictionaryBuilder,
}

impl SecKeyGeneratePairParams {
    /// Create a new `SecKeyGeneratePairParams`
    pub fn new(key_type: SecAttrKeyType, key_size: usize) -> Self {
        Self {
            key_type,
            key_size,
            attrs: <_>::default(),
        }
    }

    /// Set the access control policy (a.k.a. ACL) for the `SecKey`.
    ///
    /// Wrapper for the `kSecAttrAccessControl` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattraccesscontrol>
    pub fn access_control(mut self, access_control: &SecAccessControl) -> Self {
        self.attrs
            .add(SecAttr::AccessControl, &access_control.as_CFType());
        self
    }

    /// Set a tag (private, application-specific identifier) on this key.
    /// Tags are useful as the "primary key" for looking up keychain items.
    ///
    /// Wrapper for `kSecAttrApplicationTag` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrapplicationtag>
    pub fn application_tag<T>(mut self, tag: T) -> Self
    where
        T: Into<SecAttrApplicationTag>,
    {
        self.attrs.add_attr(&tag.into());
        self
    }

    /// Set whether this key is stored permanently in the keychain (default: false).
    ///
    /// Wrapper for the `kSecAttrIsPermanent` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrispermanent>
    pub fn permanent(mut self, value: bool) -> Self {
        self.attrs.add_boolean(SecAttr::IsPermanent, value);
        self
    }

    /// Set a string label on this key. SecAttrLabels are useful for providing
    /// additional descriptions or context on keys.
    ///
    /// Wrapper for the `kSecAttrLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    pub fn label<L: Into<SecAttrLabel>>(mut self, label: L) -> Self {
        self.attrs.add_attr(&label.into());
        self
    }

    /// Set whether this key can be synchronized with other devices owned by
    /// the same account (default: false).
    ///
    /// Wrapper for the `kSecAttrSynchronizable` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrsynchronizable>
    pub fn synchronizable(mut self, value: bool) -> Self {
        self.attrs.add_boolean(SecAttr::Synchronizable, value);
        self
    }

    /// Store this key in an external token i.e. Secure Enclave Processor (SEP).
    ///
    /// Wrapper for the `kSecAttrTokenID` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenid>
    pub fn token_id(mut self, value: SecAttrTokenId) -> Self {
        self.attrs.add_attr(&value);
        self
    }
}

impl From<SecKeyGeneratePairParams> for CFDictionary {
    fn from(params: SecKeyGeneratePairParams) -> CFDictionary {
        let mut result = CFDictionaryBuilder::new();
        result.add_attr(&params.key_type);
        result.add_number(SecAttr::KeySizeInBits, params.key_size as i64);
        result.add(
            unsafe { kSecPrivateKeyAttrs },
            &CFDictionary::from(params.attrs),
        );
        result.into()
    }
}

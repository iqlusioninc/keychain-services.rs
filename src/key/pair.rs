use core_foundation::base::TCFType;
use std::ptr;

use super::*;
use access::AccessControl;
use dictionary::*;
use error::Error;

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
    pub fn generate(params: KeyPairGenerateParams) -> Result<KeyPair, Error> {
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
pub struct KeyPairGenerateParams {
    key_type: AttrKeyType,
    key_size: usize,
    attrs: DictionaryBuilder,
}

impl KeyPairGenerateParams {
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
        self.attrs.add(Attr::AccessControl, access_control);
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

impl From<KeyPairGenerateParams> for Dictionary {
    fn from(params: KeyPairGenerateParams) -> Dictionary {
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

use super::*;
use crate::{access::AccessControl, dictionary::*, error::Error};
use core_foundation::base::TCFType;
use std::ptr;

/// Public key pairs (i.e. public and private key) stored in the keychain.
#[derive(Debug)]
pub struct KeyPair {
    /// Public key
    pub public_key: Key,

    /// Private key
    pub private_key: Key,
}

impl KeyPair {
    /// An asymmetric cryptographic key pair is composed of a public and a private key that are generated together.
    /// The public key can be distributed freely, but keep the private key secret.
    /// One or both may be stored in a keychain for safekeeping.
    ///
    /// Wrapper for the `SecKeyCreateRandomKey` function see:
    /// <https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey>
    pub fn create(params: KeyPairGenerateParams) -> Result<KeyPair, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let private_key_ref: KeyRef = unsafe {
            SecKeyCreateRandomKey(Dictionary::from(params).as_concrete_TypeRef(), &mut error)
        };
        if private_key_ref.is_null() {
            Err(error.into())
        } else {
            let public_key_ref = unsafe { SecKeyCopyPublicKey(private_key_ref) };
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
        self.attrs.add(AttrKind::AccessControl, access_control);
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

    /// Set whether this key can be used in a key derivation operation
    ///
    /// Wrapper for the `kSecKeyDerive` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeyderive>
    pub fn can_derive(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Derive, value);
        self
    }

    /// Set whether this key can be used in a decrypt operation.
    ///
    /// Wrapper for the `kSecKeyDecrypt` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeydecrypt>
    pub fn can_decrypt(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Decrypt, value);
        self
    }

    /// Set whether this key can be used in a encrypt operation.
    ///
    /// Wrapper for the `kSecKeyEncrypt` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeyencrypt>
    pub fn can_encrypt(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Encrypt, value);
        self
    }

    /// Set whether this key can be used in a signing operation.
    ///
    /// Wrapper for the `kSecKeySign` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeysign>
    pub fn can_sign(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Sign, value);
        self
    }

    /// Set whether this key can be used to verify a signatures.
    ///
    /// Wrapper for the `kSecKeyVerify` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeyverify>
    pub fn can_verify(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Verify, value);
        self
    }

    /// Set whether this key can be used to wrap another key.
    ///
    /// Wrapper for the `kSecKeyWrap` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeywrap>
    pub fn can_wrap(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Wrap, value);
        self
    }

    /// Set whether this key can be used to unwrap another key.
    ///
    /// Wrapper for the `kSecKeyUnwrap` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeyunwrap>
    pub fn can_unwrap(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Unwrap, value);
        self
    }

    /// Set a key's cryptographic class.
    ///
    /// Wrapper for the `kSecAttrKeyClass` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclass>
    pub fn key_class(mut self, value: AttrKeyClass) -> Self {
        self.attrs.add(AttrKind::KeyClass, &value.as_CFString());
        self
    }

    /// Set whether this key can be extractable when wrapped
    ///
    /// Wrapper for the `kSecKeyExtractable` attribute key. See:
    /// <https://developer.apple.com/documentation/security/kseckeyextractable>
    pub fn extractable(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Extractable, value);
        self
    }

    /// Set whether this key is stored permanently in the keychain (default: false).
    ///
    /// Wrapper for the `kSecAttrIsPermanent` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrispermanent>
    pub fn permanent(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Permanent, value);
        self
    }

    /// Set whether this key can be wrapped with NONE algorithm. True
    /// means it cannot be wrapped with NONE, false means it can.
    ///
    /// Wrapper for `kSecKeySensitive` attribute key. See
    /// <https://developer.apple.com/documentation/security/kseckeysensitive>
    pub fn sensitive(mut self, value: bool) -> Self {
        self.attrs.add_boolean(AttrKind::Sensitive, value);
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
        self.attrs.add_boolean(AttrKind::Synchronizable, value);
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
        result.add_number(AttrKind::KeySizeInBits, params.key_size as i64);
        result.add(
            unsafe { kSecPrivateKeyAttrs },
            &Dictionary::from(params.attrs),
        );
        result.into()
    }
}

/// Builder for restoring a key from an external representation of that key parameters
/// (passed to the underlying `SecKeyCreateWithData` function).
///
/// The key must have already been imported or generated.
///
/// For more information on restoring cryptographic keys in keychain, see
/// <https://developer.apple.com/documentation/security/1643701-seckeycreatewithdata>
#[derive(Clone, Debug)]
pub struct RestoreKeyParams {
    /// The category the key fits (public, private, or symmetric)
    pub key_class: AttrKeyClass,
    /// Data representing the key. The format of the data depends on the type of key
    /// being created.
    ///
    /// - RSA: PKCS#1 format
    /// - EC: ANSI X9.63 bytestring:
    ///   - Public key: `04 || X || Y`
    ///   - Private key: Concatenation of public key with big endian encoding
    ///     of the secret scalar, i.e. `04 || X || Y || K`
    ///
    /// All representations use fixed-size integers with leading zeroes.
    pub key_data: Vec<u8>,
    /// The type of key algorithm
    pub key_type: AttrKeyType,
}

impl RestoreKeyParams {
    /// Return the attributes that will be used to restore the key
    pub fn attributes(&self) -> Dictionary {
        let mut result = DictionaryBuilder::new();
        result.add_attr(&self.key_type);
        result.add(AttrKind::KeyClass, &self.key_class.as_CFString());
        result.add_number(AttrKind::KeySizeInBits, (self.key_data.len() * 8) as i64);
        result.into()
    }

    /// Return the `key_data` as a slice
    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.as_slice()
    }
}

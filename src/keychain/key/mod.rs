//! Keys stored in macOS Keychain Services.

mod algorithm;
mod operation;
mod pair;

pub use self::{algorithm::*, operation::*, pair::*};
use crate::{
    attr::*,
    ciphertext::Ciphertext,
    dictionary::{Dictionary, DictionaryBuilder},
    error::Error,
    ffi::*,
    keychain::item::{self, MatchLimit},
    signature::Signature,
};
use core_foundation::{
    base::{CFIndexConvertible, CFType, CFTypeRef, FromVoid, TCFType},
    data::{CFData, CFDataRef},
    error::CFErrorRef,
    string::{CFString, CFStringRef},
};
use std::{
    ffi::c_void,
    fmt::{self, Debug},
    ptr,
};

declare_TCFType! {
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
    pub fn find(query: item::Query) -> Result<Self, Error> {
        let mut params = DictionaryBuilder::from(query);
        params.add(unsafe { kSecClass }, &item::Class::Key.as_CFString());
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
        self.attributes()
            .find(AttrKind::ApplicationLabel)
            .map(|tag| {
                AttrApplicationLabel(unsafe {
                    CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
                })
            })
    }

    /// Get the `AttrApplicationTag` for this `Key`.
    pub fn application_tag(&self) -> Option<AttrApplicationTag> {
        self.attributes().find(AttrKind::ApplicationTag).map(|tag| {
            AttrApplicationTag(unsafe {
                CFData::wrap_under_get_rule(tag.as_CFTypeRef() as CFDataRef)
            })
        })
    }

    /// Get the `AttrLabel` for this `Key`.
    pub fn label(&self) -> Option<AttrLabel> {
        self.attributes().find(AttrKind::Label).map(|label| {
            AttrLabel(unsafe { CFString::wrap_under_get_rule(label.as_CFTypeRef() as CFStringRef) })
        })
    }

    /// Get the `AttrKeyClass` for this `Key`.
    pub fn class(&self) -> Option<AttrKeyClass> {
        self.attributes()
            .find(AttrKind::KeyClass)
            .map(|class| AttrKeyClass::from(class.as_CFTypeRef() as CFStringRef))
    }

    /// Get the `AttrKeyType` for this `Key`.
    pub fn key_type(&self) -> Option<AttrKeyType> {
        self.attributes()
            .find(AttrKind::KeyType)
            .map(|keytype| AttrKeyType::from(keytype.as_CFTypeRef() as CFStringRef))
    }

    /// Determine whether a key is suitable for an operation using a certain algorithm
    ///
    /// Wrapper for the `SecKeyIsAlgorithmSupported` function. See:
    /// <https://developer.apple.com/documentation/security/1644057-seckeyisalgorithmsupported>
    pub fn is_supported(&self, operation: KeyOperation, alg: KeyAlgorithm) -> bool {
        let res = unsafe {
            SecKeyIsAlgorithmSupported(
                self.as_concrete_TypeRef(),
                operation.to_CFIndex(),
                alg.as_CFString().as_CFTypeRef(),
            )
        };
        res == 1
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

    /// Verifies the cryptographic signature of the given data using this key.
    ///
    /// Wrapper for the `SecKeyVerifySignature` function. See:
    /// <https://developer.apple.com/documentation/security/1643715-seckeyverifysignature>
    pub fn verify(&self, signed_data: &[u8], signature: &Signature) -> Result<bool, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let result = unsafe {
            SecKeyVerifySignature(
                self.as_concrete_TypeRef(),
                signature.algorithm().as_CFString().as_CFTypeRef(),
                CFData::from_buffer(signed_data).as_concrete_TypeRef(),
                CFData::from_buffer(signature.as_bytes()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            Ok(result == 0x1)
        } else {
            Err(error.into())
        }
    }

    /// Encrypts a block of data using a public key and specified algorithm
    ///
    /// Wrapper for the `SecKeyCreateEncryptedData` function. See:
    /// <https://developer.apple.com/documentation/security/1643957-seckeycreateencrypteddata>
    pub fn encrypt(&self, alg: KeyAlgorithm, plaintext: &[u8]) -> Result<Ciphertext, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let ciphertext = unsafe {
            SecKeyCreateEncryptedData(
                self.as_concrete_TypeRef(),
                alg.as_CFString().as_CFTypeRef(),
                CFData::from_buffer(plaintext).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            let bytes = unsafe { CFData::wrap_under_create_rule(ciphertext) }.to_vec();
            Ok(Ciphertext::new(alg, bytes))
        } else {
            Err(error.into())
        }
    }

    /// Decrypts a block of data using a private key and specified algorithm
    ///
    /// Wrapper for the `SecKeyCreateDecryptedData` function. See:
    /// <https://developer.apple.com/documentation/security/1644043-seckeycreatedecrypteddata>
    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<Vec<u8>, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let plaintext = unsafe {
            SecKeyCreateDecryptedData(
                self.as_concrete_TypeRef(),
                ciphertext.algorithm().as_CFString().as_CFTypeRef(),
                CFData::from_buffer(ciphertext.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            let bytes = unsafe { CFData::wrap_under_create_rule(plaintext) }.to_vec();
            Ok(bytes)
        } else {
            Err(error.into())
        }
    }

    /// Delete this key from the keychain
    ///
    /// Wrapper for `SecItemDelete` function. See:
    /// <https://developer.apple.com/documentation/security/1395547-secitemdelete>
    pub fn delete(self) -> Result<(), Error> {
        let mut query = DictionaryBuilder::new();
        let key_class = self.class().unwrap();
        query.add(unsafe { kSecClass }, &item::Class::Key.as_CFString());
        query.add(unsafe { kSecAttrKeyClass }, &key_class.as_CFString());
        if key_class == AttrKeyClass::Public {
            query.add(unsafe { kSecAttrKeyType }, &self.key_type().unwrap().as_CFString());
            query.add(
                unsafe { kSecAttrApplicationTag },
                &self.application_tag().unwrap().as_CFType(),
            );
        } else if key_class == AttrKeyClass::Private {
            println!("label = {:?}", self.application_label());
            query.add(
                unsafe { kSecAttrApplicationLabel },
                &self.application_label().unwrap().as_CFType(),
            );
            query.add_boolean(unsafe { kSecReturnRef }, true);
        }
        let status = unsafe { SecItemDelete(Dictionary::from(query).as_concrete_TypeRef()) };
        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(())
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

    /// Restores a key from an external representation of that key.
    ///
    /// Wrapper for the `SecKeyCreateWithData` function. See:
    /// <https://developer.apple.com/documentation/security/1643701-seckeycreatewithdata>
    pub fn from_external_representation(params: RestoreKeyParams) -> Result<Self, Error> {
        let mut error: CFErrorRef = ptr::null_mut();
        let data = unsafe {
            SecKeyCreateWithData(
                CFData::from_buffer(params.as_bytes()).as_concrete_TypeRef(),
                params.attributes().as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            Ok(unsafe { Key::wrap_under_create_rule(data) })
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

fn _keyring_type_to_string(value: *const c_void) -> String {
    let new_value = unsafe { CFType::from_void(value) };
    let value_string = new_value.downcast::<CFString>().unwrap();
    value_string.to_string()
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

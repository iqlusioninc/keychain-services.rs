//! Keys stored in macOS Keychain Services.

mod algorithm;
mod pair;

pub use self::{algorithm::*, pair::*};
use crate::{
    attr::*,
    dictionary::{Dictionary, DictionaryBuilder},
    error::Error,
    ffi::*,
    keychain::item::{self, MatchLimit},
    signature::Signature,
};
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

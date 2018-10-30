//! Query the keychain, looking for particular items

use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};

use attr::*;
use ffi::*;
use item::SecClass;

/// Limit the number of matched items to one or an unlimited number.
///
/// Wrapper for the `kSecMatchLimit` attribute key. See:
/// <https://developer.apple.com/documentation/security/ksecmatchlimit>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecMatchLimit {
    /// Match exactly one item.
    ///
    /// Wrapper for the `kSecMatchLimitOne` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecmatchlimitone>
    One,

    /// Match the specified number of items.
    ///
    /// Equivalent to passing a `CFNumberRef` as the value for
    /// `kSecMatchLimit`. See:
    /// <https://developer.apple.com/documentation/security/ksecmatchlimit>
    Number(usize),

    /// Match an unlimited number of items.
    ///
    /// Wrapper for the `kSecMatchLimitAll` attribute value. See:
    /// <https://developer.apple.com/documentation/security/ksecmatchlimitall>
    All,
}

impl SecMatchLimit {
    /// Get `CFType` containing the `kSecMatchLimit` dictionary value for
    /// this particular `SecMatchLimit`.
    pub fn as_CFType(self) -> CFType {
        match self {
            SecMatchLimit::One => {
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) }.as_CFType()
            }
            SecMatchLimit::Number(n) => CFNumber::from(n as i64).as_CFType(),
            SecMatchLimit::All => {
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll) }.as_CFType()
            }
        }
    }
}

/// Query builder for locating particular keychain items.
///
/// For more information, see "Search Attribute Keys and Values":
/// <https://developer.apple.com/documentation/security/keychain_services/keychain_items/search_attribute_keys_and_values>
#[derive(Default, Debug)]
pub struct SecItemQueryParams {
    pub(crate) application_label: Option<SecAttrApplicationLabel>,
    pub(crate) application_tag: Option<SecAttrApplicationTag>,
    pub(crate) class: Option<SecClass>,
    pub(crate) permanent: Option<bool>,
    pub(crate) key_class: Option<SecAttrKeyClass>,
    pub(crate) key_type: Option<SecAttrKeyType>,
    pub(crate) label: Option<SecAttrLabel>,
    pub(crate) match_limit: Option<SecMatchLimit>,
    pub(crate) return_ref: Option<bool>,
    pub(crate) synchronizable: Option<bool>,
    pub(crate) token_id: Option<SecAttrTokenId>,
    pub(crate) use_operation_prompt: Option<CFString>,
}

impl SecItemQueryParams {
    /// Create a new keychain item query builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Query for keychain items with the provided `SecAttrApplicationLabel`
    /// (not to be confused with a `SecAttrLabel`), i.e. the hash/fingerprint
    /// of a public key in the keychain.
    ///
    /// Both the private and public key in a keypair have a
    /// `SecAttrApplicationLabel` set to the public key's fingerprint.
    ///
    /// Wrapper for the `kSecAttrApplicationLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    pub fn application_label<L: Into<SecAttrApplicationLabel>>(mut self, label: L) -> Self {
        self.application_label = Some(label.into());
        self
    }

    /// Query for keychain items with the provided `SecAttrApplicationTag`.
    ///
    /// Wrapper for `kSecAttrApplicationTag` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrapplicationtag>
    pub fn application_tag<T>(mut self, tag: T) -> Self
    where
        T: Into<SecAttrApplicationTag>,
    {
        self.application_tag = Some(tag.into());
        self
    }

    /// Query for keys which are or not permanent members of the default keychain.
    ///
    /// Wrapper for the `kSecAttrIsPermanent` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrispermanent>
    pub fn permanent(mut self, value: bool) -> Self {
        self.permanent = Some(value);
        self
    }

    /// Query for keys with the given `SecAttrKeyClass`.
    ///
    /// Wrapper for the `kSecAttrKeyClass` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeyclass>
    pub fn key_class(mut self, key_class: SecAttrKeyClass) -> Self {
        self.key_class = Some(key_class);
        self
    }

    /// Query for keys with the given `SecAttrKeyType`.
    ///
    /// Wrapper for the `kSecAttrKeyType` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrkeytype>
    pub fn key_type(mut self, key_type: SecAttrKeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Query for a particular (human-meaningful) label on keys
    ///
    /// Wrapper for the `kSecAttrLabel` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrlabel>
    pub fn label<L: Into<SecAttrLabel>>(mut self, label: L) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Query for keys which are or are not synchronizable.
    ///
    /// Wrapper for the `kSecAttrSynchronizable` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrsynchronizable>
    pub fn synchronizable(mut self, value: bool) -> Self {
        self.synchronizable = Some(value);
        self
    }

    /// Query for keys stored in an external token i.e. the
    /// Secure Enclave Processor (SEP).
    ///
    /// Wrapper for the `kSecAttrTokenID` attribute key. See:
    /// <https://developer.apple.com/documentation/security/ksecattrtokenid>
    pub fn token_id(mut self, value: SecAttrTokenId) -> Self {
        self.token_id = Some(value);
        self
    }

    /// Prompt the user with the given custom message when using keys returned
    /// from this query.
    ///
    /// Wrapper for the `kSecUseOperationPrompt`. See:
    /// <https://developer.apple.com/documentation/security/ksecuseoperationprompt>
    pub fn use_operation_prompt(mut self, value: &str) -> Self {
        self.use_operation_prompt = Some(value.into());
        self
    }

    /// Build a `CFDictionary` from the configured options
    pub fn into_CFDictionary(self) -> CFDictionary<CFType, CFType> {
        let mut params = vec![];

        if let Some(application_label) = self.application_label {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) }.as_CFType(),
                application_label.as_CFType(),
            ));
        }

        if let Some(application_tag) = self.application_tag {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationTag) }.as_CFType(),
                application_tag.as_CFType(),
            ));
        }

        if let Some(class) = self.class {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecClass) }.as_CFType(),
                class.as_CFString().as_CFType(),
            ));
        }

        if let Some(permanent) = self.permanent {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) }.as_CFType(),
                CFBoolean::from(permanent).as_CFType(),
            ));
        }

        if let Some(key_class) = self.key_class {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClass) }.as_CFType(),
                key_class.as_CFString().as_CFType(),
            ));
        }

        if let Some(key_type) = self.key_type {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) }.as_CFType(),
                key_type.as_CFString().as_CFType(),
            ));
        }

        if let Some(label) = self.label {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrLabel) }.as_CFType(),
                label.as_CFType(),
            ))
        }

        if let Some(match_limit) = self.match_limit {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) }.as_CFType(),
                match_limit.as_CFType(),
            ))
        }

        if let Some(return_ref) = self.return_ref {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecReturnRef) }.as_CFType(),
                CFBoolean::from(return_ref).as_CFType(),
            ))
        }

        if let Some(synchronizable) = self.synchronizable {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) }.as_CFType(),
                CFBoolean::from(synchronizable).as_CFType(),
            ));
        }

        if let Some(token_id) = self.token_id {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) }.as_CFType(),
                token_id.as_CFString().as_CFType(),
            ))
        }

        if let Some(use_operation_prompt) = self.use_operation_prompt {
            params.push((
                unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) }.as_CFType(),
                use_operation_prompt.as_CFType(),
            ))
        }

        println!("params: {:?}", params);
        CFDictionary::from_CFType_pairs(&params)
    }
}

//! Builder for constructing a `CFDictionary` from attribute pairs.

use core_foundation::{
    self,
    base::{CFType, TCFType},
    boolean::CFBoolean,
    number::CFNumber,
    string::{CFString, CFStringRef},
};

use attr::TAttr;

/// All CFDictionary types we use follow this signature
pub(crate) type Dictionary = core_foundation::dictionary::CFDictionary<CFType, CFType>;

/// Builder for attribute/parameter dictionaries we pass as arguments.
#[derive(Clone, Default, Debug)]
pub(crate) struct DictionaryBuilder(Vec<(CFType, CFType)>);

impl DictionaryBuilder {
    /// Create a new dictionary builder
    pub(crate) fn new() -> DictionaryBuilder {
        DictionaryBuilder(vec![])
    }

    /// Add a key/value pair to the dictionary
    pub(crate) fn add<K, V>(&mut self, key: K, value: &V)
    where
        K: Into<CFStringRef>,
        V: TCFType,
    {
        self.0.push((
            unsafe { CFString::wrap_under_get_rule(key.into()) }.as_CFType(),
            value.as_CFType(),
        ))
    }

    /// Add an attribute (i.e. `TSecAttr`) to the dictionary
    pub(crate) fn add_attr(&mut self, attr: &TAttr) {
        self.add(attr.kind(), &attr.as_CFType())
    }

    /// Add a key/value pair with a `bool` value to the dictionary
    pub(crate) fn add_boolean<K>(&mut self, key: K, value: bool)
    where
        K: Into<CFStringRef>,
    {
        self.add(key, &CFBoolean::from(value))
    }

    /// Add a key/value pair with an `i64` value to the dictionary
    pub(crate) fn add_number<K>(&mut self, key: K, value: i64)
    where
        K: Into<CFStringRef>,
    {
        self.add(key, &CFNumber::from(value))
    }

    /// Add a key/value pair with an `AsRef<str>` value to the dictionary
    pub(crate) fn add_string<K, V>(&mut self, key: K, value: V)
    where
        K: Into<CFStringRef>,
        V: AsRef<str>,
    {
        self.add(key, &CFString::from(value.as_ref()))
    }
}

impl From<DictionaryBuilder> for Dictionary {
    fn from(builder: DictionaryBuilder) -> Dictionary {
        Dictionary::from_CFType_pairs(&builder.0)
    }
}

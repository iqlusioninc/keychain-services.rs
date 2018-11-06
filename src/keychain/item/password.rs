use std::str;
use zeroize::Zeroize;

use attr::*;
use dictionary::DictionaryBuilder;
use error::Error;
use ffi::*;
use keychain::*;

/// Generic passwords
pub struct GenericPassword(Item);

impl GenericPassword {
    /// Create a new generic password item in the given keychain.
    pub fn create(
        keychain: &Keychain,
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let mut attrs = DictionaryBuilder::new();
        attrs.add_class(item::Class::GenericPassword);
        attrs.add_string(AttrKind::Service, service);
        attrs.add_string(AttrKind::Account, account);
        attrs.add_string(unsafe { kSecValueData }, password);

        Ok(GenericPassword(keychain.add_item(attrs)?))
    }

    /// Find a generic password in the given keychain.
    pub fn find(keychain: &Keychain, service: &str, account: &str) -> Result<Self, Error> {
        let mut attrs = DictionaryBuilder::new();
        attrs.add_class(item::Class::GenericPassword);
        attrs.add_string(AttrKind::Service, service);
        attrs.add_string(AttrKind::Account, account);

        Ok(GenericPassword(keychain.find_item(attrs)?))
    }

    /// Get the account this password is associated with
    pub fn account(&self) -> Result<String, Error> {
        self.0.attribute(AttrKind::Account)
    }

    /// Get the service this password is associated with
    pub fn service(&self) -> Result<String, Error> {
        self.0.attribute(AttrKind::Service)
    }

    /// Get the raw password value
    pub fn password(&self) -> Result<PasswordData, Error> {
        Ok(PasswordData(self.0.data()?))
    }
}

/// Internet passwords
pub struct InternetPassword(Item);

impl InternetPassword {
    /// Create a new Internet password item in the given keychain.
    pub fn create(
        keychain: &Keychain,
        server: &str,
        account: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let mut attrs = DictionaryBuilder::new();
        attrs.add_class(item::Class::InternetPassword);
        attrs.add_string(AttrKind::Server, server);
        attrs.add_string(AttrKind::Account, account);
        attrs.add_string(unsafe { kSecValueData }, password);

        Ok(InternetPassword(keychain.add_item(attrs)?))
    }

    /// Find an Internet password in the given keychain.
    pub fn find(
        keychain: &Keychain,
        server: &str,
        account: &str,
        protocol: Option<AttrProtocol>,
    ) -> Result<Self, Error> {
        let mut attrs = DictionaryBuilder::new();
        attrs.add_class(item::Class::InternetPassword);
        attrs.add_string(AttrKind::Server, server);
        attrs.add_string(AttrKind::Account, account);

        if let Some(proto) = protocol {
            attrs.add_attr(&proto);
        }

        Ok(InternetPassword(keychain.find_item(attrs)?))
    }

    /// Get the account this password is associated with
    pub fn account(&self) -> Result<String, Error> {
        self.0.attribute(AttrKind::Account)
    }

    /// Get the service this password is associated with
    pub fn server(&self) -> Result<String, Error> {
        self.0.attribute(AttrKind::Server)
    }

    /// Get the raw password value
    pub fn password(&self) -> Result<PasswordData, Error> {
        Ok(PasswordData(self.0.data()?))
    }
}

/// Wrapper around password data that ensures it is cleared from memory after
/// being used.
#[derive(Clone)]
pub struct PasswordData(Vec<u8>);

impl PasswordData {
    /// Borrow the password as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Borrow the password as a `str` (if valid UTF-8), panicking if the
    /// UTF-8 conversion fails.
    pub fn as_str(&self) -> &str {
        self.try_as_str().expect("password contained invalid UTF-8")
    }

    /// Borrow the password as a `str` (if valid UTF-8), returning a
    /// `Utf8Error` if the UTF-8 conversion failed.
    pub fn try_as_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_bytes())
    }
}

impl AsRef<[u8]> for PasswordData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Drop for PasswordData {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

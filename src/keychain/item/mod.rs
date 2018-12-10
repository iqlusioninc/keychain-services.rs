//! Items stored in a keychain (e.g. certificates, keys, passwords)

mod class;
mod password;
mod query;

pub use self::{class::*, password::*, query::*};
use crate::{attr::AttrKind, error::*, ffi::*};
use core_foundation::base::TCFType;
use std::{mem, os::raw::c_void, ptr, slice};

declare_TCFType! {
    /// Items stored in the keychain.
    ///
    /// Wrapper for the `SecKeychainItem`/`SecKeychainItemRef` types:
    /// <https://developer.apple.com/documentation/security/seckeychainitemref>
    Item, ItemRef
}

impl_TCFType!(Item, ItemRef, SecKeychainItemGetTypeID);

impl Item {
    /// Get the class of this item
    pub fn class(&self) -> Class {
        let mut result = FourCharacterCode::from(b"NULL");

        Error::maybe_from_OSStatus(unsafe {
            SecKeychainItemCopyContent(
                self.as_concrete_TypeRef(),
                &mut result,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })
        .unwrap();

        result.into()
    }

    /// Get the raw data associated with this keychain item
    pub(crate) fn data(&self) -> Result<Vec<u8>, Error> {
        let result_ptr: *mut u8 = ptr::null_mut();
        let mut length = 0;

        let status = unsafe {
            SecKeychainItemCopyContent(
                self.as_concrete_TypeRef(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut length,
                &mut (result_ptr as *mut c_void),
            )
        };

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else if result_ptr.is_null() {
            Err(Error::new(
                ErrorKind::MissingEntitlement,
                "SecKeychainItemCopyContent refused to return data",
            ))
        } else {
            // Copy the data into a vector we've allocated
            let result = Vec::from(unsafe { slice::from_raw_parts(result_ptr, length as usize) });

            // Free the original data
            Error::maybe_from_OSStatus(unsafe {
                SecKeychainItemFreeContent(ptr::null_mut(), result_ptr as *mut c_void)
            })
            .unwrap();

            Ok(result)
        }
    }

    /// Get an attribute of this item as a `String`.
    // TODO: handle attribute types other than `String`?
    pub(crate) fn attribute(&self, attr_kind: AttrKind) -> Result<String, Error> {
        let mut attrs = unsafe { self.attributes() }?;

        let result = attrs
            .iter()
            .find(|attr| {
                if let Some(kind) = AttrKind::from_tag(attr.tag()) {
                    kind == attr_kind
                } else {
                    false
                }
            })
            .map(|attr| String::from_utf8(attr.data().unwrap().into()).unwrap());

        Error::maybe_from_OSStatus(unsafe {
            SecKeychainItemFreeContent(&mut attrs, ptr::null_mut())
        })
        .unwrap();

        result.ok_or_else(|| {
            Error::new(
                ErrorKind::NoSuchAttr,
                &format!("missing attribute {:?}", attr_kind),
            )
        })
    }

    /// Get the attributes of a keychain item. Note that this does not handle
    /// deallocating the attribute list so the caller must take care to do so.
    unsafe fn attributes(&self) -> Result<SecKeychainAttributeList, Error> {
        let mut result: SecKeychainAttributeList = mem::zeroed();

        let status = SecKeychainItemCopyContent(
            self.as_concrete_TypeRef(),
            ptr::null_mut(),
            &mut result,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if let Some(e) = Error::maybe_from_OSStatus(status) {
            Err(e)
        } else {
            Ok(result)
        }
    }
}

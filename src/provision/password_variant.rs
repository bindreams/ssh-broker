//! provision::password_variant — the password as the `VARIANT` the Task Scheduler call takes.
//!
//! `RegisterTask` wants the password as a BSTR inside a VARIANT, which is one more copy of the
//! password that this process makes and so must unmake: the characters are zeroed before the
//! VARIANT is cleared and the BSTR freed. (Task Scheduler's own copy, and the RPC buffers that carry
//! it, are outside this process's reach and are not claimed.)

use windows::Win32::System::Variant::VARIANT;
use windows::core::BSTR;

use crate::password_entry::Password;

pub struct PasswordVariant(VARIANT);

impl PasswordVariant {
    pub fn new(password: &Password) -> PasswordVariant {
        PasswordVariant(VARIANT::from(BSTR::from_wide(password.as_wide())))
    }

    /// The variant to pass to the call. It stays owned by `self`.
    pub fn variant(&self) -> &VARIANT {
        &self.0
    }

    /// Zero the characters of the BSTR. The string keeps its length.
    pub fn wipe(&mut self) {
        // SAFETY: `new` made a BSTR variant, so `bstrVal` is the live string it owns.
        unsafe {
            let bstr: &BSTR = &self.0.Anonymous.Anonymous.Anonymous.bstrVal;
            let (ptr, len) = (bstr.as_ptr().cast_mut(), bstr.len());
            for offset in 0..len {
                ptr.add(offset).write_volatile(0);
            }
        }
    }

    /// The characters held, for tests.
    #[doc(hidden)]
    pub fn units(&self) -> Vec<u16> {
        // SAFETY: as in `wipe`.
        unsafe { self.0.Anonymous.Anonymous.Anonymous.bstrVal.to_vec() }
    }
}

impl Drop for PasswordVariant {
    fn drop(&mut self) {
        self.wipe();
        // The VARIANT field drops next and clears the (now zero) BSTR.
    }
}

impl std::fmt::Debug for PasswordVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordVariant(..)")
    }
}

#[cfg(test)]
#[path = "password_variant_tests.rs"]
mod password_variant_tests;

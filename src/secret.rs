//! A buffer for text that must not outlive its use: password code units.
//!
//! The store is fully initialised and never has spare capacity that was written and then
//! forgotten: growth allocates a larger store, copies, and wipes the old one before it is freed, so
//! no stale copy of a half-typed password is left on the heap.

use zeroize::{Zeroize, Zeroizing};

const INITIAL_UNITS: usize = 32;

/// UTF-16 code units that are wiped on [`SecretUnits::wipe`] and on drop. No `Clone`; `Debug` shows
/// no content.
pub struct SecretUnits {
    /// Every unit past `len` is zero.
    backing: Box<[u16]>,
    len: usize,
}

impl SecretUnits {
    pub fn new() -> Self {
        Self {
            backing: vec![0u16; INITIAL_UNITS].into_boxed_slice(),
            len: 0,
        }
    }

    pub fn push(&mut self, unit: u16) {
        if self.len == self.backing.len() {
            let mut grown = vec![0u16; self.backing.len() * 2].into_boxed_slice();
            grown[..self.len].copy_from_slice(&self.backing[..self.len]);
            self.backing.zeroize();
            self.backing = grown;
        }
        self.backing[self.len] = unit;
        self.len += 1;
    }

    /// Remove the last scalar value: two units for a surrogate pair, one otherwise, nothing when
    /// empty. The removed units are zeroed.
    pub fn pop_scalar(&mut self) {
        let units = self.as_units();
        let take = match units {
            [.., high, low] if (0xD800..0xDC00).contains(high) && (0xDC00..0xE000).contains(low) => 2,
            [] => 0,
            _ => 1,
        };
        let from = self.len - take;
        self.backing[from..self.len].zeroize();
        self.len = from;
    }

    pub fn as_units(&self) -> &[u16] {
        &self.backing[..self.len]
    }

    /// Zero the whole store and empty it.
    pub fn wipe(&mut self) {
        self.backing.zeroize();
        self.len = 0;
    }

    /// Call `f` with a NUL-terminated copy of the units. The copy is wiped before this returns, also
    /// when `f` panics.
    pub fn with_nul<R>(&self, f: impl FnOnce(&[u16]) -> R) -> R {
        let mut copy = Zeroizing::new(Vec::with_capacity(self.len + 1));
        copy.extend_from_slice(self.as_units());
        copy.push(0);
        f(&copy)
    }

    /// The whole store, for tests.
    #[doc(hidden)]
    pub fn backing(&self) -> &[u16] {
        &self.backing
    }
}

impl Default for SecretUnits {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretUnits {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl std::fmt::Debug for SecretUnits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretUnits(..)")
    }
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod secret_tests;

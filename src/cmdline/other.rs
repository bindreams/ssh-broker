//! Non-Windows hosts have no raw command line; this only keeps the crate buildable for
//! development. The product is Windows-only.

use super::Encoding;

pub fn current() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

/// No sshd to ask: the form every non-PTY session has.
pub fn detect() -> Encoding {
    Encoding::Escaped
}

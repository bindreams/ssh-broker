//! Non-Windows hosts have no raw command line; this only keeps the crate buildable for
//! development. The product is Windows-only.

pub fn current() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

/// No sshd to ask; the default every real one starts with.
pub fn detect() -> super::Detected {
    super::Detected {
        encoding: super::Encoding::Escaped,
        warning: None,
    }
}

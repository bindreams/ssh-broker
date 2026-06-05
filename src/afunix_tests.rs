//! Unit tests for the `afunix` module.
use std::path::Path;

#[test]
fn unix_addr_accepts_a_normal_short_path() {
    assert!(super::unix_addr(Path::new("/tmp/ssh-broker/a.sock")).is_ok());
}

#[test]
fn unix_addr_rejects_an_overlong_path() {
    // sockaddr_un sun_path is ~108 bytes; a 200-char path must be rejected loudly.
    let long = format!("/tmp/{}.sock", "x".repeat(200));
    assert!(super::unix_addr(Path::new(&long)).is_err());
}

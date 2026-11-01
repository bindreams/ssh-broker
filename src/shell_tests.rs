//! Host tests for the path helpers `shell` shares (pure; runs on any platform).

use std::path::{Path, PathBuf};

use super::{is_absolute_windows, join_windows};

#[test]
fn windows_paths_join_with_a_backslash_on_every_host() {
    assert_eq!(
        join_windows(Path::new(r"C:\Users\me"), &[".config", "ssh-broker", "config.yaml"]),
        PathBuf::from(r"C:\Users\me\.config\ssh-broker\config.yaml")
    );
    // No doubled separator after a base that ends in one, and a `/` base is kept as it is.
    assert_eq!(join_windows(Path::new(r"C:\"), &["x"]), PathBuf::from(r"C:\x"));
    assert_eq!(join_windows(Path::new("C:/x/"), &["y"]), PathBuf::from(r"C:/x/y"));
    assert_eq!(join_windows(Path::new(r"C:\x"), &[]), PathBuf::from(r"C:\x"));
}

#[test]
fn only_drive_and_unc_paths_are_absolute() {
    for path in [r"C:\x", "c:/x", r"\\server\share\x", r"\\?\C:\x", "//server/share"] {
        assert!(is_absolute_windows(Path::new(path)), "{path}");
    }
    for path in [
        "",
        "pwsh.exe",
        r"sub\pwsh.exe",
        r"\x",
        "/x",
        "C:x",
        "C:",
        r"1:\x",
        "..",
        r".\x",
    ] {
        assert!(!is_absolute_windows(Path::new(path)), "{path}");
    }
}

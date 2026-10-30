//! Where cargo puts the `command_line_probe` example: a program that records the raw command line it
//! was started with, used as a stand-in shell.
#![allow(dead_code)]

use std::path::PathBuf;

/// The built probe, next to the test binary's `deps` directory.
pub fn path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let probe = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("command_line_probe.exe");
    assert!(
        probe.is_file(),
        "the probe {probe:?} is not built: run `cargo build --examples` (`cargo test` builds it)"
    );
    probe
}

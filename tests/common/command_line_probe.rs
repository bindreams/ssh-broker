//! Where cargo puts the examples that stand in for a shell: `command_line_probe` records the raw
//! command line it was started with, `missing_dll` is a program the loader cannot load.
#![allow(dead_code)]

use std::path::PathBuf;

/// The built probe, next to the test binary's `deps` directory.
pub fn path() -> PathBuf {
    example("command_line_probe")
}

/// The built example `name`, next to the test binary's `deps` directory.
pub fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let built = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("{name}.exe"));
    assert!(
        built.is_file(),
        "the example {built:?} is not built: run `cargo build --examples` (`cargo test` builds it)"
    );
    built
}

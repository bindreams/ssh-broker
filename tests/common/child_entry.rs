//! The two halves of a parent/child test pair, so that a pair cannot pass having proven nothing.
//!
//! The child half is an `#[ignore]`d test of the same binary, started with `--exact <name>
//! --ignored`. libtest exits 0 when that filter matches no test (a renamed or moved entry), and a
//! child that quietly skips its checks also exits 0. So the child proves its claim in a file: it
//! knows it is the child from a signal on its command line, panics when its input is unreadable,
//! and writes the result only after its checks; the parent asserts the result's content. A run
//! that matched nothing, or stopped early, leaves no result, and the parent fails on that.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A positional argument (libtest takes it as one more filter, which matches no test name) that
/// carries the pair's working directory to the child.
pub const SIGNAL: &str = "sb-child-dir=";
const INPUT: &str = "input.txt";
const RESULT: &str = "result.txt";

/// The arguments that start the child half `test` of this binary with the pair's directory `dir`.
pub fn args(test: &str, dir: &Path) -> Vec<String> {
    vec![
        "--exact".into(),
        test.into(),
        "--ignored".into(),
        "--nocapture".into(),
        format!("{SIGNAL}{}", dir.display()),
    ]
}

/// A command line for `exe` running [`args`], with each argument quoted.
pub fn command_line(exe: &Path, test: &str, dir: &Path) -> String {
    let quoted: Vec<String> = args(test, dir).iter().map(|a| format!("\"{a}\"")).collect();
    format!("\"{}\" {}", exe.display(), quoted.join(" "))
}

/// Parent: write what the child reads.
pub fn write_input(dir: &Path, text: &str) {
    std::fs::write(dir.join(INPUT), text).unwrap_or_else(|e| panic!("write the child's input in {dir:?}: {e}"));
}

/// Child: the pair's directory, from the signal in `args`. Panics without one: a child half run
/// outside its parent (`cargo test -- --ignored`) is a mistake, not a pass.
pub fn dir_from(args: impl IntoIterator<Item = String>) -> PathBuf {
    args.into_iter()
        .find_map(|a| a.strip_prefix(SIGNAL).map(PathBuf::from))
        .unwrap_or_else(|| panic!("this is a child half; its parent starts it with a {SIGNAL}<directory> argument"))
}

/// Child: [`dir_from`] this process's arguments.
pub fn dir() -> PathBuf {
    dir_from(std::env::args())
}

/// Child: the input its parent wrote. Panics when it cannot be read, for any reason.
pub fn input(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(INPUT)).unwrap_or_else(|e| panic!("read the child's input in {dir:?}: {e}"))
}

/// Child: record `text` as the result. Call it last, after every check.
pub fn write_result(dir: &Path, text: &str) {
    std::fs::write(dir.join(RESULT), text).unwrap_or_else(|e| panic!("write the child's result in {dir:?}: {e}"));
}

/// Where [`write_result`] puts the result.
pub fn result_path(dir: &Path) -> PathBuf {
    dir.join(RESULT)
}

/// Parent: the child's result. Panics when there is none: the child did not run (its filter
/// matched no test), or it stopped before the end of its checks.
pub fn result(dir: &Path) -> String {
    std::fs::read_to_string(result_path(dir)).unwrap_or_else(|e| {
        panic!("the child wrote no result in {dir:?} ({e}): it did not run, or stopped before the end of its checks")
    })
}

//! `capture <outfile> <event> <program> [args...]`: run a program with its output in a file, then
//! signal an event. A SYSTEM task runs it for M5(e), where no one else can see SYSTEM's credential
//! vault.

use std::os::windows::process::CommandExt;

use crate::win::Event;

pub fn run(args: &[String]) -> i32 {
    let file = std::fs::File::create(&args[0]).expect("create the output file");
    let status = std::process::Command::new(&args[2])
        .args(&args[3..])
        .stdout(file.try_clone().expect("duplicate the output file"))
        .stderr(file)
        .creation_flags(0x0800_0000)
        .status();
    Event::open(&args[1]).expect("open the event").set();
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    }
}

//! Runs a command line the way sshd runs a PTY session, for the tests that need the process to
//! see a console and the command line conhost leaves it.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Pipes::CreatePipe;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// What a command line did under conhost.
pub struct ConhostRun {
    /// conhost's own exit code, which is not the client's.
    pub code: Option<i32>,
    /// What the client wrote to the console, as the VT stream conhost emits on its stdout.
    pub console: String,
}

/// Run `client_line` (a program and its arguments) as sshd runs a PTY session
/// (`win32_pty.c:90-106`): `conhost.exe --headless --width W --height H --signal <pipe> --
/// <client_line>` on pipes, without a window. conhost splits `client_line` into arguments and
/// starts the client with them escaped again. Returns when conhost exits, which it does when the
/// client has.
pub fn run_under_conhost(client_line: &str, env: &[(&str, &OsStr)]) -> ConhostRun {
    // conhost reads its control messages from this pipe and does not run the client without it.
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    unsafe { CreatePipe(&mut read, &mut write, Some(&inheritable), 0) }.expect("create the signal pipe");
    let (signal_read, signal_write) = (OwnedHandle(read), OwnedHandle(write));
    // Only conhost's end is inherited.
    unsafe { SetHandleInformation(signal_write.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .expect("keep the signal pipe's write end private");

    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    let mut command = Command::new(std::path::PathBuf::from(system_root).join(r"System32\conhost.exe"));
    command
        .raw_arg(format!(
            "--headless --width 80 --height 25 --signal 0x{:x} -- {client_line}",
            signal_read.raw()
        ))
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("start conhost.exe");
    drop(signal_read);
    // Both stay open until conhost exits, as sshd keeps them open for the session.
    let stdin = child.stdin.take();
    let output = child.wait_with_output().expect("wait for conhost.exe");
    drop(stdin);
    drop(signal_write);
    ConhostRun {
        code: output.status.code(),
        console: String::from_utf8_lossy(&output.stdout).into_owned(),
    }
}

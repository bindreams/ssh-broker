//! Host tests of the reader of the kernel's socket table: the listeners are this test process's own, on loopback,
//! and the processes that own none are children of it.
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};

use super::*;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A `cmd.exe` that owns no socket and exits when its stdin closes.
fn child_without_sockets() -> Child {
    let cmd =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe");
    Command::new(cmd)
        .args(["/d", "/c", "set /p unused="])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap()
}

#[test]
fn rows_that_fit_in_the_buffer_are_read() {
    // A 4-byte count, then rows of 24 bytes: 4 + 3 * 24 = 76 bytes, held by 19 `u32`s.
    assert!(rows_fit(19, 4, 24, 3));
    assert!(rows_fit(19, 4, 24, 0));
}

#[test]
fn one_row_more_than_the_buffer_holds_is_refused() {
    assert!(!rows_fit(19, 4, 24, 4));
    assert!(!rows_fit(19, 4, 24, usize::MAX));
}

#[test]
fn zero_rows_in_a_buffer_that_holds_only_the_count_fit() {
    assert!(rows_fit(1, 4, 24, 0));
    assert!(!rows_fit(1, 4, 24, 1));
}

#[test]
fn a_process_with_an_ipv4_listener_listens() {
    let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(listens(std::process::id()).unwrap());
}

#[test]
fn a_process_with_an_ipv6_listener_listens() {
    let _listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("this machine has an IPv6 loopback");
    assert!(listens(std::process::id()).unwrap());
}

#[test]
fn a_process_that_owns_no_listener_does_not_listen_while_another_does() {
    let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut child = child_without_sockets();
    let pid = child.id();
    assert!(!listens(pid).unwrap());
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(!listens(pid).unwrap(), "a pid that has exited owns nothing");
}

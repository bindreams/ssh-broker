//! The shim on a console of its own, as an account's network token, driven by key events and read
//! as text. **CI only.**
//!
//! A helper started as the account (the `pty` role of `examples/session_stand_in`) hosts the shim in a
//! pseudoconsole and relays it over standard handles. The test types into the console as win32 input
//! mode key events, the form the agent's own pseudoconsoles take, and reads the VT it writes back.
//!
//! The including crate declares `account_fixture`, `bounded_wait`, `desktop` and `stand_in`.
#![allow(dead_code)]

use std::path::Path;

use ssh_broker::conpty::{read_handle, write_all_handle};
use ssh_broker::vtinput::{KeyEvent, encode_key_event};
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::CREATE_PROCESS_LOGON_FLAGS;

use crate::account_fixture::{Account, Spawned};
use crate::stand_in::Kit;

const LEFT_CTRL: u32 = 0x0008;

/// A pipe whose read end is `read` and write end `write`; the end named by `inherit_read` is the one
/// the child gets (inheritable), the other stays private.
fn pipe(inherit_read: bool) -> (OwnedHandle, OwnedHandle) {
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: valid out-pointers; the handles are closed by `OwnedHandle`.
    unsafe { CreatePipe(&mut read, &mut write, Some(&inheritable), 0) }.expect("CreatePipe");
    let (read, write) = (OwnedHandle(read), OwnedHandle(write));
    let private = if inherit_read { &write } else { &read };
    // SAFETY: a valid handle.
    unsafe { SetHandleInformation(private.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.expect("keep one end private");
    (read, write)
}

/// A shim running on a pseudoconsole as `account`.
pub struct PtyRun {
    helper: Spawned,
    input: OwnedHandle,
    output: OwnedHandle,
    /// Everything the shim has written so far.
    transcript: Vec<u8>,
}

impl PtyRun {
    /// Start the shim (`shim_exe`, no arguments: an interactive login) as `account`.
    pub fn start(kit: &Kit, account: &Account, shim_exe: &Path) -> PtyRun {
        let (child_in, my_in) = pipe(true);
        let (my_out, child_out) = pipe(false);
        let command_line = format!(
            "\"{helper}\" pty \"{dir}\" \"\\\"{shim}\\\"\"",
            helper = kit.helper.display(),
            dir = kit.dir().display(),
            shim = shim_exe.display()
        );
        let helper = account.spawn_with_stdio(
            &kit.helper,
            &command_line,
            kit.dir(),
            &[kit.dir().to_path_buf()],
            CREATE_PROCESS_LOGON_FLAGS(0),
            None,
            Some([child_in.0, child_out.0, child_out.0]),
        );
        helper.resume();
        // The child's ends are the child's now; keeping ours open would hold the pipes past its exit.
        drop(child_in);
        drop(child_out);
        PtyRun {
            helper,
            input: my_in,
            output: my_out,
            transcript: Vec::new(),
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        assert!(
            write_all_handle(self.input.raw(), bytes),
            "could not write to the console; it showed:\n{}",
            self.text()
        );
    }

    /// Raw bytes as the terminal would send them (UTF-8 text, for instance).
    pub fn send_raw(&mut self, text: &str) {
        self.send(text.as_bytes());
    }

    fn key(vk: u16, ch: u16, down: bool, control_key_state: u32) -> Vec<u8> {
        encode_key_event(&KeyEvent {
            virtual_key_code: vk,
            virtual_scan_code: 0,
            unicode_char: ch,
            key_down: down,
            control_key_state,
            repeat_count: 1,
        })
    }

    /// Type `text` as key events (a character per event, the way a terminal types).
    pub fn type_text(&mut self, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend(Self::key(0, unit, true, 0));
            bytes.extend(Self::key(0, unit, false, 0));
        }
        self.send(&bytes);
    }

    pub fn press_enter(&mut self) {
        let mut bytes = Self::key(0x0D, 0x0D, true, 0);
        bytes.extend(Self::key(0x0D, 0x0D, false, 0));
        self.send(&bytes);
    }

    pub fn type_line(&mut self, text: &str) {
        self.type_text(text);
        self.press_enter();
    }

    /// Ctrl+C as the console delivers it under raw input: a key record with the character 0x03.
    pub fn ctrl_c(&mut self) {
        let mut bytes = Self::key(0x43, 0x03, true, LEFT_CTRL);
        bytes.extend(Self::key(0x43, 0x03, false, LEFT_CTRL));
        self.send(&bytes);
    }

    /// Ctrl+D with the character 0x04.
    pub fn ctrl_d_character(&mut self) {
        let mut bytes = Self::key(0x44, 0x04, true, LEFT_CTRL);
        bytes.extend(Self::key(0x44, 0x04, false, LEFT_CTRL));
        self.send(&bytes);
    }

    /// Ctrl+D as a virtual key that carries no character.
    pub fn ctrl_d_virtual_key(&mut self) {
        let mut bytes = Self::key(0x44, 0, true, LEFT_CTRL);
        bytes.extend(Self::key(0x44, 0, false, LEFT_CTRL));
        self.send(&bytes);
    }

    /// Everything shown so far, as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    /// The raw bytes shown so far.
    pub fn bytes(&self) -> &[u8] {
        &self.transcript
    }

    /// Read until the console has shown one of `needles`; returns which. The wait is on the shim
    /// producing output, and ends in a failure that prints the transcript if the console closes first.
    pub fn read_until_any(&mut self, needles: &[&str]) -> usize {
        loop {
            let text = self.text();
            if let Some(found) = needles.iter().position(|needle| text.contains(needle)) {
                return found;
            }
            let mut buf = [0u8; 4096];
            let n = read_handle(self.output.raw(), &mut buf);
            assert!(
                n > 0,
                "the console closed before it showed any of {needles:?}; it showed:\n{text}"
            );
            self.transcript.extend_from_slice(&buf[..n]);
        }
    }

    pub fn read_until(&mut self, needle: &str) {
        self.read_until_any(&[needle]);
    }

    /// Read until the console closes, and return the shim's exit code.
    pub fn finish(&mut self) -> i32 {
        loop {
            let mut buf = [0u8; 4096];
            let n = read_handle(self.output.raw(), &mut buf);
            if n == 0 {
                break;
            }
            self.transcript.extend_from_slice(&buf[..n]);
        }
        self.helper.wait() as i32
    }
}

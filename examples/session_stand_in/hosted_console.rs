//! One process on a pseudoconsole, inside the job sshd keeps its session in.
//!
//! `ssh_broker::conpty::PtySession` is the agent's way to host a shell, and it contains the shell in a
//! kill-on-close job that refuses breakaway. That is not what a shim runs in under sshd (measured, M8:
//! kill-on-close with `JOB_OBJECT_LIMIT_BREAKAWAY_OK`), and a shim hosted in it could not start a
//! session that outlives its console: the job ends with the console and takes the agent along. So the
//! stand-in builds the pseudoconsole itself and puts the process in the job the caller gives it.

use std::ffi::c_void;
use std::path::Path;

use ssh_broker::winutil::{AttrList, OwnedHandle};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

#[path = "../../tests/common/job.rs"]
pub mod job;

/// `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`.
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
/// `PSEUDOCONSOLE_RESIZE_QUIRK | PSEUDOCONSOLE_WIN32_INPUT_MODE`, and with `PSEUDOCONSOLE_PASSTHROUGH_MODE`
/// (build 22621 and later): the flags `conpty` asks for, so the shim sees the console it sees from the agent.
const BASE_FLAGS: u32 = 0x2 | 0x4;
const PASSTHROUGH_FLAG: u32 = 0x8;

pub struct HostedConsole {
    hpc: Option<HPCON>,
    process: OwnedHandle,
    _thread: OwnedHandle,
    pub in_write: OwnedHandle,
    pub out_read: OwnedHandle,
}

impl HostedConsole {
    /// Start `command` on a new 80x25 pseudoconsole in `cwd`, in `job` before its first instruction.
    pub fn start(command: &str, cwd: &Path, job: &job::KillOnCloseJob) -> windows::core::Result<HostedConsole> {
        let size = COORD { X: 80, Y: 25 };
        let (in_read, in_write) = pipe()?;
        let (out_read, out_write) = pipe()?;
        // SAFETY: valid pipe ends; the pseudoconsole keeps its own references to them.
        let hpc = unsafe {
            CreatePseudoConsole(size, in_read.0, out_write.0, BASE_FLAGS | PASSTHROUGH_FLAG)
                .or_else(|_| CreatePseudoConsole(size, in_read.0, out_write.0, BASE_FLAGS))?
        };
        drop(in_read);
        drop(out_write);
        let mut console = HostedConsole {
            hpc: Some(hpc),
            process: OwnedHandle(HANDLE::default()),
            _thread: OwnedHandle(HANDLE::default()),
            in_write,
            out_read,
        };

        // The attribute's value is the HPCON itself, not a pointer to it.
        // SAFETY: (attribute, value, size) is the documented combination for a pseudoconsole.
        let attributes = unsafe {
            AttrList::single(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                hpc.0 as *const c_void,
                std::mem::size_of::<HPCON>(),
            )?
        };
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // Null standard handles, so the pipes the helper itself runs on do not bleed into the child.
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.lpAttributeList = attributes.as_ptr();
        let mut line: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        let directory: Vec<u16> = cwd.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is to a local that outlives the call.
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                None,
                PCWSTR(directory.as_ptr()),
                &startup.StartupInfo,
                &mut info,
            )?;
        }
        console.process = OwnedHandle(info.hProcess);
        console._thread = OwnedHandle(info.hThread);
        // In the job before it runs a single instruction, as sshd's session has it.
        job.assign(info.hProcess);
        // SAFETY: the live thread handle `CreateProcessW` returned.
        if unsafe { ResumeThread(info.hThread) } == u32::MAX {
            let error = windows::core::Error::from_thread();
            // SAFETY: the live process handle, still suspended.
            let _ = unsafe { TerminateProcess(info.hProcess, 1) };
            return Err(error);
        }
        Ok(console)
    }

    /// Wait for the process to end and return its exit code.
    pub fn wait(&self) -> i32 {
        // SAFETY: a live process handle and an out-pointer.
        unsafe {
            WaitForSingleObject(self.process.0, INFINITE);
            let mut code = 1u32;
            let _ = GetExitCodeProcess(self.process.0, &mut code);
            code as i32
        }
    }

    /// Close the pseudoconsole: its buffered tail is delivered and the output pipe then ends.
    pub fn close(&mut self) {
        if let Some(hpc) = self.hpc.take() {
            // SAFETY: the pseudoconsole `start` made, closed once.
            unsafe { ClosePseudoConsole(hpc) };
        }
    }
}

impl Drop for HostedConsole {
    fn drop(&mut self) {
        self.close();
    }
}

fn pipe() -> windows::core::Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
    // SAFETY: valid out-pointers.
    unsafe { CreatePipe(&mut read, &mut write, None, 0)? };
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

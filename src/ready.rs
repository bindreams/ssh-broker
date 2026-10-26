//! ready: the event that tells the shim "the agent's socket folder exists, look now".
//!
//! The shim makes the event before it starts the agent and passes its name on the agent's command
//! line; the agent signals it once. The name is 128 random bits and the DACL names only the
//! account, SYSTEM and Administrators, but the event grants nothing: it only says the shim may
//! start looking, and the socket's own ACL is still what decides who connects.
//!
//! The event lives in `Global\` because the shim and the agent need not share a session: the logon
//! puts the agent wherever `seclogon` puts it, and an auto-login agent is in session 0.

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, GetExitCodeProcess, INFINITE, OpenEventW, SYNCHRONIZATION_SYNCHRONIZE, SetEvent,
    WaitForMultipleObjects,
};
use windows::core::{BOOL, PCWSTR};

use crate::acl::Sid;
use crate::winutil::OwnedHandle;

/// Every ready-event name starts with this, followed by 32 lowercase hex digits.
pub const NAME_PREFIX: &str = r"Global\ssh-broker-ready-";
const RANDOM_BYTES: usize = 16;
/// `SYNCHRONIZE | EVENT_MODIFY_STATE`: what the account needs to open the event and signal it.
const ACCOUNT_RIGHTS: u32 = 0x0010_0002;

/// What ended a wait for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// The agent signalled: its socket folder exists.
    Ready,
    /// The agent process ended first, with this exit code.
    AgentExited(u32),
}

/// A manual-reset event. Closed on drop.
pub struct ReadyEvent(OwnedHandle);

/// Whether `name` has exactly the shape [`generate_name`] makes.
pub fn is_ready_name(name: &str) -> bool {
    name.strip_prefix(NAME_PREFIX)
        .is_some_and(|hex| hex.len() == 2 * RANDOM_BYTES && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// A fresh name from the system's random generator.
pub fn generate_name() -> anyhow::Result<String> {
    let mut bytes = [0u8; RANDOM_BYTES];
    // SAFETY: the buffer is valid for its length; the flag asks for the system-preferred RNG.
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    anyhow::ensure!(status.is_ok(), "BCryptGenRandom failed: {status:?}");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{NAME_PREFIX}{hex}"))
}

/// The descriptor of a ready event for the account with SID text `account_sid`: SYSTEM and
/// Administrators everything, the account `SYNCHRONIZE | EVENT_MODIFY_STATE`, and an explicit Medium
/// mandatory label that forbids only writes from below. Without a label the kernel gives the object
/// its creator's integrity, and a Medium agent could not signal the event of a High shim.
pub fn descriptor_sddl(account_sid: &str) -> String {
    format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;{ACCOUNT_RIGHTS:#x};;;{account_sid})S:(ML;;NW;;;ME)")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl ReadyEvent {
    /// Make an event for the account this process runs as. Returns it with its name, to be passed to
    /// the agent. The shim and the agent are the same account.
    pub fn create() -> anyhow::Result<(ReadyEvent, String)> {
        let sid = Sid::current_user()?.to_sddl()?;
        let name = generate_name()?;
        Ok((ReadyEvent::create_named(&name, &sid)?, name))
    }

    /// Make an event named `name` for the account `account_sid`. A name that already exists is an
    /// error: the event would be someone else's.
    pub fn create_named(name: &str, account_sid: &str) -> anyhow::Result<ReadyEvent> {
        anyhow::ensure!(is_ready_name(name), "not a ready-event name: {name:?}");
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated input and a valid out-pointer; the descriptor is freed below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide(&descriptor_sddl(account_sid)).as_ptr()),
                1, // SDDL_REVISION_1
                &mut descriptor,
                None,
            )
            .context("build the ready event's descriptor")?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: BOOL(0),
            };
            let made = CreateEventW(Some(&attributes), true, false, PCWSTR(wide(name).as_ptr()));
            let already = GetLastError() == ERROR_ALREADY_EXISTS;
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            let handle = OwnedHandle(made.context("CreateEventW")?);
            anyhow::ensure!(!already, "the ready event {name} already exists");
            Ok(ReadyEvent(handle))
        }
    }

    /// Open the event `name` for signalling and waiting. Refuses a name that is not of the generated
    /// shape.
    pub fn open(name: &str) -> anyhow::Result<ReadyEvent> {
        anyhow::ensure!(is_ready_name(name), "not a ready-event name: {name:?}");
        // SAFETY: a NUL-terminated name.
        let handle = unsafe {
            OpenEventW(
                EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR(wide(name).as_ptr()),
            )
        }
        .with_context(|| format!("open the ready event {name}"))?;
        Ok(ReadyEvent(OwnedHandle(handle)))
    }

    pub fn signal(&self) -> anyhow::Result<()> {
        // SAFETY: a valid event handle.
        unsafe { SetEvent(self.0.0) }.context("SetEvent")
    }

    /// The raw handle, for inspection. Owned by `self`.
    pub fn as_handle(&self) -> HANDLE {
        self.0.0
    }

    /// Block until the event is signalled or `agent` (a process handle with `SYNCHRONIZE` and
    /// `PROCESS_QUERY_LIMITED_INFORMATION`) ends. Both are real conditions and neither has a
    /// timeout: an agent that neither signals nor ends is a hang the user sees.
    ///
    /// If both hold, [`Waited::Ready`] wins: an agent that signalled and then left (it lost the
    /// session slot) has still made its folder.
    pub fn wait_with(&self, agent: HANDLE) -> anyhow::Result<Waited> {
        let handles = [self.0.0, agent];
        // SAFETY: both handles are valid for the duration of the call.
        let woke = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
        if woke == WAIT_OBJECT_0 {
            return Ok(Waited::Ready);
        }
        if woke.0 == WAIT_OBJECT_0.0 + 1 {
            let mut code = 0u32;
            // SAFETY: a valid process handle and out-pointer.
            unsafe { GetExitCodeProcess(agent, &mut code) }.context("read the agent's exit code")?;
            return Ok(Waited::AgentExited(code));
        }
        anyhow::bail!("waiting for the agent's ready event failed: {woke:?}")
    }
}

#[cfg(test)]
#[path = "ready_tests.rs"]
mod ready_tests;

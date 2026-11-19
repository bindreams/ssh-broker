//! provision::sshd_config::machine::service — the sshd service through the service manager: its settled state,
//! a STOP and a start, each followed by a wait on the service manager's own notification.
//!
//! A small version of what goetia's `backend/scm/wait.rs` and `wait/system.rs` do, which are measured on a
//! real service manager (its notes `Windows SCM - *`), and which cannot be used here: goetia's manager acts
//! only on services it owns. The rules taken from them:
//!
//! - The service manager says STOPPED before the process has exited, so a stop is over when the process held
//!   before the STOP has exited.
//! - A first notification on a handle fires at once for a state that is already current, and a re-arm with the
//!   same context and buffer is never delivered for an unchanged state. So every arm here has a handle and a
//!   buffer of its own, the registration comes after the action it waits for, and the status read after the
//!   registration, not the notification, decides.
//! - While a service is still stopping, a start is refused with 1056 and a second STOP with 1061, and a held
//!   pending state is never resolved by the service manager; a STOP can succeed and the service stay running.
//!   So a refusal is never judged by its code: the settled state that follows decides. The waits have no bound:
//!   a bound would only make `apply` give up and leave the machine as it is.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use windows::Win32::Foundation::ERROR_SERVICE_NOTIFY_CLIENT_LAGGING;
use windows::Win32::System::Services::{
    ControlService, NotifyServiceStatusChangeW, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_STOP, SERVICE_NOTIFY, SERVICE_NOTIFY_2W,
    SERVICE_NOTIFY_PAUSED, SERVICE_NOTIFY_RUNNING, SERVICE_NOTIFY_STATUS_CHANGE, SERVICE_NOTIFY_STOPPED,
    SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
};
use windows::Win32::System::Threading::{INFINITE, SleepEx};
use windows::core::{PCWSTR, w};

use super::{ScHandle, service_process};
use crate::provision::sshd_config::restart::{ExitCodes, ServiceState, StartOutcome, StartReply, StopOutcome};
use crate::winutil::describe_error;

/// The states a registration is made for: the settled ones. A registration made while the service is starting
/// or stopping then fires when it settles, and none fires for a pending state.
const SETTLED_MASK: SERVICE_NOTIFY =
    SERVICE_NOTIFY(SERVICE_NOTIFY_RUNNING.0 | SERVICE_NOTIFY_PAUSED.0 | SERVICE_NOTIFY_STOPPED.0);

/// What a `dwCurrentState` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    Settled(ServiceState),
    /// Starting, stopping, pausing or continuing: waited for.
    Pending,
    /// A value that is none of the seven states.
    Unknown(u32),
}

fn classify(raw: u32) -> Reading {
    match raw {
        r if r == SERVICE_RUNNING.0 => Reading::Settled(ServiceState::Running),
        r if r == SERVICE_PAUSED.0 => Reading::Settled(ServiceState::Paused),
        r if r == SERVICE_STOPPED.0 => Reading::Settled(ServiceState::Stopped),
        r if r == SERVICE_START_PENDING.0
            || r == SERVICE_STOP_PENDING.0
            || r == SERVICE_CONTINUE_PENDING.0
            || r == SERVICE_PAUSE_PENDING.0 =>
        {
            Reading::Pending
        }
        other => Reading::Unknown(other),
    }
}

/// A settled state with the exit codes the service manager recorded with it.
struct Settled {
    state: ServiceState,
    exit: ExitCodes,
}

/// The sshd service, opened for the reads and controls this module makes. One per run of `apply`'s step.
pub(super) struct SshdService {
    _manager: ScHandle,
    service: ScHandle,
}

impl SshdService {
    pub(super) fn open() -> anyhow::Result<SshdService> {
        let (manager, service) = open_handles(SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP)?;
        Ok(SshdService {
            _manager: manager,
            service,
        })
    }

    /// What the service manager says now: the state and the exit codes it recorded, and the service's process id.
    fn status(&self) -> anyhow::Result<SERVICE_STATUS_PROCESS> {
        query(&self.service)
    }

    /// The settled state, once the service manager says one: see [`SshdService::settle`].
    pub(super) fn settled(&self) -> anyhow::Result<ServiceState> {
        Ok(self.settle()?.state)
    }

    /// Wait, with no bound, until the service manager says the service is running, paused or stopped. The
    /// registration is made on handles of its own before the status is read, so a state reached in between is
    /// seen by the read and one reached after it is delivered; the status decides, and a notification only says
    /// that it is time to read again.
    fn settle(&self) -> anyhow::Result<Settled> {
        loop {
            let registration = Registration::arm()?;
            let status = self.status()?;
            match classify(status.dwCurrentState.0) {
                Reading::Settled(state) => {
                    return Ok(Settled {
                        state,
                        exit: ExitCodes {
                            win32: status.dwWin32ExitCode,
                            specific: status.dwServiceSpecificExitCode,
                        },
                    });
                }
                Reading::Pending => registration.wait(),
                Reading::Unknown(raw) => anyhow::bail!("the service manager reported the unknown state {raw}"),
            }
        }
    }

    /// Hold the service's process, send the STOP, and say what settled. The process is the mark that makes
    /// "stopped" mean the old sshd is gone: the service manager says stopped before it has exited.
    pub(super) fn stop(&self) -> anyhow::Result<StopOutcome> {
        let held = service_process().context("hold the process of the sshd service before stopping it")?;
        let mut status = SERVICE_STATUS::default();
        // SAFETY: the handle was opened with the right to stop; `status` is a local the call fills.
        let refusal = unsafe { ControlService(self.service.0, SERVICE_CONTROL_STOP, &mut status) }
            .err()
            .map(|e| describe_error(&e));
        Ok(match self.settle() {
            Err(e) => StopOutcome::Unknown {
                cause: format!("{e:#}"),
            },
            Ok(Settled {
                state: ServiceState::Stopped,
                ..
            }) => match held.map(|process| process.wait_for_exit()).transpose() {
                Ok(_) => StopOutcome::Stopped,
                Err(e) => StopOutcome::Unknown {
                    cause: format!("{e:#}"),
                },
            },
            Ok(Settled { state, .. }) => StopOutcome::NotStopped { state, refusal },
        })
    }

    /// Start the service and say what the service manager answered and what settled after.
    pub(super) fn start(&self) -> StartOutcome {
        // SAFETY: the handle was opened with the right to start; no arguments are passed.
        let reply = match unsafe { StartServiceW(self.service.0, None) } {
            Ok(()) => StartReply::Accepted,
            Err(e) => StartReply::Refused(describe_error(&e)),
        };
        match self.settle() {
            Err(e) => StartOutcome::Unreadable {
                reply,
                cause: format!("{e:#}"),
            },
            Ok(Settled {
                state: ServiceState::Running,
                ..
            }) => StartOutcome::Running(reply),
            Ok(Settled {
                state: ServiceState::Paused,
                ..
            }) => StartOutcome::Paused(reply),
            Ok(Settled {
                state: ServiceState::Stopped,
                exit,
            }) => StartOutcome::Stopped { reply, exit },
        }
    }
}

/// The service manager and the sshd service on it, opened with `access` to the service.
pub(super) fn open_handles(access: u32) -> anyhow::Result<(ScHandle, ScHandle)> {
    // SAFETY: null names mean this machine and the active database; the handles are closed by their guards.
    let manager = ScHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .context("open the service manager")?,
    );
    // SAFETY: `manager` is open; the name is a NUL-terminated literal.
    let service = ScHandle(unsafe { OpenServiceW(manager.0, w!("sshd"), access) }.context("open the sshd service")?);
    Ok((manager, service))
}

/// `QueryServiceStatusEx` of `service`.
pub(super) fn query(service: &ScHandle) -> anyhow::Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: the buffer is `status`, whole, and lives as long as the call.
    let queried = unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            (&raw mut status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
    };
    queried.context("ask the service manager about sshd")?;
    Ok(status)
}

// the notification -----

/// What the service manager writes to when it delivers a notification, and the flag its callback sets.
#[repr(C)]
struct Notification {
    buffer: SERVICE_NOTIFY_2W,
    fired: AtomicBool,
}

/// The callback: runs on the thread that waits alertably, with the buffer the registration passed.
///
/// # Safety
///
/// `parameter` is the `SERVICE_NOTIFY_2W` of a live [`Notification`]. The registration frees it only after
/// its service handle was closed successfully (no more notifications are queued after that) and the queued
/// callback was drained; after a failed close it is never freed, so a callback that runs late still finds it.
unsafe extern "system" fn on_notification(parameter: *const c_void) {
    let buffer = parameter.cast::<SERVICE_NOTIFY_2W>();
    // SAFETY: see above; `pContext` is the address of that notification's `fired`.
    unsafe {
        let fired = (*buffer).pContext.cast::<AtomicBool>();
        (*fired).store(true, Ordering::Release);
    }
}

/// One registration of a notification for the settled states, on handles of its own.
///
/// The registration ends when its service handle is closed, and only a close that succeeded promises that no
/// further notification is queued. So the drop closes that handle itself and reads the result: after a failed
/// close the notification is leaked, never freed, because a callback may still write into it.
struct Registration {
    /// Heap-pinned: the service manager holds its address until the service handle is closed.
    notification: *mut Notification,
    /// Closed first when the registration ends, so that no new notification is queued.
    handles: Option<(ScHandle, ScHandle)>,
}

impl Registration {
    /// Open fresh handles and register on them. The service manager answers
    /// `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` when it is behind; its documented remedy is to close the handles,
    /// open new ones and register again, so that is what is done, for as long as it answers so.
    fn arm() -> anyhow::Result<Registration> {
        loop {
            let (manager, service) = open_handles(SERVICE_QUERY_STATUS)?;
            let notification = Box::into_raw(Box::new(Notification {
                buffer: SERVICE_NOTIFY_2W {
                    dwVersion: SERVICE_NOTIFY_STATUS_CHANGE,
                    pfnNotifyCallback: Some(on_notification),
                    ..SERVICE_NOTIFY_2W::default()
                },
                fired: AtomicBool::new(false),
            }));
            // SAFETY: `notification` is a live allocation this function owns; the context is the address of its
            // own `fired`.
            let code = unsafe {
                (*notification).buffer.pContext = (&raw mut (*notification).fired).cast();
                NotifyServiceStatusChangeW(service.0, SETTLED_MASK, (&raw mut (*notification).buffer).cast_const())
            };
            let registration = Registration {
                notification,
                handles: Some((manager, service)),
            };
            match code {
                0 => return Ok(registration),
                code if code == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING.0 => continue,
                code => {
                    return Err(std::io::Error::from_raw_os_error(code as i32))
                        .context("register for the sshd service's state changes");
                }
            }
        }
    }

    /// Block, with no bound, until the notification has been delivered. The wait is alertable and ends on the
    /// delivery itself; an unrelated callback wakes it and it waits again.
    fn wait(&self) {
        // SAFETY: the notification is live until `self` is dropped.
        while !unsafe { &(*self.notification).fired }.load(Ordering::Acquire) {
            // SAFETY: no pointers; alertable, so the delivery's callback runs on this thread.
            unsafe { SleepEx(INFINITE, true) }; // sleep-ok: unbounded alertable wait for the service manager's notification callback, not a timeout
        }
    }
}

impl Drop for Registration {
    /// The service handle closes first, which ends the registration; a notification already queued is then
    /// run, so it writes into a notification that still exists, and the notification is freed last, when the
    /// close succeeded.
    fn drop(&mut self) {
        let closed = match self.handles.take() {
            Some((manager, service)) => {
                let closed = service.close();
                drop(manager);
                closed
            }
            None => Ok(()),
        };
        release(self.notification, closed);
    }
}

/// What became of a notification when its registration ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseOutcome {
    Freed,
    /// Left allocated for good: its service handle could not be closed.
    Leaked,
}

/// End the use of `notification` once its service handle was closed with `closed`: run the callbacks already
/// queued to this thread, then free it. After a failed close it is not freed, and the leak is logged.
///
/// `notification` came from `Box::into_raw` in [`Registration::arm`] and is released once.
fn release(notification: *mut Notification, closed: windows::core::Result<()>) -> ReleaseOutcome {
    // SAFETY: a zero-length alertable wait runs the callbacks already queued to this thread.
    unsafe { SleepEx(0, true) }; // sleep-ok: runs the queued notification callback, waits for nothing
    if let Err(error) = closed {
        tracing::warn!(
            "the sshd service handle could not be closed ({}); the notification registered on it is never freed, \
             for a late callback may still write into it",
            describe_error(&error)
        );
        return ReleaseOutcome::Leaked;
    }
    // SAFETY: the close succeeded, so no callback is queued after the drain above; the pointer came from
    // `Box::into_raw` and is freed once, here.
    drop(unsafe { Box::from_raw(notification) });
    ReleaseOutcome::Freed
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod service_tests;

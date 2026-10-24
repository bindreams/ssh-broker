//! provision::sessions — which sessions `apply` starts an agent in.
//!
//! The logon trigger starts an agent at each logon; it does not reach a user who is already
//! logged on when `apply` runs (the first install, or an upgrade). `apply` starts one in each such
//! session, so nobody has to log off and on again.

use anyhow::Context;
use windows::Win32::System::RemoteDesktop::{
    WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSDisconnected,
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
};
use windows::core::PWSTR;

/// What `apply` needs to know about one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u32,
    pub state: SessionState,
    /// Whether a user is logged on in it (the logon screen of an idle session has none), or why
    /// that could not be told.
    pub has_user: Result<bool, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Disconnected,
    /// Connecting, listening, shadowing and the rest: nobody to serve yet.
    Other,
}

/// The sessions to start an agent in, and those that might need one but could not be checked.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Targets {
    pub ids: Vec<u32>,
    /// Sessions whose user could not be looked up, with why. No agent is started there, but they
    /// count in [`Targets::total`] so the summary does not undercount.
    pub unknown: Vec<(u32, String)>,
}

impl Targets {
    /// Every session `apply` tried to cover.
    pub fn total(&self) -> usize {
        self.ids.len() + self.unknown.len()
    }
}

/// The sessions to start an agent in: logged-on users who are connected or disconnected. Never
/// session 0, which is the services session.
pub fn target_sessions(all: &[SessionInfo]) -> Targets {
    let mut targets = Targets::default();
    for s in all {
        if s.id == 0 || !matches!(s.state, SessionState::Active | SessionState::Disconnected) {
            continue;
        }
        match &s.has_user {
            Ok(true) => targets.ids.push(s.id),
            Ok(false) => {}
            Err(why) => targets.unknown.push((s.id, why.clone())),
        }
    }
    targets
}

/// [`target_sessions`] of this host's sessions.
pub fn interactive_sessions() -> anyhow::Result<Targets> {
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: valid out-pointers; the returned array is freed below with `WTSFreeMemory`.
    unsafe { WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut list, &mut count) }
        .context("enumerate sessions")?;
    // SAFETY: on success `list` points at `count` entries that stay valid until freed.
    let found: Vec<SessionInfo> = unsafe { entries(list, count) }
        .iter()
        .map(|s| SessionInfo {
            id: s.SessionId,
            state: state_of(s.State),
            has_user: has_user(s.SessionId),
        })
        .collect();
    if !list.is_null() {
        // SAFETY: `list` came from `WTSEnumerateSessionsW` and is freed once.
        unsafe { WTSFreeMemory(list.cast()) };
    }
    Ok(target_sessions(&found))
}

/// The `count` entries at `list`, or none if `list` is null.
///
/// `WTSEnumerateSessionsW` documents a null list only together with a zero count, so a null list
/// with entries is a broken contract; release builds still return an empty slice rather than
/// build one from a null pointer.
///
/// # Safety
/// A non-null `list` must point at `count` initialised entries that outlive the returned borrow.
unsafe fn entries<'a>(list: *const WTS_SESSION_INFOW, count: u32) -> &'a [WTS_SESSION_INFOW] {
    debug_assert!(
        !list.is_null() || count == 0,
        "WTSEnumerateSessionsW returned a null list with {count} entries"
    );
    if list.is_null() {
        return &[];
    }
    // SAFETY: the caller guarantees `count` entries at the non-null `list`.
    unsafe { std::slice::from_raw_parts(list, count as usize) }
}

fn state_of(state: WTS_CONNECTSTATE_CLASS) -> SessionState {
    if state == WTSActive {
        SessionState::Active
    } else if state == WTSDisconnected {
        SessionState::Disconnected
    } else {
        SessionState::Other
    }
}

/// Whether session `id` has a user name; the error text if the query failed. A failed query is
/// never taken for "no user": the caller reports the session and starts nothing in it.
fn has_user(id: u32) -> Result<bool, String> {
    let mut name = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: valid out-pointers; the buffer is freed below.
    if let Err(e) =
        unsafe { WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), id, WTSUserName, &mut name, &mut bytes) }
    {
        return Err(e.to_string());
    }
    // SAFETY: on success `name` is a NUL-terminated wide string we own until freed.
    let present = !name.is_null() && unsafe { name.as_wide() }.iter().any(|&u| u != 0);
    // SAFETY: `name` came from `WTSQuerySessionInformationW` and is freed once.
    unsafe { WTSFreeMemory(name.0.cast()) };
    Ok(present)
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod sessions_tests;

//! provision::probe — the parity checks run IN session 1 by `verify-probe`, plus the pure
//! line format/parse the parent `verify` uses to read the result.
//!
//! `verify` itself runs in whatever session sshd dropped it into (session 0 over the network),
//! so the DPAPI/symlink/session checks MUST run in an agent-spawned child (which is in session
//! 1) — running them in verify's own process would false-negative on a correctly-installed box.

/// Symlink-traversal probe outcome. `Skipped` means the link could not even be created (a
/// LeastPrivilege token lacks `SeCreateSymbolicLinkPrivilege`), so traversal was untestable —
/// distinct from `Blocked` (created but RedirectionGuard refused to follow it). Only `Blocked`
/// is a parity FAILURE; `Skipped` is informational (the session-id check is the real gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkState {
    Ok,
    Blocked,
    Skipped,
}

impl SymlinkState {
    fn as_str(self) -> &'static str {
        match self {
            SymlinkState::Ok => "ok",
            SymlinkState::Blocked => "blocked",
            SymlinkState::Skipped => "skip",
        }
    }
    fn parse(s: &str) -> SymlinkState {
        match s {
            "ok" => SymlinkState::Ok,
            "blocked" => SymlinkState::Blocked,
            _ => SymlinkState::Skipped, // missing/unknown → untestable, not a failure
        }
    }
    /// Whether this outcome should fail parity (only a confirmed block does).
    pub fn is_failure(self) -> bool {
        matches!(self, SymlinkState::Blocked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResult {
    pub session_id: u32,
    pub dpapi_ok: bool,
    pub symlink: SymlinkState,
}

/// The single line `verify-probe` prints to stdout.
pub fn format_probe_line(session_id: u32, dpapi_ok: bool, symlink: SymlinkState) -> String {
    format!(
        "PROBE session_id={session_id} dpapi={} symlink={}",
        if dpapi_ok { "ok" } else { "fail" },
        symlink.as_str()
    )
}

/// Parse the `PROBE …` line out of the child's stdout (tolerant of surrounding noise).
/// Default-deny on the gating keys: a missing line errors; missing dpapi reads as fail and a
/// missing session_id as 0. Symlink defaults to `Skipped` (informational, never a false fail).
pub fn parse_probe_line(stdout: &str) -> anyhow::Result<ProbeResult> {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("PROBE "))
        .ok_or_else(|| anyhow::anyhow!("no PROBE line in probe output"))?;
    let mut r = ProbeResult { session_id: 0, dpapi_ok: false, symlink: SymlinkState::Skipped };
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("session_id=") {
            r.session_id = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("dpapi=") {
            r.dpapi_ok = v == "ok";
        } else if let Some(v) = tok.strip_prefix("symlink=") {
            r.symlink = SymlinkState::parse(v);
        }
    }
    Ok(r)
}

// ── Windows parity checks (run in the session-1 probe child) ───────────────────────

/// The session this process runs in (`ProcessIdToSessionId`). In the agent-spawned child this
/// IS the agent's session — the actual session-1 guarantee.
#[cfg(windows)]
pub fn current_session_id() -> u32 {
    let mut sid = 0u32;
    let _ =
        unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(std::process::id(), &mut sid) };
    sid
}

/// The active physical console session id (`WTSGetActiveConsoleSessionId`); `0xFFFF_FFFF` if
/// none. Parity holds when `current_session_id()` equals this and is not 0.
#[cfg(windows)]
pub fn active_console_session() -> u32 {
    unsafe { windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() }
}

/// DPAPI round-trip: protect then unprotect a blob and confirm it survives. Proves this
/// process has a usable user profile / master key (absent in a bare network-logon session).
#[cfg(windows)]
pub fn dpapi_roundtrip(sample: &[u8]) -> bool {
    dpapi_protect(sample)
        .and_then(|blob| dpapi_unprotect(&blob))
        .map(|round| round == sample)
        .unwrap_or(false)
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, None, None, None, None, 0, &mut out)?;
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
        Ok(bytes)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&input, None, None, None, None, 0, &mut out)?;
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
        Ok(bytes)
    }
}

/// Create a symlink in a fresh temp dir and read through it. In a network-logon session
/// RedirectionGuard can block following the link (`STATUS_UNTRUSTED_MOUNT_POINT`); a session-1
/// token traverses it. Returns `Skipped` if the link could not be created (no privilege — the
/// common case for a LeastPrivilege agent, so this must NOT fail parity), `Blocked` if created
/// but not followable, `Ok` if it traversed. (A privilege-free, discriminating probe would use
/// a pre-existing cross-context link; that refinement is a Phase-8 item. The session-id check
/// is the primary parity proof.)
#[cfg(windows)]
pub fn symlink_probe() -> SymlinkState {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("sb-symprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = (|| -> SymlinkState {
        if std::fs::create_dir_all(&dir).is_err() {
            return SymlinkState::Skipped;
        }
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        if std::fs::File::create(&target).and_then(|mut f| f.write_all(b"parity")).is_err() {
            return SymlinkState::Skipped;
        }
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            return SymlinkState::Skipped; // no SeCreateSymbolicLinkPrivilege — untestable
        }
        match std::fs::read(&link) {
            Ok(c) if c == b"parity" => SymlinkState::Ok,
            _ => SymlinkState::Blocked, // created but the read was refused (RedirectionGuard)
        }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    state
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

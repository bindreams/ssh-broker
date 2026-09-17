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
    /// Whether the payload `verify` sent UPSTREAM reached the child unchanged. Only the child can
    /// see what arrived, so the PROBE line is the only way to learn the client → child direction;
    /// the downstream half is checked by comparing the child's stdout directly.
    pub upstream: UpstreamState,
}

/// Outcome of the upstream (client → child) transparency check.
///
/// `Absent` is deliberately distinct from `Fail`. `apply` tolerates NOT replacing the canonical
/// exe when a running agent holds it open (see `install_self`), so a probe child older than this
/// check is a reachable state on an otherwise healthy box. Reporting that as "the payload did not
/// reach the child intact" would be a diagnosis the code cannot support: the payload may have
/// arrived perfectly and the child simply never looked. Both still FAIL the gate — the difference
/// is only in what `verify` tells the operator to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamState {
    Ok,
    Fail,
    Absent,
}

impl UpstreamState {
    fn parse(s: &str) -> UpstreamState {
        if s == "ok" {
            UpstreamState::Ok
        } else {
            UpstreamState::Fail
        }
    }

    /// Proven intact. Default-deny: ONLY `Ok` passes, so an exe too old to report cannot silently
    /// restore the unverified assertion this check exists to replace.
    pub fn proven(self) -> bool {
        matches!(self, UpstreamState::Ok)
    }

    /// The `verify` row detail — never a claim the code cannot support.
    pub fn detail(self) -> String {
        match self {
            UpstreamState::Ok => String::new(),
            UpstreamState::Fail => "the payload verify sent upstream did not reach the child intact".into(),
            UpstreamState::Absent => "the installed probe child predates this check and reported nothing — \
                 re-run `apply` (stop the agent first: it cannot replace the exe while the agent holds it open)"
                .into(),
        }
    }
}

// ── binary-transparency probe ────────────────────────────────────────────────────────

/// Brackets around the binary-transparency payload in the probe child's stdout.
///
/// These cannot collide with the data they delimit. [`binary_probe_payload`] is the 256 byte
/// values in ascending order, so every window of it is a consecutive ascending run — and neither
/// `BINPROBE<` (`42 49 4E 50 52 4F 42 45 3C`) nor `>BINPROBE` is. A naive byte search therefore
/// cannot land inside the payload, which matters precisely because the payload is arbitrary bytes.
const BINARY_PROBE_OPEN: &[u8] = b"BINPROBE<";
const BINARY_PROBE_CLOSE: &[u8] = b">BINPROBE";

/// The payload the probe child writes and `verify` checks: every one of the 256 byte values, so
/// NUL, `0xFF`, a lone CR, a lone LF and invalid UTF-8 all have to survive the real path.
pub fn binary_probe_payload() -> Vec<u8> {
    (0..=255u8).collect()
}

/// Write the bracketed payload. Deliberately `write_all` on a raw handle rather than `println!`:
/// the whole point is that no layer between here and `verify` reinterprets a byte.
pub fn emit_binary_probe<W: std::io::Write>(w: &mut W) -> std::io::Result<()> {
    w.write_all(BINARY_PROBE_OPEN)?;
    w.write_all(&binary_probe_payload())?;
    w.write_all(BINARY_PROBE_CLOSE)?;
    w.write_all(b"\n")?; // so the PROBE line that follows starts cleanly
    w.flush()
}

/// Whether the payload crossed the agent, the child's pipes and the frame relay byte for byte.
///
/// This is the end-to-end half of a claim the in-memory relay tests cannot reach: they exercise
/// the shim's framing over a duplex in one process, never a real `CreatePipe`, a real child or a
/// real socket. Default-deny — a missing or truncated marker is a FAILURE, not a skip, so an
/// installed binary too old to emit it is reported rather than silently passed.
pub fn binary_probe_ok(stdout: &[u8]) -> bool {
    extract_binary_probe(stdout).is_some_and(|got| got == binary_probe_payload())
}

/// Whether the payload that arrived on the probe child's stdin is the one `verify` sent upstream.
///
/// Pure, and host-tested, on purpose. Its only caller (`provision::imp::verify_probe`) is
/// `#[cfg(windows)]` and has no test module, so mutating the comparison THERE to a bare `true`
/// would make `verify` print a PASS for the client → child row unconditionally with the whole
/// suite still green — restoring exactly the unverified assertion that row exists to replace.
///
/// Default-deny by construction: a short or empty read compares unequal, and an I/O error
/// propagates so the caller reports it rather than mistaking it for "arrived intact".
pub fn upstream_payload_ok<R: std::io::Read>(r: &mut R) -> std::io::Result<bool> {
    let mut got = Vec::new();
    r.read_to_end(&mut got)?;
    Ok(got == binary_probe_payload())
}

fn extract_binary_probe(stdout: &[u8]) -> Option<&[u8]> {
    let open = find_bytes(stdout, BINARY_PROBE_OPEN)? + BINARY_PROBE_OPEN.len();
    let rest = &stdout[open..];
    let close = find_bytes(rest, BINARY_PROBE_CLOSE)?;
    Some(&rest[..close])
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The single line `verify-probe` prints to stdout.
pub fn format_probe_line(session_id: u32, dpapi_ok: bool, symlink: SymlinkState, upstream_ok: bool) -> String {
    format!(
        "PROBE session_id={session_id} dpapi={} symlink={} upstream={}",
        if dpapi_ok { "ok" } else { "fail" },
        symlink.as_str(),
        if upstream_ok { "ok" } else { "fail" }
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
    let mut r = ProbeResult {
        session_id: 0,
        dpapi_ok: false,
        symlink: SymlinkState::Skipped,
        // Default-deny, like `dpapi`: a probe child too old to report it must read as "not
        // proven", never as proven. This one gates a claim the README makes, so a silent
        // default of "ok" would restore exactly the unverified assertion it exists to replace.
        // `Absent` rather than `Fail` so the row can say WHICH of the two happened.
        upstream: UpstreamState::Absent,
    };
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("session_id=") {
            r.session_id = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("dpapi=") {
            r.dpapi_ok = v == "ok";
        } else if let Some(v) = tok.strip_prefix("symlink=") {
            r.symlink = SymlinkState::parse(v);
        } else if let Some(v) = tok.strip_prefix("upstream=") {
            r.upstream = UpstreamState::parse(v);
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
    let _ = unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(std::process::id(), &mut sid) };
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
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
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
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
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
        if std::fs::File::create(&target)
            .and_then(|mut f| f.write_all(b"parity"))
            .is_err()
        {
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

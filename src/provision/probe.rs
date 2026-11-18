//! provision::probe — the parity checks run IN session 1 by `verify-probe`, plus the pure
//! line format/parse the parent `verify` uses to read the result.
//!
//! `verify` itself runs in whatever session sshd dropped it into (session 0 over the network),
//! so the DPAPI/symlink/session checks MUST run in an agent-spawned child (which is in session
//! 1) — running them in verify's own process would false-negative on a correctly-installed box.

use crate::socket_loc::Elevation;

#[cfg(windows)]
pub mod link;

/// Outcome of reading through a junction in the probe's temp directory. The junction is one that a
/// token below High made: RedirectionGuard refuses to follow a link a non-administrator made, and a
/// process that made the link itself always follows it, so only a followed junction proves anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkState {
    /// The junction was followed.
    Ok,
    /// The junction exists and the read was refused as an untrusted mount point (error 448):
    /// RedirectionGuard is on in this session.
    Blocked,
    /// The junction was made, and the read failed for another reason. Also what a probe that reported
    /// no outcome gets.
    Failed,
    /// The junction could not be made (a temp directory on a volume with no reparse points, say), so
    /// following it was not tested. Informational: it fails nothing.
    Skipped,
}

impl SymlinkState {
    fn as_str(self) -> &'static str {
        match self {
            SymlinkState::Ok => "ok",
            SymlinkState::Blocked => "blocked",
            SymlinkState::Failed => "fail",
            SymlinkState::Skipped => "skip",
        }
    }
    fn parse(s: &str) -> SymlinkState {
        match s {
            "ok" => SymlinkState::Ok,
            "blocked" => SymlinkState::Blocked,
            "skip" => SymlinkState::Skipped,
            _ => SymlinkState::Failed, // missing or unknown: nothing was proven
        }
    }
    /// Whether this outcome fails parity: a junction that was made and not followed.
    pub fn is_failure(self) -> bool {
        matches!(self, SymlinkState::Blocked | SymlinkState::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub session_id: u32,
    pub dpapi_ok: bool,
    pub symlink: SymlinkState,
    /// Whether the payload `verify` sent UPSTREAM reached the child unchanged. Only the child can
    /// see what arrived, so the PROBE line is the only way to learn the client → child direction;
    /// the downstream half is checked by comparing the child's stdout directly.
    pub upstream: UpstreamState,
    /// The logon type of the probe's logon session (`SECURITY_LOGON_TYPE`), when it could be read.
    /// `None` is "not proven", like a missing `dpapi`.
    pub logon_type: Option<u32>,
    /// How much of an administrator's power the probe's own token has, when it could say. `None` is
    /// "not proven": a row about the session being elevated never passes on it.
    pub elevation: Option<Elevation>,
    /// The relative id of the probe's integrity label (`0x2000` Medium, `0x3000` High), when it could
    /// be read. `None` is "not proven".
    pub integrity: Option<u32>,
}

/// `SECURITY_LOGON_TYPE` Interactive.
const LOGON_TYPE_INTERACTIVE: u32 = 2;
/// `SECURITY_LOGON_TYPE` Batch: what Task Scheduler gives an auto-login task.
const LOGON_TYPE_BATCH: u32 = 4;

/// Whether a probe that ran in session `session_id` with a logon session of `logon_type` is in a
/// genuine user session. Session 0 is the services session of a network logon, the limited
/// environment this tool exists to leave; but a user's own interactive or batch logon (the
/// auto-login task's) lands there too and has a loaded profile and DPAPI. Default-deny: a network
/// logon, an unknown type or an unreadable one in session 0 is not genuine.
pub fn is_genuine_session(session_id: u32, logon_type: Option<u32>) -> bool {
    session_id != 0 || matches!(logon_type, Some(LOGON_TYPE_INTERACTIVE | LOGON_TYPE_BATCH))
}

/// Outcome of the upstream (client → child) transparency check.
///
/// `Absent` is deliberately distinct from `Fail`. A probe child older than this check is
/// reachable: `apply` has not been run since the build that added it (a failed `apply` leaves
/// the old exe in place). Reporting that as "the payload did not
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
            // State what is KNOWN, then the likely cause — the same discipline the `Fail` arm
            // follows. All the parser can tell is that no `upstream=` token arrived; an exe older
            // than this check is the usual reason, but a truncated or garbled PROBE line and a
            // child killed mid-write produce it too, and those are not fixed by re-running `apply`.
            UpstreamState::Absent => "no `upstream=` token in the PROBE line (usually an installed exe older \
                 than this check — re-run `apply`, stopping the agent first so the exe can be replaced)"
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

/// The word of an [`Elevation`] on the PROBE line.
fn elevation_word(elevation: Elevation) -> &'static str {
    match elevation {
        Elevation::Full => "full",
        Elevation::Filtered => "filtered",
        Elevation::Standard => "standard",
    }
}

fn parse_elevation(word: &str) -> Option<Elevation> {
    [Elevation::Full, Elevation::Filtered, Elevation::Standard]
        .into_iter()
        .find(|&elevation| elevation_word(elevation) == word)
}

/// A relative id as the line writes it (`0x2000`), and back.
fn parse_integrity(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

/// The single line `verify-probe` prints to stdout.
pub fn format_probe_line(r: &ProbeResult) -> String {
    let mut line = format!(
        "PROBE session_id={} dpapi={} symlink={} upstream={}",
        r.session_id,
        if r.dpapi_ok { "ok" } else { "fail" },
        r.symlink.as_str(),
        if r.upstream.proven() { "ok" } else { "fail" }
    );
    if let Some(logon_type) = r.logon_type {
        line.push_str(&format!(" logon={logon_type}"));
    }
    if let Some(elevation) = r.elevation {
        line.push_str(&format!(" elevation={}", elevation_word(elevation)));
    }
    if let Some(rid) = r.integrity {
        line.push_str(&format!(" integrity={rid:#x}"));
    }
    line
}

/// Parse the `PROBE …` line out of the child's stdout (tolerant of surrounding noise).
/// Default-deny on every key: a missing line errors; a missing dpapi reads as fail, a missing
/// session_id as 0, a missing or unknown symlink as `Failed`, and a missing elevation or integrity
/// as `None`, which no row passes on.
pub fn parse_probe_line(stdout: &str) -> anyhow::Result<ProbeResult> {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("PROBE "))
        .ok_or_else(|| anyhow::anyhow!("no PROBE line in probe output"))?;
    let mut r = ProbeResult {
        session_id: 0,
        dpapi_ok: false,
        symlink: SymlinkState::Failed,
        // Default-deny, like `dpapi`: a probe child too old to report it must read as "not
        // proven", never as proven. This one gates a claim the README makes, so a silent
        // default of "ok" would restore exactly the unverified assertion it exists to replace.
        // `Absent` rather than `Fail` so the row can say WHICH of the two happened.
        upstream: UpstreamState::Absent,
        logon_type: None,
        elevation: None,
        integrity: None,
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
        } else if let Some(v) = tok.strip_prefix("logon=") {
            r.logon_type = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("elevation=") {
            r.elevation = parse_elevation(v);
        } else if let Some(v) = tok.strip_prefix("integrity=") {
            r.integrity = parse_integrity(v);
        }
    }
    Ok(r)
}

// ── what a probe says about its junction ───────────────────────────────────────────────

/// What the probe writes before each line of its stderr about the junction (why it could not make one,
/// why it could not read through it, what it could not remove), so `verify` can show those lines and no
/// others.
pub const JUNCTION_SAID: &str = "ssh-broker: junction: ";
/// How much of that `verify` shows on a row.
pub const JUNCTION_NOTE_LINES: usize = 4;
pub const JUNCTION_NOTE_CHARS: usize = 400;

/// The junction lines of a probe's `stderr`, a few of them and joined with `; `: the probe's own words
/// about what it could not do, for the row of the junction.
pub fn junction_notes(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix(JUNCTION_SAID))
        .map(str::trim)
        .take(JUNCTION_NOTE_LINES)
        .collect();
    lines.join("; ").chars().take(JUNCTION_NOTE_CHARS).collect()
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

/// The logon type of this process's logon session, read from LSA by the token's logon id. `None`
/// when any step fails: the caller treats "unknown" as "not proven".
#[cfg(windows)]
pub fn current_logon_type() -> Option<u32> {
    use windows::Win32::Security::Authentication::Identity::{
        LsaFreeReturnBuffer, LsaGetLogonSessionData, SECURITY_LOGON_SESSION_DATA,
    };
    use windows::Win32::Security::{TOKEN_STATISTICS, TokenStatistics};

    let token = crate::winutil::own_token().ok()?;
    let info = crate::winutil::token_information(token.0, TokenStatistics).ok()?;
    // SAFETY: `TOKEN_STATISTICS` is plain data.
    let stats = unsafe { info.header::<TOKEN_STATISTICS>() }.ok()?;
    let mut data: *mut SECURITY_LOGON_SESSION_DATA = std::ptr::null_mut();
    // SAFETY: a valid logon id and out-pointer; the buffer LSA allocates is freed below.
    let status = unsafe { LsaGetLogonSessionData(&stats.AuthenticationId, &mut data) };
    if status.0 != 0 || data.is_null() {
        return None;
    }
    // SAFETY: LSA returned a valid structure, read before it is freed.
    let logon_type = unsafe { (*data).LogonType };
    // SAFETY: the buffer came from LSA.
    let _ = unsafe { LsaFreeReturnBuffer(data.cast()) };
    Some(logon_type)
}

/// This process's own elevation and integrity level, read from its token by the one reader `account`
/// has. Each is `None` when it could not be read: the caller treats "unknown" as "not proven".
#[cfg(windows)]
pub fn current_token_facts() -> (Option<Elevation>, Option<u32>) {
    let Ok(token) = crate::winutil::own_token() else {
        return (None, None);
    };
    (
        crate::account::elevation_of(token.0).ok(),
        crate::account::integrity_of(token.0).ok(),
    )
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

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

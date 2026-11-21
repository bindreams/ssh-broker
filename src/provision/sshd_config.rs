//! provision::sshd_config — making sshd accept `SSH_BROKER_ELEVATION` from a client.
//!
//! `install` owns a drop-in file, [`DROP_IN_NAME`] in `sshd_config.d`, that holds one `AcceptEnv` line, and
//! adds one [`INCLUDE_LINE`] to `sshd_config` when sshd does not read the drop-in already. When the folder or
//! the drop-in cannot be used, it puts the [`ACCEPT_LINE`] itself into `sshd_config`. This module is the pure
//! part: the text edit, the reader of `sshd -T`, and the `doctor` row. [`configure`] is the flow over a
//! [`configure::SshdHost`], which tests stand in for; the Windows implementation is `machine::Machine`.
//!
//! What it rests on: sshd hands an accepted variable to the DefaultShell and drops
//! another silently; an `Include` is read only above the first `Match` for every account; plain `sshd -T`
//! prints `acceptenv` when the variable is in effect and `sshd -T -C user=` fails for a local account on
//! Windows, so the effective configuration is asked globally; a server's own `SetEnv` beats the client's
//! value; and a change needs a restart of the service.

use configure::ConfigRead;

use super::report::Check;
use crate::socket_loc::Elevation;

pub mod configure;
#[cfg(windows)]
pub mod machine;
pub mod restart;

/// The folder of drop-ins, beside `sshd_config`.
pub const DROP_IN_DIR_NAME: &str = "sshd_config.d";

/// The drop-in's file name in [`DROP_IN_DIR_NAME`].
pub const DROP_IN_NAME: &str = "10-ssh-broker.conf";

/// The line that makes sshd accept the variable: the drop-in's one line, and the line `sshd_config` gets, above
/// its first `Match`, when the folder cannot be used.
pub const ACCEPT_LINE: &str = "AcceptEnv SSH_BROKER_ELEVATION";

/// What the drop-in holds, written whole each time and compared exactly.
pub fn drop_in_text() -> String {
    format!("{ACCEPT_LINE}\r\n")
}

/// The one line `sshd_config` gets, above its first `Match`, when sshd does not read the drop-in.
pub const INCLUDE_LINE: &str = "Include sshd_config.d/*.conf";

/// What to do about sshd at this PC when what `install` said does not settle whether it runs.
pub(crate) const CHECK_SSHD: &str =
    "Check sshd at this PC: `sc query sshd`; start it with `net start sshd` if it is stopped.";

/// The variable's name, as the `doctor` row and `sshd -T` know it.
const VARIABLE: &str = crate::protocol::ElevationPolicy::VARIABLE;

/// Why a file cannot be edited by [`with_line`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cannot(pub String);

impl std::fmt::Display for Cannot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Cannot {}

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// `text` with `line` ([`INCLUDE_LINE`] or [`ACCEPT_LINE`]) as a line of its own immediately above the first
/// line whose first token is `Match` (without regard to case), or at the end when there is none. What follows
/// a `Match` belongs to that block, so the line has to come before it. A UTF-8 BOM and the file's line ending
/// (that of its first line break; CRLF when it has none) are kept, and no other byte changes: at the end of a
/// file that does not end in a line break, the break goes before the inserted line and the file still ends as
/// it did.
///
/// A file that is not UTF-8 or ASCII text (UTF-16, a NUL) or has a line break that is neither CRLF nor LF
/// is [`Cannot`]: where its lines are is not known.
pub fn with_line(text: &[u8], line: &str) -> Result<Vec<u8>, Cannot> {
    if text.starts_with(&[0xFF, 0xFE]) || text.starts_with(&[0xFE, 0xFF]) {
        return Err(Cannot(
            "it is UTF-16 text, and only UTF-8 or ASCII text is edited".into(),
        ));
    }
    if text.contains(&0) {
        return Err(Cannot("it holds a NUL byte, so it is not text".into()));
    }
    let (bom, body) = match text.strip_prefix(BOM) {
        Some(body) => (BOM, body),
        None => (&[][..], text),
    };
    let body = std::str::from_utf8(body).map_err(|_| Cannot("it is not valid UTF-8".into()))?;
    let bytes = body.as_bytes();
    if bytes
        .iter()
        .enumerate()
        .any(|(at, &byte)| byte == b'\r' && bytes.get(at + 1) != Some(&b'\n'))
    {
        return Err(Cannot("it has a line break that is neither CRLF nor LF".into()));
    }
    let eol = match body.find('\n') {
        Some(at) if at > 0 && bytes[at - 1] == b'\r' => "\r\n",
        Some(_) => "\n",
        None => "\r\n",
    };
    let first_match = {
        let mut offset = 0;
        body.split_inclusive('\n').find_map(|line| {
            let here = offset;
            offset += line.len();
            keyword(line)
                .is_some_and(|(word, _)| word.eq_ignore_ascii_case("match"))
                .then_some(here)
        })
    };
    let mut out = Vec::with_capacity(text.len() + line.len() + 2);
    out.extend_from_slice(bom);
    match first_match {
        Some(at) => {
            out.extend_from_slice(&bytes[..at]);
            out.extend_from_slice(format!("{line}{eol}").as_bytes());
            out.extend_from_slice(&bytes[at..]);
        }
        None if body.is_empty() || body.ends_with('\n') => {
            out.extend_from_slice(bytes);
            out.extend_from_slice(format!("{line}{eol}").as_bytes());
        }
        None => {
            out.extend_from_slice(bytes);
            out.extend_from_slice(format!("{eol}{line}").as_bytes());
        }
    }
    Ok(out)
}

/// The keyword of a line of `sshd_config` and the rest of it, as sshd tokenises: it skips leading spaces, tabs,
/// CRs and form feeds, ends the keyword at white space or an `=`, and skips the white space and one `=` that
/// follow. The rest has no trailing white space. `None` for a line with no keyword (blank, or a comment: its
/// first token begins with `#`).
fn keyword(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start_matches([' ', '\t', '\r', '\x0c']);
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let (word, rest) = line.split_at(end);
    if word.is_empty() || word.starts_with('#') {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    Some((word, rest))
}

/// The first `Include` line of `text` (trimmed) that does not name exactly [`INCLUDE_LINE`]'s argument, and so
/// brings in files from another location. The text is decoded lossily: an argument that does not survive it
/// is another one. Nothing an `Include` brings in is read.
pub fn include_elsewhere(text: &[u8]) -> Option<String> {
    let ours = INCLUDE_LINE.split_once(' ').map(|(_, argument)| argument)?;
    let text = String::from_utf8_lossy(text);
    text.trim_start_matches('\u{feff}').split('\n').find_map(|line| {
        let (word, rest) = keyword(line)?;
        (word.eq_ignore_ascii_case("include") && rest != ours).then(|| line.trim().to_owned())
    })
}

/// The words after `keyword` on the lines of `sshd -T` output that begin with it (the keyword compared
/// without regard to case).
fn keyword_words<'a>(sshd_t_output: &'a str, keyword: &'a str) -> impl Iterator<Item = &'a str> {
    sshd_t_output
        .lines()
        .map(str::trim)
        .filter_map(move |line| {
            let mut words = line.split_whitespace();
            words
                .next()
                .filter(|first| first.eq_ignore_ascii_case(keyword))
                .map(|_| words)
        })
        .flatten()
        .map(|word| word.trim_matches('"'))
}

/// Whether `sshd -T` says clients may send `name`: some `acceptenv` pattern matches it by sshd's rules (`*`
/// and `?`, case-sensitive, no negation).
pub fn accepts(sshd_t_output: &str, name: &str) -> bool {
    keyword_words(sshd_t_output, "acceptenv").any(|pattern| glob(pattern.as_bytes(), name.as_bytes()))
}

/// sshd's `match_pattern`: `*` is any run, `?` any one character, everything else itself.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it has covered up to.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// The value the server itself gives `name`: a global `setenv` line in `sshd -T` that sets it. The server's
/// own value beats the client's, and it needs no `AcceptEnv`. When the name is set more than once the last
/// is the one a session gets.
pub fn pinned(sshd_t_output: &str, name: &str) -> Option<String> {
    keyword_words(sshd_t_output, "setenv")
        .filter_map(|assignment| assignment.split_once('='))
        .filter(|(set, _)| *set == name)
        .map(|(_, value)| value.to_owned())
        .last()
}

/// Whether the variable is in force in what `sshd -T` printed: some `acceptenv` pattern takes it, or the
/// server pins its value itself. The one judgement of `install` and of the `doctor` row.
pub fn in_force(sshd_t_output: &str) -> bool {
    accepts(sshd_t_output, VARIABLE) || pinned(sshd_t_output, VARIABLE).is_some()
}

const ROW_NAME: &str = "sshd accepts SSH_BROKER_ELEVATION";

/// What the `doctor` row is given about sshd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshdReading {
    /// The sshd service runs with arguments, which can name another configuration file: nothing else was read.
    WithArguments(String),
    /// `sshd -T`'s output, and whether the running sshd has read the files (it reads them only when it starts).
    Read { listing: String, read: ConfigRead },
}

/// The `doctor` row for sshd's configuration. `sshd -T` reads sshd's host keys, which only administrators and
/// SYSTEM can read, so the row is judged only by an elevated administrator ([`Elevation::Full`]) and `reading`
/// is asked only there; for any other process the row is informational and passes. An elevated
/// administrator's row passes when the variable is in force
/// ([`in_force`]) and sshd has read what was changed; it fails when sshd started before a file of its
/// configuration changed (or at that moment), when the variable is not in force, and, with the cause, when
/// `reading` fails or when the `elevation` could not be read. A file whose time is ahead of the clock, or an
/// `Include` of another location, cannot be judged: the row passes and says so. A service that runs with
/// arguments is not checked: the row passes and says so.
pub fn accepts_row(
    elevation: &anyhow::Result<Elevation>,
    reading: impl FnOnce() -> anyhow::Result<SshdReading>,
) -> Check {
    let elevation = match elevation {
        Ok(elevation) => *elevation,
        Err(e) => {
            return Check::new(
                ROW_NAME,
                false,
                format!(
                    "{}, so whether sshd accepts {VARIABLE} is not known",
                    crate::offer::text::elevation_unreadable_clause(&format!("{e:#}"))
                ),
            );
        }
    };
    if elevation != Elevation::Full {
        return Check::new(
            ROW_NAME,
            true,
            "not checked here: sshd's configuration is read by an administrator's elevated `doctor`",
        );
    }
    let (listing, read) = match reading() {
        Err(e) => return Check::new(ROW_NAME, false, format!("{e:#}")),
        Ok(SshdReading::WithArguments(arguments)) => {
            return Check::new(
                ROW_NAME,
                true,
                format!(
                    "not checked: the sshd service runs with arguments (`{arguments}`), which can name another \
                     configuration file"
                ),
            );
        }
        Ok(SshdReading::Read { listing, read }) => (listing, read),
    };
    if !in_force(&listing) {
        return Check::new(
            ROW_NAME,
            false,
            format!(
                "sshd does not accept {VARIABLE} from clients; `ssh-broker install` sets it up, and says what it \
                 could not do. `ssh-broker elevate` works without it."
            ),
        );
    }
    let in_force_as = match pinned(&listing, VARIABLE) {
        Some(value) if !accepts(&listing, VARIABLE) => format!("pinned by the server to {value}"),
        _ => format!("sshd accepts {VARIABLE} from clients"),
    };
    match read {
        ConfigRead::Read | ConfigRead::NotRunning => Check::new(ROW_NAME, true, in_force_as),
        ConfigRead::Unread(file) => Check::new(
            ROW_NAME,
            false,
            format!(
                "sshd was started before {} was last changed and has not read it; `ssh-broker install` restarts it, or \
                 restart the sshd service",
                file.display()
            ),
        ),
        ConfigRead::AheadOfClock(file) => Check::new(
            ROW_NAME,
            true,
            format!(
                "{in_force_as}; {}'s change time is ahead of the clock, so whether the running sshd has read it \
                 cannot be told (`ssh-broker install` restarts it to be sure, or restart the sshd service)",
                file.display()
            ),
        ),
        ConfigRead::IncludesOther { file, line } => Check::new(
            ROW_NAME,
            true,
            format!(
                "{in_force_as}; {} has `{line}`, so whether the running sshd has read its configuration cannot be \
                 told (`ssh-broker install` restarts it to be sure, or restart the sshd service)",
                file.display()
            ),
        ),
    }
}

#[cfg(test)]
#[path = "sshd_config_tests.rs"]
mod sshd_config_tests;

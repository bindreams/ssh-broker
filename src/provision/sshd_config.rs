//! provision::sshd_config — making sshd accept `SSH_BROKER_ELEVATION` from a client.
//!
//! `apply` owns a drop-in file, [`DROP_IN_NAME`] in `sshd_config.d`, that holds one `AcceptEnv` line, and
//! adds one [`INCLUDE_LINE`] to `sshd_config` when sshd does not read the drop-in already. This module is
//! the pure part: the text edit, the reader of `sshd -T`, and the `verify` row. [`configure`] is the flow
//! over a [`configure::SshdHost`], which tests stand in for; the Windows implementation is
//! `machine::Machine`.
//!
//! What it rests on (spike 4, measured): sshd hands an accepted variable to the DefaultShell and drops
//! another silently; an `Include` is read only above the first `Match` for every account; plain `sshd -T`
//! prints `acceptenv` when the variable is in effect and `sshd -T -C user=` fails for a local account on
//! Windows, so the effective configuration is asked globally; a server's own `SetEnv` beats the client's
//! value; and a change needs a restart of the service.

use super::report::Check;
use crate::socket_loc::Integrity;

pub mod configure;
#[cfg(windows)]
pub mod machine;

/// The drop-in's file name in `sshd_config.d`.
pub const DROP_IN_NAME: &str = "10-ssh-broker.conf";

/// What the drop-in holds, written whole each time and compared exactly.
pub const DROP_IN_TEXT: &str = "AcceptEnv SSH_BROKER_ELEVATION\r\n";

/// The one line `sshd_config` gets, above its first `Match`, when sshd does not read the drop-in.
pub const INCLUDE_LINE: &str = "Include sshd_config.d/*.conf";

/// The variable's name, as the `verify` row and `sshd -T` know it.
const VARIABLE: &str = crate::protocol::ElevationPolicy::VARIABLE;

/// Why a file cannot be edited by [`with_include`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cannot(pub String);

impl std::fmt::Display for Cannot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Cannot {}

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// `text` with [`INCLUDE_LINE`] as a line of its own immediately above the first line whose first token is
/// `Match` (without regard to case), or at the end when there is none. What follows a `Match` belongs to
/// that block, so the line has to come before it. A UTF-8 BOM and the file's line ending (that of its first
/// line break; CRLF when it has none) are kept, and no other byte changes: at the end of a file that does
/// not end in a line break, the break goes before the inserted line and the file still ends as it did.
///
/// A file that is not UTF-8 or ASCII text (UTF-16, a NUL) or has a line break that is neither CRLF nor LF
/// is [`Cannot`]: where its lines are is not known.
pub fn with_include(text: &[u8]) -> Result<Vec<u8>, Cannot> {
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
            is_match_line(line).then_some(here)
        })
    };
    let mut out = Vec::with_capacity(text.len() + INCLUDE_LINE.len() + 2);
    out.extend_from_slice(bom);
    match first_match {
        Some(at) => {
            out.extend_from_slice(&bytes[..at]);
            out.extend_from_slice(format!("{INCLUDE_LINE}{eol}").as_bytes());
            out.extend_from_slice(&bytes[at..]);
        }
        None if body.is_empty() || body.ends_with('\n') => {
            out.extend_from_slice(bytes);
            out.extend_from_slice(format!("{INCLUDE_LINE}{eol}").as_bytes());
        }
        None => {
            out.extend_from_slice(bytes);
            out.extend_from_slice(format!("{eol}{INCLUDE_LINE}").as_bytes());
        }
    }
    Ok(out)
}

/// Whether the first token of `line` is the keyword `Match`.
fn is_match_line(line: &str) -> bool {
    line.trim_start_matches([' ', '\t'])
        .split(char::is_whitespace)
        .next()
        .is_some_and(|token| token.eq_ignore_ascii_case("match"))
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

const ROW_NAME: &str = "sshd accepts SSH_BROKER_ELEVATION";

/// The `verify` row for sshd's configuration. `sshd -T` reads sshd's host keys, which only administrators and
/// SYSTEM can read, so the row is judged only at [`Integrity::High`] and `sshd_t` is asked only there; below
/// it the row is informational and passes. At High it passes when the effective configuration accepts the
/// variable or the server sets it itself, and fails with the cause when `sshd -T` cannot run.
pub fn accepts_row(integrity: Integrity, sshd_t: impl FnOnce() -> anyhow::Result<String>) -> Check {
    if integrity != Integrity::High {
        return Check::new(
            ROW_NAME,
            true,
            "not checked here: sshd's configuration is read by an elevated `verify`",
        );
    }
    match sshd_t() {
        Err(e) => Check::new(ROW_NAME, false, format!("cannot ask sshd for its configuration: {e:#}")),
        Ok(output) if accepts(&output, VARIABLE) => {
            Check::new(ROW_NAME, true, format!("sshd accepts {VARIABLE} from clients"))
        }
        Ok(output) => match pinned(&output, VARIABLE) {
            Some(value) => Check::new(ROW_NAME, true, format!("pinned by the server to {value}")),
            None => Check::new(
                ROW_NAME,
                false,
                format!(
                    "sshd does not accept {VARIABLE} from clients; add the line `{INCLUDE_LINE}` above the first \
                     `Match` in sshd_config and restart sshd. `ssh-broker elevate` works without it."
                ),
            ),
        },
    }
}

#[cfg(test)]
#[path = "sshd_config_tests.rs"]
mod sshd_config_tests;

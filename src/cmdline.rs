//! The raw process command line, and the `-c` command recovered from it.
//!
//! `std::env::args` has already split and unquoted the command line, which loses the exact
//! command sshd sent: see [`decode_command`] for the three forms it arrives in, and
//! [`encoding`] for how the shim tells them apart.

#[cfg(not(windows))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use other::{current, encoding};
#[cfg(windows)]
pub use windows::{current, encoding};

/// How sshd built the `DefaultShell` command line; see [`decode_command`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// A PTY session: the command is appended as written.
    Verbatim,
    /// No PTY, `DefaultShellEscapeArguments` on (the default): the command is one escaped argument.
    Escaped,
    /// No PTY, `DefaultShellEscapeArguments=0`: the command is wrapped in quotes, unescaped.
    Wrapped,
}

/// Space and tab separate arguments; nothing else does.
const SEPARATORS: [char; 2] = [' ', '\t'];

/// Split `line` into arguments by the MSVCRT rules, the program name included.
pub fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut rest = line;
    while let Some((arg, after)) = next_arg(rest) {
        args.push(arg);
        rest = after;
    }
    args
}

/// The first argument of `s` and what follows it, or `None` when only separators remain.
fn next_arg(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start_matches(SEPARATORS);
    if s.is_empty() {
        return None;
    }
    let mut arg = String::new();
    let mut in_quotes = false;
    let mut chars = s.char_indices().peekable();
    let mut end = s.len();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                let mut backslashes = 1;
                while chars.next_if(|&(_, c)| c == '\\').is_some() {
                    backslashes += 1;
                }
                if chars.next_if(|&(_, c)| c == '"').is_some() {
                    // 2n backslashes then a quote: n backslashes, and the quote delimits.
                    // 2n+1: n backslashes and a literal quote.
                    arg.extend(std::iter::repeat_n('\\', backslashes / 2));
                    if backslashes % 2 == 1 {
                        arg.push('"');
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    arg.extend(std::iter::repeat_n('\\', backslashes));
                }
            }
            '"' => {
                if in_quotes && chars.next_if(|&(_, c)| c == '"').is_some() {
                    arg.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            }
            c if !in_quotes && SEPARATORS.contains(&c) => {
                end = i;
                break;
            }
            c => arg.push(c),
        }
    }
    Some((arg, &s[end..]))
}

/// The program name, which has no escape rules: a leading quote ends at the next quote.
fn after_program(line: &str) -> &str {
    let line = line.trim_start_matches(SEPARATORS);
    let end = match line.strip_prefix('"') {
        Some(quoted) => quoted.find('"').map_or(line.len(), |i| i + 2),
        None => line.find(SEPARATORS).unwrap_or(line.len()),
    };
    &line[end..]
}

/// The text after the `-c` token, as written; `None` when the line's first argument is not `-c`.
///
/// Exactly one separator is dropped: sshd puts one space between `-c` and the command, and any
/// further whitespace belongs to the command.
pub fn dash_c_tail(line: &str) -> Option<&str> {
    let (first, rest) = next_arg(after_program(line))?;
    (first == "-c").then(|| rest.strip_prefix(SEPARATORS).unwrap_or(rest))
}

/// The command a `-c` tail carries, as `encoding` says sshd wrote it; `None` when there is none.
///
/// Win32-OpenSSH builds the `DefaultShell` command line in three ways (`w32-doexec.c` and
/// `misc.c` at commit 274893f), and each has its own inverse:
///
/// - [`Encoding::Verbatim`], a PTY session (`ssh -t host cmd`): the command is appended to
///   `"shim" -c ` as written, so the tail is the command.
/// - [`Encoding::Escaped`], no PTY: the command is one argument. sshd wraps it in quotes when it
///   contains a space and does not start with `'`, escapes every `"`, and doubles a backslash
///   only when a `"` follows it. A tail starting with `"` is therefore a wrapped argument
///   whose last character is the closing quote, even when a backslash precedes it, which a
///   C-runtime splitter would read as an escaped quote. Inside, `\"` is a quote and a backslash
///   run before it halves. A command with a space or tab left unwrapped (`'a b'`, a tab with
///   no space) is not split.
/// - [`Encoding::Wrapped`], no PTY and `DefaultShellEscapeArguments=0`: the command is wrapped
///   in quotes with nothing escaped, so the quotes inside it are its own.
///
/// An empty command leaves nothing after `-c` in the first two forms, and is `None`.
pub fn decode_command(tail: &str, encoding: Encoding) -> Option<String> {
    if tail.is_empty() {
        return None;
    }
    Some(match encoding {
        Encoding::Verbatim => tail.to_string(),
        Encoding::Escaped => unescape_argument(unwrap_quotes(tail).unwrap_or(tail)),
        Encoding::Wrapped => unwrap_quotes(tail).unwrap_or(tail).to_string(),
    })
}

/// `s` without the quote that opens and the quote that closes it; `None` if it has no such pair.
fn unwrap_quotes(s: &str) -> Option<&str> {
    s.strip_prefix('"')?.strip_suffix('"')
}

/// Undo sshd's per-argument escaping: `\"` is a quote, and the backslashes before it were doubled.
/// Backslashes anywhere else are literal.
fn unescape_argument(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let mut run = 1;
        while chars.next_if_eq(&'\\').is_some() {
            run += 1;
        }
        if chars.next_if_eq(&'"').is_some() {
            out.extend(std::iter::repeat_n('\\', run / 2));
            out.push('"');
        } else {
            out.extend(std::iter::repeat_n('\\', run));
        }
    }
    out
}

#[cfg(test)]
#[path = "cmdline_tests.rs"]
mod cmdline_tests;

#[cfg(test)]
#[path = "cmdline_encoder_tests.rs"]
mod cmdline_encoder_tests;

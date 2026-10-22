//! The raw process command line, and the `-c` command recovered from it.
//!
//! `std::env::args` has already split and unquoted the command line, which loses the exact
//! command sshd sent: see [`decode_command`] for the three shapes it arrives in.

#[cfg(not(windows))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use other::current;
#[cfg(windows)]
pub use windows::current;

/// Space and tab separate arguments; nothing else does.
const SEPARATORS: [char; 2] = [' ', '\t'];

/// Split `line` into arguments by the MSVCRT rules, the program name included.
pub(crate) fn split_args(line: &str) -> Vec<String> {
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
pub fn dash_c_tail(line: &str) -> Option<&str> {
    let (first, rest) = next_arg(after_program(line))?;
    (first == "-c").then(|| rest.trim_start_matches(SEPARATORS))
}

/// The command a `-c` tail carries; `None` when the tail is empty.
///
/// Win32-OpenSSH builds the `DefaultShell` command line three ways (`w32-doexec.c`, `misc.c`
/// at commit 274893f), and the shim cannot tell which it got:
///
/// - Non-PTY, default `DefaultShellEscapeArguments`: the command is one argument, wrapped in
///   quotes when it holds a space and with every `"` escaped. Unescaping it restores the command.
/// - PTY (`ssh -t host cmd`): the command is appended to `"shim" -c ` as written. It is
///   unquoted, may itself hold several quoted tokens, and is the command already.
/// - Non-PTY, escaping disabled: the command is wrapped in quotes with no escaping.
///
/// A tail that is exactly one argument is unescaped. Anything else is already the command and
/// is kept as written, so quotes, empty arguments and runs of spaces survive. Only a PTY
/// command that is a single token containing quotes (`"C:\a b\p.exe"` alone) is unquoted
/// where it should not be, and `CreateProcessW` resolves the unquoted form to the same program.
pub fn decode_command(tail: &str) -> Option<String> {
    let mut args = split_args(tail);
    match args.len() {
        0 => None,
        1 => args.pop(),
        _ => Some(tail.to_string()),
    }
}

#[cfg(test)]
#[path = "cmdline_tests.rs"]
mod cmdline_tests;

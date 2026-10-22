//! The raw process command line, and the `-c` command recovered from it.
//!
//! `std::env::args` has already split and unquoted the command line, which loses the exact
//! command sshd sent: see [`decode_command`] for the three forms it arrives in, and
//! [`detect`] for how the shim tells them apart. [`resolve_exec`] is the step from what
//! `route` finds to the command.

#[cfg(not(windows))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use other::{current, detect};
#[cfg(windows)]
pub use windows::{current, detect};

/// The `-c` command as `route` found it, before sshd's encoding is undone ([`resolve_exec`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawExec {
    /// The text after `-c` in the raw command line, as written.
    Tail(String),
    /// argv joined with spaces: the raw line did not show the `-c` argv reported.
    Argv(String),
}

/// The command `exec` carries. A tail is decoded by the form [`detect`] reports, called here
/// rather than at startup because it reads the registry and the console and only a `-c` session
/// needs it; its warning is logged, so the caller opens the log first.
pub fn resolve_exec(exec: RawExec, detect: impl FnOnce() -> Detected) -> String {
    match exec {
        RawExec::Tail(tail) => {
            let Detected { encoding, warning } = detect();
            if let Some(warning) = warning {
                tracing::warn!("{warning}");
            }
            decode_command(&tail, encoding)
        }
        RawExec::Argv(command) => {
            tracing::warn!("the raw command line has no `-c` although argv does; running the joined argv");
            command
        }
    }
}

/// What [`detect`] found: how sshd encoded the command line, and, when that rests on an assumption,
/// what to log once logging is up (detection runs before the log is opened).
#[derive(Debug)]
pub struct Detected {
    pub encoding: Encoding,
    pub warning: Option<String>,
}

/// How sshd built the `DefaultShell` command line; see [`decode_command`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// A PTY session. sshd appends the command to the shim's line as written, but starts the
    /// shell as `conhost.exe --headless ... -- <line>`, and conhost splits that line into
    /// arguments and escapes each one again. The shim receives the command conhost rebuilt, not
    /// the one the client typed (runs of spaces between arguments become one, quotes around
    /// an argument with no space are dropped) and relays it as received.
    Verbatim,
    /// No PTY, `DefaultShellEscapeArguments` on (the default): the command is one escaped argument.
    Escaped,
    /// No PTY, `DefaultShellEscapeArguments=0`: the command is wrapped in quotes, unescaped.
    Wrapped,
}

/// The kinds of `DefaultShell` path sshd tells apart (`w32-doexec.c:308-318`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Cmd,
    PowerShell,
    ShellHost,
    Bash,
    Cygwin,
    Other,
}

/// Classify a `DefaultShell` path the way sshd does: it lowercases the path and turns `/` into
/// `\` (`pwd.c:113-114`, `wmisc.c:919`, `:1288`), then takes the first substring that matches,
/// in this order (`w32-doexec.c:308-318`).
pub fn shell_kind(path: &str) -> ShellKind {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    if path.contains(r"system32\cmd") {
        ShellKind::Cmd
    } else if path.contains("powershell") {
        ShellKind::PowerShell
    } else if path.contains("ssh-shellhost") {
        ShellKind::ShellHost
    } else if path.contains(r"\bash") {
        ShellKind::Bash
    } else if path.contains("cygwin") {
        ShellKind::Cygwin
    } else {
        ShellKind::Other
    }
}

impl ShellKind {
    /// The non-PTY form sshd uses for this kind of shell, or `None` when `DefaultShellEscapeArguments`
    /// decides: sshd escapes for PowerShell, bash and cygwin, wraps for cmd and ssh-shellhost, and
    /// reads the flag only for any other path (`w32-doexec.c:370-371`).
    pub fn encoding(self) -> Option<Encoding> {
        match self {
            ShellKind::Cmd | ShellKind::ShellHost => Some(Encoding::Wrapped),
            ShellKind::PowerShell | ShellKind::Bash | ShellKind::Cygwin => Some(Encoding::Escaped),
            ShellKind::Other => None,
        }
    }
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
/// `misc.c`), and each has its own inverse:
///
/// - [`Encoding::Verbatim`], a PTY session (`ssh -t host cmd`): the command is appended to
///   `"shim" -c ` as written and conhost then rewrites the line, so the tail is the command in
///   conhost's form, relayed as received.
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
/// An empty tail is an empty command: `-c` was given, so the client asked to run something.
///
/// A tail that cannot come from its form (a wrapped command with no quotes around it, an escaped
/// one that opens a quote and never closes it) is logged and decoded as far as it goes, and
/// asserts in a debug build.
pub fn decode_command(tail: &str, encoding: Encoding) -> String {
    match encoding {
        Encoding::Verbatim => tail.to_string(),
        // An unwrapped escaped argument never starts with a quote: sshd escapes it as `\"`.
        Encoding::Escaped if tail.starts_with('"') => unescape_argument(unwrap_or_log(tail, encoding)),
        Encoding::Escaped => unescape_argument(tail),
        Encoding::Wrapped if tail.is_empty() => String::new(),
        Encoding::Wrapped => unwrap_or_log(tail, encoding).to_string(),
    }
}

/// [`unwrap_quotes`] for a tail that must be wrapped; the tail itself when it is not.
fn unwrap_or_log(tail: &str, encoding: Encoding) -> &str {
    unwrap_quotes(tail).unwrap_or_else(|| {
        tracing::warn!("a {encoding:?} -c tail does not fit its form ({tail:?}); decoding it as written");
        debug_assert!(false, "a {encoding:?} -c tail does not fit its form: {tail:?}");
        tail
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

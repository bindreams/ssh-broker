//! The command corpus of Task 0: the union of `tests/conhost_windows.rs::COMMANDS` and
//! `src/cmdline_encoder_tests.rs::CORPUS`, plus the Review Focus 2 shapes neither holds.

pub const CORPUS: &[&str] = &[
    "whoami",
    "echo hi",
    "echo  two  spaces",
    "echo\ttab",
    "a\tb",
    "\tleading-tab",
    "trailing-tab\t",
    "\t",
    "\t\t",
    "trailing   ",
    "  leading",
    "  leading and trailing  ",
    " ",
    "  ",
    "",
    "\n",
    "\r\n",
    "\r\nx\r\n",
    " \r\n",
    "x\ny",
    "x\r\ny z",
    r#"echo "a b""#,
    r#"echo  "a  b"   x"#,
    "cmd /c echo a   b",
    r#"echo "a"b"#,
    r#"x""y"#,
    r#"a"b"#,
    r#""quoted""#,
    r#"--opt="a b""#,
    r#"git commit -m "a b""#,
    r#"""#,
    r#"""x"#,
    r#"echo "a""b" c"#,
    r#"echo "a"" b" c"#,
    r#"echo """ x"#,
    r#"echo "x""""#,
    r#"echo "a b""c d" e"#,
    "'single quoted start' x",
    "'x'",
    r#"'a "b" c'"#,
    "x 'a b' y",
    r#"echo \"a b\""#,
    r#"echo a\\"b c"#,
    r#"echo "a b"\"#,
    r"echo C:\dir\",
    r"echo C:\a b\",
    r"echo C:\a b\\",
    r"echo \server\share\x y",
    r"\",
    r"\\",
    r#"\""#,
    r#""C:\a b\p.exe" "x y""#,
    r#"p.exe "" end"#,
    r#""C:\a b\p.exe" "x y" "" end  of  line"#,
    r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO",
    r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#,
    "echo héllo wörld ✓",
    "echo 日本語 \"x y\"",
    "echo 😀 x",
    "echo %PATH%",
    "%PATH%",
    "echo a & echo b",
    "a | b",
    "a < b > c",
    "echo ^& $HOME `x` $(y) !z",
    "scp -t /x",
    "SCP.exe -f /x",
    "scp",
    "sftp-server -l INFO",
    "Sftp-Server.EXE -l INFO",
    "sftp-server.exe",
    "internal-sftp",
    "internal-sftp -l INFO",
    "agent",
    "-c x",
    "--width 5",
    "-- x",
];

/// A command of 32,000 characters: long, but still under what `ssh.exe`'s own command line can carry.
pub fn long_command() -> String {
    format!("echo {}", "a".repeat(32_000))
}

/// A short, quote-free rendering for the log: long text keeps its length, head and tail.
pub fn shown(text: &str) -> String {
    if text.chars().count() <= 300 {
        return format!("{text:?}");
    }
    let head: String = text.chars().take(60).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(60)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("(len {}) {head:?}...{tail:?}", text.chars().count())
}

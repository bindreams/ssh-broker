//! What conhost does to the command line of a PTY session, measured against the real thing.
//!
//! sshd starts a PTY session's shell as `conhost.exe --headless ... -- "shell" -c <command>`
//! (`win32_pty.c:90-106`). conhost splits that into arguments and joins them again, so the shell
//! gets a normalized command line, not the client's text. `tests/common/sshd_encoder.rs` models
//! the step; these tests run the real `conhost.exe` (windowless, in a temp dir) and compare.
//!
//! The probe is `examples/command_line_probe.rs`, which cargo builds for `cargo test`.
#![cfg(windows)]

use std::ffi::OsStr;
use std::path::PathBuf;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::core::PCWSTR;

#[path = "common/pty.rs"]
mod pty;
#[path = "common/sshd_encoder.rs"]
mod sshd_encoder;

/// Commands the model must get right: the shapes that make conhost change the text, and the ones
/// that must pass through untouched.
const COMMANDS: &[&str] = &[
    "whoami",
    "echo hi",
    r#"echo  "a  b"   x"#,
    "cmd /c echo a   b",
    r#"echo "a"b"#,
    r#"x""y"#,
    "a\tb",
    "trailing   ",
    "  leading",
    "",
    " ",
    r#"echo "a b""#,
    r#"a"b"#,
    r#""quoted""#,
    r#"--opt="a b""#,
    r#"git commit -m "a b""#,
    r#"""#,
    r#"""x"#,
    "'single quoted start' x",
    r#"'a "b" c'"#,
    r#"echo \"a b\""#,
    r#"echo a\\"b c"#,
    r#"echo "a b"\"#,
    r"echo C:\dir\",
    r"echo C:\a b\",
    r"echo C:\a b\\",
    r"echo \\server\share\x y",
    r"\",
    r#""C:\a b\p.exe" "x y""#,
    r#"p.exe "" end"#,
    r#""C:\a b\p.exe" "x y" "" end  of  line"#,
    r"C:\Program Files\OpenSSH\sftp-server.exe -l INFO",
    r#""C:\Program Files\OpenSSH\sftp-server.exe" -l INFO"#,
    "echo héllo wörld ✓",
    "echo 日本語 \"x y\"",
    // A doubled quote inside quotes.
    r#"echo "a""b" c"#,
    r#"echo "a"" b" c"#,
    r#"echo """ x"#,
    r#"echo "x""""#,
    r#"echo "a b""c d" e"#,
    "x\ny",
    "-c x",
    "--width 5",
    "-- x",
];

fn probe() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let probe = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("command_line_probe.exe");
    assert!(
        probe.is_file(),
        "the probe {probe:?} is not built: run `cargo build --examples` (`cargo test` builds it)"
    );
    probe
}

/// The command line the probe received when conhost ran `"<probe>" -c <command>`.
fn received_under_conhost(probe: &std::path::Path, command: &str, out: &std::path::Path) -> String {
    let _ = std::fs::remove_file(out);
    let line = sshd_encoder::pty_line(&probe.display().to_string(), command);
    let run = pty::run_under_conhost(&line, &[("PROBE_OUT", out.as_os_str())]);
    std::fs::read_to_string(out).unwrap_or_else(|e| {
        panic!(
            "the probe wrote nothing for {command:?} ({e}); conhost exit {:?}, console {:?}",
            run.code, run.console
        )
    })
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn conhost_rebuilds_the_command_line_as_the_model_says() {
    let probe = probe();
    let dir = temp_dir("sb-conhost");
    let out = dir.join("line.txt");
    let mut failures = Vec::new();
    for command in COMMANDS {
        let want = sshd_encoder::verbatim_line(&probe.display().to_string(), command);
        let got = received_under_conhost(&probe, command, &out);
        if got != want {
            failures.push(format!("{command:?}\n  want: {want:?}\n  got:  {got:?}"));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `CommandLineToArgvW` is what conhost and the C runtime split with; the model's tokenizer must
/// agree with it on everything conhost can be handed.
#[test]
fn the_models_tokenizer_matches_command_line_to_argv_w() {
    fn api(line: &str) -> Vec<String> {
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut count = 0;
        unsafe {
            let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut count);
            assert!(!argv.is_null(), "CommandLineToArgvW failed for {line:?}");
            let args = (0..count as usize)
                .map(|i| String::from_utf16_lossy((*argv.add(i)).as_wide()))
                .collect();
            LocalFree(Some(HLOCAL(argv.cast())));
            args
        }
    }

    let alphabet = ['a', ' ', '\t', '"', '\\', '\n'];
    let mut lines: Vec<String> = COMMANDS.iter().map(|c| format!("p {c}")).collect();
    let mut layer = vec![String::new()];
    for _ in 0..6 {
        layer = layer
            .iter()
            .flat_map(|prefix| alphabet.iter().map(move |c| format!("{prefix}{c}")))
            .collect();
        lines.extend(layer.iter().map(|text| format!("p {text}")));
    }
    for line in lines {
        assert_eq!(sshd_encoder::tokenize(&line), api(&line), "{line:?}");
    }
}

/// Escaping then splitting gives the argument back, for every argument conhost can hold.
#[test]
fn the_models_escaping_round_trips_through_command_line_to_argv_w() {
    let alphabet = ['a', ' ', '\t', '"', '\\'];
    let mut layer = vec![String::new()];
    let mut args = vec![String::new()];
    for _ in 0..6 {
        layer = layer
            .iter()
            .flat_map(|prefix| alphabet.iter().map(move |c| format!("{prefix}{c}")))
            .collect();
        args.extend(layer.iter().cloned());
    }
    for arg in args {
        let line = format!("p {}", sshd_encoder::conhost_escape(&arg));
        assert_eq!(sshd_encoder::tokenize(&line), ["p", arg.as_str()], "{arg:?}");
    }
}

/// The probe's own `GetCommandLineW` is what `cmdline::current` returns, so the shim sees these
/// lines. A plain run (no conhost) is the control: the probe writes what it was given.
#[test]
fn the_probe_reports_its_raw_command_line() {
    let probe = probe();
    let dir = temp_dir("sb-conhost-control");
    let out = dir.join("line.txt");
    let status = std::process::Command::new(&probe)
        .env("PROBE_OUT", OsStr::new(&out))
        .status()
        .expect("run the probe");
    assert!(status.success());
    let line = std::fs::read_to_string(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(line.contains("command_line_probe"), "{line:?}");
}

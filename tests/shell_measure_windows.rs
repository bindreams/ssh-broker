//! Task 0 of the U1-C plan: CI-only measurements for the transparent shell. Spike branch `U1-C-spike`,
//! never merged. Windows only; **Elevated (CI only)**: the account tests change sshd's `DefaultShell` and
//! make a throwaway account. Each measurement prints `SPIKE <key>=<value>` lines; the workflow runs one
//! test per step.
//!
//! M1 binary safety through sshd, M2 MSYS2 argument parsing, M3 what stock sshd gives a shell,
//! M4 file identity of `cmd.exe` spellings, M5 `SearchPathW`, M6 PowerShell's stdin and stdout.
#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ssh_broker::provision::procwait::file_id;
use windows::Win32::Storage::FileSystem::{GetShortPathNameW, SearchPathW};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::core::{PCWSTR, PWSTR};

#[path = "common/account.rs"]
mod account_fixture;
#[path = "common/bounded_wait.rs"]
mod bounded_wait;
#[path = "shell_measure/corpus.rs"]
mod corpus;
#[path = "common/desktop.rs"]
mod desktop;
#[path = "common/hard_errors.rs"]
mod hard_errors;
#[path = "common/process_list.rs"]
mod process_list;
#[path = "shell_measure/rig.rs"]
mod rig;

use corpus::{CORPUS, long_command, shown};
use rig::{CREATE_NO_WINDOW, Rig, example, fact, os, run, run_tool, set_shell, work_dir};

const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// M1 =====

/// Deterministic noise (a linear congruential generator), so a failure can be reproduced.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

fn hex_window(bytes: &[u8], at: usize) -> String {
    let from = at.saturating_sub(6);
    let to = (at + 10).min(bytes.len());
    bytes[from..to]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// "equal", or what differs: the lengths, the first differing offset and the bytes around it.
fn diff(want: &[u8], got: Option<&[u8]>) -> String {
    let Some(got) = got else {
        return "MISSING (no file)".to_owned();
    };
    if want == got {
        return "equal".to_owned();
    }
    let first = want
        .iter()
        .zip(got)
        .position(|(a, b)| a != b)
        .unwrap_or(want.len().min(got.len()));
    let same_len_diffs = if want.len() == got.len() {
        format!(
            " differing-bytes={}",
            want.iter().zip(got).filter(|(a, b)| a != b).count()
        )
    } else {
        String::new()
    };
    format!(
        "DIFFERENT want-len={} got-len={} first-diff-at={first}{same_len_diffs} want[..]={} got[..]={}",
        want.len(),
        got.len(),
        hex_window(want, first),
        hex_window(got, first)
    )
}

fn clip(text: &str) -> String {
    let text = text.trim();
    let clipped: String = text.chars().take(240).collect();
    format!("{clipped:?}")
}

/// Elevated (CI only). M1: every byte value through `scp -O`, `scp` (SFTP mode) and `sftp`, both ways,
/// with stock sshd's `DefaultShell` = `cmd.exe` and = `pwsh.exe`.
#[test]
fn m1_binary_safety() {
    let rig = Rig::new("m1");
    let profile = rig.account.profile().to_path_buf();
    let system = PathBuf::from(system_dir()).join("cmd.exe");
    let shells = [("cmd", system), ("pwsh", PathBuf::from(PWSH))];
    let files = [
        ("all256", (0..=255u8).collect::<Vec<u8>>()),
        ("noise1m", noise(1 << 20)),
    ];
    let target = rig.target();

    for (shell_name, shell) in &shells {
        assert!(shell.is_file(), "{shell:?} is not on this image");
        set_shell(shell, None);
        let mut args = rig.options();
        args.extend([
            rig.target().into(),
            "--".into(),
            "echo $PSVersionTable.PSVersion.Major".into(),
        ]);
        let who = run_tool("ssh", &args, &rig.work, false, &rig.work);
        fact(&format!(
            "m1.{shell_name}.which-shell-answered={} (cmd.exe prints the text as typed; pwsh prints its major version)",
            clip(&String::from_utf8_lossy(&who.stdout))
        ));
        for (file_name, bytes) in &files {
            let source = format!("m1-src-{file_name}.bin");
            std::fs::write(rig.work.join(&source), bytes).unwrap();
            let remote_source = format!("m1-remote-{file_name}.bin");
            std::fs::write(profile.join(&remote_source), bytes).unwrap();
            for tool in ["scp-O", "scp", "sftp"] {
                // Upload.
                let up_remote = format!("m1-up-{shell_name}-{tool}-{file_name}.bin");
                let _ = std::fs::remove_file(profile.join(&up_remote));
                let args = transfer_args(
                    &rig,
                    tool,
                    &format!("put {source} {up_remote}"),
                    &source,
                    &format!("{target}:{up_remote}"),
                );
                let outcome = run_tool(tool_exe(tool), &args, &rig.work, false, &rig.work);
                let got = std::fs::read(profile.join(&up_remote)).ok();
                fact(&format!(
                    "m1.{shell_name}.{tool}.upload.{file_name}={} exit={:?} stderr={} stdout={}",
                    diff(bytes, got.as_deref()),
                    outcome.code,
                    clip(&outcome.stderr),
                    clip(&String::from_utf8_lossy(&outcome.stdout)),
                ));
                // Download.
                let down_local = format!("m1-down-{shell_name}-{tool}-{file_name}.bin");
                let _ = std::fs::remove_file(rig.work.join(&down_local));
                let args = transfer_args(
                    &rig,
                    tool,
                    &format!("get {remote_source} {down_local}"),
                    &format!("{target}:{remote_source}"),
                    &down_local,
                );
                let outcome = run_tool(tool_exe(tool), &args, &rig.work, false, &rig.work);
                let got = std::fs::read(rig.work.join(&down_local)).ok();
                fact(&format!(
                    "m1.{shell_name}.{tool}.download.{file_name}={} exit={:?} stderr={} stdout={}",
                    diff(bytes, got.as_deref()),
                    outcome.code,
                    clip(&outcome.stderr),
                    clip(&String::from_utf8_lossy(&outcome.stdout)),
                ));
            }
        }
    }
}

fn tool_exe(tool: &str) -> &'static str {
    if tool == "sftp" { "sftp" } else { "scp" }
}

/// The arguments of one transfer. `batch_line` is the sftp batch command; `from` and `to` are the scp
/// operands.
fn transfer_args(rig: &Rig, tool: &str, batch_line: &str, from: &str, to: &str) -> Vec<OsString> {
    let mut args = rig.options();
    match tool {
        "sftp" => {
            let batch = rig.work.join("m1.batch");
            std::fs::write(&batch, format!("{batch_line}\n")).unwrap();
            args.extend(os(&["-b", "m1.batch"]));
            args.push(rig.target().into());
        }
        "scp-O" => {
            args.push("-O".into());
            args.extend([from, to].map(OsString::from));
        }
        _ => args.extend([from, to].map(OsString::from)),
    }
    args
}

// M2 =====

/// The standard MSVC quoting of the plan's Task 1 (`CommandLineToArgvW` reads it back exactly).
fn msvc_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Elevated (CI only; needs no account). M2: what Git Bash's `bash.exe` sees as `$1` for the corpus packed
/// as `cmd` (wrapped in quotes, unescaped) and as standard MSVC quoting. Harness `c`:
/// `bash.exe -c "printf %s \"$1\"" _ <packed>`; harness `file` is the control: `bash.exe show.sh <packed>`.
#[test]
fn m2_msys2() {
    let work = work_dir();
    let script = work.join("show.sh");
    std::fs::write(&script, "printf %s \"$1\"\n").unwrap();
    let script_posix = script.to_string_lossy().replace('\\', "/");
    let bashes = [
        ("bin", r"C:\Program Files\Git\bin\bash.exe"),
        ("usr-bin", r"C:\Program Files\Git\usr\bin\bash.exe"),
    ];
    for (name, bash) in bashes {
        assert!(Path::new(bash).is_file(), "{bash} is not on this image");
        let mut counts = std::collections::BTreeMap::new();
        for harness in ["c", "file"] {
            for packing in ["cmd", "msvc"] {
                for (i, entry) in CORPUS.iter().enumerate() {
                    let packed = match packing {
                        "cmd" => format!("\"{entry}\""),
                        _ => msvc_quote(entry),
                    };
                    let tail = match harness {
                        "c" => format!("-c \"printf %s \\\"$1\\\"\" _ {packed}"),
                        _ => format!("{script_posix} {packed}"),
                    };
                    let out = Command::new(bash)
                        .raw_arg(&tail)
                        .stdin(Stdio::null())
                        .creation_flags(CREATE_NO_WINDOW)
                        .output()
                        .unwrap_or_else(|e| panic!("{bash} did not run: {e}"));
                    let got = String::from_utf8_lossy(&out.stdout).into_owned();
                    let same = got == *entry;
                    *counts
                        .entry(format!("{harness}.{packing}.{}", if same { "same" } else { "DIFF" }))
                        .or_insert(0) += 1;
                    fact(&format!(
                        "m2.{name}.{harness}.{packing}.{i}={} entry={} line={} saw={} exit={:?}",
                        if same { "SAME" } else { "DIFF" },
                        shown(entry),
                        shown(&tail),
                        shown(&got),
                        out.status.code(),
                    ));
                }
            }
        }
        fact(&format!("m2.{name}.summary={counts:?}"));
    }
}

// M3 =====

/// `debug1: Sending command: <text>` from `ssh -v`: what the client really sent.
fn sent_command(stderr: &str) -> String {
    match stderr.find("Sending command: ") {
        Some(at) => {
            let rest = &stderr[at + "Sending command: ".len()..];
            shown(rest.split('\n').next().unwrap_or("").trim_end_matches('\r'))
        }
        None => "(no 'Sending command' line)".to_owned(),
    }
}

/// M3 for one persona: the probe copied to `rel` under the work directory (the path decides which form sshd
/// uses, see `sshd_encoder::flag_decides_form`), made sshd's `DefaultShell`, and every corpus command sent
/// with and without a PTY. Records the exact line the probe was started with.
fn m3(tag: &str, rel: &str, escapes: &[Option<u32>]) {
    let rig = Rig::new(tag);
    let exe = rig.work.join(rel);
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::copy(example("shell_measure_probe"), &exe).unwrap();
    let mut line_path = exe.clone().into_os_string();
    line_path.push(".line");
    let line_path = PathBuf::from(line_path);
    let long = long_command();
    let mut commands: Vec<&str> = CORPUS.to_vec();
    commands.push(&long);

    for escape in escapes {
        set_shell(&exe, *escape);
        fact(&format!(
            "m3.{tag}.escape={escape:?}.registry={:?}",
            run("reg", &["query", rig::OPENSSH_REG]).1
        ));
        for pty in [false, true] {
            for (i, command) in commands.iter().enumerate() {
                let _ = std::fs::remove_file(&line_path);
                let mut args = os(&["-v", if pty { "-tt" } else { "-T" }]);
                args.extend(rig.options());
                args.push(rig.target().into());
                // `--`: a command that starts with `-` is an option to ssh otherwise.
                args.push("--".into());
                args.push((*command).into());
                let outcome = run_tool("ssh", &args, &rig.work, pty, &rig.work);
                let seen = match std::fs::read(&line_path) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        text.lines().map(shown).collect::<Vec<_>>().join(" ; ")
                    }
                    Err(_) => format!(
                        "(probe wrote nothing) ssh-errors={}",
                        clip(&error_lines(&outcome.stderr))
                    ),
                };
                fact(&format!(
                    "m3.{tag}.escape={escape:?}.pty={pty}.{i}: cmd={} sent={} ssh-exit={:?} probe={seen}",
                    shown(command),
                    sent_command(&outcome.stderr),
                    outcome.code,
                ));
            }
        }
    }
}

/// The lines of ssh's stderr that are not its own debug output, each cut to 200 characters.
fn error_lines(stderr: &str) -> String {
    stderr
        .lines()
        .filter(|line| !line.starts_with("debug"))
        .map(|line| line.chars().take(200).collect::<String>())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Elevated (CI only). Generic path: the flag decides the form.
#[test]
fn m3_generic() {
    m3("generic", r"generic\probe.exe", &[None, Some(0), Some(1)]);
}

/// Elevated (CI only). A path with `powershell`: the path alone fixes the form.
#[test]
fn m3_pwsh() {
    m3("pwsh", r"PowerShell\7\pwsh.exe", &[None, Some(1)]);
}

/// Elevated (CI only). A path with `\bash`.
#[test]
fn m3_bash() {
    m3("bash", r"Git\bin\bash.exe", &[None]);
}

/// Elevated (CI only). A path with `system32\cmd`.
#[test]
fn m3_cmd() {
    m3("cmd", r"system32\cmd.exe", &[None]);
}

/// Elevated (CI only). A generic path with a space in it.
#[test]
fn m3_spaced() {
    m3("spaced", r"with space\probe.exe", &[None]);
}

// M4 =====

fn system_dir() -> String {
    let mut buffer = vec![0u16; 260];
    // SAFETY: the buffer is the length the call is told.
    let n = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    assert!(n > 0 && n < buffer.len(), "GetSystemDirectoryW failed");
    String::from_utf16_lossy(&buffer[..n])
}

fn short_path(path: &Path) -> Option<String> {
    let long = wide(&path.to_string_lossy());
    let mut buffer = vec![0u16; 520];
    // SAFETY: NUL-terminated input; the buffer is the length the call is told.
    let n = unsafe { GetShortPathNameW(PCWSTR(long.as_ptr()), Some(&mut buffer)) } as usize;
    (n > 0 && n < buffer.len()).then(|| String::from_utf16_lossy(&buffer[..n]))
}

/// Elevated (CI only; needs no account). M4: `procwait::file_id` equality for spellings of the system
/// `cmd.exe`. Every row prints the path used and `equal` against `GetSystemDirectoryW\cmd.exe`.
#[test]
fn m4_cmd_identity() {
    let sys = PathBuf::from(system_dir());
    let base = sys.join("cmd.exe");
    let windir = sys.parent().unwrap().to_path_buf();
    let dir = work_dir().join("m4");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    fact(&format!("m4.system-directory={sys:?}"));

    let mut rows: Vec<(&str, String, PathBuf)> = vec![
        ("system", "equal".into(), base.clone()),
        (
            "lower-case",
            "equal".into(),
            PathBuf::from(sys.to_string_lossy().to_lowercase()).join("CMD.EXE"),
        ),
    ];
    match short_path(&base) {
        Some(short) => rows.push(("8.3-name", "equal".into(), PathBuf::from(short))),
        None => fact("m4.8.3-name=GetShortPathNameW failed"),
    }
    fact(&format!("m4.8.3-of-system-directory={:?}", short_path(&sys)));
    let junction = dir.join("junction");
    let (ok, text) = run(
        "cmd",
        &["/c", "mklink", "/J", junction.to_str().unwrap(), sys.to_str().unwrap()],
    );
    fact(&format!("m4.mklink-junction=ok:{ok} {}", clip(&text)));
    rows.push(("junction-to-system32", "equal".into(), junction.join("cmd.exe")));
    let dir_link = dir.join("dirlink");
    let (ok, text) = run(
        "cmd",
        &["/c", "mklink", "/D", dir_link.to_str().unwrap(), sys.to_str().unwrap()],
    );
    fact(&format!("m4.mklink-dir-symlink=ok:{ok} {}", clip(&text)));
    rows.push((
        "dir-symlink-to-system32 (extra)",
        "equal".into(),
        dir_link.join("cmd.exe"),
    ));
    let file_link = dir.join("filelink.exe");
    let (ok, text) = run(
        "cmd",
        &["/c", "mklink", file_link.to_str().unwrap(), base.to_str().unwrap()],
    );
    fact(&format!("m4.mklink-file-symlink=ok:{ok} {}", clip(&text)));
    rows.push(("file-symlink-to-cmd (extra)", "equal".into(), file_link));
    let hard = dir.join("hardlink.exe");
    match std::fs::hard_link(&base, &hard) {
        Ok(()) => rows.push(("hard-link-to-cmd", "equal".into(), hard)),
        Err(e) => fact(&format!("m4.hard-link-to-system-cmd=NOT CREATED: {e}")),
    }
    rows.push((
        "extended-prefix (extra)",
        "equal".into(),
        PathBuf::from(format!(r"\\?\{}", base.display())),
    ));
    rows.push((
        "forward-slashes (extra)",
        "equal".into(),
        PathBuf::from(base.to_string_lossy().replace('\\', "/")),
    ));
    rows.push((
        "dot-dot (extra)",
        "equal".into(),
        sys.join("..").join("System32").join("cmd.exe"),
    ));
    rows.push(("SysWOW64", "different".into(), windir.join("SysWOW64").join("cmd.exe")));
    rows.push(("Sysnative", "absent".into(), windir.join("Sysnative").join("cmd.exe")));
    let copy = dir.join("cmd-copy.exe");
    std::fs::copy(&base, &copy).unwrap();
    rows.push(("copy", "different".into(), copy.clone()));
    let copy_link = dir.join("cmd-copy-hardlink.exe");
    std::fs::hard_link(&copy, &copy_link).unwrap();
    rows.push((
        "hard-link-to-the-copy (control: equals the copy, not the system cmd)",
        "different".into(),
        copy_link,
    ));

    let base_id = file_id(&base).expect("identity of the system cmd.exe");
    fact(&format!("m4.system-id={base_id:?}"));
    for (label, expected, path) in rows {
        let verdict = match file_id(&path) {
            Ok(id) => format!("{} id={id:?}", if id == base_id { "EQUAL" } else { "DIFFERENT" }),
            Err(e) => format!("ERROR {e}"),
        };
        fact(&format!("m4.{label}: expected={expected} got={verdict} path={path:?}"));
    }
    let copy_id = file_id(&copy).unwrap();
    fact(&format!(
        "m4.control-hard-link-equals-copy={}",
        file_id(&dir.join("cmd-copy-hardlink.exe")).unwrap() == copy_id
    ));
}

// M5 =====

/// `SearchPathW(list, name, extension)`: the found path, or the error.
fn search(list: Option<&str>, name: &str, extension: Option<&str>) -> String {
    let list_w = list.map(wide);
    let name_w = wide(name);
    let extension_w = extension.map(wide);
    let mut buffer = vec![0u16; 1024];
    // SAFETY: NUL-terminated inputs; the buffer is the length the call is told.
    let n = unsafe {
        SearchPathW(
            list_w.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr())),
            PCWSTR(name_w.as_ptr()),
            extension_w.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr())),
            Some(&mut buffer),
            None::<*mut PWSTR>,
        )
    } as usize;
    if n == 0 {
        format!("NOT FOUND ({})", windows::core::Error::from_thread())
    } else {
        format!("FOUND {}", String::from_utf16_lossy(&buffer[..n]))
    }
}

/// Elevated (CI only; needs no account). M5: `SearchPathW` with an explicit directory list.
#[test]
fn m5_search_path() {
    let root = work_dir().join("m5");
    let _ = std::fs::remove_dir_all(&root);
    let (a, b, cwd) = (root.join("a"), root.join("b"), root.join("cwd"));
    for d in [&a, &b, &cwd] {
        std::fs::create_dir_all(d).unwrap();
    }
    let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let touch = |p: PathBuf| std::fs::write(p, b"x").unwrap();
    std::env::set_current_dir(&cwd).unwrap();
    touch(cwd.join("m5cwd.exe"));
    touch(exe_dir.join("m5exe.exe"));
    touch(a.join("pwsh.exe"));
    touch(b.join("pwsh.exe"));
    touch(a.join("pwsh.7.exe"));
    touch(b.join("pwsh.8"));
    touch(a.join("plain"));
    touch(a.join("both"));
    touch(a.join("both.exe"));
    std::fs::create_dir(a.join("m5dir.exe")).unwrap();
    touch(b.join("m5dir.exe"));
    std::fs::create_dir(a.join("onlydir.exe")).unwrap();
    std::fs::create_dir(a.join("dirnoext")).unwrap();

    let list = |dirs: &[&PathBuf]| {
        dirs.iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(";")
    };
    let (la, lb, lab, lba) = (list(&[&a]), list(&[&b]), list(&[&a, &b]), list(&[&b, &a]));
    let cases: Vec<(String, String)> = vec![
        ("pwsh, list a, ext .exe".into(), search(Some(&la), "pwsh", Some(".exe"))),
        (
            "pwsh.exe, list a, ext .exe".into(),
            search(Some(&la), "pwsh.exe", Some(".exe")),
        ),
        ("pwsh, list a;b".into(), search(Some(&lab), "pwsh", Some(".exe"))),
        ("pwsh, list b;a".into(), search(Some(&lba), "pwsh", Some(".exe"))),
        (
            "pwsh, list a, no extension argument".into(),
            search(Some(&la), "pwsh", None),
        ),
        (
            "pwsh.7, a holds pwsh.7.exe only, ext .exe".into(),
            search(Some(&la), "pwsh.7", Some(".exe")),
        ),
        (
            "pwsh.8, b holds the file pwsh.8 only, ext .exe".into(),
            search(Some(&lb), "pwsh.8", Some(".exe")),
        ),
        (
            "plain, a holds the file plain (no .exe), ext .exe".into(),
            search(Some(&la), "plain", Some(".exe")),
        ),
        (
            "both, a holds both and both.exe, ext .exe".into(),
            search(Some(&la), "both", Some(".exe")),
        ),
        (
            "m5cwd (only in the current directory), list a".into(),
            search(Some(&la), "m5cwd", Some(".exe")),
        ),
        ("CONTROL m5cwd, NULL list".into(), search(None, "m5cwd", Some(".exe"))),
        (
            "m5exe (only in the test exe's directory), list a".into(),
            search(Some(&la), "m5exe", Some(".exe")),
        ),
        ("CONTROL m5exe, NULL list".into(), search(None, "m5exe", Some(".exe"))),
        (
            "m5dir (a holds a DIRECTORY m5dir.exe, b a file), list a;b".into(),
            search(Some(&lab), "m5dir", Some(".exe")),
        ),
        (
            "m5dir, list a (directory only)".into(),
            search(Some(&la), "m5dir", Some(".exe")),
        ),
        (
            "onlydir (a holds only a directory onlydir.exe), list a".into(),
            search(Some(&la), "onlydir", Some(".exe")),
        ),
        (
            "dirnoext (a holds a directory with no extension), list a".into(),
            search(Some(&la), "dirnoext", Some(".exe")),
        ),
        (
            "a name with a separator: a\\pwsh.exe relative to cwd, list b".into(),
            search(Some(&lb), r"a\pwsh.exe", Some(".exe")),
        ),
        (
            "an absolute name, list b".into(),
            search(Some(&lb), a.join("pwsh.exe").to_str().unwrap(), Some(".exe")),
        ),
    ];
    let _ = std::fs::remove_file(exe_dir.join("m5exe.exe"));
    fact(&format!(
        "m5.current-directory={cwd:?} exe-directory={exe_dir:?} a={a:?} b={b:?}"
    ));
    for (label, result) in cases {
        fact(&format!("m5.{label} => {result}"));
    }
}

// M6 =====

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

/// The ways PowerShell can be started: the plan's `pwsh -c`, and the flags Q7 (c) names.
fn pwsh_flag_sets() -> Vec<Vec<&'static str>> {
    vec![vec![], vec!["-NoProfile"], vec!["-NoProfile", "-NonInteractive"]]
}

/// Elevated (CI only; needs no account). M6: does a native child of `pwsh -c <exe>` inherit a redirected
/// stdin? The child reads it to the end and reports count and hash; the data is 1,024 bytes (every byte
/// value four times). Controls: the probe run directly, and under `cmd /c`.
#[test]
fn m6_stdin() {
    let work = work_dir();
    let probe = work.join("stdin_probe.exe");
    std::fs::copy(example("stdin_probe"), &probe).unwrap();
    let probe_text = probe.to_string_lossy().into_owned();
    let data: Vec<u8> = (0..4).flat_map(|_| 0..=255u8).collect();
    fact(&format!("m6.stdin.expected=n={} fnv={:016x}", data.len(), fnv(&data)));

    let mut launches: Vec<(String, String, Vec<OsString>)> = vec![
        ("direct".into(), probe_text.clone(), vec![]),
        ("cmd /c".into(), "cmd.exe".into(), os(&["/c", &probe_text])),
    ];
    for flags in pwsh_flag_sets() {
        let mut args = os(&flags);
        args.push("-c".into());
        args.push(probe_text.clone().into());
        launches.push((format!("pwsh {} -c", flags.join(" ")), PWSH.into(), args));
    }
    for (label, program, args) in launches {
        for kind in ["pipe", "file", "null"] {
            let mut command = Command::new(&program);
            command
                .args(&args)
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = match kind {
                "pipe" => {
                    let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
                    use std::io::Write as _;
                    child.stdin.take().unwrap().write_all(&data).unwrap();
                    child
                }
                "file" => {
                    let path = work.join("m6-stdin.bin");
                    std::fs::write(&path, &data).unwrap();
                    command.stdin(std::fs::File::open(path).unwrap()).spawn().unwrap()
                }
                _ => command.stdin(Stdio::null()).spawn().unwrap(),
            };
            let out = child.wait_with_output().unwrap();
            fact(&format!(
                "m6.stdin.{label}.stdin-is-{kind}: exit={:?} stdout={} stderr={}",
                out.status.code(),
                clip(&String::from_utf8_lossy(&out.stdout)),
                clip(&String::from_utf8_lossy(&out.stderr)),
            ));
        }
    }
}

/// Elevated (CI only; needs no account). M6 (stdout half): the bytes of a native child's stdout through
/// `pwsh -c <exe> out` into a pipe. The child writes every byte value once.
#[test]
fn m6_stdout() {
    let work = work_dir();
    let probe = work.join("stdin_probe.exe");
    std::fs::copy(example("stdin_probe"), &probe).unwrap();
    let probe_text = probe.to_string_lossy().into_owned();
    let want: Vec<u8> = (0..=255u8).collect();

    let mut launches: Vec<(String, String, Vec<OsString>)> = vec![
        ("direct".into(), probe_text.clone(), os(&["out"])),
        ("cmd /c".into(), "cmd.exe".into(), os(&["/c", &probe_text, "out"])),
    ];
    for flags in pwsh_flag_sets() {
        let mut args = os(&flags);
        args.push("-c".into());
        args.push(format!("{probe_text} out").into());
        launches.push((format!("pwsh {} -c", flags.join(" ")), PWSH.into(), args));
    }
    for (label, program, args) in launches {
        let out = Command::new(&program)
            .args(&args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        fact(&format!(
            "m6.stdout.{label}: {} exit={:?} stderr={}",
            diff(&want, Some(&out.stdout)),
            out.status.code(),
            clip(&String::from_utf8_lossy(&out.stderr)),
        ));
    }
}

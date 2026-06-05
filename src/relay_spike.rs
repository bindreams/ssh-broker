//! Spike #2: nested ConPTY relay.
//!
//! Hand-rolls ConPTY#2 (RESIZE_QUIRK | WIN32_INPUT_MODE | PASSTHROUGH, with a
//! two-tier fallback), spawns a shell into it, and relays it through our own
//! stdout/stdin — which, over SSH, are the *client* side of ConPTY#1. Goal:
//! validate end-to-end that a full TUI survives the double ConPTY with
//! passthrough, that win32-input-mode key forwarding works, that resize
//! propagates, and that the 24H2 close-then-drain ordering avoids tail loss.
//!
//! Spike scope: keys + resize forwarded; mouse/focus deferred to the next
//! increment. Teardown is process::exit (real lifecycle teardown is a v2 task).

use std::thread;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::*;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR, Result};

// Handles cross thread boundaries as isize (Send + Copy), rebuilt inside the closure.

// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE (processthreadsapi) + ConPTY creation flags (consoleapi).
const ATTR_PSEUDOCONSOLE: usize = 0x0002_0016;
const PC_RESIZE_QUIRK: u32 = 0x2;
const PC_WIN32_INPUT: u32 = 0x4;
const PC_PASSTHROUGH: u32 = 0x8;

fn win_size(sbi: &CONSOLE_SCREEN_BUFFER_INFO) -> COORD {
    COORD {
        X: (sbi.srWindow.Right - sbi.srWindow.Left + 1).max(1),
        Y: (sbi.srWindow.Bottom - sbi.srWindow.Top + 1).max(1),
    }
}

/// Write the WHOLE buffer to a handle, looping on short writes. `WriteFile` may
/// write fewer bytes than requested and still return Ok; ignoring that loses the
/// tail of a frame (a half-emitted VT/CSI sequence corrupts the terminal). Returns
/// false on failure (broken pipe, or a 0-byte write) so the relay stops cleanly
/// instead of silently dropping data or spinning on a dead downstream.
unsafe fn write_all(h: HANDLE, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let mut w = 0u32;
        if unsafe { WriteFile(h, Some(buf), Some(&mut w), None) }.is_err() || w == 0 {
            return false;
        }
        buf = &buf[w as usize..];
    }
    true
}

// ---- diagnostic: spawn one child (optionally attached to a fresh ConPTY) and
// report its exit code + captured output. Used to bisect the 0xC0000142 failure.
fn try_case(label: &str, cmdline: &str, conpty_flags: Option<u32>) -> String {
    use std::sync::{Arc, Mutex};
    unsafe {
        let mut report = format!("[{label}] flags={conpty_flags:?}\n  cmd={cmdline}\n");
        let size = COORD { X: 120, Y: 30 };
        let mut out_read = HANDLE::default();
        let mut in_write = HANDLE::default();
        // UpdateProcThreadAttribute copies the HPCON VALUE into the list (lpValue is the
        // handle itself), so what must outlive CreateProcessW is `attr` (the list buffer),
        // not this HPCON. We hold hpc_keep only to ClosePseudoConsole it afterward.
        let mut hpc_keep = HPCON(0isize);
        let mut si = STARTUPINFOEXW::default();
        let mut attr: Vec<u8> = Vec::new();
        let mut creation = PROCESS_CREATION_FLAGS(0);

        if let Some(flags) = conpty_flags {
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            // ConPTY + a parent whose stdio is REDIRECTED (pipes, as under SSH): the
            // console child fails DLL init (0xC0000142) unless we null the std handles
            // and set STARTF_USESTDHANDLES, so the parent's pipes don't bleed in and the
            // pseudoconsole supplies the child's real stdio. microsoft/terminal#4380.
            si.StartupInfo.hStdInput = HANDLE::default();
            si.StartupInfo.hStdOutput = HANDLE::default();
            si.StartupInfo.hStdError = HANDLE::default();
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            let mut in_read = HANDLE::default();
            let mut out_write = HANDLE::default();
            if CreatePipe(&mut in_read, &mut in_write, None, 0).is_err()
                || CreatePipe(&mut out_read, &mut out_write, None, 0).is_err()
            {
                return format!("{report}  CreatePipe FAILED\n");
            }
            let hpc = match CreatePseudoConsole(size, in_read, out_write, flags) {
                Ok(h) => { report.push_str("  CreatePseudoConsole=OK\n"); h }
                Err(e) => return format!("{report}  CreatePseudoConsole FAILED: {e:?}\n"),
            };
            let _ = CloseHandle(in_read);
            let _ = CloseHandle(out_write);
            hpc_keep = hpc;
            let mut bytes = 0usize;
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut bytes);
            report.push_str(&format!("  attr_list_bytes={bytes}\n"));
            attr = vec![0u8; bytes];
            let al = LPPROC_THREAD_ATTRIBUTE_LIST(attr.as_mut_ptr() as *mut _);
            // lpValue for PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE is the HPCON value ITSELF
            // (an opaque handle/pointer), NOT a pointer to it. Passing &hpc hands the child
            // a stack address as its "console" -> it can't connect -> 0xC0000142.
            if InitializeProcThreadAttributeList(Some(al), 1, None, &mut bytes).is_err()
                || UpdateProcThreadAttribute(al, 0, ATTR_PSEUDOCONSOLE, Some(hpc_keep.0 as *const core::ffi::c_void), std::mem::size_of::<HPCON>(), None, None).is_err()
            {
                return format!("{report}  attribute-list setup FAILED\n");
            }
            si.lpAttributeList = al;
            creation = EXTENDED_STARTUPINFO_PRESENT;
        } else {
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        }

        let mut cmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pi = PROCESS_INFORMATION::default();
        match CreateProcessW(PCWSTR::null(), Some(PWSTR(cmd.as_mut_ptr())), None, None, false, creation, None, PCWSTR::null(), &si.StartupInfo, &mut pi) {
            Ok(()) => report.push_str("  CreateProcessW=OK\n"),
            Err(e) => return format!("{report}  CreateProcessW FAILED: {e:?}\n"),
        }

        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let mut reader = None;
        if conpty_flags.is_some() {
            let c2 = captured.clone();
            let ori = out_read.0 as isize;
            reader = Some(std::thread::spawn(move || unsafe {
                let out_read = HANDLE(ori as *mut core::ffi::c_void);
                let mut b = [0u8; 8192];
                loop {
                    let mut n = 0u32;
                    if ReadFile(out_read, Some(&mut b), Some(&mut n), None).is_err() || n == 0 { break; }
                    c2.lock().unwrap().extend_from_slice(&b[..n as usize]);
                }
            }));
        }

        let w = WaitForSingleObject(pi.hProcess, 10000); // failure bound: a quick child must exit fast
        let mut code = 0u32;
        let _ = GetExitCodeProcess(pi.hProcess, &mut code);
        report.push_str(&format!("  wait=0x{:X}  exit=0x{:08X} ({})\n", w.0, code, code));
        if w.0 == 0x0000_0102 { let _ = TerminateProcess(pi.hProcess, 1); } // WAIT_TIMEOUT: a still-running child (e.g. GUI notepad)

        if conpty_flags.is_some() { ClosePseudoConsole(hpc_keep); }
        if let Some(r) = reader { let _ = r.join(); }
        if conpty_flags.is_some() {
            let cap = captured.lock().unwrap().clone();
            let s: String = String::from_utf8_lossy(&cap).chars().take(160).collect();
            report.push_str(&format!("  out({}b)={s:?}\n", cap.len()));
            let _ = CloseHandle(in_write);
            let _ = CloseHandle(out_read);
        }
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
        report
    }
}

// ---- reference: spawn the SAME child through the known-good `conpty` crate.
// If this succeeds where our hand-rolled try_case fails, the bug is in our FFI;
// if it fails too, the cause is environmental (conhost can't come up here).
fn try_conpty_crate(cmdline: &str) -> String {
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    let mut report = format!("[conpty-crate] cmd={cmdline}\n");
    let mut proc = match conpty::spawn(cmdline) {
        Ok(p) => p,
        Err(e) => return format!("{report}  spawn FAILED: {e:?}\n"),
    };
    report.push_str(&format!("  spawn=OK pid={}\n", proc.pid()));
    let cap = Arc::new(Mutex::new(Vec::<u8>::new()));
    let reader = match proc.output() {
        Ok(mut r) => {
            let c2 = cap.clone();
            Some(thread::spawn(move || {
                let mut b = [0u8; 8192];
                loop {
                    match r.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => c2.lock().unwrap().extend_from_slice(&b[..n]),
                    }
                }
            }))
        }
        Err(e) => {
            report.push_str(&format!("  output() FAILED: {e:?}\n"));
            None
        }
    };
    // failure bound on an external child-process exit (the allowed time exception).
    match proc.wait(Some(10000)) {
        Ok(code) => report.push_str(&format!("  wait exit=0x{code:08X} ({code})\n")),
        Err(e) => report.push_str(&format!("  wait FAILED/timeout: {e:?}\n")),
    }
    drop(proc); // closes the pseudoconsole -> the reader hits EOF and the thread ends
    if let Some(r) = reader {
        let _ = r.join();
    }
    let cap = cap.lock().unwrap().clone();
    let s: String = String::from_utf8_lossy(&cap).chars().take(160).collect();
    report.push_str(&format!("  out({}b)={s:?}\n", cap.len()));
    report
}

pub fn run_ptytest() -> windows::core::Result<()> {
    let cmd = "cmd.exe /c echo CHILD-RAN";
    let cases: [(&str, Option<u32>); 7] = [
        ("no-conpty", None),
        ("flags=0", Some(0x0)),
        ("RESIZE_QUIRK(2)", Some(0x2)),
        ("WIN32_INPUT(4)", Some(0x4)),
        ("PASSTHROUGH(8)", Some(0x8)),
        ("RESIZE|WIN32(6)", Some(0x6)),
        ("ALL(2|4|8=E)", Some(0xE)),
    ];
    let mut sid = 0u32;
    unsafe {
        let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(std::process::id(), &mut sid);
    }
    let mut report = format!("=== ssh-broker ptytest: ConPTY flag matrix (child=cmd.exe)  running_in_session={sid} ===\n");
    for (label, flags) in cases {
        report.push_str(&try_case(label, cmd, flags));
        report.push('\n');
    }
    // GUI control: notepad never attaches to a console. If it does NOT die with
    // 0xC0000142 while cmd does, the failure is specifically console-attach.
    report.push_str(&try_case("notepad-GUI(flags=0)", "notepad.exe", Some(0x0)));
    report.push('\n');
    // Known-good reference path.
    report.push_str(&try_conpty_crate("cmd.exe /c echo CONPTY-CRATE-RAN"));
    report.push('\n');
    let path = format!(
        "{}\\ptytest.txt",
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Test.User".into())
    );
    std::fs::write(&path, &report).expect("write ptytest.txt");
    println!("ptytest suite done -> {path}");
    Ok(())
}

pub fn run_conpty(shell: &str) -> Result<()> {
    unsafe {
        let stdin = GetStdHandle(STD_INPUT_HANDLE)?;
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;

        let mut sbi = CONSOLE_SCREEN_BUFFER_INFO::default();
        GetConsoleScreenBufferInfo(stdout, &mut sbi)?;
        let size = win_size(&sbi);

        // pipes: parent keeps in_write (to child stdin) + out_read (from child stdout)
        let mut in_read = HANDLE::default();
        let mut in_write = HANDLE::default();
        let mut out_read = HANDLE::default();
        let mut out_write = HANDLE::default();
        CreatePipe(&mut in_read, &mut in_write, None, 0)?;
        CreatePipe(&mut out_read, &mut out_write, None, 0)?;

        let (hpc, passthrough) = match CreatePseudoConsole(
            size,
            in_read,
            out_write,
            PC_RESIZE_QUIRK | PC_WIN32_INPUT | PC_PASSTHROUGH,
        ) {
            Ok(h) => (h, true),
            Err(_) => (
                CreatePseudoConsole(size, in_read, out_write, PC_RESIZE_QUIRK | PC_WIN32_INPUT)?,
                false,
            ),
        };
        let _ = CloseHandle(in_read);
        let _ = CloseHandle(out_write);
        eprintln!("[conpty] passthrough={passthrough} size={}x{}\r", size.X, size.Y);

        // STARTUPINFOEX carrying the pseudoconsole attribute
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // Null std handles + STARTF_USESTDHANDLES so our (pipe/console) handles don't bleed
        // into the child; the pseudoconsole supplies its stdio. microsoft/terminal#4380.
        si.StartupInfo.hStdInput = HANDLE::default();
        si.StartupInfo.hStdOutput = HANDLE::default();
        si.StartupInfo.hStdError = HANDLE::default();
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        let mut bytes: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut bytes);
        let mut attr = vec![0u8; bytes];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr.as_mut_ptr() as *mut _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut bytes)?;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            ATTR_PSEUDOCONSOLE,
            Some(hpc.0 as *const core::ffi::c_void), // the HPCON value itself, not &hpc
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )?;
        si.lpAttributeList = attr_list;

        // Identifying init so the NESTED shell is unmistakable in this hand-test:
        // it prints its own pid + parent process and sets a distinct prompt.
        let userprofile =
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Test.User".into());
        let ps1 = format!("{userprofile}\\nested_id.ps1");
        let _ = std::fs::write(
            &ps1,
            "$me=$PID; $par=(Get-CimInstance Win32_Process -Filter \"ProcessId=$me\").ParentProcessId; \
$pn=(Get-CimInstance Win32_Process -Filter \"ProcessId=$par\").Name; \
Write-Host \"=== NESTED SHELL  pid=$me  parent=$pn ($par) ===\" -ForegroundColor Green; \
function prompt { \"NESTED[$PID]> \" }\r\n",
        );
        eprintln!(
            "[ssh-broker] this process IS ssh-broker.exe (pid={}); launching the nested shell now...\r",
            std::process::id()
        );
        let line = format!("\"{shell}\" -NoLogo -NoExit -File \"{ps1}\"");
        let mut cmd: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pi = PROCESS_INFORMATION::default();
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )?;
        DeleteProcThreadAttributeList(attr_list);

        // raw input; VT-processed output (ConPTY#1 renders the relayed VT)
        let mut in_orig = CONSOLE_MODE(0);
        GetConsoleMode(stdin, &mut in_orig)?;
        SetConsoleMode(stdin, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS)?;
        let mut out_orig = CONSOLE_MODE(0);
        GetConsoleMode(stdout, &mut out_orig)?;
        SetConsoleMode(
            stdout,
            out_orig | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN,
        )?;

        // output relay: ConPTY#2 stdout -> our stdout
        let out_read_i = out_read.0 as isize;
        let stdout_i = stdout.0 as isize;
        let out_thread = thread::spawn(move || unsafe {
            let out_read = HANDLE(out_read_i as *mut core::ffi::c_void);
            let stdout = HANDLE(stdout_i as *mut core::ffi::c_void);
            let mut buf = [0u8; 16384];
            loop {
                let mut n = 0u32;
                if ReadFile(out_read, Some(&mut buf), Some(&mut n), None).is_err() || n == 0 {
                    break;
                }
                if !write_all(stdout, &buf[..n as usize]) {
                    break; // downstream (ConPTY#1 client) gone: stop, don't spin
                }
            }
        });

        // input relay: console records -> win32-input CSI -> ConPTY#2 stdin (+ resize)
        let in_write_i = in_write.0 as isize;
        let stdin_i = stdin.0 as isize;
        let stdout_i2 = stdout.0 as isize;
        let hpc_i = hpc.0 as isize;
        thread::spawn(move || unsafe {
            let in_write = HANDLE(in_write_i as *mut core::ffi::c_void);
            let stdin = HANDLE(stdin_i as *mut core::ffi::c_void);
            let stdout = HANDLE(stdout_i2 as *mut core::ffi::c_void);
            let hpc = HPCON(hpc_i);
            let mut recs: [INPUT_RECORD; 64] = std::mem::zeroed();
            loop {
                let mut n = 0u32;
                if ReadConsoleInputW(stdin, &mut recs, &mut n).is_err() {
                    break;
                }
                let mut out: Vec<u8> = Vec::new();
                for rec in &recs[..n as usize] {
                    match rec.EventType {
                        0x0001 => {
                            let k = rec.Event.KeyEvent;
                            out.extend_from_slice(
                                format!(
                                    "\x1b[{};{};{};{};{};{}_",
                                    k.wVirtualKeyCode,
                                    k.wVirtualScanCode,
                                    k.uChar.UnicodeChar,
                                    if k.bKeyDown.as_bool() { 1 } else { 0 },
                                    k.dwControlKeyState,
                                    k.wRepeatCount
                                )
                                .as_bytes(),
                            );
                        }
                        0x0004 => {
                            let mut sbi2 = CONSOLE_SCREEN_BUFFER_INFO::default();
                            if GetConsoleScreenBufferInfo(stdout, &mut sbi2).is_ok() {
                                let _ = ResizePseudoConsole(hpc, win_size(&sbi2));
                            }
                        }
                        _ => {} // mouse / focus: next increment
                    }
                }
                if !out.is_empty() && !write_all(in_write, &out) {
                    break; // child stdin closed: stop forwarding input
                }
            }
        });

        // wait for child, then 24H2-correct teardown: close, THEN drain to EOF
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(pi.hProcess, &mut code);
        let _ = SetConsoleMode(stdin, in_orig);
        let _ = SetConsoleMode(stdout, out_orig);
        eprintln!(
            "\r\n[ssh-broker] nested shell exited (code={code}). ssh-broker is exiting now -> you should land back in the OUTER shell that launched it, NOT in macOS.\r"
        );
        ClosePseudoConsole(hpc);
        let _ = out_thread.join();
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(in_write);
        std::process::exit(code as i32);
    }
}

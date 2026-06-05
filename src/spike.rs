//! spike: feasibility-spike scaffolding, kept behind `--features spike` (Windows only).
//!
//! This is NOT production code. It is preserved as:
//!   - the `ptytest` ConPTY flag-matrix regression harness, and
//!   - the `conpty`-crate known-good reference (`try_conpty_crate`),
//! both of which pinned down the `0xC0000142` HPCON `lpValue` root cause.
//! The production relay is reimplemented under TDD in the conpty/agent/shim modules.
//!
//! `diag` puts the console into raw, mouse-enabled input mode and logs every
//! INPUT_RECORD, proving (Spike #1) that a single ReadConsoleInputW captures all
//! input classes under win32-input-mode.

#[path = "relay_spike.rs"]
mod relay_spike;

use std::io::Write;

/// If `args` names a spike subcommand, run it and return `Some(result)`; otherwise
/// `None` so `main` falls through to the production `route()`.
pub fn try_dispatch(args: &[String]) -> Option<anyhow::Result<()>> {
    match args.first().map(String::as_str) {
        Some("diag") => Some(run_diag().map_err(|e| anyhow::anyhow!("diag: {e:?}"))),
        Some("ptytest") => {
            Some(relay_spike::run_ptytest().map_err(|e| anyhow::anyhow!("ptytest: {e:?}")))
        }
        Some("conpty") => {
            let shell = args
                .get(1)
                .map(String::as_str)
                .unwrap_or("C:\\Program Files\\PowerShell\\7\\pwsh.exe");
            Some(relay_spike::run_conpty(shell).map_err(|e| anyhow::anyhow!("conpty: {e:?}")))
        }
        _ => None,
    }
}

fn run_diag() -> windows::core::Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::*;

    let log_path = format!(
        "{}\\diag.log",
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Test.User".into())
    );
    let mut log = std::fs::File::create(&log_path).expect("create diag.log");

    unsafe {
        let h: HANDLE = GetStdHandle(STD_INPUT_HANDLE)?;
        let mut original = CONSOLE_MODE(0);
        GetConsoleMode(h, &mut original)?;

        // Raw + mouse: window + mouse + extended flags; NO processed/line/echo
        // (and no quick-edit, so mouse reaches us instead of being eaten by selection).
        let set = ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(h, set)?;

        writeln!(
            log,
            "# ssh-broker diag  original_mode=0x{:08X}  set_mode=0x{:08X}",
            original.0, set.0
        )
        .ok();
        println!("ssh-broker diag: original input mode = 0x{:08X}", original.0);
        println!("Type keys, hold modifiers, move/click/scroll the mouse, PASTE text, RESIZE the window.");
        println!("Press Esc THREE times in a row to quit (or just disconnect).\n");

        let mut buf: [INPUT_RECORD; 64] = std::mem::zeroed();
        let mut esc_run = 0u32;

        'outer: loop {
            let mut n = 0u32;
            ReadConsoleInputW(h, &mut buf, &mut n)?;
            for rec in &buf[..n as usize] {
                let line = describe(rec);
                writeln!(log, "{line}").ok();
                if !line.starts_with("MOUSE move") {
                    println!("{line}"); // echo everything except mouse-move spam
                }
                if rec.EventType == 0x0001 {
                    let ke = rec.Event.KeyEvent;
                    if ke.bKeyDown.as_bool() {
                        if ke.wVirtualKeyCode == 0x1B {
                            esc_run += 1;
                            if esc_run >= 3 {
                                break 'outer;
                            }
                        } else {
                            esc_run = 0;
                        }
                    }
                }
            }
        }

        SetConsoleMode(h, original).ok();
    }

    println!("\nssh-broker diag: done — wrote events to {log_path}");
    Ok(())
}

fn describe(rec: &windows::Win32::System::Console::INPUT_RECORD) -> String {
    unsafe {
        match rec.EventType {
            0x0001 => {
                let ke = rec.Event.KeyEvent;
                format!(
                    "KEY  {:<4} vk=0x{:02X} sc=0x{:02X} uc=0x{:04X} cks=0x{:08X} rep={}",
                    if ke.bKeyDown.as_bool() { "down" } else { "up" },
                    ke.wVirtualKeyCode,
                    ke.wVirtualScanCode,
                    ke.uChar.UnicodeChar,
                    ke.dwControlKeyState,
                    ke.wRepeatCount
                )
            }
            0x0002 => {
                let m = rec.Event.MouseEvent;
                let kind = if m.dwEventFlags & 0x0001 != 0 {
                    "move"
                } else if m.dwEventFlags & 0x0002 != 0 {
                    "dblclick"
                } else if m.dwEventFlags & 0x0004 != 0 {
                    "wheel"
                } else if m.dwEventFlags & 0x0008 != 0 {
                    "hwheel"
                } else {
                    "button"
                };
                format!(
                    "MOUSE {:<8} pos=({},{}) btn=0x{:08X} flags=0x{:X} cks=0x{:08X}",
                    kind,
                    m.dwMousePosition.X,
                    m.dwMousePosition.Y,
                    m.dwButtonState,
                    m.dwEventFlags,
                    m.dwControlKeyState
                )
            }
            0x0004 => {
                let w = rec.Event.WindowBufferSizeEvent;
                format!("RESIZE buffer dwSize=({},{})", w.dwSize.X, w.dwSize.Y)
            }
            0x0008 => "MENU (internal)".to_string(),
            0x0010 => {
                let f = rec.Event.FocusEvent;
                format!("FOCUS set={}", f.bSetFocus.as_bool())
            }
            other => format!("UNKNOWN EventType=0x{other:04X}"),
        }
    }
}

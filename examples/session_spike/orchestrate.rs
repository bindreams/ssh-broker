//! The orchestrator: `session_spike <group>...` with groups `env m1 m3 m4 m5 m6 m7 m8`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::harness::Shared;
use crate::rec::{emit, fact, open_summary};
use crate::{groups, m5, m8, win};

/// The spike creates accounts and logs them on: only a CI runner, and only an elevated administrator.
fn preflight() -> Result<(), String> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("GITHUB_ACTIONS is not true: this spike runs only in CI, never on a workstation".into());
    }
    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the token is closed by `OwnedHandle`.
    let elevated = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|e| e.to_string())?;
        let token = ssh_broker::winutil::OwnedHandle(token);
        let mut info = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .map_err(|e| e.to_string())?;
        info.TokenIsElevated != 0
    };
    if !elevated {
        return Err("the process is not an elevated administrator".into());
    }
    Ok(())
}

pub fn run(groups_wanted: &[String]) -> i32 {
    open_summary();
    if let Err(why) = preflight() {
        eprintln!("session_spike refuses to run: {why}");
        return 2;
    }
    if let Err(e) = win::enable_privilege("SeDebugPrivilege") {
        fact("orchestrator", "se_debug_privilege", format!("not enabled: {e}"));
    }
    crate::tasks::init_com();
    let shared = Shared::new();
    emit(&format!(
        "SPIKE begin groups={groups_wanted:?} shared_dir={}",
        shared.root.display()
    ));
    for group in groups_wanted {
        emit(&format!("SPIKE group.{group}=begin"));
        let outcome = catch_unwind(AssertUnwindSafe(|| match group.as_str() {
            "env" => groups::env(&shared),
            "m1" => groups::m1(&shared),
            "m3" => groups::m3(&shared),
            "m4" => groups::m4(&shared),
            "m5" => m5::m5(&shared),
            "m6" => groups::m6(&shared),
            "m7" => groups::m7(&shared),
            "m8" => m8::m8(&shared),
            other => fact(other, "fatal", "unknown group"),
        }));
        if let Err(panic) = outcome {
            let text = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "panic".into());
            fact(group, "fatal", text);
        }
        emit(&format!("SPIKE group.{group}=end"));
    }
    0
}

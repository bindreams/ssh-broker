//! The process the logon starts: the `ssh-broker agent --background` stand-in. It records what a
//! background agent would see, then optionally holds until told to go on.
//!
//! `child <rundir> <name> [junction=<dir>] [ready=<event>] [go=<event>] [ack=<event>] [grandchild=1]`

use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;

use windows::Win32::Foundation::HANDLE;

use crate::rec::Rec;
use crate::win::{self, Event};

pub fn run(args: &[String]) -> i32 {
    let dir = Path::new(&args[0]);
    let name = &args[1];
    let opt = |key: &str| {
        args[2..]
            .iter()
            .find_map(|a| a.strip_prefix(&format!("{key}=")))
            .map(str::to_owned)
    };
    let rec = Rec::create(dir, name);
    facts(&rec, opt("junction").as_deref());

    // A shell of the session: another process of the same logon.
    let mut grandchild = None;
    if opt("grandchild").is_some() {
        let ready = opt("ready").expect("grandchild needs ready");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("child")
            .arg(dir)
            .arg(format!("{name}gc"))
            .arg(format!("ready={ready}-gc"))
            .arg(format!("go={}", opt("go").expect("grandchild needs go")))
            .creation_flags(0x0800_0000)
            .spawn();
        match child {
            Ok(child) => {
                rec.put("grandchild_pid", child.id());
                grandchild = Some(child);
            }
            Err(e) => rec.put("grandchild", format!("ERROR {e}")),
        }
    }

    if let Some(ready) = opt("ready") {
        if let Some(child) = &grandchild {
            let gc_ready = Event::open(&format!("{ready}-gc")).expect("open the grandchild's ready event");
            win::wait_any(&[gc_ready.handle(), HANDLE(child.as_raw_handle())]);
        }
        Event::open(&ready).expect("open the ready event").set();
    }
    if let Some(go) = opt("go") {
        win::wait_one(Event::open(&go).expect("open the go event").handle());
        rec.put("after_go", "alive");
        if let Some(ack) = opt("ack") {
            Event::open(&ack).expect("open the ack event").set();
        }
    }
    0
}

fn facts(rec: &Rec, junction: Option<&str>) {
    let pid = std::process::id();
    rec.put("pid", pid);
    rec.put("parent_pid", win::parent_of(pid));
    rec.put("ts_session", win::session_of(pid));
    rec.put("lib_session_id", ssh_broker::provision::probe::current_session_id());
    win::own_token_facts(rec, "self");
    win::redirection_guard_state(rec, "self");
    win::own_job_facts(rec, "self");
    for var in ["USERPROFILE", "LOCALAPPDATA", "USERNAME"] {
        rec.put(
            &format!("env.{var}"),
            std::env::var(var).unwrap_or_else(|_| "(unset)".into()),
        );
    }
    win::profile_dir_facts(rec, "self");
    if let Some((sid, _)) = win::process_identity(pid) {
        rec.put("profile_list_entry", win::profile_list_entry(&sid));
        rec.put("hive_loaded_in_hku", win::hive_loaded(&sid));
    }
    win::dpapi_facts(rec, "self");
    rec.put(
        "lib_dpapi_roundtrip",
        ssh_broker::provision::probe::dpapi_roundtrip(b"ssh-broker-parity-probe"),
    );
    rec.put(
        "lib_symlink_probe",
        format!("{:?}", ssh_broker::provision::probe::symlink_probe()),
    );
    if let Some(link) = junction {
        win::read_through_junction(rec, "junction_the_account_made", Path::new(link));
    }
}

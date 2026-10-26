//! M8: M1 to M3 from a real `sshd` session. Best effort: it needs the OpenSSH server capability.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::account::{Account, Kind};
use crate::harness::{Shared, create_events};
use crate::rec::{Follower, Input, Rec, fact};
use crate::win::{self, event_name, wait_bounded};
use crate::{desktop, evlog};

/// How long sshd may take to end a session after the client is gone. sshd is an external party
/// that may never end it (the question M3 asks), so the bound is reported as a bound.
const SESSION_END_SECONDS: u32 = 60;

fn lines(program: &str, args: &[&str]) -> Vec<String> {
    match Command::new(program).args(args).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&out.stderr).lines())
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(e) => vec![format!("{program} did not run: {e}")],
    }
}

fn icacls(path: &Path, args: &[&str]) {
    let status = desktop::status(Command::new("icacls").arg(path).args(args)).expect("run icacls");
    assert!(status.success(), "icacls {path:?} {args:?}");
}

pub fn m8(shared: &Shared) {
    let installed = lines("sc", &["query", "sshd"]);
    if !installed.iter().any(|l| l.contains("SERVICE_NAME")) {
        fact(
            "m8",
            "result",
            format!("skipped: the sshd service is not installed ({installed:?})"),
        );
        return;
    }
    for line in lines("net", &["start", "sshd"]) {
        fact("m8", "net_start_sshd", line);
    }
    evlog::enable_logon_audit("m8");
    let b = Account::create("b", true, Kind::Standard);
    let profile = b.profile.clone().expect("b has a profile");
    configure_sshd();

    // A key for b, in the way sshd wants it.
    let keys = std::env::temp_dir().join(format!("sb-spike-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    std::fs::create_dir_all(&keys).unwrap();
    let key = keys.join("id");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status();
    if !matches!(made, Ok(s) if s.success()) {
        fact("m8", "result", format!("skipped: ssh-keygen failed ({made:?})"));
        return;
    }
    icacls(
        &keys,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
    );
    // b is a standard user, so sshd reads <profile>\.ssh\authorized_keys (an administrator's keys
    // are in %ProgramData%\ssh\administrators_authorized_keys). Only SYSTEM, Administrators and the
    // user may hold the file, the way sshd's permission check wants it.
    let dot_ssh = profile.join(".ssh");
    std::fs::create_dir_all(&dot_ssh).unwrap();
    let authorized = dot_ssh.join("authorized_keys");
    std::fs::copy(keys.join("id.pub"), &authorized).unwrap();
    let grants = [
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        &format!("*{}:(OI)(CI)F", b.sid_text),
    ];
    icacls(&dot_ssh, &grants);
    icacls(&authorized, &grants);
    for (what, path) in [
        ("profile", &profile),
        (".ssh", &dot_ssh),
        ("authorized_keys", &authorized),
    ] {
        for (i, line) in lines("icacls", &[&path.to_string_lossy()]).into_iter().enumerate() {
            fact("m8", &format!("acl.{what}.{i:02}"), line);
        }
    }
    fact(
        "m8",
        "authorized_keys.content_length",
        std::fs::metadata(&authorized).map_or_else(|e| format!("ERROR {e}"), |m| m.len().to_string()),
    );

    // The run: the same stand-in as M1, started by sshd instead of by us.
    let dir = shared.run_dir("m8");
    let child_ready = event_name("child-ready");
    let go = event_name("go");
    let ack = event_name("ack");
    let standin_ready = event_name("standin-ready");
    let events = create_events("m8", &[&child_ready, &go, &ack, &standin_ready], Some(&b.sid_text));
    Input::write(
        &dir,
        &[
            ("user", b.name.clone()),
            ("password", b.password.clone()),
            ("sid", b.sid_text.clone()),
            ("exe", shared.exe.display().to_string()),
            ("ready", child_ready),
            ("go", go),
            ("ack", ack),
            ("standin_ready", standin_ready),
        ],
    );
    let follower = Follower::start("m8", &dir);
    let openssh_mark = evlog::mark(&evlog::OPENSSH);
    let audit_mark = evlog::mark(&evlog::LOGON_AUDIT);
    let dump_logs = || {
        evlog::dump_since("m8", &evlog::OPENSSH, openssh_mark);
        evlog::dump_since("m8", &evlog::LOGON_AUDIT, audit_mark);
    };
    let remote = format!("\"{}\" stand-in \"{}\" m1", shared.exe.display(), dir.display());
    let ssh_out = std::fs::File::create(dir.join("ssh-client-stdout.txt")).unwrap();
    let ssh_err = std::fs::File::create(dir.join("ssh-client-stderr.txt")).unwrap();
    let spawned = desktop::spawn(
        Command::new("ssh")
            .args(["-v", "-i"])
            .arg(&key)
            .args([
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=NUL",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PasswordAuthentication=no",
            ])
            .arg(format!("{}@localhost", b.name))
            .arg(&remote)
            .stdin(Stdio::null())
            .stdout(ssh_out)
            .stderr(ssh_err),
    );
    let mut ssh = match spawned {
        Ok(child) => child,
        Err(e) => {
            fact("m8", "result", format!("could not run ssh: {e}"));
            follower.finish();
            return;
        }
    };
    use std::os::windows::io::AsRawHandle;
    let ssh_handle = windows::Win32::Foundation::HANDLE(ssh.as_raw_handle());
    if win::wait_any(&[events[3].handle(), ssh_handle]) == 1 {
        fact(
            "m8",
            "result",
            "ssh ended before the stand-in reported; its output follows",
        );
        for name in ["ssh-client-stdout.txt", "ssh-client-stderr.txt"] {
            for (i, line) in std::fs::read_to_string(dir.join(name))
                .unwrap_or_default()
                .lines()
                .enumerate()
            {
                fact("m8", &format!("{name}.{i:02}"), line);
            }
        }
        for line in lines("sc", &["query", "sshd"]) {
            fact("m8", "sshd_state", line);
        }
        dump_logs();
        follower.finish();
        return;
    }

    let read = |name: &str, key: &str| Rec::read_back(&dir, name, key);
    let child_pid: u32 = read("standin", "child_pid")
        .and_then(|v| v.parse().ok())
        .expect("child pid");
    let standin_pid: u32 = read("standin", "pid")
        .and_then(|v| v.parse().ok())
        .expect("stand-in pid");
    let child = win::open_for_wait(child_pid).expect("open the child");
    let standin = win::open_for_wait(standin_pid).expect("open the stand-in");
    fact(
        "m8",
        "orchestrator.stand_in_parent_image",
        win::image_of(win::parent_of(standin_pid).parse().unwrap_or(0)),
    );
    fact(
        "m8",
        "orchestrator.child_parent_image",
        win::image_of(win::parent_of(child_pid).parse().unwrap_or(0)),
    );

    // The disconnect.
    let _ = ssh.kill();
    let _ = ssh.wait();
    let ended = wait_bounded(standin.0, SESSION_END_SECONDS);
    fact(
        "m8",
        "orchestrator.stand_in_ended_after_disconnect",
        format!(
            "{ended} (false: still running {SESSION_END_SECONDS} s after the client was killed; sshd did not end its session in that time)"
        ),
    );
    events[1].set();
    let survived = win::wait_any(&[events[2].handle(), child.0]) == 0;
    fact("m8", "orchestrator.child_survived_the_disconnect", survived);

    win::terminate(child.0);
    win::terminate(standin.0);
    dump_logs();
    follower.finish();
}

/// Make sshd accept the test account's key and say why it refuses if it still does. The runner's
/// image is thrown away after the job, so the file is edited in place.
///
/// - `StrictModes no`: sshd's permission check on the account's `authorized_keys` and profile is a
///   known reason for "Permission denied (publickey)" with a correct key.
/// - `PubkeyAuthentication yes`, `LogLevel DEBUG3`: the reason lands in the `OpenSSH/Operational` log.
///
/// sshd takes the first value it reads of a directive, so the lines go first (before any `Match`).
fn configure_sshd() {
    let config = Path::new(&std::env::var_os("ProgramData").expect("ProgramData"))
        .join("ssh")
        .join("sshd_config");
    let original = std::fs::read_to_string(&config);
    match &original {
        Ok(text) => {
            for (shown, line) in text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .enumerate()
            {
                fact("m8", &format!("sshd_config_before.{shown:02}"), line);
            }
        }
        Err(e) => fact("m8", "sshd_config_before", format!("unreadable: {e}")),
    }
    let text = format!(
        "StrictModes no\nPubkeyAuthentication yes\nLogLevel DEBUG3\n{}",
        original.unwrap_or_default()
    );
    match std::fs::write(&config, text) {
        Ok(()) => fact(
            "m8",
            "sshd_config_edit",
            "prepended StrictModes no, PubkeyAuthentication yes, LogLevel DEBUG3",
        ),
        Err(e) => fact("m8", "sshd_config_edit", format!("ERROR {e}")),
    }
    for line in lines("net", &["stop", "sshd"]) {
        fact("m8", "net_stop_sshd", line);
    }
    for line in lines("net", &["start", "sshd"]) {
        fact("m8", "net_restart_sshd", line);
    }
    let wanted = [
        "authorizedkeysfile",
        "strictmodes",
        "pubkeyauthentication",
        "passwordauthentication",
        "allowusers",
        "allowgroups",
        "denyusers",
        "denygroups",
        "authenticationmethods",
        "loglevel",
    ];
    for line in lines("sshd", &["-T"]) {
        if wanted.iter().any(|w| line.starts_with(w)) {
            fact("m8", "sshd_effective_config", line);
        }
    }
}

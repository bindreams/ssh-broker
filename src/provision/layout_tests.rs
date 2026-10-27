use super::*;
use crate::acl;
use crate::provision::schtasks::agent_task_xml;
use crate::test_support::{FILE_READ_EXECUTE, aces};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A not-yet-created base directory under the temp dir that is removed on drop.
struct TempBase(PathBuf);

impl TempBase {
    fn new(tag: &str) -> TempBase {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TempBase(std::env::temp_dir().join(format!("ssh-broker-layout-{tag}-{}-{n}", std::process::id())))
    }
    fn layout(&self) -> Layout {
        Layout { base: self.0.clone() }
    }
    /// An existing plain directory, which `ensure_base` would refuse.
    fn existing(tag: &str) -> TempBase {
        let base = TempBase::new(tag);
        std::fs::create_dir_all(&base.0).unwrap();
        base
    }
}

/// [`ensure_base`], then [`prepare_in`]: what `apply` does.
fn prepare(
    layout: &Layout,
    current_exe: &Path,
    agent_task_xml: Option<&str>,
    stop_agents: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let base = ensure_base(layout)?;
    prepare_in(&base, current_exe, agent_task_xml, stop_agents)
}

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A witness for a directory that was never checked, so the code behind it can run without
/// elevation. Only these tests can build one: the field is private to `layout`.
fn forged(layout: &Layout) -> TrustedBase<'_> {
    TrustedBase { layout }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The queried XML of an agent task an earlier build registered: one account, no group.
const LEGACY_TASK_XML: &str = r#"<Task><Principals><Principal id="Author"><UserId>DOM\someone</UserId>
<LogonType>InteractiveToken</LogonType></Principal></Principals></Task>"#;

/// What a single-user install left in the install directory.
fn plant_legacy(base: &TempBase) {
    std::fs::write(base.0.join("config.toml"), "target_user = \"someone\"\n").unwrap();
    let socket_dir = base.0.join("s");
    std::fs::create_dir(&socket_dir).unwrap();
    // A real AF_UNIX socket file, which is a reparse point, as the old agent left it.
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    sock.bind(&socket2::SockAddr::unix(socket_dir.join("a.sock")).unwrap())
        .unwrap();
}

// The trust gate ------------------------------------------------------------------------

#[test]
fn ensure_base_writes_nothing_into_a_hostile_preexisting_base() {
    let base = TempBase::existing("hostile");
    std::fs::write(base.0.join("planted.txt"), "x").unwrap();

    let err = format!("{:#}", ensure_base(&base.layout()).expect_err("hostile base"));

    assert!(err.contains(&base.0.display().to_string()), "{err}");
    assert_eq!(names_in(&base.0), ["planted.txt"], "ensure_base must not write into it");
}

#[test]
fn check_base_gives_the_reason_for_an_untrusted_directory() {
    let base = TempBase::existing("check");

    let layout = base.layout();

    let reason = check_base(&layout).expect_err("a default directory is untrusted");

    // A directory under the temp dir inherits its ACL, whoever owns it (the user, or
    // Administrators for an elevated one), so the ACL clause is the reason in either case. Every
    // reason mentions an owner, so that word alone would prove nothing.
    assert!(reason.contains("its ACL is not the hardened one"), "{reason}");
    assert!(names_in(&base.0).is_empty(), "check_base only reads");
}

#[test]
fn check_base_reports_a_missing_directory_as_a_reason_not_a_panic() {
    let base = TempBase::new("check-missing");

    let reason = check_base(&base.layout()).expect_err("a missing directory is untrusted");

    assert!(reason.contains(&base.0.display().to_string()), "{reason}");
    assert!(!base.0.exists(), "check_base must not create it");
}

#[test]
fn trusted_base_gate_does_not_run_the_action_on_an_untrusted_base() {
    let layout = TempBase::new("gate").layout();
    let ran = std::cell::Cell::new(false);
    let run = |base: &TrustedBase<'_>| {
        ran.set(true);
        Ok(base.layout().base.clone())
    };

    let untrusted: BaseCheck<'_> = Err("planted by someone".into());
    let err = format!("{:#}", run_if_trusted_base(&untrusted, run).unwrap_err());
    assert!(err.contains("install dir untrusted"), "{err}");
    assert!(err.contains("planted by someone"), "the reason must survive: {err}");
    assert!(!ran.get(), "the action must not run");

    assert_eq!(run_if_trusted_base(&Ok(forged(&layout)), run).unwrap(), layout.base);
    assert!(ran.get());
}

// Legacy detection ------------------------------------------------------------------------

#[test]
fn a_clean_base_has_no_legacy_artifacts() {
    let base = TempBase::existing("legacy-clean");
    let layout = base.layout();
    let found = legacy_artifacts(&forged(&layout), None).unwrap();
    assert!(!found.any());
    let found = legacy_artifacts(&forged(&layout), Some(&agent_task_xml(r"C:\x.exe"))).unwrap();
    assert!(!found.any(), "the group-form task is the current one, not a legacy one");
}

#[test]
fn legacy_is_detected_from_the_config_alone() {
    let base = TempBase::existing("legacy-config");
    std::fs::write(base.0.join("config.toml"), "x").unwrap();
    let found = legacy_artifacts(&forged(&base.layout()), None).unwrap();
    assert!(found.any() && found.config && !found.socket_dir && !found.task);
}

#[test]
fn legacy_is_detected_from_the_socket_dir_alone() {
    let base = TempBase::existing("legacy-sdir");
    std::fs::create_dir(base.0.join("s")).unwrap();
    let found = legacy_artifacts(&forged(&base.layout()), None).unwrap();
    assert!(found.any() && found.socket_dir && !found.config && !found.task);
}

#[test]
fn legacy_is_detected_from_a_per_user_task_alone() {
    // A half-finished earlier migration or a manual cleanup can leave only the old task, and with
    // it a running legacy agent. No config and no `s\`: the task is what says so.
    let base = TempBase::existing("legacy-task");
    let found = legacy_artifacts(&forged(&base.layout()), Some(LEGACY_TASK_XML)).unwrap();
    assert!(found.any() && found.task && !found.config && !found.socket_dir);
}

#[test]
fn a_legacy_path_that_cannot_be_inspected_is_an_error_naming_it_not_an_absent_one() {
    // Only NotFound means absent. Any other failure (here an invalid path, in life an access
    // error) leaves the question open, and a migration that guesses "absent" skips the cleanup.
    let layout = Layout {
        base: PathBuf::from("C:\\ssh-broker\0unusable"),
    };
    let err = format!("{:#}", legacy_artifacts(&forged(&layout), None).unwrap_err());
    assert!(err.contains("config.toml"), "{err}");
}

#[test]
fn only_not_found_counts_as_absent() {
    let base = TempBase::existing("present");
    std::fs::write(base.0.join("here"), "x").unwrap();
    assert!(present(&base.0.join("here")).unwrap());
    assert!(!present(&base.0.join("missing")).unwrap());
    // A NUL in the path is a different failure from NotFound.
    assert!(present(&base.0.join("bad\0name")).is_err());
}

// Removing the legacy artifacts ----------------------------------------------------------

#[test]
fn remove_legacy_deletes_the_old_socket_dir_and_config() {
    let base = TempBase::existing("remove");
    plant_legacy(&base);
    let layout = base.layout();
    let base_ref = forged(&layout);
    let found = legacy_artifacts(&base_ref, None).unwrap();
    assert!(found.config && found.socket_dir, "control");

    remove_legacy(&base_ref, &found).unwrap();

    assert!(names_in(&base.0).is_empty(), "{:?}", names_in(&base.0));
    assert!(!legacy_artifacts(&base_ref, None).unwrap().any());
}

#[test]
fn remove_legacy_is_a_noop_on_a_clean_base() {
    let base = TempBase::existing("remove-clean");
    std::fs::write(base.0.join("keep.txt"), "x").unwrap();
    let layout = base.layout();
    remove_legacy(&forged(&layout), &Legacy::default()).unwrap();
    assert_eq!(names_in(&base.0), ["keep.txt"]);
}

#[test]
fn remove_legacy_leaves_exe_logs_and_other_files() {
    let base = TempBase::existing("remove-others");
    plant_legacy(&base);
    std::fs::write(base.0.join("ssh-broker.exe"), "exe").unwrap();
    std::fs::create_dir(base.0.join("logs")).unwrap();
    std::fs::write(base.0.join("logs").join("shim.log"), "old log").unwrap();
    let layout = base.layout();
    let base_ref = forged(&layout);

    remove_legacy(&base_ref, &legacy_artifacts(&base_ref, None).unwrap()).unwrap();

    assert_eq!(names_in(&base.0), ["logs", "ssh-broker.exe"]);
    assert_eq!(names_in(&base.0.join("logs")), ["shim.log"]);
}

// The apply sequence ----------------------------------------------------------------------

/// A stand-in for the running exe: any file, since `prepare` only copies it.
fn new_exe(base: &TempBase, bytes: &str) -> PathBuf {
    let path = base.0.join("new-build.exe");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn prepare_refuses_a_hostile_base_before_it_reads_or_stops_anything() {
    let base = TempBase::existing("prepare-hostile");
    std::fs::write(base.0.join("config.toml"), "planted").unwrap();
    let stopped = std::cell::Cell::new(false);

    let err = format!(
        "{:#}",
        prepare(
            &base.layout(),
            &std::env::current_exe().unwrap(),
            Some(LEGACY_TASK_XML),
            || {
                stopped.set(true);
                Ok(())
            }
        )
        .expect_err("hostile base")
    );

    assert!(err.contains("cannot be trusted"), "{err}");
    assert_eq!(names_in(&base.0), ["config.toml"], "nothing may be written into it");
    assert!(!stopped.get(), "no agent is stopped on the word of an untrusted base");
}

#[test]
fn prepare_in_stops_the_legacy_agent_before_replacing_the_exe() {
    // A live agent holds its exe open, so the copy would fail with a sharing violation and the
    // old exe would stay under the new tasks. The stop has to come first.
    let base = TempBase::existing("prepare-order");
    plant_legacy(&base);
    std::fs::write(base.0.join("ssh-broker.exe"), "old build").unwrap();
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let seen = std::cell::RefCell::new(None);

    let exe = prepare_in(&forged(&layout), &source, None, || {
        *seen.borrow_mut() = Some(std::fs::read_to_string(layout.canonical_exe()).unwrap());
        Ok(())
    })
    .unwrap();

    assert_eq!(
        seen.borrow().as_deref(),
        Some("old build"),
        "the old exe was still in place"
    );
    assert_eq!(std::fs::read_to_string(exe).unwrap(), "new build");
    assert!(!base.0.join("config.toml").exists() && !base.0.join("s").exists());
}

#[test]
fn prepare_in_stops_the_agent_for_a_legacy_task_with_no_files() {
    let base = TempBase::existing("prepare-task");
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let stopped = std::cell::Cell::new(false);

    prepare_in(&forged(&layout), &source, Some(LEGACY_TASK_XML), || {
        stopped.set(true);
        Ok(())
    })
    .unwrap();

    assert!(stopped.get());
}

#[test]
fn prepare_in_stops_the_agents_before_it_replaces_a_changed_exe() {
    // Not a migration: a newer build over an installed one. Every running agent holds the old exe
    // open, so without the stop the copy fails and the old exe stays under the new tasks.
    let base = TempBase::existing("prepare-update");
    std::fs::write(base.0.join("ssh-broker.exe"), "old build").unwrap();
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let group = agent_task_xml(r"C:\x.exe");
    let seen = std::cell::RefCell::new(None);

    let exe = prepare_in(&forged(&layout), &source, Some(&group), || {
        *seen.borrow_mut() = Some(std::fs::read_to_string(layout.canonical_exe()).unwrap());
        Ok(())
    })
    .unwrap();

    assert_eq!(
        seen.borrow().as_deref(),
        Some("old build"),
        "agents were stopped while the old exe was still in place"
    );
    assert_eq!(std::fs::read_to_string(exe).unwrap(), "new build");
}

#[test]
fn prepare_in_does_not_stop_agents_when_the_exe_is_unchanged() {
    // Re-running `apply`, and the boot self-heal, with the build that is installed.
    let base = TempBase::existing("prepare-same");
    std::fs::write(base.0.join("ssh-broker.exe"), "same build").unwrap();
    let source = new_exe(&base, "same build");
    let layout = base.layout();
    let group = agent_task_xml(r"C:\x.exe");

    prepare_in(&forged(&layout), &source, Some(&group), || {
        panic!("the exe is not replaced, so no agent needs to leave")
    })
    .unwrap();
}

#[test]
fn prepare_in_changes_nothing_when_agents_cannot_be_stopped_for_an_update() {
    let base = TempBase::existing("prepare-update-stuck");
    std::fs::write(base.0.join("ssh-broker.exe"), "old build").unwrap();
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let group = agent_task_xml(r"C:\x.exe");

    let err = format!(
        "{:#}",
        prepare_in(&forged(&layout), &source, Some(&group), || anyhow::bail!(
            "access denied"
        ))
        .unwrap_err()
    );

    assert!(err.contains("access denied"), "{err}");
    assert_eq!(std::fs::read_to_string(layout.canonical_exe()).unwrap(), "old build");
}

#[test]
fn prepare_in_fails_when_the_exe_is_still_in_use_after_the_stop() {
    // An agent started by hand (`ssh-broker agent`) is not a task instance, so the stop misses it
    // and it keeps the exe open. `apply` must not report `ok` with the old exe under the new tasks.
    use std::os::windows::fs::OpenOptionsExt;
    let base = TempBase::existing("prepare-held");
    std::fs::write(base.0.join("ssh-broker.exe"), "old build").unwrap();
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let group = agent_task_xml(r"C:\x.exe");
    // Exclusive: no sharing, so the copy over it fails as it does over a running exe.
    let _held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(layout.canonical_exe())
        .unwrap();

    let err = format!(
        "{:#}",
        prepare_in(&forged(&layout), &source, Some(&group), || Ok(())).unwrap_err()
    );

    assert!(err.contains("in use"), "{err}");
    assert!(err.contains("started by hand"), "{err}");
    assert!(err.contains("ssh-broker.exe"), "{err}");
}

#[test]
fn an_exe_in_use_is_blamed_on_both_possible_holders_and_the_message_says_how_to_find_them() {
    // The exe is sshd's DefaultShell, so the shim of any open SSH session holds it as well as a
    // hand-started agent does; naming only the agent sends the administrator looking for a
    // process that may not exist.
    let msg = copy_failure(
        Path::new(r"C:\x\ssh-broker.exe"),
        &std::io::Error::from_raw_os_error(32),
    );
    assert!(msg.contains("started by hand"), "{msg}");
    assert!(msg.contains("SSH session"), "{msg}");
    assert!(msg.contains("tasklist"), "how to find the holders: {msg}");
    assert!(msg.contains("run apply again"), "{msg}");
}

#[test]
fn a_copy_stopped_by_a_sharing_violation_is_called_in_use() {
    for code in [32, 1224] {
        let msg = copy_failure(
            Path::new(r"C:\x\ssh-broker.exe"),
            &std::io::Error::from_raw_os_error(code),
        );
        assert!(msg.contains("in use"), "{msg}");
        assert!(msg.contains("started by hand"), "{msg}");
        assert!(msg.contains(&format!("os error {code}")), "{msg}");
    }
}

#[test]
fn a_copy_that_failed_for_another_reason_is_reported_by_its_error_not_as_in_use() {
    // 5: access denied; 112: disk full.
    for code in [5, 112] {
        let msg = copy_failure(
            Path::new(r"C:\x\ssh-broker.exe"),
            &std::io::Error::from_raw_os_error(code),
        );
        assert!(!msg.contains("in use"), "{msg}");
        assert!(!msg.contains("started by hand"), "{msg}");
        assert!(!msg.contains("SSH session"), "{msg}");
        assert!(msg.contains(&format!("os error {code}")), "{msg}");
        assert!(msg.contains("ssh-broker.exe"), "{msg}");
    }
}

#[test]
fn prepare_in_reports_a_failed_copy_by_its_cause() {
    // The destination is a directory: the copy fails, but not because anything holds it open.
    let base = TempBase::existing("prepare-copy-fails");
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    std::fs::create_dir(layout.canonical_exe()).unwrap();

    let err = format!(
        "{:#}",
        prepare_in(&forged(&layout), &source, None, || Ok(())).unwrap_err()
    );

    assert!(err.contains("ssh-broker.exe"), "{err}");
    assert!(err.contains("os error"), "{err}");
    assert!(!err.contains("in use"), "{err}");
}

#[test]
fn prepare_in_does_not_stop_agents_when_nothing_is_legacy() {
    // Re-running `apply`, and the boot self-heal, must leave live agents alone.
    let base = TempBase::existing("prepare-clean");
    let source = new_exe(&base, "new build");
    let layout = base.layout();
    let group = agent_task_xml(r"C:\x.exe");

    prepare_in(&forged(&layout), &source, Some(&group), || {
        panic!("a clean install has no legacy agent to stop")
    })
    .unwrap();
}

#[test]
fn prepare_in_fails_and_changes_nothing_when_the_agent_cannot_be_stopped() {
    let base = TempBase::existing("prepare-stuck");
    plant_legacy(&base);
    std::fs::write(base.0.join("ssh-broker.exe"), "old build").unwrap();
    let source = new_exe(&base, "new build");
    let layout = base.layout();

    let err = format!(
        "{:#}",
        prepare_in(&forged(&layout), &source, None, || anyhow::bail!("access denied")).unwrap_err()
    );

    assert!(err.contains("access denied"), "{err}");
    assert!(
        base.0.join("config.toml").exists() && base.0.join("s").exists(),
        "nothing removed"
    );
    assert_eq!(std::fs::read_to_string(layout.canonical_exe()).unwrap(), "old build");
}

/// Elevated (CI only): `prepare` creates the base.
#[test]
fn populate_builds_a_verified_layout() {
    let base = TempBase::new("populate");
    let layout = base.layout();

    let exe = prepare(&layout, &std::env::current_exe().unwrap(), None, || Ok(())).unwrap();

    assert_eq!(exe, layout.canonical_exe());
    assert!(exe.is_file());
    assert!(acl::verify_install_dir_acl(&layout.base).unwrap());
    assert_eq!(
        names_in(&layout.base),
        ["ssh-broker.exe"],
        "nothing else lives in the install dir"
    );
}

// Rows of the verify report ---------------------------------------------------------------

#[test]
fn install_dir_row_carries_the_reason_the_directory_is_untrusted() {
    let base = TempBase::new("row");
    let layout = base.layout();

    let bad = install_dir_row(&Err("its owner is X, not the Administrators group".into()));
    assert!(!bad.pass);
    assert_eq!(bad.detail, "its owner is X, not the Administrators group");

    let good = install_dir_row(&Ok(forged(&layout)));
    assert!(good.pass);
    assert_eq!(good.detail, layout.base.display().to_string());
}

// Reading a DACL by SID -------------------------------------------------------------------

#[test]
fn aces_reads_an_sddl_dacl() {
    assert_eq!(
        aces("D:AI(A;OICIID;FA;;;SY)(A;OICIID;FRFX;;;BA)(A;;0x1200a9;;;BU)"),
        [
            ("A", "OICIID", crate::test_support::FILE_ALL, "SY"),
            ("A", "OICIID", FILE_READ_EXECUTE, "BA"),
            ("A", "", FILE_READ_EXECUTE, "BU"),
        ]
    );
}

/// `canonical_exe` is the path the cfg-free pins (`sshd_reads_the_flag_for_the_path_apply_registers`)
/// assert on, so it must be the one `apply` installs to and registers.
#[test]
fn the_production_layout_installs_the_exe_that_the_cfg_free_pins_assert_on() {
    assert_eq!(Layout::production().canonical_exe(), crate::provision::canonical_exe());
}

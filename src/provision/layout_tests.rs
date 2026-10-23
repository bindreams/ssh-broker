use super::*;
use crate::acl::{self, Sid};
use crate::provision::config::Config;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::core::{PCWSTR, PWSTR};

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

fn config_for(user: &str) -> String {
    Config {
        target_user: user.into(),
    }
    .to_toml()
    .unwrap()
}

fn plant_config(base: &TempBase, user: &str) {
    std::fs::write(base.0.join("config.toml"), config_for(user)).unwrap();
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

    assert!(reason.contains("owner"), "{reason}");
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

// The saved account -----------------------------------------------------------------------

#[test]
fn saved_user_is_none_when_there_is_no_config() {
    let base = TempBase::existing("saved-none");
    let layout = base.layout();

    assert_eq!(saved_user(&forged(&layout)).unwrap(), None);
}

#[test]
fn saved_user_reads_the_config() {
    let base = TempBase::existing("saved");
    plant_config(&base, "saved-user");
    let layout = base.layout();

    assert_eq!(saved_user(&forged(&layout)).unwrap().as_deref(), Some("saved-user"));
}

#[test]
fn saved_user_is_an_error_for_a_malformed_config() {
    let base = TempBase::existing("saved-bad");
    std::fs::write(base.0.join("config.toml"), "target_user = [").unwrap();
    let layout = base.layout();

    let err = format!("{:#}", saved_user(&forged(&layout)).unwrap_err());

    assert!(err.contains("config.toml"), "{err}");
}

#[test]
fn saved_user_is_an_error_for_a_config_it_cannot_read() {
    let base = TempBase::existing("saved-unreadable");
    std::fs::create_dir(base.0.join("config.toml")).unwrap();
    let layout = base.layout();

    let err = format!("{:#}", saved_user(&forged(&layout)).unwrap_err());

    assert!(err.contains("config.toml"), "{err}");
}

#[test]
fn resolve_user_prefers_cli_then_the_saved_config_then_the_interactive_user() {
    let base = TempBase::existing("resolve");
    let layout = base.layout();
    let trusted = forged(&layout);
    assert_eq!(resolve_user(&trusted, None, Some("me")).unwrap(), "me");

    plant_config(&base, "saved-user");
    assert_eq!(resolve_user(&trusted, None, Some("me")).unwrap(), "saved-user");
    assert_eq!(
        resolve_user(&trusted, Some("cli-user"), Some("me")).unwrap(),
        "cli-user"
    );
}

#[test]
fn resolve_user_fails_on_a_malformed_config_instead_of_falling_back() {
    let base = TempBase::existing("resolve-bad");
    std::fs::write(base.0.join("config.toml"), "target_user = [").unwrap();
    let layout = base.layout();

    let err = format!("{:#}", resolve_user(&forged(&layout), None, Some("me")).unwrap_err());

    assert!(err.contains("config.toml"), "{err}");
    assert!(err.contains("--user"), "the error says how to recover: {err}");
}

#[test]
fn resolve_user_ignores_a_malformed_config_when_the_cli_names_the_user() {
    let base = TempBase::existing("resolve-bad-cli");
    std::fs::write(base.0.join("config.toml"), "target_user = [").unwrap();
    let layout = base.layout();

    assert_eq!(
        resolve_user(&forged(&layout), Some("cli-user"), Some("me")).unwrap(),
        "cli-user"
    );
}

#[test]
fn resolve_user_reads_the_config_for_an_empty_cli_user() {
    let base = TempBase::existing("resolve-bad-empty-cli");
    std::fs::write(base.0.join("config.toml"), "target_user = [").unwrap();
    let layout = base.layout();

    assert!(resolve_user(&forged(&layout), Some(""), Some("me")).is_err());
}

// The apply sequence ----------------------------------------------------------------------

#[test]
fn prepare_refuses_a_hostile_base_before_it_reads_its_config() {
    let base = TempBase::existing("prepare-hostile");
    plant_config(&base, "planted-user");

    // Read first, the planted config would supply the user and get past the lookup's
    // "cannot resolve" failure; it must fail at the base instead.
    let err = format!(
        "{:#}",
        prepare(&base.layout(), &std::env::current_exe().unwrap(), None, None).expect_err("hostile base")
    );

    assert!(err.contains("cannot be trusted"), "{err}");
    assert_eq!(names_in(&base.0), ["config.toml"], "nothing may be written into it");
}

/// Elevated (CI only): `prepare` creates the base.
#[test]
fn prepare_resolves_the_user_before_it_writes_anything() {
    let base = TempBase::new("prepare-no-user");
    let layout = base.layout();

    let err = format!(
        "{:#}",
        prepare(&layout, &std::env::current_exe().unwrap(), None, None).expect_err("no user to resolve")
    );

    assert!(err.contains("cannot resolve the target user"), "{err}");
    assert!(layout.base.is_dir(), "the base itself is made first");
    assert!(
        names_in(&layout.base).is_empty(),
        "nothing may be written before the user resolves"
    );
}

/// Elevated (CI only): `prepare` creates the base.
#[test]
fn prepare_looks_the_account_up_before_it_writes_anything() {
    let base = TempBase::new("prepare-bad-user");
    let layout = base.layout();

    let err = format!(
        "{:#}",
        prepare(
            &layout,
            &std::env::current_exe().unwrap(),
            Some("no-such-account-for-ssh-broker-tests"),
            None
        )
        .expect_err("no such account")
    );

    assert!(err.contains("no-such-account-for-ssh-broker-tests"), "{err}");
    assert!(
        names_in(&layout.base).is_empty(),
        "nothing may be written before the lookup"
    );
}

/// Elevated (CI only): `ensure_base` creates the base.
#[test]
fn populate_builds_a_verified_layout() {
    let base = TempBase::new("populate");
    let layout = base.layout();
    let me = Sid::current_user().unwrap();
    let trusted = ensure_base(&layout).unwrap();

    let exe = populate(&trusted, &std::env::current_exe().unwrap(), "layout-test-user", &me).unwrap();

    assert_eq!(exe, layout.canonical_exe());
    assert!(exe.is_file());
    assert!(acl::verify_install_dir_acl(&layout.base).unwrap());
    assert!(acl::verify_dir_acl(&layout.socket_dir(), &me).unwrap());
    assert_eq!(saved_user(&trusted).unwrap().as_deref(), Some("layout-test-user"));

    // logs\ carries exactly the install directory's DACL, inherited: no extra access, none missing.
    assert!(layout.logs_dir().is_dir());
    assert_eq!(
        aces(&dacl_sddl(&layout.logs_dir())),
        [
            ("A", "OICIID", FILE_ALL, "SY"),
            ("A", "OICIID", FILE_ALL, "BA"),
            ("A", "OICIID", FILE_READ_EXECUTE, "BU"),
        ]
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

#[test]
fn socket_dir_row_does_not_read_the_config_of_an_untrusted_base() {
    let base = TempBase::existing("row-untrusted");
    plant_config(&base, "planted-user");

    let row = socket_dir_row(&Err("planted".into()));

    assert!(!row.pass);
    assert!(row.detail.contains("untrusted"), "{}", row.detail);
    assert!(
        !row.detail.contains("planted-user"),
        "the planted config must not be read: {}",
        row.detail
    );
}

#[test]
fn socket_dir_row_fails_without_a_saved_account() {
    let base = TempBase::existing("row-none");
    let layout = base.layout();

    let row = socket_dir_row(&Ok(forged(&layout)));

    assert!(!row.pass);
    assert!(row.detail.contains("no config target_user"), "{}", row.detail);
}

#[test]
fn socket_dir_row_names_an_account_that_does_not_resolve() {
    let base = TempBase::existing("row-lookup");
    plant_config(&base, "no-such-account-for-ssh-broker-tests");
    let layout = base.layout();

    let row = socket_dir_row(&Ok(forged(&layout)));

    assert!(!row.pass);
    assert!(
        row.detail.contains("no-such-account-for-ssh-broker-tests"),
        "{}",
        row.detail
    );
}

#[test]
fn socket_dir_row_passes_for_a_hardened_socket_dir_of_the_saved_account() {
    let base = TempBase::existing("row-ok");
    let layout = base.layout();
    let user = std::env::var("USERNAME").expect("USERNAME is set for an interactive user");
    plant_config(&base, &user);
    std::fs::create_dir(layout.socket_dir()).unwrap();
    acl::harden_dir(&layout.socket_dir(), &Sid::current_user().unwrap()).unwrap();

    let row = socket_dir_row(&Ok(forged(&layout)));

    assert!(row.pass, "{}", row.detail);

    // The same account with an unhardened socket dir fails.
    let other = TempBase::existing("row-unhardened");
    plant_config(&other, &user);
    std::fs::create_dir(other.layout().socket_dir()).unwrap();
    assert!(!socket_dir_row(&Ok(forged(&other.layout()))).pass);
}

// Reading a DACL by SID -------------------------------------------------------------------

const FILE_ALL: u32 = 0x1f_01ff;
const FILE_READ_EXECUTE: u32 = 0x12_00a9;

/// The DACL of `path` as an SDDL string (`D:AI(A;OICIID;FA;;;SY)...`). Well-known SIDs print as
/// two-letter aliases, so this does not depend on the display language.
fn dacl_sddl(path: &Path) -> String {
    let path_w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap();
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .unwrap();
        let sddl = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut core::ffi::c_void)));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        sddl
    }
}

/// `(type, flags, access mask, trustee)` of each ACE in an SDDL DACL, in order.
fn aces(sddl: &str) -> Vec<(&str, &str, u32, &str)> {
    sddl.split('(')
        .skip(1)
        .map(|ace| {
            let f: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
            let mask = match f[2] {
                "FA" => FILE_ALL,
                "FRFX" => FILE_READ_EXECUTE,
                hex => u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("unrecognised rights {hex:?} in {sddl}")),
            };
            (f[0], f[1], mask, f[5])
        })
        .collect()
}

#[test]
fn aces_reads_an_sddl_dacl() {
    assert_eq!(
        aces("D:AI(A;OICIID;FA;;;SY)(A;OICIID;FRFX;;;BA)(A;;0x1200a9;;;BU)"),
        [
            ("A", "OICIID", FILE_ALL, "SY"),
            ("A", "OICIID", FILE_READ_EXECUTE, "BA"),
            ("A", "", FILE_READ_EXECUTE, "BU"),
        ]
    );
}

#[test]
fn dacl_sddl_reports_the_inherited_aces_of_a_plain_directory() {
    let base = TempBase::existing("sddl");
    let sddl = dacl_sddl(&base.0);

    let entries = aces(&sddl);
    assert!(!entries.is_empty(), "{sddl}");
    assert!(
        entries
            .iter()
            .all(|(kind, flags, _, _)| *kind == "A" && flags.contains("ID")),
        "a plain temp directory inherits every ACE: {sddl}"
    );
}

/// `canonical_exe` is the path the cfg-free pins (`sshd_reads_the_flag_for_the_path_apply_registers`)
/// assert on, so it must be the one `apply` installs to and registers.
#[test]
fn the_production_layout_installs_the_exe_that_the_cfg_free_pins_assert_on() {
    assert_eq!(Layout::production().canonical_exe(), crate::provision::canonical_exe());
}

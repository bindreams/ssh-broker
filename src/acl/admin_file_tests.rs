use super::*;
use crate::acl::acl_tests::in_memory;
use std::sync::atomic::{AtomicUsize, Ordering};

fn problem_of(sddl: &str) -> Option<String> {
    problem_from_security(&in_memory(sddl))
}

/// A path for a file under the temp dir that is removed on drop.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(tag: &str) -> TempFile {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TempFile(std::env::temp_dir().join(format!("sb-admin-file-{tag}-{}-{n}", std::process::id())))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// the policy -----

#[test]
fn the_policy_accepts_exactly_system_and_administrators_with_full_control() {
    assert_eq!(problem_of(ADMIN_FILE_SDDL), None);
}

#[test]
fn a_users_read_grant_is_refused() {
    // What the install directory hands every file made in it: the grant that lets a standard user
    // open the file and lock it.
    let problem = problem_of("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)");
    assert!(problem.is_some_and(|p| p.contains("ACL")));
}

#[test]
fn an_inherited_dacl_is_refused() {
    assert!(problem_of("O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)").is_some(), "not protected");
    assert!(
        problem_of("O:BAD:P(A;ID;FA;;;SY)(A;ID;FA;;;BA)").is_some(),
        "inherited ACEs"
    );
}

#[test]
fn a_missing_or_reduced_grant_is_refused() {
    assert!(problem_of("O:BAD:P(A;;FA;;;SY)").is_some(), "no Administrators");
    assert!(
        problem_of("O:BAD:P(A;;FA;;;SY)(A;;FRFX;;;BA)").is_some(),
        "reduced mask"
    );
}

#[test]
fn a_deny_or_a_duplicate_ace_is_refused() {
    assert!(problem_of("O:BAD:P(D;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)").is_some());
    assert!(problem_of("O:BAD:P(A;;FA;;;SY)(A;;FA;;;SY)(A;;FA;;;BA)").is_some());
}

#[test]
fn an_owner_who_is_not_trusted_is_refused_and_named() {
    // The owner can always rewrite the DACL, so an exact ACL under a standard user's ownership
    // protects nothing.
    let problem = problem_of("O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)").expect("a Users-owned file");
    assert!(problem.contains("owner"), "{problem}");
}

#[test]
fn a_system_owner_is_accepted() {
    assert_eq!(problem_of("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"), None);
}

// the file -----

/// Elevated (CI only): the owner is set at creation, which a filtered token cannot do.
#[test]
fn a_file_the_function_makes_is_born_with_the_policy() {
    crate::test_support::assert_elevated();
    let file = TempFile::new("born");
    ensure_admin_only_file(&file.0).unwrap();
    assert!(file.0.is_file());
    assert_eq!(admin_only_file_problem(&file.0).unwrap(), None);
}

#[test]
fn a_file_the_function_made_is_accepted_again_unchanged() {
    crate::test_support::assert_elevated();
    let file = TempFile::new("again");
    ensure_admin_only_file(&file.0).unwrap();
    std::fs::write(&file.0, b"kept").unwrap();
    ensure_admin_only_file(&file.0).unwrap();
    assert_eq!(std::fs::read(&file.0).unwrap(), b"kept");
}

#[test]
fn a_file_with_the_default_acl_is_refused_by_name_and_left_alone() {
    let file = TempFile::new("default");
    std::fs::write(&file.0, b"somebody else's").unwrap();

    let err = format!("{:#}", ensure_admin_only_file(&file.0).unwrap_err());

    assert!(err.contains(&file.0.display().to_string()), "names the file: {err}");
    assert!(err.contains("remove"), "says how to fix it: {err}");
    assert_eq!(std::fs::read(&file.0).unwrap(), b"somebody else's");
}

#[test]
fn a_directory_in_its_place_is_refused() {
    let dir = TempFile::new("dir");
    std::fs::create_dir(&dir.0).unwrap();
    let err = format!("{:#}", ensure_admin_only_file(&dir.0).unwrap_err());
    std::fs::remove_dir(&dir.0).unwrap();
    assert!(err.contains("directory"), "{err}");
}

#[test]
fn a_create_that_fails_for_another_reason_than_rights_does_not_blame_the_rights() {
    use windows::Win32::Foundation::ERROR_PATH_NOT_FOUND;
    // The parent directory is missing: not elevated or not, the create fails the same way.
    let missing = TempFile::new("no-parent").0.join("child");
    let error = ensure_admin_only_file(&missing).unwrap_err();
    let err = format!("{error:#}");
    assert!(err.contains(&missing.display().to_string()), "names the file: {err}");
    assert!(
        !err.contains("elevated administrator"),
        "sends the user to elevate for a missing directory: {err}"
    );
    // The code, not the OS's message, which is in the machine's language.
    let os = error
        .downcast_ref::<windows::core::Error>()
        .unwrap_or_else(|| panic!("keeps the OS error: {err}"));
    assert_eq!(
        os.code(),
        HRESULT::from_win32(ERROR_PATH_NOT_FOUND.0),
        "gives the OS error: {err}"
    );
}

#[test]
fn a_create_refused_for_rights_says_to_elevate() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER};
    for code in [ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER] {
        let error = windows::core::Error::from(HRESULT::from_win32(code.0));
        let text = format!("{:#}", create_failure(error, Path::new(r"C:\x\apply.lock")));
        assert!(text.contains("elevated administrator"), "{code:?}: {text}");
    }
}

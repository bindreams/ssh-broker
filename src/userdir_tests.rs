//! Tests for the current user's profile and socket location.
//!
//! Anything that needs a second account or elevation lives in `tests/user_isolation_windows.rs`.
use super::*;
use crate::winutil::own_token;
use std::path::PathBuf;

#[test]
fn current_profile_matches_userprofile_of_this_process() {
    let profile = profile_dir_of_token(own_token().unwrap().0).unwrap();
    let env = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE is set for a test run"));
    assert_eq!(
        profile.to_string_lossy().to_lowercase(),
        env.to_string_lossy().to_lowercase()
    );
}

#[test]
fn current_socket_location_lies_inside_the_profile() {
    let profile = profile_dir_of_token(own_token().unwrap().0).unwrap();
    let loc = current_socket_location().unwrap();
    assert!(loc.path().starts_with(&profile));
    assert!(loc.path().ends_with(r"AppData\Local\ssh-broker\agent.sock"));
}

#[test]
fn current_socket_location_fits_sockaddr_un() {
    let loc = current_socket_location().unwrap();
    assert!(crate::afunix::unix_addr(loc.path()).is_ok());
}

#[test]
fn profile_dir_of_token_rejects_an_invalid_handle_with_the_windows_error() {
    let err = profile_dir_of_token(HANDLE::default()).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("GetUserProfileDirectoryW"), "{text}");
    assert!(err.downcast_ref::<NoProfile>().is_none(), "{text}");
}

/// A required length of 0 with `ERROR_INSUFFICIENT_BUFFER` is "no profile yet" (measured: a
/// never-logged-on account gets 0x8007007a with length 0, an account with a profile the same error
/// with a length). Any other failure that leaves the length 0 is not.
#[test]
fn only_an_insufficient_buffer_with_no_length_is_no_profile() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER};
    let insufficient = windows::core::Error::from(windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0));
    let denied = windows::core::Error::from(windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0));

    let no_profile = probe_failure(&insufficient, 0).unwrap_err();
    assert!(no_profile.downcast_ref::<NoProfile>().is_some(), "{no_profile:#}");

    let other = probe_failure(&denied, 0).unwrap_err();
    assert!(other.downcast_ref::<NoProfile>().is_none(), "{other:#}");
    assert!(format!("{other:#}").contains("GetUserProfileDirectoryW"), "{other:#}");

    assert_eq!(
        probe_failure(&insufficient, 42).unwrap(),
        42,
        "a length is the size to read"
    );
    assert_eq!(probe_failure(&denied, 42).unwrap(), 42);
}

#[test]
fn for_profile_limit_agrees_with_unix_addr() {
    // Pins `MAX_SOCKET_PATH_BYTES` to what `socket2` accepts on this platform.
    let profile_named = |name: &str| PathBuf::from(format!(r"C:\Users\{name}"));
    let fixed = crate::socket_loc::for_profile(&profile_named("x"))
        .unwrap()
        .path()
        .as_os_str()
        .len();
    for bytes in 105..=109 {
        let profile = profile_named(&"x".repeat(1 + bytes - fixed));
        let location = crate::socket_loc::for_profile(&profile);
        let path = profile
            .join("AppData")
            .join("Local")
            .join(crate::socket_loc::SOCKET_DIR_NAME)
            .join(crate::socket_loc::SOCKET_FILE_NAME);
        assert_eq!(
            location.is_ok(),
            crate::afunix::unix_addr(&path).is_ok(),
            "at {bytes} bytes"
        );
    }
}

// Re-run as a child with a decoy environment -----

const CHILD_FLAG: &str = "SSH_BROKER_USERDIR_TEST_CHILD";
const DECOY_PROFILE: &str = r"C:\decoy\profile";

/// Child half of [`current_socket_location_ignores_decoy_environment`], started only by it. Knows
/// it is the child from [`CHILD_FLAG`] and panics without it, so a bare `--ignored` run is not a
/// pass. Prints the location it resolves, after checking that the decoy reached it; the parent
/// fails when the line is missing.
#[test]
#[ignore = "run as a child of current_socket_location_ignores_decoy_environment"]
fn child_prints_its_socket_location() {
    assert!(
        std::env::var_os(CHILD_FLAG).is_some(),
        "this is a child half; its parent starts it with {CHILD_FLAG} set"
    );
    assert_eq!(
        std::env::var("USERPROFILE").as_deref(),
        Ok(DECOY_PROFILE),
        "the decoy environment did not reach the child"
    );
    let loc = current_socket_location().unwrap();
    println!("LOCATION={}", loc.path().display());
}

#[test]
fn current_socket_location_ignores_decoy_environment() {
    // The environment is the caller's to set; the token is not. A resolver that read
    // %USERPROFILE% or %LOCALAPPDATA% would follow the decoy into another account's folder.
    let expected = current_socket_location().unwrap().path().to_path_buf();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "userdir::userdir_tests::child_prints_its_socket_location",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_FLAG, "1")
        .env("USERPROFILE", DECOY_PROFILE)
        .env("LOCALAPPDATA", r"C:\decoy\profile\AppData\Local")
        .env("APPDATA", r"C:\decoy\profile\AppData\Roaming")
        .env("HOMEDRIVE", "C:")
        .env("HOMEPATH", r"\decoy\profile")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("LOCATION="))
        .unwrap_or_else(|| panic!("the child printed no location (it did not run?): {stdout}"));
    assert_eq!(PathBuf::from(line), expected);
}

// ensure_socket_dir ---------------------------------------------------------------------

use crate::acl::{self, Sid};
use crate::test_support::{FILE_ALL, TempProfile, aces, dacl_sddl};
use std::path::Path;

fn me() -> Sid {
    Sid::current_user().unwrap()
}

#[test]
fn ensure_socket_dir_creates_a_dir_that_verifies() {
    let profile = TempProfile::new("create");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(loc.dir(), &me()).unwrap());
}

#[test]
fn ensure_socket_dir_is_idempotent() {
    let profile = TempProfile::new("idem");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(loc.dir(), &me()).unwrap());
    assert!(loc.lock_path().is_file(), "what was inside is left alone");
}

#[test]
fn ensure_socket_dir_refuses_a_dir_widened_with_an_everyone_ace_and_leaves_it() {
    let profile = TempProfile::new("widened");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let status = std::process::Command::new("icacls")
        .arg(loc.dir())
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!acl::verify_dir_acl(loc.dir(), &me()).unwrap(), "control: widened");
    let before = crate::test_support::tree_state(&profile.0);

    let err = format!("{:#}", ensure_socket_dir(&loc, &me()).unwrap_err());

    assert!(err.contains(&loc.dir().display().to_string()), "{err}");
    assert!(err.contains("remove"), "{err}");
    assert_eq!(crate::test_support::tree_state(&profile.0), before, "left as it was");
}

#[test]
fn ensure_socket_dir_does_not_create_a_missing_profile() {
    let profile = TempProfile::new("missing");
    std::fs::remove_dir_all(profile.0.join("AppData")).unwrap();
    let loc = profile.location();
    assert!(ensure_socket_dir(&loc, &me()).is_err());
    assert!(!profile.0.join("AppData").exists(), "nothing was invented");
}

#[test]
fn ensure_socket_dir_refuses_a_junction_at_the_dir() {
    let profile = TempProfile::new("junction");
    let loc = profile.location();
    let target = profile.0.join("elsewhere");
    std::fs::create_dir(&target).unwrap();
    let before = dacl_sddl(&target);
    let out = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(loc.dir())
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mklink /J: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let err = format!("{:#}", ensure_socket_dir(&loc, &me()).unwrap_err());
    assert!(err.contains("reparse point"), "{err}");
    assert_eq!(dacl_sddl(&target), before, "the junction target was not touched");

    std::fs::remove_dir(loc.dir()).unwrap();
}

#[test]
fn ensure_socket_dir_refuses_a_file_at_the_dir() {
    let profile = TempProfile::new("file");
    let loc = profile.location();
    std::fs::write(loc.dir(), "x").unwrap();
    let err = format!("{:#}", ensure_socket_dir(&loc, &me()).unwrap_err());
    assert!(err.contains("not a directory"), "{err}");
    assert_eq!(std::fs::read_to_string(loc.dir()).unwrap(), "x");
}

/// The three ACEs a private directory carries, by SDDL alias, as `(type, mask, trustee)`.
fn trustees(path: &Path) -> Vec<(String, u32, String)> {
    let sddl = dacl_sddl(path);
    let mut out: Vec<_> = aces(&sddl)
        .into_iter()
        .map(|(kind, _, mask, who)| (kind.to_owned(), mask, who.to_owned()))
        .collect();
    out.sort();
    out
}

#[test]
fn ensure_socket_dir_acl_is_exactly_user_system_administrators() {
    let profile = TempProfile::new("exact");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let sddl = dacl_sddl(loc.dir());
    assert!(sddl.starts_with("D:P"), "protected: {sddl}");
    let list = trustees(loc.dir());
    assert_eq!(list.len(), 3, "{sddl}");
    assert!(
        list.iter().all(|(kind, mask, _)| kind == "A" && *mask == FILE_ALL),
        "{sddl}"
    );
    for alias in ["SY", "BA"] {
        assert!(list.iter().any(|(_, _, who)| who == alias), "{alias} in {sddl}");
    }
    assert!(!sddl.contains("ID;"), "nothing is inherited: {sddl}");
}

#[test]
fn ensure_socket_dir_creates_a_logs_dir_with_the_same_exact_acl() {
    let profile = TempProfile::new("logs");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(loc.logs_dir().is_dir());
    assert!(acl::verify_file_acl(&loc.logs_dir(), &me()).unwrap());
    assert_eq!(trustees(&loc.logs_dir()), trustees(loc.dir()));
}

#[test]
fn ensure_socket_dir_gives_what_it_makes_inside_exactly_the_three_aces() {
    let profile = TempProfile::new("born");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    assert!(acl::verify_file_acl(&loc.lock_path(), &me()).unwrap());
    assert_eq!(trustees(&loc.lock_path()), trustees(loc.dir()));
}

/// An ACL change on `logs` alone (a user, a backup tool) costs the log and nothing else.
#[test]
fn a_refused_logs_folder_leaves_the_socket_folder_serving() {
    let profile = TempProfile::new("logs-ref");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    crate::test_support::widen(&loc.logs_dir());
    let before = tree_state(&profile.0);

    let folder = open_socket_dir(&loc, &me()).expect("the socket folder is exact");

    let err = format!("{:#}", folder.logs.as_ref().err().expect("logs is refused"));
    assert!(err.contains(&loc.logs_dir().display().to_string()), "{err}");
    assert!(err.contains("remove"), "{err}");
    assert_eq!(folder.dir.path(), loc.dir());
    assert_eq!(tree_state(&profile.0), before, "left as it was");
}

#[test]
fn a_refused_socket_folder_is_still_refused_as_a_whole() {
    let profile = TempProfile::new("dir-refused");
    let loc = profile.location();
    std::fs::write(loc.dir(), "x").unwrap();
    assert!(open_socket_dir(&loc, &me()).is_err());
}

// A link above the folder ----------------------------------------------------------------

use crate::test_support::{junction, tree_state};

/// A stand-in for a folder the elevated token could re-own (the install directory is one): a real
/// `ssh-broker` folder the user owns, not hardened, with a file inside, under `outside`'s
/// `AppData\Local`.
fn outside_folder(tag: &str) -> TempProfile {
    let outside = TempProfile::new(tag);
    let folder = outside.location().dir().to_path_buf();
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("note.txt"), "x").unwrap();
    outside
}

/// Replace `link_at` (below the profile) with a junction to `target`.
fn link_in_place_of(profile: &TempProfile, link_at: &str, target: &Path) {
    let link = profile.0.join(link_at);
    std::fs::remove_dir_all(&link).unwrap();
    junction(&link, target);
}

/// `ensure_socket_dir` with a junction at `link_at` (below the profile) that leads into `outside`.
/// Nothing outside the profile may change, and the folder is refused.
fn refuses_a_junction_above_the_folder(link_at: &str) {
    let profile = TempProfile::new("up");
    let outside = outside_folder("up-out");
    let before = tree_state(&outside.0);
    link_in_place_of(&profile, link_at, &outside.0.join(link_at));

    let result = ensure_socket_dir(&profile.location(), &me());

    assert_eq!(
        tree_state(&outside.0),
        before,
        "a junction at {link_at}: something outside the profile was changed (result: {result:?})"
    );
    assert!(result.is_err(), "a junction at {link_at} must be refused");
}

/// Reproduces the by-path repair of the private folder: a junction above the folder, which a
/// process of the same account at lower integrity can make, is followed, so the folder that is
/// checked and re-ACLed is not in the profile. Fails until the folder is reached by handle.
#[test]
fn ensure_socket_dir_changes_nothing_outside_the_profile_when_local_is_a_junction() {
    refuses_a_junction_above_the_folder(r"AppData\Local");
}

#[test]
fn ensure_socket_dir_changes_nothing_outside_the_profile_when_appdata_is_a_junction() {
    refuses_a_junction_above_the_folder("AppData");
}

// open_existing_socket_dir -----

/// What the elevated shim does to look at the folder: it must find a real folder, say "none yet"
/// for one that is not there, refuse a link, and in no case make or change anything.
#[test]
fn an_existing_folder_is_opened_and_left_as_it_is() {
    let profile = TempProfile::new("look");
    ensure_socket_dir(&profile.location(), &me()).unwrap();
    std::fs::write(profile.location().lock_path(), "").unwrap();
    let before = tree_state(&profile.0);

    let dir = open_existing_socket_dir(&profile.location()).unwrap().unwrap();

    assert_eq!(dir.path(), profile.location().dir());
    assert_eq!(tree_state(&profile.0), before);
}

#[test]
fn a_folder_that_is_not_there_yet_is_none_at_every_level_and_nothing_is_made() {
    // The stand-in profile has `AppData\Local` and no `ssh-broker`: the first case.
    for missing in [r"AppData\Local\ssh-broker", r"AppData\Local", "AppData"] {
        let profile = TempProfile::new("none");
        if missing != r"AppData\Local\ssh-broker" {
            std::fs::remove_dir_all(profile.0.join(missing)).unwrap();
        }
        assert!(
            open_existing_socket_dir(&profile.location()).unwrap().is_none(),
            "nothing at {missing}"
        );
        assert!(!profile.0.join(r"AppData\Local\ssh-broker").exists(), "{missing}: made");
    }
}

#[test]
fn a_profile_directory_that_is_not_there_is_none() {
    let gone = TempProfile::new("none-gone");
    let loc = gone.location();
    drop(gone);
    assert!(open_existing_socket_dir(&loc).unwrap().is_none());
}

#[test]
fn a_link_at_any_level_is_refused_and_nothing_outside_is_made_or_changed() {
    for link_at in ["AppData", r"AppData\Local", r"AppData\Local\ssh-broker"] {
        let profile = TempProfile::new("looklink");
        let outside = outside_folder("looklink-out");
        std::fs::write(outside.location().lock_path(), "").unwrap();
        let before = tree_state(&outside.0);
        std::fs::create_dir_all(profile.0.join(r"AppData\Local\ssh-broker")).unwrap();
        link_in_place_of(&profile, link_at, &outside.0.join(link_at));

        let err = open_existing_socket_dir(&profile.location())
            .err()
            .unwrap_or_else(|| panic!("a junction at {link_at} was not refused"));

        assert!(format!("{err:#}").contains("reparse point"), "{err:#}");
        assert_eq!(tree_state(&outside.0), before, "a junction at {link_at}");
    }
}

// The pin -----

/// The OS error of renaming `from` to `to` in this process, or `None` if it worked.
fn rename_error(from: &Path, to: &Path) -> Option<i32> {
    std::fs::rename(from, to).err().map(|e| e.raw_os_error().unwrap_or(-1))
}

/// The folders of the walk, from the one nearest the profile directory.
fn walked_folders(loc: &SocketLocation) -> [PathBuf; 4] {
    let local = loc.dir().parent().unwrap().to_path_buf();
    [
        local.parent().unwrap().to_path_buf(),
        local,
        loc.dir().to_path_buf(),
        loc.logs_dir(),
    ]
}

/// While a walk's folders are held, none of them can be renamed or removed by anyone else: the path
/// then names the folders held. Once they are dropped, they can.
fn a_held_walk_pins_every_folder_of_it(tag: &str, walk: impl Fn(&SocketLocation, &Sid) -> anyhow::Result<SocketDir>) {
    const SHARING_VIOLATION: i32 = 32;
    let profile = TempProfile::new(tag);
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let folders = walk(&loc, &me()).unwrap();

    for folder in walked_folders(&loc) {
        let aside = folder.with_file_name("aside");
        let error = rename_error(&folder, &aside);
        assert!(
            error.is_some(),
            "{} was renamed while the walk held it",
            folder.display()
        );
        assert!(!aside.exists(), "{} moved", folder.display());
    }
    // The ones the walk opened itself are refused for sharing, which is what stops a swap.
    for folder in &walked_folders(&loc)[1..] {
        let aside = folder.with_file_name("aside");
        assert_eq!(
            rename_error(folder, &aside),
            Some(SHARING_VIOLATION),
            "{}",
            folder.display()
        );
    }

    drop(folders);
    for folder in walked_folders(&loc).iter().rev() {
        let aside = folder.with_file_name("aside");
        assert_eq!(
            rename_error(folder, &aside),
            None,
            "{} cannot be renamed once the walk lets go",
            folder.display()
        );
        std::fs::rename(&aside, folder).unwrap();
    }
}

#[test]
fn a_held_making_walk_pins_every_folder_of_it() {
    a_held_walk_pins_every_folder_of_it("pin-make", open_socket_dir);
}

#[test]
fn a_held_looking_walk_pins_every_folder_of_it() {
    a_held_walk_pins_every_folder_of_it("pin-look", inspect_socket_dir);
}

/// Open `dir` with delete access, as a program that is about to delete or rename it does, and
/// share everything.
fn hold_for_deletion(dir: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .unwrap_or_else(|e| panic!("hold {} for deletion: {e}", dir.display()))
}

/// Stated limit 6: another program that holds `AppData` or `Local` open for deletion or renaming
/// makes the walk refuse, in the words of the limit and with the folder named. It does not wait for
/// the holder: the call returns while the holder still holds.
#[test]
fn a_folder_held_open_for_deletion_refuses_the_walk_with_the_limit_s_sentence() {
    for (held, which) in [(0, "AppData"), (1, "Local")] {
        for walk in [open_socket_dir, inspect_socket_dir] {
            let profile = TempProfile::new("held");
            let loc = profile.location();
            let folder = walked_folders(&loc)[held].clone();
            let holder = hold_for_deletion(&folder);

            let err = walk(&loc, &me())
                .err()
                .unwrap_or_else(|| panic!("{which} was held and the walk went on"));

            let text = format!("{err:#}");
            assert!(err.root_cause().is::<acl::Refused>(), "{which}: {text}");
            assert!(text.contains(&folder.display().to_string()), "{which}: {text}");
            assert!(
                text.contains("another program is deleting or renaming it"),
                "{which}: {text}"
            );
            drop(holder);
        }
    }
}

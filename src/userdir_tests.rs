//! Tests for the current user's profile and socket location.
//!
//! Anything that needs a second account or elevation lives in `tests/user_isolation_windows.rs`.
use super::*;
use crate::account::{INTEGRITY_HIGH, INTEGRITY_LOW, INTEGRITY_MEDIUM, integrity_of};
use crate::socket_loc::Integrity;
use crate::test_support::{assert_elevated, own_token_at};
use crate::winutil::own_token;
use std::path::PathBuf;

/// The integrity level of this process by the same rule the product uses, read here through the token's
/// integrity level and not through `userdir`.
fn integrity_of_this_process() -> Integrity {
    if integrity_of(own_token().unwrap().0).unwrap() >= INTEGRITY_HIGH {
        Integrity::High
    } else {
        Integrity::Medium
    }
}

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
    let folder = match integrity_of_this_process() {
        Integrity::Medium => "ssh-broker",
        Integrity::High => "ssh-broker-elevated",
    };
    assert!(loc.path().ends_with(format!(r"AppData\Local\{folder}\agent.sock")));
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
    let profile_named = &profile_named;
    for integrity in [Integrity::Medium, Integrity::High] {
        let fixed = crate::socket_loc::for_profile(&profile_named("x"), integrity)
            .unwrap()
            .request_path()
            .as_os_str()
            .len();
        for bytes in 105..=109 {
            let profile = profile_named(&"x".repeat(1 + bytes - fixed));
            let location = crate::socket_loc::for_profile(&profile, integrity);
            let path = profile
                .join("AppData")
                .join("Local")
                .join(integrity.dir_name())
                .join(crate::socket_loc::REQUEST_SOCKET_FILE_NAME);
            assert_eq!(
                location.is_ok(),
                crate::afunix::unix_addr(&path).is_ok(),
                "{integrity:?} at {bytes} bytes"
            );
        }
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
    assert!(acl::verify_dir_acl(loc.dir(), &me(), Integrity::Medium).unwrap());
}

#[test]
fn ensure_socket_dir_is_idempotent() {
    let profile = TempProfile::new("idem");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    ensure_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(loc.dir(), &me(), Integrity::Medium).unwrap());
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
    assert!(
        !acl::verify_dir_acl(loc.dir(), &me(), Integrity::Medium).unwrap(),
        "control: widened"
    );
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
    assert!(acl::verify_file_acl(&loc.logs_dir(), &me(), Integrity::Medium).unwrap());
    assert_eq!(trustees(&loc.logs_dir()), trustees(loc.dir()));
}

#[test]
fn ensure_socket_dir_gives_what_it_makes_inside_exactly_the_three_aces() {
    let profile = TempProfile::new("born");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    std::fs::write(loc.lock_path(), "").unwrap();
    assert!(acl::verify_file_acl(&loc.lock_path(), &me(), Integrity::Medium).unwrap());
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

// The hold -----

/// The OS error of renaming `from` to `to` in this process, or `None` if it worked.
fn rename_error(from: &Path, to: &Path) -> Option<i32> {
    std::fs::rename(from, to).err().map(|e| e.raw_os_error().unwrap_or(-1))
}

/// The folders of the walk that are held, or whose open descendant holds them, from the one nearest
/// the profile directory: `AppData`, `Local` and the private folder.
fn held_folders(loc: &SocketLocation) -> [PathBuf; 3] {
    let local = loc.dir().parent().unwrap().to_path_buf();
    [local.parent().unwrap().to_path_buf(), local, loc.dir().to_path_buf()]
}

/// While a walk's `SocketDir` is held the private folder cannot be renamed (a sharing violation) and
/// neither can `Local` or `AppData` (access denied: Windows does not rename a directory with an open
/// descendant), so the path names the folders held. Once it is dropped they can be.
fn a_held_walk_holds_the_private_folder_and_through_it_its_parents(
    tag: &str,
    walk: impl Fn(&SocketLocation, &Sid) -> anyhow::Result<SocketDir>,
) {
    const ACCESS_DENIED: i32 = 5;
    const SHARING_VIOLATION: i32 = 32;
    let profile = TempProfile::new(tag);
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let folders = walk(&loc, &me()).unwrap();

    let [app_data, local, private] = held_folders(&loc);
    for (folder, code) in [
        (&private, SHARING_VIOLATION),
        (&local, ACCESS_DENIED),
        (&app_data, ACCESS_DENIED),
    ] {
        let aside = folder.with_file_name("aside");
        assert_eq!(
            rename_error(folder, &aside),
            Some(code),
            "{} while the walk holds the private folder",
            folder.display()
        );
        assert!(!aside.exists(), "{} moved", folder.display());
    }

    drop(folders);
    for folder in [&private, &local, &app_data] {
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
fn a_held_making_walk_holds_the_private_folder_and_through_it_its_parents() {
    a_held_walk_holds_the_private_folder_and_through_it_its_parents("hold-make", open_socket_dir);
}

#[test]
fn a_held_looking_walk_holds_the_private_folder_and_through_it_its_parents() {
    a_held_walk_holds_the_private_folder_and_through_it_its_parents("hold-look", inspect_socket_dir);
}

use crate::test_support::{hold_for_deletion, hold_without_sharing_read};

/// The walk's opens of `AppData` and `Local` take no part in sharing checks, so a program that holds
/// either one open with the right to delete it does not stop the walk (and the walk does not stop it).
#[test]
fn a_parent_held_open_for_deletion_does_not_stop_the_walk() {
    for (held, which) in [(0, "AppData"), (1, "Local")] {
        for walk in [open_socket_dir, inspect_socket_dir] {
            let profile = TempProfile::new("held-parent");
            let loc = profile.location();
            ensure_socket_dir(&loc, &me()).unwrap();
            let holder = hold_for_deletion(&held_folders(&loc)[held]);

            let walked = walk(&loc, &me());

            assert!(
                walked.is_ok(),
                "{which} was held open for deletion and the walk failed: {:#}",
                walked.err().unwrap()
            );
            drop(holder);
        }
    }
}

/// `logs` is held by nothing: a program that holds it open with the right to delete it, or without
/// sharing read, stops no walk.
#[test]
fn a_logs_folder_held_open_by_another_program_does_not_stop_any_walk() {
    for kind in ["with the right to delete", "without sharing read"] {
        let profile = TempProfile::new("held-logs");
        let loc = profile.location();
        ensure_socket_dir(&loc, &me()).unwrap();
        let holder = match kind {
            "with the right to delete" => hold_for_deletion(&loc.logs_dir()),
            _ => hold_without_sharing_read(&loc.logs_dir()),
        };
        for (name, walk) in every_walk() {
            let walked = walk(&loc, &me());
            assert!(
                walked.is_ok(),
                "{name}: logs was held open {kind} and the walk failed: {:#}",
                walked.err().unwrap()
            );
        }
        drop(holder);
    }
}

/// The walk's handle on `logs` shares everything, so `logs` can be renamed while a `SocketDir` is held.
#[test]
fn logs_can_be_renamed_while_a_walk_is_held() {
    for (tag, walk) in [
        (
            "rn-logs-make",
            open_socket_dir as fn(&SocketLocation, &Sid) -> anyhow::Result<SocketDir>,
        ),
        ("rn-logs-look", inspect_socket_dir),
    ] {
        let profile = TempProfile::new(tag);
        let loc = profile.location();
        ensure_socket_dir(&loc, &me()).unwrap();
        let folders = walk(&loc, &me()).unwrap();
        assert!(folders.logs.is_ok());
        let aside = loc.logs_dir().with_file_name("aside");

        let error = rename_error(&loc.logs_dir(), &aside);

        assert_eq!(error, None, "{tag}: logs was held by the walk");
        drop(folders);
    }
}

/// A parent swapped between the walk's halves is refused, naming `Local`.
#[test]
fn a_parent_swapped_for_a_link_while_the_walk_is_open_is_refused_naming_it() {
    let profile = TempProfile::new("swap");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let parents = open_parents(&loc).unwrap();
    let local = held_folders(&loc)[1].clone();
    let aside = local.with_file_name("Local.aside");
    std::fs::rename(&local, &aside).unwrap();
    junction(&local, &aside);

    let err = hold_and_confirm(&loc, parents, |local| {
        acl::open_existing_private_dir(local, socket_loc::SOCKET_DIR_NAME, Integrity::Medium)
    })
    .err()
    .expect("the swapped Local was accepted");

    assert!(err.root_cause().is::<acl::Refused>(), "{err:#}");
    let text = format!("{err:#}");
    assert!(text.contains(&local.display().to_string()), "{text}");
    assert!(text.contains("reparse point"), "{text}");
}

/// What `hold_and_confirm` says of a stand-in profile whose folders `disturb` has moved after the
/// walk opened `AppData` and `Local` and before it held the private folder.
fn confirm_after(tag: &str, disturb: impl FnOnce(&Path)) -> anyhow::Error {
    let profile = TempProfile::new(tag);
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let parents = open_parents(&loc).unwrap();
    disturb(&profile.0);
    hold_and_confirm(&loc, parents, |local| {
        acl::open_existing_private_dir(local, socket_loc::SOCKET_DIR_NAME, Integrity::Medium)
    })
    .err()
    .expect("the disturbed walk was accepted")
}

/// `Local` leaves `AppData` for another folder of the profile, and a junction to that folder takes
/// `AppData`'s place: by its path `AppData\Local` still leads to the `Local` the walk went through, but
/// `Local` is no longer in the `AppData` the walk went through. The walk says so.
#[test]
fn a_local_that_left_the_appdata_the_walk_went_through_is_refused_even_if_the_path_still_reaches_it() {
    let err = confirm_after("moved-out", |profile| {
        let other = profile.join("Other");
        std::fs::create_dir(&other).unwrap();
        std::fs::rename(profile.join(r"AppData\Local"), other.join("Local")).unwrap();
        std::fs::rename(profile.join("AppData"), profile.join("AppData.aside")).unwrap();
        junction(&profile.join("AppData"), &other);
    });

    assert!(err.root_cause().is::<acl::Refused>(), "{err:#}");
    let text = format!("{err:#}");
    assert!(text.contains(r"AppData\Local"), "{text}");
    assert!(text.contains("was moved"), "{text}");
}

/// `Local`, which the walk went through, is gone from its place when the walk confirms it: a failed
/// confirmation, not "no folder yet", which is what every caller reads `Missing` as. (`AppData` cannot
/// be renamed while the walk holds `Local`, so it is `acl::confirm_dir`'s own test.)
#[test]
fn a_local_renamed_aside_while_the_walk_is_open_is_refused_and_not_missing() {
    let err = confirm_after("aside", |profile| {
        let local = profile.join(r"AppData\Local");
        std::fs::rename(&local, local.with_file_name("aside")).unwrap();
    });

    assert!(err.root_cause().is::<acl::Refused>(), "{err:#}");
    assert!(!err.is::<acl::Missing>(), "reported as no folder yet: {err:#}");
}

type WalkFn = fn(&SocketLocation, &Sid) -> anyhow::Result<()>;

/// The three walks to the private folder, by name, each reduced to whether it got there.
fn every_walk() -> [(&'static str, WalkFn); 3] {
    [
        ("open_socket_dir", |loc, user| open_socket_dir(loc, user).map(drop)),
        ("inspect_socket_dir", |loc, user| {
            inspect_socket_dir(loc, user).map(drop)
        }),
        ("open_existing_socket_dir", |loc, _| {
            open_existing_socket_dir(loc).map(drop)
        }),
    ]
}

/// Another program that holds the private folder open in a way that keeps the broker from holding it:
/// with the right to delete it, or without sharing read. Every walk refuses at once with the stated
/// limit, naming the folder.
#[test]
fn a_private_folder_held_by_another_program_is_refused_at_once_by_every_walk() {
    for kind in ["with the right to delete", "without sharing read"] {
        let profile = TempProfile::new("held-other");
        let loc = profile.location();
        ensure_socket_dir(&loc, &me()).unwrap();
        let holder = match kind {
            "with the right to delete" => hold_for_deletion(loc.dir()),
            _ => hold_without_sharing_read(loc.dir()),
        };
        for (name, walk) in every_walk() {
            let err = walk(&loc, &me()).expect_err(&format!("{name} {kind}: the walk held a folder it cannot hold"));
            assert!(err.root_cause().is::<acl::Refused>(), "{name} {kind}: {err:#}");
            let text = format!("{err:#}");
            assert!(
                text.contains(&crate::offer::text::folder_held(loc.dir())),
                "{name} {kind}: {text}"
            );
        }
        drop(holder);
    }
}

/// A private folder with a deny entry for the right to traverse it cannot be held (holding takes that
/// right; the privilege to bypass traverse checking does not override a deny entry). Every walk refuses it
/// for what is wrong with it, its ACL, and not for a denial it cannot explain.
#[test]
fn a_private_folder_that_denies_traversing_is_refused_for_its_acl_by_every_walk() {
    let profile = TempProfile::new("no-traverse");
    let loc = profile.location();
    ensure_socket_dir(&loc, &me()).unwrap();
    let user = format!("*{}", me().to_sddl().unwrap());
    crate::test_support::icacls(loc.dir(), &["/deny", &format!("{user}:(X)")]);

    let walked: Vec<_> = every_walk()
        .into_iter()
        .map(|(name, walk)| (name, walk(&loc, &me())))
        .collect();
    crate::test_support::icacls(loc.dir(), &["/remove:d", &user]);

    for (name, walked) in walked {
        let err = walked.expect_err(&format!("{name}: a folder that cannot be traversed was accepted"));
        assert!(err.root_cause().is::<acl::Refused>(), "{name}: {err:#}");
        let text = format!("{err:#}");
        assert!(text.contains(&loc.dir().display().to_string()), "{name}: {text}");
        assert!(text.contains("its ACL is not exactly"), "{name}: {text}");
        assert!(!text.contains("denied access to read its ACL"), "{name}: {text}");
    }
}

// the elevated folder -----

#[test]
fn a_token_below_high_gets_the_plain_folder() {
    for level in [INTEGRITY_LOW, INTEGRITY_MEDIUM] {
        let token = own_token_at(level);
        let loc = socket_location_of_token(token.0).unwrap();
        assert_eq!(loc.integrity(), Integrity::Medium, "level {level:#x}");
        assert!(loc.dir().ends_with("ssh-broker"), "level {level:#x}");
    }
}

/// Elevated (CI only): the level of the token alone chooses the folder.
#[test]
fn a_token_at_high_gets_the_elevated_folder() {
    assert_elevated();
    let token = own_token_at(INTEGRITY_HIGH);
    let loc = socket_location_of_token(token.0).unwrap();
    assert_eq!(loc.integrity(), Integrity::High);
    assert!(loc.dir().ends_with("ssh-broker-elevated"));
    assert_eq!(
        current_socket_location().unwrap(),
        loc,
        "the process's own location is its token's"
    );
}

/// Elevated (CI only): the folder is born labelled, and what is made inside it carries the label.
#[test]
fn the_elevated_folder_is_born_labelled_and_so_is_what_is_made_in_it() {
    assert_elevated();
    let profile = TempProfile::new("hb");
    let loc = profile.location_at(Integrity::High);
    let folder = open_socket_dir(&loc, &me()).unwrap();
    assert!(acl::verify_dir_acl(loc.dir(), &me(), Integrity::High).unwrap());
    assert!(folder.logs.is_ok(), "the log folder is made inside it");
    assert!(acl::verify_dir_acl(&loc.logs_dir(), &me(), Integrity::High).unwrap());
    std::fs::write(loc.lock_path(), "").unwrap();
    assert!(acl::verify_file_acl(&loc.lock_path(), &me(), Integrity::High).unwrap());
    drop(folder);
    open_socket_dir(&loc, &me()).expect("an existing labelled folder is accepted");
    inspect_socket_dir(&loc, &me()).expect("and looked at");
}

/// An `ssh-broker-elevated` without the label is refused with the words every
/// refusal uses, and left as it is: the label is never put on a folder that exists.
#[test]
fn an_elevated_folder_without_the_label_is_refused_and_left_as_it_is() {
    let profile = TempProfile::new("hp");
    let loc = profile.location_at(Integrity::High);
    // The plain folder's own walk makes exactly the folder in question, except for its name and label.
    let plain = profile.location_at(Integrity::Medium);
    ensure_socket_dir(&plain, &me()).unwrap();
    std::fs::rename(plain.dir(), loc.dir()).unwrap();
    let before = crate::test_support::tree_state(&profile.0);

    for walk in [open_socket_dir, inspect_socket_dir] {
        let err = format!("{:#}", walk(&loc, &me()).err().expect("refused"));
        assert!(err.contains(&loc.dir().display().to_string()), "{err}");
        assert!(err.contains("High mandatory label"), "{err}");
        assert!(
            err.contains("left as it is: inspect it, remove it, and it is created again"),
            "{err}"
        );
    }
    assert_eq!(crate::test_support::tree_state(&profile.0), before, "left as it was");
    assert!(
        crate::test_support::dacl_sddl(loc.dir()).contains("D:P"),
        "and still the DACL it had"
    );
}

/// `connect` and `connect_request` name the two sockets of the held folder, and each reaches only its own.
#[test]
fn connect_request_reaches_request_sock_and_connect_reaches_agent_sock() {
    let profile = TempProfile::new("rq");
    let loc = profile.location_at(Integrity::Medium);
    let folder = open_socket_dir(&loc, &me()).unwrap();
    let requests = crate::afunix::Listener::bind(&loc.request_path(), Integrity::Medium).unwrap();
    assert!(
        folder.connect().is_err(),
        "nothing listens on agent.sock, and connect does not reach request.sock"
    );
    let _client = folder.connect_request().expect("request.sock has a listener");
    requests.accept().expect("the connection came to request.sock");

    drop(requests);
    let agent = crate::afunix::Listener::bind(loc.path(), Integrity::Medium).unwrap();
    let _client = folder.connect().expect("agent.sock has a listener");
    agent.accept().expect("the connection came to agent.sock");
}

#[test]
fn a_plain_folder_is_judged_as_it_was_and_asks_for_no_label() {
    let profile = TempProfile::new("md-plain");
    let loc = profile.location_at(Integrity::Medium);
    ensure_socket_dir(&loc, &me()).unwrap();
    inspect_socket_dir(&loc, &me()).unwrap();
}

/// The one walk serves both: a High location's walk goes through `AppData` and `Local` to the folder
/// named for it, and a missing folder is the same `Missing` for the look-only caller.
#[test]
fn looking_for_the_elevated_folder_that_is_not_there_finds_it_missing() {
    let profile = TempProfile::new("hn");
    let loc = profile.location_at(Integrity::High);
    let err = inspect_socket_dir(&loc, &me()).err().expect("nothing is there");
    assert!(err.is::<acl::Missing>(), "{err:#}");
    assert!(open_existing_socket_dir(&loc).unwrap().is_none());
    assert!(!loc.dir().exists(), "nothing was made");
}

/// What `walk` asks of each folder it makes or opens, for a location at `integrity`: the name and the
/// level. The folders are plain directories opened as they are, so this runs at any level.
fn walked_at(integrity: Integrity) -> Vec<(String, Integrity)> {
    let profile = crate::test_support::TempProfile::new("wl");
    let loc = profile.location_at(integrity);
    std::fs::create_dir_all(loc.logs_dir()).unwrap();
    let asked = std::cell::RefCell::new(Vec::new());
    let walked = walk(&loc, "look at", |parent, name, _hold, level| {
        asked.borrow_mut().push((name.to_owned(), level));
        acl::open_dir(parent, name)
    })
    .unwrap();
    assert!(walked.logs.is_ok());
    asked.into_inner()
}

#[test]
fn the_walk_judges_the_log_folder_at_the_level_of_the_folder_it_is_in() {
    for (integrity, folder) in [
        (Integrity::Medium, "ssh-broker"),
        (Integrity::High, "ssh-broker-elevated"),
    ] {
        assert_eq!(
            walked_at(integrity),
            [(folder.to_owned(), integrity), ("logs".to_owned(), integrity)],
            "the private folder and its logs are judged at {integrity:?}"
        );
    }
}

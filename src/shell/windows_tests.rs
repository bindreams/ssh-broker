//! Tests for the Windows host. They read file identities and search directories; none starts a process.

use std::path::{Path, PathBuf};

use super::{WindowsHost, find_in};
use crate::shell::Host;
use crate::test_support::TempProfile;

fn system_dir() -> PathBuf {
    WindowsHost
        .system_cmd()
        .unwrap()
        .parent()
        .expect("cmd.exe is in a directory")
        .to_path_buf()
}

fn touch(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"MZ").unwrap();
}

// is_system_cmd -----

#[test]
fn the_built_in_is_cmd_exe_in_the_system_directory() {
    let cmd = WindowsHost.system_cmd().unwrap();
    assert!(cmd.is_absolute(), "{cmd:?}");
    assert!(cmd.is_file(), "{cmd:?}");
    assert!(cmd.ends_with("cmd.exe"), "{cmd:?}");
    assert_eq!(WindowsHost.is_file(&cmd).ok(), Some(true));
    assert!(WindowsHost.is_system_cmd(&cmd).unwrap());
}

#[test]
fn cmd_by_path_in_any_spelling_is_the_system_cmd() {
    let dir = system_dir();
    let mut spellings: Vec<PathBuf> = vec![
        PathBuf::from(WindowsHost.system_cmd().unwrap().to_string_lossy().to_uppercase()),
        PathBuf::from(WindowsHost.system_cmd().unwrap().to_string_lossy().to_lowercase()),
        PathBuf::from(WindowsHost.system_cmd().unwrap().to_string_lossy().replace('\\', "/")),
        dir.join("..").join(dir.file_name().unwrap()).join("cmd.exe"),
        dir.join(".").join("CMD.EXE"),
    ];
    // The 8.3 name, where the volume keeps one.
    spellings.push(short_path(&WindowsHost.system_cmd().unwrap()));
    for path in spellings {
        assert!(WindowsHost.is_system_cmd(&path).unwrap(), "{path:?}");
    }
}

#[test]
fn syswow64_and_a_copy_are_not_the_system_cmd() {
    let wow = dir_sibling("SysWOW64").join("cmd.exe");
    assert_eq!(
        WindowsHost.is_file(&wow).ok(),
        Some(true),
        "{wow:?} is missing: is this a 64-bit Windows?"
    );
    assert!(!WindowsHost.is_system_cmd(&wow).unwrap());

    let temp = TempProfile::new("shell-host-copy");
    let copy = temp.0.join("cmd.exe");
    std::fs::copy(WindowsHost.system_cmd().unwrap(), &copy).unwrap();
    assert!(!WindowsHost.is_system_cmd(&copy).unwrap());
}

#[test]
fn a_path_that_does_not_exist_is_an_error_not_false() {
    let missing = system_dir().join("no-such-cmd.exe");
    assert!(WindowsHost.is_system_cmd(&missing).is_err());
    assert_eq!(WindowsHost.is_file(&missing).ok(), Some(false));
}

/// A directory is not a file, and a path the system cannot examine is an error with its reason,
/// not "missing".
#[test]
fn is_file_tells_a_directory_from_a_failure() {
    assert_eq!(WindowsHost.is_file(&system_dir()).ok(), Some(false));
    let error = WindowsHost
        .is_file(Path::new("C:\\a\0b"))
        .expect_err("a name with a NUL cannot be examined");
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn find_program_in_searches_the_given_directories_before_path() {
    let temp = TempProfile::new("shell-host-first");
    let (a, b) = (temp.0.join("a"), temp.0.join("b"));
    touch(&b.join("only-here.exe"));
    touch(&a.join("only-here.exe"));
    assert_eq!(
        WindowsHost.find_program_in(&[a.clone(), b.clone()], "only-here"),
        Some(a.join("only-here.exe"))
    );
    assert_eq!(
        WindowsHost.find_program_in(&[b.clone(), a], "only-here"),
        Some(b.join("only-here.exe"))
    );
    // PATH still follows the directories.
    assert_eq!(
        WindowsHost.find_program_in(&[b], "cmd.exe"),
        WindowsHost.find_program("cmd.exe")
    );
}

fn dir_sibling(name: &str) -> PathBuf {
    system_dir().parent().unwrap().join(name)
}

fn short_path(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: `wide` is NUL-terminated and `buf` is the length the call is told.
    let len = unsafe {
        ::windows::Win32::Storage::FileSystem::GetShortPathNameW(::windows::core::PCWSTR(wide.as_ptr()), Some(&mut buf))
    } as usize;
    assert!(len > 0 && len < buf.len(), "GetShortPathNameW failed");
    PathBuf::from(std::ffi::OsString::from_wide(&buf[..len]))
}

// resolve_program -----

/// `apply` decides whether the shell sshd ran exists through `WindowsHost`: `DefaultShell = ...\pwsh`
/// is the file `...\pwsh.exe`, as `CreateProcess` finds it.
#[test]
fn an_absolute_path_without_an_extension_finds_the_exe_on_disk() {
    use crate::shell::resolve_program;
    let temp = TempProfile::new("shell-host-bare-abs");
    touch(&temp.0.join("pwsh.exe"));
    let bare = temp.0.join("pwsh");
    assert_eq!(
        resolve_program(&WindowsHost, &bare.to_string_lossy()),
        Ok(temp.0.join("pwsh.exe"))
    );
    let none = temp.0.join("nonesuch");
    assert!(resolve_program(&WindowsHost, &none.to_string_lossy()).is_err());
}

// find_in -----

#[test]
fn a_bare_name_is_found_only_on_path_in_order() {
    let temp = TempProfile::new("shell-host-path");
    let (a, b) = (temp.0.join("a"), temp.0.join("b"));
    touch(&b.join("pwsh.exe"));
    assert_eq!(find_in(&[a.clone(), b.clone()], "pwsh.exe"), Some(b.join("pwsh.exe")));
    touch(&a.join("pwsh.exe"));
    assert_eq!(find_in(&[a.clone(), b.clone()], "pwsh.exe"), Some(a.join("pwsh.exe")));
    assert_eq!(find_in(&[b.clone(), a.clone()], "pwsh.exe"), Some(b.join("pwsh.exe")));
    assert_eq!(find_in(&[a, b], "nonesuch.exe"), None);
}

#[test]
fn the_current_directory_and_the_exe_directory_are_not_searched() {
    let temp = TempProfile::new("shell-host-cwd");
    // Where the test exe lives, and where the process runs: both hold files by these names, and
    // neither is on the list.
    let exe_name = std::env::current_exe().unwrap().file_name().unwrap().to_owned();
    let list = [temp.0.clone()];
    assert_eq!(find_in(&list, &exe_name.to_string_lossy()), None);
    let here = std::env::current_dir().unwrap();
    let in_here = std::fs::read_dir(&here)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.path().is_file())
        .expect("the working directory holds a file");
    assert_eq!(find_in(&list, &in_here.file_name().to_string_lossy()), None);
}

#[test]
fn relative_entries_on_the_list_are_skipped() {
    // A relative entry means "the current directory", which the search excludes.
    let here = std::env::current_dir().unwrap();
    let file = std::fs::read_dir(&here)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.path().is_file())
        .expect("the working directory holds a file");
    let name = file.file_name().to_string_lossy().into_owned();
    assert_eq!(find_in(&[PathBuf::from("."), PathBuf::new()], &name), None);
}

#[test]
fn exe_is_appended_only_to_a_name_without_an_extension() {
    let temp = TempProfile::new("shell-host-ext");
    touch(&temp.0.join("pwsh.exe"));
    touch(&temp.0.join("tool.7"));
    touch(&temp.0.join("tool.7.exe"));
    let list = [temp.0.clone()];
    assert_eq!(find_in(&list, "pwsh"), Some(temp.0.join("pwsh.exe")));
    // The file system ignores case; SearchPathW reports the name as asked.
    let upper = find_in(&list, "PWSH.EXE").expect("found in any case");
    assert!(
        upper
            .as_os_str()
            .eq_ignore_ascii_case(temp.0.join("pwsh.exe").as_os_str()),
        "{upper:?}"
    );
    assert_eq!(find_in(&list, "tool.7"), Some(temp.0.join("tool.7")));
    assert_eq!(find_in(&list, "tool"), None);
}

#[test]
fn a_directory_named_like_the_program_is_skipped() {
    let temp = TempProfile::new("shell-host-dirname");
    let (a, b) = (temp.0.join("a"), temp.0.join("b"));
    std::fs::create_dir_all(a.join("pwsh.exe")).unwrap();
    touch(&b.join("pwsh.exe"));
    assert_eq!(find_in(&[a.clone(), b.clone()], "pwsh.exe"), Some(b.join("pwsh.exe")));
    assert_eq!(find_in(&[a], "pwsh.exe"), None);
}

#[test]
fn a_directory_on_the_list_that_does_not_exist_is_skipped() {
    let temp = TempProfile::new("shell-host-missing");
    touch(&temp.0.join("pwsh.exe"));
    assert_eq!(
        find_in(&[temp.0.join("nope"), temp.0.clone()], "pwsh.exe"),
        Some(temp.0.join("pwsh.exe"))
    );
}

// read_file -----

#[test]
fn a_missing_file_is_none_and_a_directory_is_an_error() {
    let temp = TempProfile::new("shell-host-read");
    assert_eq!(WindowsHost.read_file(&temp.0.join("absent.yaml")).unwrap(), None);
    assert_eq!(
        WindowsHost
            .read_file(&temp.0.join("no-dir").join("absent.yaml"))
            .unwrap(),
        None
    );
    let dir = temp.0.join("config.yaml");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(WindowsHost.read_file(&dir).is_err());
    let file = temp.0.join("real.yaml");
    std::fs::write(&file, b"shell: x\n").unwrap();
    assert_eq!(WindowsHost.read_file(&file).unwrap().unwrap(), b"shell: x\n");
}

#[test]
fn the_system_config_is_in_the_install_directory() {
    assert_eq!(
        WindowsHost.system_config_path(),
        PathBuf::from(r"C:\ProgramData\ssh-broker\config.yaml")
    );
}

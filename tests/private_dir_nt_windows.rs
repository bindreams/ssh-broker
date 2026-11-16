//! What Windows does when the private folder is reached by handle and not by path. Windows only.
//!
//! Measurements, not a feature: each test records one behaviour that a fix for the private folder
//! (`userdir::ensure_socket_dir`, `filelog`) would rest on, so a change of that behaviour on a newer
//! Windows fails here first. Everything happens in a temporary directory; nothing needs elevation
//! (a symlink needs Developer Mode or the symlink privilege, and fails loudly without it).
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use ssh_broker::acl::Sid;
use ssh_broker::winutil::OwnedHandle;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS, NtCreateFile, NtOpenFile,
};
use windows::Win32::Foundation::{
    HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, OBJECT_ATTRIBUTE_FLAGS, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    GetFileInformationByHandle, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::core::{BOOL, PCWSTR, PWSTR};

#[path = "common/fs_state.rs"]
mod fs_state;
use fs_state::{default_owner_sid, junction, owner_sid_of, sddl_of};

/// STATUS_REPARSE_POINT_ENCOUNTERED: what `OBJ_DONT_REPARSE` answers at a link.
const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = 0xC000_050Bu32 as i32;

// A stand-in profile -----

/// A directory tree under the temp dir, removed on drop (a junction is removed, not followed).
struct Tree(PathBuf);

impl Tree {
    fn new(tag: &str) -> Tree {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sb-nt-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Tree(root)
    }

    /// `<root>\profile\AppData\Local\ssh-broker\logs`, all real directories.
    fn with_profile(tag: &str) -> Tree {
        let tree = Tree::new(tag);
        std::fs::create_dir_all(tree.profile().join(r"AppData\Local\ssh-broker\logs")).unwrap();
        tree
    }

    fn profile(&self) -> PathBuf {
        self.0.join("profile")
    }

    fn local(&self) -> PathBuf {
        self.profile().join(r"AppData\Local")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `link` as a directory symlink to `target`. Needs Developer Mode or the symlink privilege.
fn symlink(link: &Path, target: &Path) {
    std::os::windows::fs::symlink_dir(target, link).unwrap_or_else(|e| {
        panic!(
            "symlink {} -> {}: {e} (needs Developer Mode or the symlink privilege)",
            link.display(),
            target.display()
        )
    });
}

// Raw NT opens and creates -----

const SHARE_ALL: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
const NONE: OBJECT_ATTRIBUTE_FLAGS = OBJECT_ATTRIBUTE_FLAGS(0);
/// The rights to list, enter and add to a directory, and read its ACL.
const DIR_WORK: u32 = FILE_LIST_DIRECTORY.0
    | FILE_ADD_FILE.0
    | FILE_ADD_SUBDIRECTORY.0
    | FILE_TRAVERSE.0
    | FILE_READ_ATTRIBUTES.0
    | READ_CONTROL.0
    | SYNCHRONIZE.0;

/// `\??\C:\...` for an absolute drive path.
fn nt_name(path: &Path) -> String {
    format!(r"\??\{}", path.display())
}

/// A name as the `UNICODE_STRING` the NT calls take; `units` must outlive it.
fn unicode(units: &mut [u16]) -> UNICODE_STRING {
    let bytes = u16::try_from(units.len() * 2).unwrap();
    UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: PWSTR(units.as_mut_ptr()),
    }
}

/// `NtOpenFile` of `name` (relative to `root` if given) for `READ_CONTROL | FILE_READ_ATTRIBUTES`,
/// sharing everything. `Err` is the NTSTATUS.
fn nt_open(root: Option<HANDLE>, name: &str, flags: OBJECT_ATTRIBUTE_FLAGS, options: u32) -> Result<OwnedHandle, i32> {
    nt_open_for(
        root,
        name,
        READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0,
        SHARE_ALL,
        flags,
        options,
    )
}

/// [`nt_open`] with the access and the sharing given. `flags` are the object-attribute flags besides
/// `OBJ_CASE_INSENSITIVE`; `options` the open options besides `FILE_OPEN_FOR_BACKUP_INTENT`.
fn nt_open_for(
    root: Option<HANDLE>,
    name: &str,
    access: u32,
    share: FILE_SHARE_MODE,
    flags: OBJECT_ATTRIBUTE_FLAGS,
    options: u32,
) -> Result<OwnedHandle, i32> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    let name = unicode(&mut units);
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.unwrap_or_default(),
        ObjectName: &name,
        Attributes: OBJECT_ATTRIBUTE_FLAGS(OBJ_CASE_INSENSITIVE.0 | flags.0),
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer is to a local that outlives the call.
    let status = unsafe {
        NtOpenFile(
            &mut handle,
            access,
            &attributes,
            &mut io,
            share.0,
            FILE_OPEN_FOR_BACKUP_INTENT.0 | options,
        )
    };
    if status.0 >= 0 {
        Ok(OwnedHandle(handle))
    } else {
        Err(status.0)
    }
}

/// What `NtCreateFile` made: the handle and `IO_STATUS_BLOCK.Information` (1 opened, 2 created).
struct Made {
    handle: OwnedHandle,
    information: usize,
}

const FILE_OPENED: usize = 1;
const FILE_CREATED: usize = 2;

/// `NtCreateFile` of `name` under `root`, with `sd` as the object's security descriptor if given.
fn nt_create(
    root: HANDLE,
    name: &str,
    access: u32,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: NTCREATEFILE_CREATE_OPTIONS,
    flags: OBJECT_ATTRIBUTE_FLAGS,
    sd: Option<&Sd>,
) -> Result<Made, i32> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    let name = unicode(&mut units);
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &name,
        Attributes: OBJECT_ATTRIBUTE_FLAGS(OBJ_CASE_INSENSITIVE.0 | flags.0),
        SecurityDescriptor: sd.map_or(std::ptr::null(), |sd| sd.0.0 as *const _),
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer is to a local that outlives the call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_ACCESS_RIGHTS(access),
            &attributes,
            &mut io,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0),
            SHARE_ALL,
            disposition,
            NTCREATEFILE_CREATE_OPTIONS(options.0 | FILE_OPEN_FOR_BACKUP_INTENT.0 | FILE_SYNCHRONOUS_IO_NONALERT.0),
            None,
            0,
        )
    };
    if status.0 >= 0 {
        Ok(Made {
            handle: OwnedHandle(handle),
            information: io.Information,
        })
    } else {
        Err(status.0)
    }
}

/// Whether `handle` is a reparse point itself.
fn is_reparse_point(handle: &OwnedHandle) -> bool {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: a valid handle and an out-pointer to a local.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }.unwrap();
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

/// The path the handle names, as the system reports it, to tell where an open landed.
fn final_path(handle: &OwnedHandle) -> String {
    use windows::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW};
    let mut buf = vec![0u16; 1024];
    // SAFETY: the buffer is as long as it is told.
    let n = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn hex(status: i32) -> String {
    format!("{:#010x}", status as u32)
}

// Security descriptors -----

/// An owned security descriptor made from SDDL.
struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    fn from_sddl(sddl: &str) -> Sd {
        let w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated string, valid out-pointer; freed in `Drop`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), SDDL_REVISION_1, &mut psd, None)
        }
        .unwrap();
        Sd(psd)
    }

    /// `(owner, dacl)` pointing into the descriptor.
    fn owner_and_dacl(&self) -> (PSID, *mut ACL) {
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner = PSID::default();
        // SAFETY: valid out-pointers into a live descriptor.
        unsafe {
            GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted).unwrap();
            GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted).unwrap();
        }
        (owner, dacl)
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: allocated by the converter with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn me_sddl() -> String {
    Sid::current_user().unwrap().to_sddl().unwrap()
}

/// The private folder's security descriptor: the user, SYSTEM and Administrators, Full Control,
/// protected, inherited by what is made inside; the owner too if `with_owner`.
fn private_sd(with_owner: bool) -> Sd {
    let me = me_sddl();
    let owner = if with_owner { format!("O:{me}") } else { String::new() };
    Sd::from_sddl(&format!("{owner}D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
}

// Opening without following a link -----

/// A stand-in profile, and `outside`: a directory with the same `Local\ssh-broker\logs` tree that a
/// link can lead to.
fn profile_and_outside(tag: &str) -> (Tree, Tree) {
    let outside = Tree::new(&format!("{tag}-outside"));
    std::fs::create_dir_all(outside.0.join(r"Local\ssh-broker\logs")).unwrap();
    (Tree::with_profile(tag), outside)
}

const REL: &str = r"AppData\Local\ssh-broker\logs";

/// Where `link_at` (a path under the profile, relative to it) is replaced by a link: the junction
/// or symlink leads to the same-named folder of `outside`.
fn replace_with_link(profile: &Tree, outside: &Tree, link_at: &str, symlinked: bool) {
    let link = profile.profile().join(link_at);
    // The same folder, one level up from `Local`, in the outside tree.
    let target = outside.0.join(link_at.strip_prefix(r"AppData\").unwrap_or(""));
    let target = if link_at == "AppData" {
        outside.0.clone()
    } else {
        target
    };
    std::fs::remove_dir_all(&link).unwrap();
    if symlinked {
        symlink(&link, &target);
    } else {
        junction(&link, &target);
    }
}

const LINKS: [&str; 4] = [
    "AppData",
    r"AppData\Local",
    r"AppData\Local\ssh-broker",
    r"AppData\Local\ssh-broker\logs",
];

#[test]
fn a_dont_reparse_open_refuses_a_junction_or_symlink_at_every_component() {
    // Measured on 10.0.26100: the flag is accepted, the status is STATUS_REPARSE_POINT_ENCOUNTERED
    // wherever the link is, for a junction and for a symlink, relative to a root handle and for an
    // absolute `\??\C:\...` name alike.
    for symlinked in [false, true] {
        for link_at in LINKS {
            let (profile, outside) = profile_and_outside("dontreparse");
            replace_with_link(&profile, &outside, link_at, symlinked);
            let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
            let what = format!("{} at {link_at}", if symlinked { "symlink" } else { "junction" });
            assert_eq!(
                nt_open(Some(root.0), REL, OBJ_DONT_REPARSE, 0).map(|_| ()),
                Err(STATUS_REPARSE_POINT_ENCOUNTERED),
                "relative: {what}"
            );
            assert_eq!(
                nt_open(None, &nt_name(&profile.profile().join(REL)), OBJ_DONT_REPARSE, 0).map(|_| ()),
                Err(STATUS_REPARSE_POINT_ENCOUNTERED),
                "absolute: {what}"
            );
        }
    }
}

#[test]
fn a_dont_reparse_open_of_real_directories_succeeds_relative_and_absolute() {
    let (profile, _outside) = profile_and_outside("dontreparse-real");
    let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
    let relative = nt_open(Some(root.0), REL, OBJ_DONT_REPARSE, 0).unwrap();
    let absolute = nt_open(None, &nt_name(&profile.profile().join(REL)), OBJ_DONT_REPARSE, 0).unwrap();
    assert_eq!(final_path(&relative), final_path(&absolute));
    assert!(!is_reparse_point(&relative));
}

#[test]
fn an_open_without_the_flag_follows_a_link_out_of_the_profile() {
    let (profile, outside) = profile_and_outside("follow");
    replace_with_link(&profile, &outside, r"AppData\Local", false);
    let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
    let outside_logs =
        final_path(&nt_open(None, &nt_name(&outside.0.join(r"Local\ssh-broker\logs")), NONE, 0).unwrap());
    // Neither no flag nor `FILE_OPEN_REPARSE_POINT` stops a link above the last component.
    for options in [0, FILE_OPEN_REPARSE_POINT.0] {
        let opened = nt_open(Some(root.0), REL, NONE, options).unwrap();
        assert_eq!(final_path(&opened), outside_logs, "options {options:#x}");
    }
}

#[test]
fn open_reparse_point_opens_a_last_component_link_itself_and_marks_it() {
    // The version-independent way to see a link: open the single name with `FILE_OPEN_REPARSE_POINT`
    // and read the attribute from the handle. A link comes back as itself with the reparse bit set.
    for symlinked in [false, true] {
        let (profile, outside) = profile_and_outside("orp");
        replace_with_link(&profile, &outside, r"AppData\Local\ssh-broker\logs", symlinked);
        let logs_parent = nt_open(None, &nt_name(&profile.local().join("ssh-broker")), NONE, 0).unwrap();
        let link = nt_open(Some(logs_parent.0), "logs", NONE, FILE_OPEN_REPARSE_POINT.0).unwrap();
        assert!(is_reparse_point(&link), "symlinked={symlinked}");
        assert!(
            !final_path(&link).contains("-outside-"),
            "the link itself, not its target"
        );
        // With the flag as well, the last component is still opened as itself.
        let again = nt_open(Some(logs_parent.0), "logs", OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT.0).unwrap();
        assert!(is_reparse_point(&again));
    }
}

/// Open `components` one at a time under `root`, each with `FILE_OPEN_REPARSE_POINT`, and give up
/// at the first that is a link. `Err` names it.
fn walk(root: &OwnedHandle, components: &[&str]) -> Result<OwnedHandle, String> {
    let mut at: Option<OwnedHandle> = None;
    for name in components {
        let parent = at.as_ref().map_or(root.0, |h| h.0);
        let next = nt_open(Some(parent), name, NONE, FILE_OPEN_REPARSE_POINT.0).map_err(hex)?;
        if is_reparse_point(&next) {
            return Err(format!("{name} is a link"));
        }
        at = Some(next);
    }
    at.ok_or_else(|| "no components".to_owned())
}

#[test]
fn a_component_walk_with_open_reparse_point_finds_a_link_at_every_level_without_the_flag() {
    for symlinked in [false, true] {
        for link_at in LINKS {
            let (profile, outside) = profile_and_outside("walk");
            replace_with_link(&profile, &outside, link_at, symlinked);
            let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
            let name = link_at.rsplit('\\').next().unwrap();
            assert_eq!(
                walk(&root, &["AppData", "Local", "ssh-broker", "logs"]).map(|_| ()),
                Err(format!("{name} is a link")),
                "symlinked={symlinked} at {link_at}"
            );
        }
    }
    let (profile, _outside) = profile_and_outside("walk-real");
    let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
    walk(&root, &["AppData", "Local", "ssh-broker", "logs"]).unwrap();
}

#[test]
fn a_root_opened_without_the_reparse_flag_follows_a_link_at_the_profile_directory_itself() {
    // What the raw call does when the profile directory itself is a junction and the open does not
    // ask for the link as itself: it follows it. `acl::open_root` relies on this: Windows loads the
    // profile through `ProfileImagePath`, links included, so the broker opens the profile directory the
    // same way. Only the names below it are opened as themselves and refused when they are links.
    let (profile, _outside) = profile_and_outside("rootlink");
    let via = Tree::new("rootlink-via");
    junction(&via.0.join("p"), &profile.profile());
    let root = nt_open(None, &nt_name(&via.0.join("p")), NONE, 0).unwrap();
    let logs = walk(&root, &["AppData", "Local", "ssh-broker", "logs"]).unwrap();
    assert!(
        final_path(&logs).ends_with(r"profile\AppData\Local\ssh-broker\logs"),
        "{}",
        final_path(&logs)
    );
    assert_eq!(
        nt_open(None, &nt_name(&via.0.join("p").join(REL)), OBJ_DONT_REPARSE, 0).map(|_| ()),
        Err(STATUS_REPARSE_POINT_ENCOUNTERED),
        "the absolute form refuses the link above the root, so it is not the walk's way in"
    );
}

// Creating relative to a handle, with the descriptor given at creation -----

#[test]
fn a_directory_created_under_a_handle_with_a_descriptor_has_exactly_that_acl() {
    let tree = Tree::with_profile("create");
    let me = Sid::current_user().unwrap();
    let local = nt_open_for(None, &nt_name(&tree.local()), DIR_WORK, SHARE_ALL, NONE, 0).unwrap();
    for (name, with_owner) in [("with-owner", true), ("without-owner", false)] {
        let made = nt_create(
            local.0,
            name,
            DIR_WORK,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            OBJ_DONT_REPARSE,
            Some(&private_sd(with_owner)),
        )
        .unwrap_or_else(|s| panic!("create {name}: {}", hex(s)));
        assert_eq!(made.information, FILE_CREATED);
        let dir = tree.local().join(name);
        assert!(ssh_broker::acl::verify_dir_acl(&dir, &me).unwrap(), "{}", sddl_of(&dir));
        // Without an owner in the descriptor the owner is the creating token's default owner: the
        // user for a plain token, Administrators for an elevated one (which `verify_dir_acl` accepts).
        let expected = if with_owner { me_sddl() } else { default_owner_sid() };
        assert_eq!(owner_sid_of(&dir), expected, "owner of {name}: {}", sddl_of(&dir));
    }
}

#[test]
fn create_and_open_if_say_which_happened_and_create_refuses_what_exists() {
    let tree = Tree::with_profile("dispositions");
    let local = nt_open_for(None, &nt_name(&tree.local()), DIR_WORK, SHARE_ALL, NONE, 0).unwrap();
    let sd = private_sd(true);
    let make = |disposition| {
        nt_create(
            local.0,
            "new",
            DIR_WORK,
            disposition,
            FILE_DIRECTORY_FILE,
            OBJ_DONT_REPARSE,
            Some(&sd),
        )
    };
    assert_eq!(make(FILE_OPEN_IF).unwrap().information, FILE_CREATED);
    assert_eq!(make(FILE_OPEN_IF).unwrap().information, FILE_OPENED);
    // STATUS_OBJECT_NAME_COLLISION
    assert_eq!(make(FILE_CREATE).map(|_| ()), Err(0xC000_0035u32 as i32));
}

#[test]
fn what_is_created_inside_such_a_directory_inherits_exactly_the_three_aces() {
    let tree = Tree::with_profile("inherit");
    let me = Sid::current_user().unwrap();
    let local = nt_open_for(None, &nt_name(&tree.local()), DIR_WORK, SHARE_ALL, NONE, 0).unwrap();
    let dir = nt_create(
        local.0,
        "new",
        DIR_WORK,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
        OBJ_DONT_REPARSE,
        Some(&private_sd(true)),
    )
    .unwrap();
    let logs = nt_create(
        dir.handle.0,
        "logs",
        DIR_WORK,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
        OBJ_DONT_REPARSE,
        None,
    )
    .unwrap();
    let name = "shim.log.2026-01-01";
    nt_create(
        logs.handle.0,
        name,
        FILE_APPEND_DATA.0 | SYNCHRONIZE.0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
        OBJ_DONT_REPARSE,
        None,
    )
    .unwrap();
    let base = tree.local().join("new");
    assert!(ssh_broker::acl::verify_file_acl(&base.join("logs"), &me).unwrap());
    assert!(ssh_broker::acl::verify_file_acl(&base.join("logs").join(name), &me).unwrap());
}

// Setting the descriptor of an open directory -----

/// `SetSecurityInfo` of the private descriptor on a fresh directory opened with `access`.
fn set_through_handle(access: u32, with_owner: bool) -> (u32, bool) {
    let t = Tree::new("bysec");
    let d = t.0.join("d");
    std::fs::create_dir(&d).unwrap();
    let h = nt_open_for(None, &nt_name(&d), access, SHARE_ALL, NONE, 0).unwrap();
    let sd = private_sd(true);
    let (owner, dacl) = sd.owner_and_dacl();
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if with_owner {
        info |= OWNER_SECURITY_INFORMATION;
    }
    // SAFETY: the handle is open; the owner and DACL live as long as `sd`.
    let rc = unsafe {
        SetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            info,
            with_owner.then_some(owner),
            None,
            Some(dacl as *const ACL),
            None,
        )
    };
    (
        rc.0,
        ssh_broker::acl::verify_dir_acl(&d, &Sid::current_user().unwrap()).unwrap(),
    )
}

#[test]
fn set_security_info_on_a_handle_needs_read_control_and_write_dac_and_write_owner_for_an_owner() {
    const ACCESS_DENIED: u32 = 5;
    let (rc, dac, own) = (READ_CONTROL.0, WRITE_DAC.0, WRITE_OWNER.0);
    assert_eq!(set_through_handle(rc | dac, false), (0, true));
    assert_eq!(set_through_handle(rc | dac | own, true), (0, true));
    // No READ_CONTROL: the call reads the old descriptor first.
    assert_eq!(set_through_handle(dac, false), (ACCESS_DENIED, false));
    assert_eq!(set_through_handle(rc, false), (ACCESS_DENIED, false));
    // Naming an owner needs WRITE_OWNER even when it is the owner already.
    assert_eq!(set_through_handle(rc | dac, true), (ACCESS_DENIED, false));
}

// Propagation -----

/// `d` with a file, a folder holding a file, and a junction `j` to `x` (which holds a file).
fn tree_with_children() -> (Tree, PathBuf, PathBuf) {
    let t = Tree::new("prop");
    let d = t.0.join("d");
    let x = t.0.join("x");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::create_dir_all(&x).unwrap();
    std::fs::write(d.join("f"), "").unwrap();
    std::fs::write(d.join(r"sub\g"), "").unwrap();
    std::fs::write(x.join("xf"), "").unwrap();
    junction(&d.join("j"), &x);
    (t, d, x)
}

fn set_private_on_path(path: &Path) {
    let sd = private_sd(true);
    let (owner, dacl) = sd.owner_and_dacl();
    let w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    // SAFETY: NUL-terminated path; the owner and DACL live as long as `sd`.
    unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            Some(owner),
            None,
            Some(dacl as *const ACL),
            None,
        )
    }
    .ok()
    .unwrap();
}

#[test]
fn a_dacl_set_through_a_handle_or_a_path_reaches_the_children_and_not_through_a_child_junction() {
    for by_handle in [true, false] {
        let (_t, d, x) = tree_with_children();
        let (f0, g0, x0, xf0) = (
            sddl_of(&d.join("f")),
            sddl_of(&d.join(r"sub\g")),
            sddl_of(&x),
            sddl_of(&x.join("xf")),
        );
        if by_handle {
            let sd = private_sd(true);
            let (owner, dacl) = sd.owner_and_dacl();
            let h = nt_open_for(
                None,
                &nt_name(&d),
                READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0,
                SHARE_ALL,
                NONE,
                0,
            )
            .unwrap();
            let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
            // SAFETY: the handle is open; the owner and DACL live as long as `sd`.
            unsafe {
                SetSecurityInfo(
                    h.0,
                    SE_FILE_OBJECT,
                    info,
                    Some(owner),
                    None,
                    Some(dacl as *const ACL),
                    None,
                )
            }
            .ok()
            .unwrap();
        } else {
            set_private_on_path(&d);
        }
        let what = if by_handle { "by handle" } else { "by path" };
        assert_ne!(f0, sddl_of(&d.join("f")), "the child file is re-inherited {what}");
        assert_ne!(g0, sddl_of(&d.join(r"sub\g")), "the grandchild is re-inherited {what}");
        assert_eq!(x0, sddl_of(&x), "the junction's target folder is not touched {what}");
        assert_eq!(xf0, sddl_of(&x.join("xf")), "nor what is in it {what}");
    }
}

#[test]
fn a_dacl_set_through_a_handle_stays_in_the_tree_the_handle_was_opened_on() {
    let t = Tree::new("swap");
    let (d, moved, x) = (t.0.join("d"), t.0.join("moved"), t.0.join("x"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("f"), "").unwrap();
    std::fs::create_dir_all(&x).unwrap();
    std::fs::write(x.join("f"), "").unwrap();
    let h = nt_open_for(
        None,
        &nt_name(&d),
        READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0,
        SHARE_ALL,
        NONE,
        0,
    )
    .unwrap();
    // The directory is moved away and a junction to somewhere else takes its name.
    std::fs::rename(&d, &moved).expect("a directory with a rights-only handle open can be renamed");
    junction(&d, &x);
    let (m0, x0, xf0) = (sddl_of(&moved.join("f")), sddl_of(&x), sddl_of(&x.join("f")));
    let sd = private_sd(true);
    let (owner, dacl) = sd.owner_and_dacl();
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    // SAFETY: the handle is open; the owner and DACL live as long as `sd`.
    unsafe {
        SetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            info,
            Some(owner),
            None,
            Some(dacl as *const ACL),
            None,
        )
    }
    .ok()
    .unwrap();
    assert_ne!(
        m0,
        sddl_of(&moved.join("f")),
        "the object the handle names was re-ACLed, wherever it now is"
    );
    assert_eq!(x0, sddl_of(&x), "what the old path now leads to was not");
    assert_eq!(xf0, sddl_of(&x.join("f")));
}

#[test]
fn named_security_calls_act_on_a_last_component_link_itself_but_follow_one_above_it() {
    // The path forms read and set the descriptor of a junction or symlink *itself* when it is the
    // last component, and of the far side when it is anywhere above. So setting the private
    // descriptor by path on a swapped last component re-ACLs only the link; a link at `AppData` or
    // `Local` is what redirects it.
    let me = Sid::current_user().unwrap();
    for (what, symlinked, middle) in [
        ("last junction", false, false),
        ("last symlink", true, false),
        ("middle junction", false, true),
    ] {
        let t = Tree::new("named");
        let x = t.0.join("x");
        std::fs::create_dir_all(x.join("ssh-broker")).unwrap();
        let path = if middle {
            junction(&t.0.join("Local"), &x);
            t.0.join(r"Local\ssh-broker")
        } else {
            let path = t.0.join("ssh-broker");
            if symlinked {
                symlink(&path, &x.join("ssh-broker"));
            } else {
                junction(&path, &x.join("ssh-broker"));
            }
            path
        };
        let target = x.join("ssh-broker");
        let before = sddl_of(&target);
        set_private_on_path(&path);
        if middle {
            assert_ne!(before, sddl_of(&target), "{what}: the far side was re-ACLed");
            assert!(ssh_broker::acl::verify_dir_acl(&target, &me).unwrap(), "{what}");
        } else {
            assert_eq!(before, sddl_of(&target), "{what}: only the link was re-ACLed");
            assert!(!ssh_broker::acl::verify_dir_acl(&target, &me).unwrap(), "{what}");
            assert!(
                ssh_broker::acl::verify_dir_acl(&path, &me).unwrap(),
                "{what}: verify read the link's own descriptor"
            );
        }
    }
}

#[test]
fn a_dacl_propagated_from_a_directory_reaches_a_hard_linked_file_outside_it() {
    // A hard link is the file itself, so repairing a folder re-ACLs what a link inside it names. A
    // repair that propagates (as `SetNamedSecurityInfoW` and `SetSecurityInfo` do) is therefore
    // not confined to the folder's own objects; a create-only or verify-only path never writes.
    let t = Tree::new("hardlink");
    let (d, outside) = (t.0.join("d"), t.0.join("outside.txt"));
    std::fs::create_dir(&d).unwrap();
    std::fs::write(&outside, "x").unwrap();
    std::fs::hard_link(&outside, d.join("link")).unwrap();
    let before = sddl_of(&outside);
    set_private_on_path(&d);
    assert_ne!(before, sddl_of(&outside), "the file outside the folder was re-ACLed");
}

// Pinning -----

#[test]
fn an_open_handle_blocks_the_rename_of_its_ancestors_but_not_of_the_directory_itself() {
    // Informational: this is NTFS behaviour with a rights-only handle sharing everything, and is
    // not something a fix should lean on (other file systems, other versions).
    let (profile, _outside) = profile_and_outside("pin");
    let root = nt_open(None, &nt_name(&profile.profile()), NONE, 0).unwrap();
    let _held = nt_open_for(
        Some(root.0),
        REL,
        READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0,
        SHARE_ALL,
        NONE,
        0,
    )
    .unwrap();
    let p = profile.profile();
    for ancestor in ["AppData", r"AppData\Local", r"AppData\Local\ssh-broker"] {
        let err = std::fs::rename(p.join(ancestor), p.join(format!("{ancestor}2"))).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(5), "{ancestor}");
    }
    std::fs::rename(p.join(REL), p.join(r"AppData\Local\ssh-broker\logs2")).expect("the held directory itself moves");
}

// A handle as the log's writer -----

#[test]
fn a_file_opened_under_the_logs_handle_serves_as_a_std_file_and_appends() {
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;
    let t = Tree::with_profile("writer");
    let logs = t.local().join(r"ssh-broker\logs");
    let dir = nt_open_for(None, &nt_name(&logs), DIR_WORK, SHARE_ALL, NONE, 0).unwrap();
    let name = "shim.log.2026-01-01";
    for line in ["one\n", "two\n"] {
        let made = nt_create(
            dir.0,
            name,
            FILE_APPEND_DATA.0 | SYNCHRONIZE.0,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
            OBJ_DONT_REPARSE,
            None,
        )
        .unwrap();
        let raw = made.handle.0;
        std::mem::forget(made.handle);
        // SAFETY: the handle is owned, and the `File` closes it.
        let mut file = unsafe { std::fs::File::from_raw_handle(raw.0) };
        file.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(std::fs::read_to_string(logs.join(name)).unwrap(), "one\ntwo\n");
}

#[test]
fn a_file_symlink_in_the_logs_folder_is_refused_by_a_dont_reparse_create_and_followed_without_it() {
    let t = Tree::with_profile("filelink");
    let logs = t.local().join(r"ssh-broker\logs");
    let dir = nt_open_for(None, &nt_name(&logs), DIR_WORK, SHARE_ALL, NONE, 0).unwrap();
    let other = t.0.join("other.txt");
    std::fs::write(&other, "keep").unwrap();
    let name = "shim.log.2026-01-02";
    std::os::windows::fs::symlink_file(&other, logs.join(name))
        .unwrap_or_else(|e| panic!("file symlink: {e} (needs Developer Mode or the symlink privilege)"));
    let open = |flags| {
        nt_create(
            dir.0,
            name,
            FILE_APPEND_DATA.0 | SYNCHRONIZE.0,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
            flags,
            None,
        )
    };
    assert_eq!(
        open(OBJ_DONT_REPARSE).map(|_| ()),
        Err(STATUS_REPARSE_POINT_ENCOUNTERED)
    );
    assert!(
        open(NONE).is_ok(),
        "without the flag the link is followed to the file outside"
    );
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "keep");
}

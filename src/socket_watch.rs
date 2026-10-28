//! socket_watch: wake the shim when a user's agent socket may have become connectable.
//!
//! The shim learns that an agent it started (or one that is starting) is ready from the file
//! system, under its own token. It uses no named kernel object: a network-logon token in session 2
//! is refused every named event (measured), so nothing the shim needs may depend on the
//! object namespace.
//!
//! What is watched depends on how far the user's profile has got:
//!
//! - no profile yet (a first logon): the `ProfileList` registry key, which the logon writes;
//! - a profile, but not yet the socket folder: the deepest folder on the way to it that exists,
//!   which wakes when the next level is made;
//! - the socket folder: its contents, whose change after `listen()` is the agent's `serving` marker
//!   (see `agent_background::mark_listening`).
//!
//! Every re-arm happens **before** the caller looks again, so a change between a wake and the next
//! look is seen by the look or by the re-armed watch.

use std::path::{Path, PathBuf};

use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME, RegCloseKey,
    RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows::core::PCWSTR;

use crate::socket_loc::SocketLocation;
use crate::userdir::NoProfile;
use crate::winutil::OwnedHandle;

/// The key Windows writes a profile's entry into when it makes the profile.
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// DirWatch -----

/// A change watch on one folder: file and folder names, size, last write. Not recursive.
pub struct DirWatch(HANDLE);

impl DirWatch {
    /// Watch `dir`. It must exist.
    pub fn arm(dir: &Path) -> anyhow::Result<DirWatch> {
        use std::os::windows::ffi::OsStrExt;
        let dir_w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated path; the handle is closed on drop.
        unsafe {
            FindFirstChangeNotificationW(
                PCWSTR(dir_w.as_ptr()),
                false,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )
        }
        .map(DirWatch)
        .with_context(|| format!("watch {}", dir.display()))
    }

    /// Start watching for the next change. Call it after a wake and before looking again.
    pub fn rearm(&self) -> anyhow::Result<()> {
        // SAFETY: a valid watch handle.
        unsafe { FindNextChangeNotification(self.0) }.context("re-arm the folder watch")
    }

    /// The handle to wait on. Owned by `self`.
    pub fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        // SAFETY: the handle from `arm`.
        let _ = unsafe { FindCloseChangeNotification(self.0) };
    }
}

/// The deepest folder on the way to `dir` (inclusive) that exists. A path component that is a file
/// is not a folder to watch.
pub fn deepest_existing(dir: &Path) -> anyhow::Result<PathBuf> {
    for candidate in dir.ancestors() {
        match std::fs::metadata(candidate) {
            Ok(meta) if meta.is_dir() => return Ok(candidate.to_path_buf()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("look at {}", candidate.display())),
        }
    }
    anyhow::bail!("no folder on the way to {} exists", dir.display())
}

// ProfileList -----

/// The registry key that fills when a profile is made: where a watch waits for a first logon.
pub struct ProfileList {
    root: HKEY,
    subkey: Option<String>,
}

impl ProfileList {
    /// `HKLM\...\ProfileList`.
    pub fn machine() -> ProfileList {
        ProfileList::under(HKEY_LOCAL_MACHINE, PROFILE_LIST)
    }

    /// A key at `root\subkey`, for tests.
    pub fn under(root: HKEY, subkey: &str) -> ProfileList {
        ProfileList {
            root,
            subkey: Some(subkey.to_owned()),
        }
    }

    /// No key at all: for a caller that knows the profile exists.
    pub fn none() -> ProfileList {
        ProfileList {
            root: HKEY::default(),
            subkey: None,
        }
    }
}

/// A notification on the profile list's subtree (new entries and changed values), signalled through
/// an unnamed event.
struct ProfileWatch {
    key: HKEY,
    event: OwnedHandle,
}

impl ProfileWatch {
    fn arm(list: &ProfileList) -> anyhow::Result<ProfileWatch> {
        let subkey = list
            .subkey
            .as_deref()
            .context("the profile is not known and there is no profile list to wait on")?;
        let mut key = HKEY::default();
        // SAFETY: a NUL-terminated name and a valid out-pointer; the key is closed on drop.
        unsafe { RegOpenKeyExW(list.root, PCWSTR(wide(subkey).as_ptr()), None, KEY_NOTIFY, &mut key) }
            .ok()
            .with_context(|| format!("open {subkey} to watch it"))?;
        // SAFETY: an unnamed manual-reset event, not signalled.
        let event = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
            Ok(event) => OwnedHandle(event),
            Err(e) => {
                // SAFETY: the key just opened.
                let _ = unsafe { RegCloseKey(key) };
                return Err(e).context("CreateEventW");
            }
        };
        let watch = ProfileWatch { key, event };
        watch.rearm()?;
        Ok(watch)
    }

    fn rearm(&self) -> anyhow::Result<()> {
        // SAFETY: valid handles. The event is reset first, so a change after the registration
        // signals it again and is not lost.
        unsafe {
            ResetEvent(self.event.0).context("reset the profile list event")?;
            RegNotifyChangeKeyValue(
                self.key,
                true,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                Some(self.event.0),
                true,
            )
            .ok()
            .context("watch the profile list")
        }
    }
}

impl Drop for ProfileWatch {
    fn drop(&mut self) {
        // SAFETY: the key from `arm`.
        let _ = unsafe { RegCloseKey(self.key) };
    }
}

// SocketWatch -----

type Locate = Box<dyn FnMut() -> anyhow::Result<SocketLocation>>;

/// Wakes when the socket of one user may have become connectable.
///
/// [`SocketWatch::handle`] is the one handle to wait on. [`SocketWatch::rearm`] re-arms it and moves
/// it to whatever is now the best thing to watch; call it after every wake, **before** the next
/// connect.
pub struct SocketWatch {
    locate: Locate,
    profiles: ProfileList,
    /// While the profile is unknown.
    profile_watch: Option<ProfileWatch>,
    location: Option<SocketLocation>,
    /// The folder watched, and its watch.
    folder: Option<(PathBuf, DirWatch)>,
}

impl SocketWatch {
    /// A watch for the location `locate` finds. `locate` fails with [`NoProfile`] while the profile
    /// does not exist, which the watch waits out in `profiles`; any other failure is an error.
    pub fn new(
        locate: impl FnMut() -> anyhow::Result<SocketLocation> + 'static,
        profiles: ProfileList,
    ) -> anyhow::Result<SocketWatch> {
        let mut watch = SocketWatch {
            locate: Box::new(locate),
            profiles,
            profile_watch: None,
            location: None,
            folder: None,
        };
        watch.rearm()?;
        Ok(watch)
    }

    /// A watch for the socket of the account this process runs as, located from its token.
    pub fn for_current_user() -> anyhow::Result<SocketWatch> {
        SocketWatch::new(crate::userdir::current_socket_location, ProfileList::machine())
    }

    /// A watch for a location that is already known.
    pub fn for_location(location: &SocketLocation) -> anyhow::Result<SocketWatch> {
        let location = location.clone();
        SocketWatch::new(move || Ok(location.clone()), ProfileList::none())
    }

    /// The socket's location, once the profile exists.
    pub fn location(&self) -> Option<&SocketLocation> {
        self.location.as_ref()
    }

    /// The handle to wait on. Owned by `self`; it changes at [`SocketWatch::rearm`].
    pub fn handle(&self) -> HANDLE {
        match (&self.profile_watch, &self.folder) {
            (Some(profiles), _) => profiles.event.0,
            (None, Some((_, folder))) => folder.handle(),
            (None, None) => unreachable!("a watch always watches something after rearm"),
        }
    }

    /// The location, or `None` while the profile does not exist.
    fn locate_profile(&mut self) -> anyhow::Result<Option<SocketLocation>> {
        match (self.locate)() {
            Ok(location) => Ok(Some(location)),
            Err(e) if e.is::<NoProfile>() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Re-arm the watch and bring it up to date: find the profile if it has appeared, and move the
    /// folder watch to the deepest folder that exists. The new watch is armed before the check that
    /// it is still the deepest, so a level made in between is not missed.
    pub fn rearm(&mut self) -> anyhow::Result<()> {
        if self.location.is_none() {
            // A missing profile is waited for in the list. The watch is armed before the second
            // look, so a profile made in between is seen by that look or wakes the watch.
            let mut found = self.locate_profile()?;
            if found.is_none() {
                match &self.profile_watch {
                    Some(profiles) => profiles.rearm()?,
                    None => self.profile_watch = Some(ProfileWatch::arm(&self.profiles)?),
                }
                found = self.locate_profile()?;
            }
            let Some(location) = found else {
                return Ok(());
            };
            self.location = Some(location);
            self.profile_watch = None;
        }
        let Some(location) = &self.location else {
            return Ok(());
        };
        loop {
            let target = deepest_existing(&location.dir)?;
            match &self.folder {
                Some((watched, watch)) if *watched == target => watch.rearm()?,
                _ => self.folder = Some((target.clone(), DirWatch::arm(&target)?)),
            }
            if deepest_existing(&location.dir)? == target {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[path = "socket_watch_tests.rs"]
mod socket_watch_tests;

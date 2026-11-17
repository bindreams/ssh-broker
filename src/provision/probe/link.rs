//! The junction `verify`'s link row reads through.
//!
//! RedirectionGuard refuses to follow a link that a non-administrator made, so a junction proves
//! something only when a token below High made it and the token under test follows it. A junction
//! needs no privilege, unlike a symbolic link, so the row is never untestable for want of one.
//!
//! A probe makes the junction in its temp directory ([`make`]); the probe that tests the session reads
//! through it ([`follow`]); `verify` removes it ([`remove`]). The directory holds the junction, the
//! folder it points at and the file read through it, so removing the directory removes all three.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

use super::SymlinkState;
use crate::route::ProbeLink;

/// The junction, and the folder and file it leads to, inside the directory [`make`] returns.
const LINK_NAME: &str = "link";
const TARGET_NAME: &str = "target";
const FILE_NAME: &str = "parity.txt";
const FILE_CONTENT: &[u8] = b"parity";

/// `ERROR_UNTRUSTED_MOUNT_POINT`: what a process under RedirectionGuard gets when it follows a
/// junction that a non-administrator made.
const UNTRUSTED_MOUNT_POINT: i32 = 448;

/// Make the directory of this process's junction under `parent`, with the folder, the file and the
/// junction in it, and return the directory. One directory per process: a stale one of the same name is
/// removed first. A directory half made when a step fails is removed again.
pub fn make(parent: &Path) -> io::Result<PathBuf> {
    let dir = parent.join(format!("sb-junction-{}", std::process::id()));
    remove(&dir)?;
    make_in(&dir).inspect_err(|_| {
        let _ = remove(&dir);
    })?;
    Ok(dir)
}

fn make_in(dir: &Path) -> io::Result<()> {
    let target = dir.join(TARGET_NAME);
    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join(FILE_NAME), FILE_CONTENT)?;
    let link = dir.join(LINK_NAME);
    std::fs::create_dir(&link)?;
    set_mount_point(&link, &std::path::absolute(&target)?)
}

/// What a probe does about the junction of the link row ([`ProbeLink`]), with its temp directory as the
/// place to make one: the outcome of reading through it, and the directory it left for `verify` to give
/// to the next probe and remove (only for [`ProbeLink::Make`]). A junction that cannot be made is
/// [`SymlinkState::Failed`], its cause on stderr.
pub fn run(link: &ProbeLink) -> (SymlinkState, Option<PathBuf>) {
    run_in(link, &std::env::temp_dir())
}

fn run_in(link: &ProbeLink, parent: &Path) -> (SymlinkState, Option<PathBuf>) {
    match link {
        ProbeLink::Follow(dir) => (follow(Path::new(dir)), None),
        ProbeLink::Own | ProbeLink::Make => match make(parent) {
            Err(e) => {
                eprintln!("ssh-broker: making a junction in {} failed: {e}", parent.display());
                (SymlinkState::Failed, None)
            }
            Ok(dir) => {
                let state = follow(&dir);
                if *link == ProbeLink::Make {
                    return (state, Some(dir));
                }
                if let Err(e) = remove(&dir) {
                    eprintln!("ssh-broker: removing {} failed: {e}", dir.display());
                }
                (state, None)
            }
        },
    }
}

/// Read the file through the junction in `dir` as this process, and say what happened. Any failure
/// but RedirectionGuard's refusal is [`SymlinkState::Failed`], with its cause on stderr.
pub fn follow(dir: &Path) -> SymlinkState {
    let read = std::fs::read(dir.join(LINK_NAME).join(FILE_NAME));
    if let Err(e) = &read
        && e.raw_os_error() != Some(UNTRUSTED_MOUNT_POINT)
    {
        eprintln!(
            "ssh-broker: reading through the junction in {} failed: {e}",
            dir.display()
        );
    }
    state_of_read(read)
}

/// What a read through the junction says: the file's content is the probe's, or the read was refused as
/// an untrusted mount point, or it failed.
fn state_of_read(read: io::Result<Vec<u8>>) -> SymlinkState {
    match read {
        Ok(content) if content == FILE_CONTENT => SymlinkState::Ok,
        Err(e) if e.raw_os_error() == Some(UNTRUSTED_MOUNT_POINT) => SymlinkState::Blocked,
        _ => SymlinkState::Failed,
    }
}

/// Remove `dir` and what is in it. A junction in it is removed itself, never followed, so what it
/// points at is left alone. A directory that is not there is removed already.
pub fn remove(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Make the empty directory `link` a junction to `target`, an absolute path.
fn set_mount_point(link: &Path, target: &Path) -> io::Result<()> {
    let buffer = mount_point_buffer(target)?;
    let handle = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(link)?;
    let length = u32::try_from(buffer.len()).map_err(|_| io::Error::other("the junction's target path is too long"))?;
    // SAFETY: `handle` is an open directory, and `buffer` is a whole `REPARSE_DATA_BUFFER` for a mount
    // point that outlives the call.
    unsafe {
        DeviceIoControl(
            HANDLE(handle.as_raw_handle()),
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            length,
            None,
            0,
            None,
            None,
        )
    }
    .map_err(io::Error::from)
}

/// The `REPARSE_DATA_BUFFER` of a mount point to `target`: the header, the substitute name
/// (`\??\C:\target`, the form the kernel follows) and the print name, each followed by a NUL.
fn mount_point_buffer(target: &Path) -> io::Result<Vec<u8>> {
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let utf16 = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let joined = |prefix: &str, rest: &[u16]| [utf16(prefix).as_slice(), rest].concat();
    let substitute = if let Some(rest) = print.strip_prefix(utf16(r"\\?\").as_slice()) {
        joined(r"\??\", rest)
    } else if let Some(rest) = print.strip_prefix(utf16(r"\\").as_slice()) {
        joined(r"\??\UNC\", rest)
    } else {
        joined(r"\??\", &print)
    };
    let names = |wide: &[u16]| {
        wide.iter()
            .flat_map(|unit| unit.to_le_bytes())
            .chain([0, 0])
            .collect::<Vec<u8>>()
    };
    let (substitute_bytes, print_bytes) = (names(&substitute), names(&print));

    // Four u16 offsets and lengths, then the path buffer.
    let data_length = u16::try_from(8 + substitute_bytes.len() + print_bytes.len())
        .map_err(|_| io::Error::other("the junction's target path is too long"))?;
    let name_length = |bytes: &[u8]| (bytes.len() - 2) as u16; // without the NUL
    let mut buffer = Vec::with_capacity(8 + usize::from(data_length));
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend(data_length.to_le_bytes());
    buffer.extend(0u16.to_le_bytes()); // reserved
    buffer.extend(0u16.to_le_bytes()); // substitute name offset
    buffer.extend(name_length(&substitute_bytes).to_le_bytes());
    buffer.extend((substitute_bytes.len() as u16).to_le_bytes()); // print name offset
    buffer.extend(name_length(&print_bytes).to_le_bytes());
    buffer.extend(substitute_bytes);
    buffer.extend(print_bytes);
    Ok(buffer)
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;

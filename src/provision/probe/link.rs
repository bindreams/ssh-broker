//! The junction `verify`'s link row reads through.
//!
//! RedirectionGuard refuses to follow a link that a non-administrator made, so a junction proves
//! something only when a token below High made it and the token under test follows it. A junction
//! needs no privilege, unlike a symbolic link, so the row is never untestable for want of one.
//!
//! A directory holds the junction, the folder it points at and the file read through it, so removing the
//! directory removes all three. Who names it and removes it is in `provision::probe_run`.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, GetVolumeInformationByHandleW,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows::Win32::System::SystemServices::{FILE_SUPPORTS_REPARSE_POINTS, IO_REPARSE_TAG_MOUNT_POINT};

use super::{JUNCTION_SAID, SymlinkState};
use crate::route::ProbeLink;

/// The junction, and the folder and file it leads to, inside the directory [`make`] is given.
const LINK_NAME: &str = "link";
const TARGET_NAME: &str = "target";
const FILE_NAME: &str = "parity.txt";
const FILE_CONTENT: &[u8] = b"parity";

/// `ERROR_UNTRUSTED_MOUNT_POINT`: what a process under RedirectionGuard gets when it follows a
/// junction that a non-administrator made.
const UNTRUSTED_MOUNT_POINT: i32 = 448;

/// A directory under `parent` for one run's junction, with a name no other run has: the process id, the
/// time and a count.
pub fn unique_dir(parent: &Path) -> PathBuf {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    parent.join(format!(
        "sb-junction-{}-{nanos:x}-{}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Where [`make`] failed, which decides what the failure means: the volume holds no junctions, or the
/// junction could not be made on one that does.
#[derive(Debug)]
pub enum MakeError {
    /// The volume says it holds no reparse points, so no junction was tried: it was not tested
    /// ([`SymlinkState::Skipped`]).
    NoJunctions,
    /// Anything else that went wrong, on a volume that holds junctions or when it could not be asked: a
    /// fault ([`SymlinkState::NotMade`]).
    NotMade(io::Error),
}

impl MakeError {
    pub fn state(&self) -> SymlinkState {
        match self {
            MakeError::NoJunctions => SymlinkState::Skipped,
            MakeError::NotMade(_) => SymlinkState::NotMade,
        }
    }

    /// What the probe says about it, for the row.
    pub fn said(&self, dir: &Path) -> String {
        match self {
            MakeError::NoJunctions => format!("the volume of {} holds no junctions", dir.display()),
            MakeError::NotMade(e) => format!("making a junction in {} failed: {e}", dir.display()),
        }
    }
}

/// Make `dir`, which must not exist, with the folder, the file and the junction in it. A path that
/// exists is an error and is left as it is.
pub fn make(dir: &Path) -> Result<(), MakeError> {
    std::fs::create_dir(dir).map_err(MakeError::NotMade)?;
    complete(dir)
}

/// Finish the directory [`make`] created. One that cannot be finished is removed again, and one that
/// cannot be removed is said on stderr.
fn complete(dir: &Path) -> Result<(), MakeError> {
    make_in(dir).inspect_err(|_| {
        if let Err(e) = remove(dir) {
            eprintln!(
                "{JUNCTION_SAID}removing the half-made directory {} failed: {e}",
                dir.display()
            );
        }
    })
}

fn make_in(dir: &Path) -> Result<(), MakeError> {
    let not_made = MakeError::NotMade;
    let target = dir.join(TARGET_NAME);
    std::fs::create_dir(&target).map_err(not_made)?;
    std::fs::write(target.join(FILE_NAME), FILE_CONTENT).map_err(not_made)?;
    let link = dir.join(LINK_NAME);
    std::fs::create_dir(&link).map_err(not_made)?;
    let handle = open_directory(&link).map_err(not_made)?;
    // The one question to the volume: what it says it cannot hold is not tested, and every failure after
    // it is a fault.
    if !holds_reparse_points(volume_flags(&handle).map_err(not_made)?) {
        return Err(MakeError::NoJunctions);
    }
    let buffer = mount_point_buffer(&std::path::absolute(&target).map_err(not_made)?).map_err(not_made)?;
    set_reparse_point(&handle, &buffer).map_err(not_made)
}

/// What a probe does about the junction of the link row ([`ProbeLink`]): the outcome of reading through
/// it, or `None` for a probe that was given no junction to make or follow. A directory that could not be
/// made is [`SymlinkState::NotMade`]; a volume that holds no junctions was not tested
/// ([`SymlinkState::Skipped`]). Whatever it could not do is on stderr, each line after [`JUNCTION_SAID`],
/// for `verify` to show.
pub fn run(link: &ProbeLink) -> Option<SymlinkState> {
    match link {
        ProbeLink::NoJunction => None,
        ProbeLink::Follow(dir) => Some(follow(Path::new(dir))),
        ProbeLink::Make(dir) => Some(made_and_followed(Path::new(dir))),
    }
}

/// Make the junction in `dir` and read through it.
fn made_and_followed(dir: &Path) -> SymlinkState {
    match make(dir) {
        Err(e) => {
            eprintln!("{JUNCTION_SAID}{}", e.said(dir));
            e.state()
        }
        Ok(()) => follow(dir),
    }
}

/// Read the file through the junction in `dir` as this process, and say what happened. Any failure
/// but RedirectionGuard's refusal is [`SymlinkState::Failed`], with its cause on stderr.
pub fn follow(dir: &Path) -> SymlinkState {
    let (state, note) = judge_read(dir, std::fs::read(dir.join(LINK_NAME).join(FILE_NAME)));
    if let Some(note) = note {
        eprintln!("{JUNCTION_SAID}{note}");
    }
    state
}

/// What a read through the junction in `dir` came to: the file's content is the probe's
/// ([`SymlinkState::Ok`]), or the read was refused as an untrusted mount point
/// ([`SymlinkState::Blocked`]), or it failed. The note says why for a read that failed or gave other
/// content, and is `None` for a followed junction and for RedirectionGuard's refusal, which is an outcome
/// of its own.
fn judge_read(dir: &Path, read: io::Result<Vec<u8>>) -> (SymlinkState, Option<String>) {
    match read {
        Ok(content) if content == FILE_CONTENT => (SymlinkState::Ok, None),
        Ok(_) => (
            SymlinkState::Failed,
            Some(format!(
                "reading through the junction in {} gave content that differs from the {:?} that was written",
                dir.display(),
                String::from_utf8_lossy(FILE_CONTENT)
            )),
        ),
        Err(e) if e.raw_os_error() == Some(UNTRUSTED_MOUNT_POINT) => (SymlinkState::Blocked, None),
        Err(e) => (
            SymlinkState::Failed,
            Some(format!("reading through the junction in {} failed: {e}", dir.display())),
        ),
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

/// Open the directory `link` itself, not what it may point at, to make it a junction.
fn open_directory(link: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(link)
}

/// The file system flags of the volume `handle` is open on.
fn volume_flags(handle: &std::fs::File) -> io::Result<u32> {
    let mut flags = 0u32;
    // SAFETY: `handle` is an open directory; `flags` is a live `u32` and the other outputs are not asked for.
    unsafe { GetVolumeInformationByHandleW(HANDLE(handle.as_raw_handle()), None, None, None, Some(&mut flags), None) }
        .map_err(io::Error::from)?;
    Ok(flags)
}

/// Whether a volume with these file system flags holds reparse points, and so junctions.
fn holds_reparse_points(flags: u32) -> bool {
    flags & FILE_SUPPORTS_REPARSE_POINTS != 0
}

/// Make the empty directory `handle` is open on a junction, with `buffer` from [`mount_point_buffer`].
fn set_reparse_point(handle: &std::fs::File, buffer: &[u8]) -> io::Result<()> {
    let length = u32::try_from(buffer.len()).map_err(|_| io::Error::other("the junction's target path is too long"))?;
    // With no `OVERLAPPED` the call needs somewhere to put the byte count, though there is no output.
    let mut returned = 0u32;
    // SAFETY: `handle` is an open directory, and `buffer` is a whole `REPARSE_DATA_BUFFER` for a mount
    // point that outlives the call; `returned` is a live `u32`.
    unsafe {
        DeviceIoControl(
            HANDLE(handle.as_raw_handle()),
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            length,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(io::Error::from)
}

/// How each form of a path starts and what the kernel's name for it starts with, in the order they are
/// tried: the longer form of a prefix before the shorter, a UNC share (`\\server\share`) before a drive path,
/// which is what is left.
const KERNEL_PREFIXES: [(&str, &str); 6] = [
    (r"\\?\UNC\", r"\??\UNC\"),
    (r"\\.\UNC\", r"\??\UNC\"),
    (r"\\?\", r"\??\"),
    (r"\\.\", r"\??\"),
    (r"\\", r"\??\UNC\"),
    ("", r"\??\"),
];

/// The `REPARSE_DATA_BUFFER` of a mount point to `target`: the header, the substitute name
/// (`\??\C:\target`, the form the kernel follows) and the print name, each followed by a NUL.
fn mount_point_buffer(target: &Path) -> io::Result<Vec<u8>> {
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let utf16 = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
    let substitute = KERNEL_PREFIXES
        .iter()
        .find_map(|(prefix, kernel)| {
            let rest = print.strip_prefix(utf16(prefix).as_slice())?;
            Some([utf16(kernel).as_slice(), rest].concat())
        })
        .expect("the last prefix is empty and matches any path");
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

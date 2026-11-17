//! winutil: shared Windows RAII guards, the process-thread attribute-list helper, and the process
//! token with its information (Windows-only).
//!
//! Used by `conpty` (the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE list), `pipes` and the shim's fail-open start
//! (`shim_pty::start_local`) (the PROC_THREAD_ATTRIBUTE_HANDLE_LIST list), so the attribute-list
//! create/cleanup and the process start are written and reasoned about once. `own_token` and
//! `token_information` are the one reader of a token: callers take a class from it and read the bytes
//! through the checked `header` and `array`, and follow a SID pointer in them through the checked `sid`.
//! `find_group` is the one walk of a token's groups.

mod file_id;
pub use file_id::FileId;
mod unelevated;
pub use unelevated::UnelevatedToken;

use crate::shell::StartError;
use anyhow::Context;
use std::mem::offset_of;
use windows::Win32::Foundation::{CloseHandle, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, PSID, SID, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenGroups,
};
use windows::Win32::System::Console::HPCON;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadErrorMode, SEM_FAILCRITICALERRORS, SetThreadErrorMode, THREAD_ERROR_MODE,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    UpdateProcThreadAttribute,
};
use windows::core::{PCWSTR, PWSTR};

/// Owns a `HANDLE`, calling `CloseHandle` on drop (no-op on an invalid handle).
pub struct OwnedHandle(pub HANDLE);

// SAFETY: an `OwnedHandle` is the SOLE owner of its kernel handle (no aliasing — handles
// flow into threads by ownership transfer, never shared). Moving sole ownership to another
// thread, which then closes it exactly once, is sound — the same reasoning as `Box<T>`.
// (Windows kernel handles are process-global, valid from any thread.)
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    /// The raw handle as `isize`, for passing to a relay thread (HANDLE is not `Send`).
    pub fn raw(&self) -> isize {
        self.0.0 as isize
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// A `TOKEN_QUERY` handle on this process's token. Read the token through this handle (`userdir`,
/// `account::elevation`, [`token_information`]); a read that needs more access than `TOKEN_QUERY`
/// opens its own.
pub fn own_token() -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer; the handle is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("open the process token")?;
    Ok(OwnedHandle(token))
}

/// What `GetTokenInformation` returned: exactly those bytes, in the storage the call filled, aligned
/// for the structures that hold pointers. The pointers Windows writes into the data are absolute
/// addresses of its own buffer, so the data is never copied or moved: the value owns the buffer and
/// hands out reads of it. Read the structure at the start with [`header`](Self::header) and
/// [`array`](Self::array), and follow a SID pointer in it only through [`sid`](Self::sid).
pub struct TokenInformation {
    storage: Vec<u64>,
    len: usize,
}

impl TokenInformation {
    fn start(&self) -> *const u8 {
        self.storage.as_ptr().cast()
    }

    /// The structure at the start of the data, copied out. An error when the data is shorter than `T`.
    ///
    /// # Safety
    /// Every bit pattern of `size_of::<T>()` bytes must be a valid `T`: plain integers, and raw
    /// pointers (never dereferenced here), not `bool`, enums or references.
    pub unsafe fn header<T: Copy>(&self) -> anyhow::Result<T> {
        const { assert!(align_of::<T>() <= align_of::<u64>()) };
        anyhow::ensure!(
            size_of::<T>() <= self.len,
            "the token information is {} bytes, shorter than its {}-byte header",
            self.len,
            size_of::<T>()
        );
        // SAFETY: the storage is 8-aligned, holds at least `size_of::<T>()` initialised bytes
        // (checked above), and the caller promises every bit pattern is a `T`.
        Ok(unsafe { self.start().cast::<T>().read() })
    }

    /// `count` elements of `T` that start `offset` bytes into the data (for a `TOKEN_GROUPS`, the
    /// `offset_of!` its `Groups`). An error when `offset` does not suit `T` or the elements run
    /// past the data.
    ///
    /// # Safety
    /// As for [`header`](Self::header): every bit pattern of `T` must be valid.
    pub unsafe fn array<T: Copy>(&self, offset: usize, count: usize) -> anyhow::Result<&[T]> {
        const { assert!(align_of::<T>() <= align_of::<u64>()) };
        anyhow::ensure!(
            offset.is_multiple_of(align_of::<T>()),
            "the token information's array starts at {offset}, which does not suit its elements"
        );
        let end = count
            .checked_mul(size_of::<T>())
            .and_then(|bytes| bytes.checked_add(offset));
        anyhow::ensure!(
            end.is_some_and(|end| end <= self.len),
            "the token information claims {count} elements at {offset} in {} bytes",
            self.len
        );
        // SAFETY: the elements lie inside the initialised bytes (checked above), the start is
        // aligned for `T` (the storage is 8-aligned and `offset` a multiple of `align_of::<T>()`),
        // and the caller promises every bit pattern is a `T`.
        Ok(unsafe { std::slice::from_raw_parts(self.start().add(offset).cast::<T>(), count) })
    }

    /// `sid` once it is known to lie wholly inside the data; an error if it is null, outside the
    /// data, misaligned, or its header or sub-authorities run past the end. The pointer is only
    /// compared, never read; the result is the one to hand to Windows.
    pub fn sid(&self, sid: PSID) -> anyhow::Result<PSID> {
        /// Everything in a SID before its sub-authorities.
        const HEADER: usize = offset_of!(SID, SubAuthority);
        const COUNT_AT: usize = offset_of!(SID, SubAuthorityCount);
        const SUB_AUTHORITY: usize = size_of::<u32>();

        anyhow::ensure!(!sid.0.is_null(), "the token information holds a null SID");
        let offset = (sid.0 as usize)
            .checked_sub(self.start() as usize)
            .filter(|&offset| offset <= self.len)
            .context("the token information holds a SID outside itself")?;
        anyhow::ensure!(
            offset.is_multiple_of(align_of::<u32>()),
            "the token information holds a SID that is not aligned for its sub-authorities"
        );
        let room = self.len - offset;
        anyhow::ensure!(
            room >= HEADER,
            "the token information holds a SID whose header runs past its end"
        );
        // SAFETY: the header lies inside the initialised bytes (checked above).
        let count = usize::from(unsafe { self.start().add(offset + COUNT_AT).read() });
        anyhow::ensure!(
            HEADER + count * SUB_AUTHORITY <= room,
            "the token information holds a SID whose {count} sub-authorities run past its end"
        );
        // SAFETY: `offset <= self.len`, so the result stays inside the storage.
        Ok(PSID(unsafe { self.start().add(offset) }.cast_mut().cast()))
    }
}

/// The attribute bits of a token group (`SID_AND_ATTRIBUTES::Attributes`, winnt.h).
pub const SE_GROUP_ENABLED: u32 = 0x4;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
/// The attribute of an integrity label.
pub const SE_GROUP_INTEGRITY: u32 = 0x20;
/// Both bits of the mask are set on a logon SID.
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

/// The result of the first group of `token` for which `pick` answers `Some`; `None` when none does.
/// `pick` gets each group's SID, which lies inside the token information it was read from (so it is
/// valid only during the call: copy it to keep it), and the group's attributes (the `SE_GROUP_*`
/// constants). An error of `pick`, or of reading the groups, ends the walk. Needs `TOKEN_QUERY`.
pub fn find_group<T>(
    token: HANDLE,
    mut pick: impl FnMut(PSID, u32) -> anyhow::Result<Option<T>>,
) -> anyhow::Result<Option<T>> {
    let buf = token_information(token, TokenGroups).context("read the token's groups")?;
    // SAFETY: the group count is a `u32`.
    let count = unsafe { buf.header::<u32>() }.context("read the token's group count")?;
    // SAFETY: every bit pattern is a valid `SID_AND_ATTRIBUTES` (a pointer and an integer).
    let groups = unsafe { buf.array::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), count as usize) }
        .context("read the token's groups")?;
    for group in groups {
        let sid = buf.sid(group.Sid).context("read a group of the token")?;
        if let Some(found) = pick(sid, group.Attributes)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// `class` of `token`, which needs `TOKEN_QUERY`. Every error carries Windows' reason; a handle
/// without the access fails with it, not with a length.
pub fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> anyhow::Result<TokenInformation> {
    read_information(|storage, told, returned| {
        // An empty storage is the documented size probe: a null buffer.
        let buffer = (!storage.is_empty()).then(|| storage.as_mut_ptr().cast());
        // SAFETY: `storage` holds at least `told` bytes, which is what the call is told, and is 8-aligned.
        unsafe { GetTokenInformation(token, class, buffer, told, returned) }
    })
}

/// Reads through `read`, a call with the shape of `GetTokenInformation`: it gets storage, the length it
/// may write and where to put the length it returned or needs. It is called first with no storage, as
/// the size probe, then with new zeroed storage of the length it reported, again and with new storage
/// of the length it reports each time it fails with `ERROR_INSUFFICIENT_BUFFER` or `ERROR_BAD_LENGTH`
/// and a length larger than it was given (the data grew since the last call). Storage is never
/// carried over: Windows writes absolute pointers into it. Any other failure is returned with Windows'
/// reason, as is one that reports no larger length.
fn read_information(
    mut read: impl FnMut(&mut [u64], u32, &mut u32) -> windows::core::Result<()>,
) -> anyhow::Result<TokenInformation> {
    let mut told = 0u32;
    let probe = read(&mut [], 0, &mut told);
    // A probe that set a length is fine whatever it returned (`ERROR_INSUFFICIENT_BUFFER` is the
    // usual); one that set none has nothing to size the read by.
    if told == 0 {
        return Err(match probe {
            Err(e) => anyhow::Error::new(e).context("GetTokenInformation (size probe)"),
            Ok(()) => anyhow::anyhow!("the token information size probe returned no length"),
        });
    }
    loop {
        let mut storage = vec![0u64; (told as usize).div_ceil(size_of::<u64>())];
        let mut returned = told;
        match read(&mut storage, told, &mut returned) {
            Ok(()) => {
                anyhow::ensure!(
                    returned <= told,
                    "GetTokenInformation returned {returned} bytes into a buffer of {told}"
                );
                return Ok(TokenInformation {
                    storage,
                    len: returned as usize,
                });
            }
            Err(e) if returned > told && is_too_small(&e) => told = returned,
            Err(e) => return Err(anyhow::Error::new(e).context("GetTokenInformation")),
        }
    }
}

/// Whether `error` says the buffer given was too small or of the wrong length.
fn is_too_small(error: &windows::core::Error) -> bool {
    [ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH]
        .iter()
        .any(|code| error.code() == windows::core::HRESULT::from_win32(code.0))
}

/// While alive, a program that `CreateProcessW` cannot start (the wrong architecture, a file that is not
/// a program, a blocked one) makes the call fail on this thread. Without it the call raises a message
/// box on the session's desktop and waits for an answer, which nobody gives in a session that is not
/// watched. It is the thread's error mode: the process, and so the programs it starts, are untouched.
/// The flag is added to the mode the thread has, and that mode is what the drop puts back.
pub struct FailCriticalErrors {
    /// The mode to put back; `None` when the mode was not changed.
    restore: Option<THREAD_ERROR_MODE>,
}

impl FailCriticalErrors {
    pub fn enter() -> Self {
        // SAFETY: no pointers.
        let previous = THREAD_ERROR_MODE(unsafe { GetThreadErrorMode() });
        // SAFETY: no pointers.
        let set = unsafe { SetThreadErrorMode(THREAD_ERROR_MODE(previous.0 | SEM_FAILCRITICALERRORS.0), None) };
        match set {
            Ok(()) => FailCriticalErrors {
                restore: Some(previous),
            },
            Err(e) => {
                tracing::warn!("could not switch off the message boxes of a failed start: {e}");
                FailCriticalErrors { restore: None }
            }
        }
    }
}

impl Drop for FailCriticalErrors {
    fn drop(&mut self) {
        if let Some(previous) = self.restore {
            // SAFETY: no pointers.
            let _ = unsafe { SetThreadErrorMode(previous, None) };
        }
    }
}

/// The error of a `CreateProcessW` (or `CreateProcessAsUserW`, with `with_token`) that failed. Blames the
/// program unless the failure is the machine's ([`is_not_the_programs`]); an unknown cause blames the
/// program, since that yields a working built-in shell plus a warning. A `cwd` that is not a directory names
/// the directory instead. With a token, `ERROR_PRIVILEGE_NOT_HELD` is the machine's: the built-in shell,
/// started with the same token, fails the same way.
pub fn start_error_of_create(
    error: windows::core::Error,
    cwd: Option<&std::path::Path>,
    with_token: bool,
) -> StartError {
    match cwd {
        Some(cwd) if !cwd.is_dir() => StartError::Other(anyhow::anyhow!(
            "the working directory {} is not a directory: {error}",
            cwd.display()
        )),
        _ if with_token && is_privilege_not_held(&error) => StartError::Other(
            anyhow::Error::new(error)
                .context("this process lacks a privilege to start a child with the token it was given"),
        ),
        _ if is_not_the_programs(&error) => StartError::Other(error.into()),
        _ => StartError::Program(error.into()),
    }
}

/// Whether `error` is `ERROR_PRIVILEGE_NOT_HELD`, as a Win32 code made into an HRESULT.
fn is_privilege_not_held(error: &windows::core::Error) -> bool {
    error.code() == windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD.0)
}

/// Whether `error` is a Win32 code for a cause that is not the program: the machine ran out of
/// memory, handles, processes, quota or commit. Any other code, listed or not, is held against the
/// program, a bad handle, parameter or buffer included: an image-specific condition can produce those
/// too, and blaming the machine for one ends the session.
fn is_not_the_programs(error: &windows::core::Error) -> bool {
    use windows::Win32::Foundation::{
        ERROR_COMMITMENT_LIMIT, ERROR_NO_PROC_SLOTS, ERROR_NO_SYSTEM_RESOURCES, ERROR_NONPAGED_SYSTEM_RESOURCES,
        ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_QUOTA, ERROR_NOT_ENOUGH_SERVER_MEMORY, ERROR_OUTOFMEMORY,
        ERROR_PAGED_SYSTEM_RESOURCES, ERROR_PAGEFILE_QUOTA, ERROR_PAGEFILE_QUOTA_EXCEEDED, ERROR_TOO_MANY_OPEN_FILES,
        ERROR_WORKING_SET_QUOTA,
    };
    // An HRESULT made from a Win32 code: severity and the Win32 facility, then the code.
    let hresult = error.code().0 as u32;
    if hresult >> 16 != 0x8007 {
        return false;
    }
    let code = hresult & 0xFFFF;
    [
        ERROR_TOO_MANY_OPEN_FILES,
        ERROR_NOT_ENOUGH_MEMORY,
        ERROR_OUTOFMEMORY,
        ERROR_NO_PROC_SLOTS,
        ERROR_PAGEFILE_QUOTA_EXCEEDED,
        ERROR_NOT_ENOUGH_SERVER_MEMORY,
        ERROR_NO_SYSTEM_RESOURCES,
        ERROR_NONPAGED_SYSTEM_RESOURCES,
        ERROR_PAGED_SYSTEM_RESOURCES,
        ERROR_WORKING_SET_QUOTA,
        ERROR_PAGEFILE_QUOTA,
        ERROR_COMMITMENT_LIMIT,
        ERROR_NOT_ENOUGH_QUOTA,
    ]
    .iter()
    .any(|known| known.0 == code)
}

/// A failure of anything but `CreateProcessW` while starting a program is not the program's.
impl From<windows::core::Error> for StartError {
    fn from(error: windows::core::Error) -> Self {
        StartError::Other(error.into())
    }
}

/// An anonymous pipe that hands bytes to a child through a handle it inherits (see [`crate::handoff`]).
///
/// Only the read end is inheritable, and a child gets it only by naming it in a
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The write end stays with the agent.
pub struct Handoff {
    read: OwnedHandle,
    write: std::fs::File,
}

impl Handoff {
    /// A pipe buffered for `capacity` bytes (0: the default size), so a write of up to that many
    /// returns without a reader.
    pub fn new(capacity: u32) -> windows::core::Result<Handoff> {
        use std::os::windows::io::FromRawHandle;
        use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows::Win32::System::Pipes::CreatePipe;
        let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
        // SAFETY: both are valid out pointers.
        unsafe { CreatePipe(&mut read, &mut write, None, capacity)? };
        let read = OwnedHandle(read);
        // SAFETY: `write` is a new handle that nothing else owns.
        let write = unsafe { std::fs::File::from_raw_handle(write.0) };
        // SAFETY: no pointers.
        unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)? };
        Ok(Handoff { read, write })
    }

    /// The read end, to name in the child's handle list; its value is the same in the child.
    pub fn read(&self) -> &OwnedHandle {
        &self.read
    }

    /// Write `bytes`, then close the pipe so the child sees the end of them. Call it after the child
    /// has started: this process's own copy of the read end is closed first, so a child that is gone
    /// makes the write fail instead of wait, and one that is alive reads while this writes.
    pub fn send(self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let Handoff { read, mut write } = self;
        drop(read);
        write.write_all(bytes)
    }
}

/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (processthreadsapi.h) — restrict the child's inherited handles
/// to exactly those listed. (windows-rs 0.62 doesn't export it as a usable `usize` FFI value; named
/// here with its documented value.)
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

/// One attribute of an [`AttrList`]: `value` and `size` are passed VERBATIM to
/// `UpdateProcThreadAttribute`; see [`AttrList::new`].
#[derive(Clone, Copy)]
pub struct Attr {
    pub attribute: usize,
    pub value: *const core::ffi::c_void,
    pub size: usize,
}

/// A process-thread attribute list. Holds exactly the attributes it was made with. Frees the list's internal
/// allocations (`DeleteProcThreadAttributeList`) on drop; the backing buffer frees with it.
/// The buffer is `Vec<usize>` so it is pointer-aligned (the list stores pointers internally).
pub struct AttrList {
    _buf: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttrList {
    /// Build a list of `attributes`. Each `value` and `size` are passed VERBATIM to
    /// `UpdateProcThreadAttribute`, so their meaning depends on `attribute`: for some
    /// attributes `value` is a pointer to a `size`-byte buffer (e.g. `HANDLE_LIST` → an
    /// array of `HANDLE`s); for others it is the value encoded directly in the pointer with
    /// `size` describing that value's width (e.g. `PSEUDOCONSOLE` → the HPCON value itself,
    /// `size = size_of::<HPCON>()`). Any buffer a `value` points to must outlive the eventual
    /// `CreateProcessW`.
    ///
    /// # Safety
    /// Every `(attribute, value, size)` must be a valid combination per the Win32 documentation, and
    /// the attributes must be distinct.
    pub unsafe fn new(attributes: &[Attr]) -> windows::core::Result<AttrList> {
        let count = attributes.len() as u32;
        let mut bytes: usize = 0;
        // First call computes the required size (returns an expected error).
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
        // Pointer-aligned backing buffer, rounded up to whole `usize`s.
        let words = bytes.div_ceil(std::mem::size_of::<usize>()).max(1);
        let mut buf: Vec<usize> = vec![0usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut _);
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut bytes)? };
        // Guard NOW so a failure of UpdateProcThreadAttribute still runs the delete.
        let owned = AttrList { _buf: buf, list };
        for Attr { attribute, value, size } in attributes {
            unsafe { UpdateProcThreadAttribute(list, 0, *attribute, Some(*value), *size, None, None)? };
        }
        Ok(owned)
    }

    /// A list of one attribute; see [`AttrList::new`].
    ///
    /// # Safety
    /// As for [`AttrList::new`].
    pub unsafe fn single(
        attribute: usize,
        value: *const core::ffi::c_void,
        size: usize,
    ) -> windows::core::Result<AttrList> {
        unsafe { AttrList::new(&[Attr { attribute, value, size }]) }
    }

    /// The list pointer to store in `STARTUPINFOEXW.lpAttributeList`.
    pub fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

/// `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (processthreadsapi.h): binds a pseudoconsole to a process being
/// created. Named here with its documented value, like [`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`].
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

/// The console a child that ssh-broker starts runs on. Neither the agent (`agent::console`) nor a shim whose
/// stdio is sshd's pipes has a console that shows anything, and a console program started from a process
/// with none gets a new console with a window, so every start names the console it wants.
pub enum ChildConsole {
    /// A pseudoconsole: its host shows no window.
    Pseudo(HPCON),
    /// A console of its own with no window (`CREATE_NO_WINDOW`).
    NoWindow,
    /// The console this process has: no window flag. The shim's shell, which shares the terminal sshd gave
    /// the shim.
    Parent,
}

/// The creation flags of [`spawn_suspended`]: suspended (so the child can be put in a job before it runs),
/// an extended startup block, and the window policy of `console`.
fn creation_flags(console: &ChildConsole) -> PROCESS_CREATION_FLAGS {
    let window = match console {
        ChildConsole::Pseudo(_) | ChildConsole::Parent => PROCESS_CREATION_FLAGS(0),
        ChildConsole::NoWindow => CREATE_NO_WINDOW,
    };
    CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | window
}

/// The handles for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: `inherit` with each handle once, in order. A handle
/// named twice fails `CreateProcessW` (measured), and a terminal session's stdout and stderr can be one
/// console handle. A null or invalid handle in `inherit` is the caller's error: the list would refuse it.
fn handle_list(inherit: &[HANDLE]) -> Vec<HANDLE> {
    let mut list: Vec<HANDLE> = Vec::with_capacity(inherit.len());
    for handle in inherit {
        debug_assert!(!handle.is_invalid(), "a null or invalid handle on the inherit list");
        if !list.contains(handle) {
            list.push(*handle);
        }
    }
    list
}

/// Start `command` suspended on `console`, optionally in `cwd`, and return its process and primary thread. The
/// only way ssh-broker starts a session's program, so that none can omit the console policy, the handle list
/// or the message-box guard.
///
/// The child's standard handles are `std_handles` (input, output, error; null ones for a pseudoconsole). It
/// inherits exactly the handles in `inherit`, each once, and none when that is empty. With `as_user` the
/// child's token is that one (`CreateProcessAsUserW`), not this process's.
///
/// # Safety
/// Every handle in `inherit` is valid and inheritable, each handle in `std_handles` is valid and inheritable
/// or null, and `console`'s pseudoconsole is open.
pub unsafe fn spawn_suspended(
    command: &str,
    cwd: Option<&std::path::Path>,
    console: ChildConsole,
    std_handles: [HANDLE; 3],
    inherit: &[HANDLE],
    as_user: Option<&UnelevatedToken>,
) -> Result<(OwnedHandle, OwnedHandle), StartError> {
    use std::os::windows::ffi::OsStrExt;
    // The pseudoconsole attribute's value is the HPCON itself, never a pointer to it (that was the cause of
    // a 0xC0000142 DLL-init failure). `inherited` outlives the create call: the list stores its address.
    let pseudo = match &console {
        ChildConsole::Pseudo(hpc) => Some(Attr {
            attribute: PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            value: hpc.0 as *const core::ffi::c_void,
            size: std::mem::size_of::<HPCON>(),
        }),
        ChildConsole::NoWindow | ChildConsole::Parent => None,
    };
    let inherited = handle_list(inherit);
    let listed = (!inherited.is_empty()).then(|| Attr {
        attribute: PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        value: inherited.as_ptr() as *const core::ffi::c_void,
        size: std::mem::size_of_val(inherited.as_slice()),
    });
    let attributes: Vec<Attr> = pseudo.into_iter().chain(listed).collect();
    let attr = unsafe { AttrList::new(&attributes) }?;

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    [
        si.StartupInfo.hStdInput,
        si.StartupInfo.hStdOutput,
        si.StartupInfo.hStdError,
    ] = std_handles;
    si.lpAttributeList = attr.as_ptr();

    let mut line: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd_wide: Option<Vec<u16>> = cwd.map(|c| c.as_os_str().encode_wide().chain(std::iter::once(0)).collect());
    let cwd_ptr = cwd_wide.as_ref().map(|w| PCWSTR(w.as_ptr())).unwrap_or(PCWSTR::null());

    let mut pi = PROCESS_INFORMATION::default();
    let _no_boxes = FailCriticalErrors::enter();
    let inherits = !inherited.is_empty();
    let flags = creation_flags(&console);
    unsafe {
        match as_user {
            Some(token) => CreateProcessAsUserW(
                Some(token.handle()),
                PCWSTR::null(),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                inherits,
                flags,
                None,
                cwd_ptr,
                &si.StartupInfo,
                &mut pi,
            ),
            None => CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                inherits,
                flags,
                None,
                cwd_ptr,
                &si.StartupInfo,
                &mut pi,
            ),
        }
    }
    .map_err(|e| start_error_of_create(e, cwd, as_user.is_some()))?;
    Ok((OwnedHandle(pi.hProcess), OwnedHandle(pi.hThread)))
}

/// Turn a `cosca` failure into a Win32 error, keeping the real OS code when there is one.
///
/// Inventing a plausible code instead (this reported `ERROR_INVALID_HANDLE` for every
/// containment failure, whatever actually went wrong) sends whoever reads the log after an
/// incident chasing a cause that was never there.
pub fn win_error_from(e: &cosca::error::Error, context: &str) -> windows::core::Error {
    // Matched, not walked. `Error::Io` is `#[error(transparent)]`, and thiserror forwards
    // `source()` to the *inner* error's source — which for an `io::Error` is `None`. A chain
    // walk therefore never reaches the `io::Error` at all and silently reports a placeholder
    // for every failure, which is the same defect as hardcoding one. The wildcard is required:
    // `cosca::error::Error` is `#[non_exhaustive]`.
    use cosca::error::Error as E;
    let os = match e {
        E::Io(io) => io.raw_os_error().filter(|c| *c != 0),
        // These carry the OS error only when the OS was actually asked something.
        E::Unassessable { source: Some(io), .. } | E::IdentityRecord { source: Some(io), .. } => {
            io.raw_os_error().filter(|c| *c != 0)
        }
        _ => None,
    };
    let hr = os.map(|c| {
        // A negative code is already an encoded HRESULT (an `io::Error` built from one), and
        // widening it a second time would corrupt it; a positive code is a bare Win32 code.
        if c < 0 {
            windows::core::HRESULT(c)
        } else {
            windows::core::HRESULT::from_win32(c as u32)
        }
    });
    windows::core::Error::new(
        hr.unwrap_or(windows::Win32::Foundation::E_FAIL),
        format!("{context}: {e}"),
    )
}

/// Contain a suspended process in a job object, then let it run.
///
/// `process` must have been created `CREATE_SUSPENDED`. That is load-bearing, not tidiness:
/// assignment has to win the race against the process spawning anything, or a descendant is
/// born outside the job and survives teardown. If assignment fails the process is killed
/// rather than resumed — resuming it would produce exactly those unreachable descendants.
///
/// # Safety
/// `process` and `thread` must be the live handles from a successful `CreateProcess*` call.
pub unsafe fn contain_and_resume(process: HANDLE, thread: HANDLE, what: &str) -> windows::core::Result<cosca::Job> {
    use std::os::windows::io::{BorrowedHandle, RawHandle};
    use windows::Win32::System::Threading::{ResumeThread, TerminateProcess};

    // Borrowed for the call only; the caller owns the handle and outlives it.
    let job = match cosca::Job::assign(unsafe { BorrowedHandle::borrow_raw(process.0 as RawHandle) }) {
        Ok(job) => job,
        Err(e) => {
            // Uncontained AND still suspended, so it must not be resumed.
            if let Err(ke) = unsafe { TerminateProcess(process, 1) } {
                // Now also unkillable: say so, or this is a leaked suspended process whose
                // only trace is an unrelated error message.
                tracing::warn!("killing the unassigned {what} also failed: {ke}");
            }
            return Err(win_error_from(&e, &format!("assign the {what} to a job object")));
        }
    };
    if unsafe { ResumeThread(thread) } == u32::MAX {
        let err = windows::core::Error::from_thread();
        if let Err(ke) = job.kill_tree() {
            tracing::warn!("killing the unresumed {what} failed: {ke}");
        }
        return Err(err);
    }
    Ok(job)
}

#[cfg(test)]
#[path = "winutil_tests.rs"]
mod winutil_tests;

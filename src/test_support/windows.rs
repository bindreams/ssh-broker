//! Helpers shared by the Windows unit tests: reading a DACL by well-known SID alias, a snapshot of a
//! tree to compare, and a stand-in profile directory.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::socket_loc::{Integrity, SocketLocation};

// What a test compares, and the link it puts in the way -----

#[path = "../../tests/common/fs_state.rs"]
mod fs_state;
pub use fs_state::{dacl_sddl, junction, tree_state};

// A child's output -----

#[path = "../../tests/common/drain.rs"]
mod drain;
pub use drain::{drain, text_of};

// A copy of this process's token -----

#[path = "../../tests/common/token_copy.rs"]
mod token_copy;

/// A primary token with all access that is a copy of this process's.
pub fn own_token_copy() -> crate::winutil::OwnedHandle {
    crate::winutil::OwnedHandle(token_copy::own_token_copy())
}

/// [`own_token_copy`] with its integrity label set to `rid`, which is at or below the process's own.
pub fn own_token_at(rid: u32) -> crate::winutil::OwnedHandle {
    crate::winutil::OwnedHandle(token_copy::own_token_at(rid, crate::winutil::SE_GROUP_INTEGRITY))
}

// Reading a DACL by SID -----

pub const FILE_ALL: u32 = 0x1f_01ff;
pub const FILE_READ_EXECUTE: u32 = 0x12_00a9;

/// `(type, flags, access mask, trustee)` of each ACE in an SDDL DACL, in order.
pub fn aces(sddl: &str) -> Vec<(&str, &str, u32, &str)> {
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

// Changing a folder's ACL -----

/// `icacls <path> <args>`, which must succeed.
pub fn icacls(path: &std::path::Path, args: &[&str]) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let status = Command::new("icacls")
        .arg(path)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .unwrap();
    assert!(status.success(), "icacls {} {args:?}", path.display());
}

/// Give Everyone Full Control of the folder `dir`, inherited, on top of what it has: a private folder
/// that is no longer exactly private.
pub fn widen(dir: &std::path::Path) {
    icacls(dir, &["/grant", "*S-1-1-0:(OI)(CI)F"]);
}

// Another program's hold on a folder -----

/// Open `dir` with delete access, as a program that is about to delete or rename it does, and share
/// everything.
pub fn hold_for_deletion(dir: &std::path::Path) -> std::fs::File {
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

/// Open `dir` for reading and let others write and delete it but not read it.
pub fn hold_without_sharing_read(dir: &std::path::Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const SHARE_WRITE_DELETE: u32 = 2 | 4;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_WRITE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .unwrap_or_else(|e| panic!("hold {} without sharing read: {e}", dir.display()))
}

// A directory of a test's own -----

/// A new, empty directory under the temp dir, named as `doctor` names the directory of its junction
/// ([`crate::provision::probe::link::unique_dir`]), removed with what is in it on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        let path = crate::provision::probe::link::unique_dir(&std::env::temp_dir());
        std::fs::create_dir(&path).unwrap();
        Scratch(path)
    }

    pub fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.0).unwrap().next().is_none()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// A stand-in profile -----

/// A stand-in profile under the temp dir, removed on drop. `AppData\Local` exists inside it, as
/// it does in a real profile.
pub struct TempProfile(pub PathBuf);

impl TempProfile {
    pub fn new(tag: &str) -> TempProfile {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sb-ud-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(root.join("AppData").join("Local")).unwrap();
        TempProfile(root)
    }

    /// The plain folder's location, which most tests walk and bind in.
    pub fn location(&self) -> SocketLocation {
        self.location_at(Integrity::Medium)
    }

    /// The location for processes at `integrity`: for `High` the elevated folder, which only an
    /// elevated process can make (born labelled).
    pub fn location_at(&self, integrity: Integrity) -> SocketLocation {
        crate::socket_loc::for_profile(&self.0, integrity).expect("the stand-in profile path is short enough")
    }
}

/// The location in the profile `profile`, which need not exist: for a test that only connects to
/// the socket and never walks to the folder.
pub fn location_in(profile: &std::path::Path) -> SocketLocation {
    crate::socket_loc::for_profile(profile, Integrity::Medium).expect("the stand-in profile path is short enough")
}

impl Drop for TempProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A temp directory holding a copy of `cmd.exe` named like the installed exe, so that the process
/// snapshot lists what runs from it as an ssh-broker process. Removed on drop.
pub struct NamedCopy {
    dir: PathBuf,
}

impl NamedCopy {
    pub fn new(tag: &str) -> NamedCopy {
        let dir = std::env::temp_dir().join(format!("sb-named-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set")).join(r"System32\cmd.exe");
        std::fs::copy(cmd, dir.join(crate::provision::EXE_NAME)).unwrap();
        NamedCopy { dir }
    }

    pub fn exe(&self) -> PathBuf {
        self.dir.join(crate::provision::EXE_NAME)
    }

    /// Spawn the copy; cmd ignores `args` and exits when its stdin closes.
    pub fn spawn(&self, args: &[&str]) -> std::process::Child {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new(self.exe())
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }
}

impl Drop for NamedCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// A connected AF_UNIX pair -----

/// A connected AF_UNIX pair in a temp dir (no ACLs: these tests exercise the reply, not the security
/// boundary). Returns the server's socket, the client's and the dir to remove.
pub fn raw_socket_pair(tag: &str) -> (socket2::Socket, socket2::Socket, PathBuf) {
    use socket2::{Domain, SockAddr, Socket, Type};
    let dir = std::env::temp_dir().join(format!("sb-pair-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    listener.listen(1).unwrap();
    let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    client.connect(&SockAddr::unix(&path).unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client, dir)
}

/// The failure bound of a read in the tests that wait for a connection's end. A read that gets nothing
/// for this long has lost its wake, and says so as `TimedOut`, which an assertion names; nothing waits
/// for it to pass.
pub const LOST_WAKE_LIMIT: Duration = Duration::from_secs(30);

/// A child process started while a connection has one more holder than its halves must not keep the
/// connection open once all of ours are closed: the client's reader must see the end while the child
/// still runs, not a reset when the child ends. `holder` makes that holder from the server's
/// [`Conn`](crate::afunix::Conn), and it is dropped with the server's halves, after the child started.
pub fn assert_a_child_does_not_hold_a_connection_open<H>(tag: &str, holder: impl FnOnce(&crate::afunix::Conn) -> H) {
    use std::io::{Read, Write};
    let home = NamedCopy::new(tag);
    let (server, client, dir) = raw_socket_pair(tag);
    let (mut rx, client_tx) = crate::afunix::split(client).unwrap();
    rx.set_read_timeout(Some(LOST_WAKE_LIMIT));
    let conn = crate::afunix::Conn::new(server).unwrap();
    let (server_rx, mut server_tx) = conn.clone().split();
    let holding = holder(&conn);
    let mut child = home.spawn(&[]);
    server_tx.write_all(b"hello").unwrap();
    drop((conn, server_rx, server_tx, holding));

    let mut got = Vec::new();
    let read = rx.read_to_end(&mut got);
    // The child waits for its input to end; release it before asserting, so a failure leaves nothing running.
    drop(child.stdin.take());
    child.wait().unwrap();
    drop(client_tx);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        read.is_ok(),
        "no end while the child ran, so the child holds the connection: {read:?}"
    );
    assert_eq!(got, b"hello");
}

/// The stdout of `whoami <switch> /fo csv /nh`, which reads this process's token through another path
/// than the library and so is an independent source for a test.
pub fn whoami_csv(switch: &str) -> String {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("whoami")
        .args([switch, "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(out.status.success(), "whoami failed: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// Elevation -----

/// Fail loudly unless this process is an elevated administrator. For the tests that need it, so
/// they stop before they touch anything when run by hand on an ordinary host.
pub fn assert_elevated() {
    use crate::account::{Elevation, elevation};

    assert_eq!(
        elevation().unwrap(),
        Elevation::Full,
        "this test needs an elevated administrator (CI runs it); not running it here"
    );
}

// Scheduled tasks -----

use crate::provision::schtasks::{create_from_xml_argv, query_task_argv, xml_file_bytes};

/// A uniquely named throwaway scheduled task, deleted when dropped. Elevated tests only: `new`
/// refuses to run anywhere else, before it touches the Task Scheduler.
pub struct ThrowawayTask(pub String);

impl ThrowawayTask {
    pub fn new(tag: &str) -> ThrowawayTask {
        assert_elevated();
        ThrowawayTask(format!("ssh-broker-test-{tag}-{}", std::process::id()))
    }

    pub fn register(&self, xml: &str) {
        let file = std::env::temp_dir().join(format!("{}.xml", self.0));
        std::fs::write(&file, xml_file_bytes(xml)).unwrap();
        let out = Command::new("schtasks")
            .args(create_from_xml_argv(&self.0, &file.to_string_lossy()))
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&file);
        assert!(
            out.status.success(),
            "schtasks /Create failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn queried_xml(&self) -> String {
        let out = Command::new("schtasks")
            .args(query_task_argv(&self.0))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // A redirected `schtasks` may emit UTF-16 or the console code page.
        let bytes = out.stdout;
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let (pairs, _) = bytes[2..].as_chunks::<2>();
            String::from_utf16_lossy(&pairs.iter().copied().map(u16::from_le_bytes).collect::<Vec<_>>())
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
}

impl Drop for ThrowawayTask {
    fn drop(&mut self) {
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", &self.0, "/F"])
            .output();
    }
}

// Waiting for a pipe to fill, and for a process to end -----

/// What `CreatePipe(.., 0)` gives a pipe when `GetNamedPipeInfo` does not report its size. In CI a
/// pseudoconsole's output pipe held 4101 bytes with the shell blocked on it and nothing reading.
pub const DEFAULT_PIPE_BUFFER: u32 = 4096;

/// The bytes waiting in the pipe whose read end is `read`, or the reason they could not be counted.
/// `read` has to be open for the call.
pub fn pipe_pending(read: isize) -> Result<u32, String> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::PeekNamedPipe;

    let mut pending = 0u32;
    // SAFETY: a size query: no buffer; the caller keeps the handle open for the call.
    unsafe {
        PeekNamedPipe(
            HANDLE(read as *mut core::ffi::c_void),
            None,
            0,
            None,
            Some(&mut pending),
            None,
        )
    }
    .map(|()| pending)
    .map_err(|e| e.to_string())
}

/// The input buffer size of the pipe whose read end is `read`, in bytes, if the system reports one.
pub fn pipe_buffer(read: isize) -> Option<u32> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeInfo;

    let mut size = 0u32;
    // SAFETY: a size query on a handle the caller keeps open for the call.
    unsafe {
        GetNamedPipeInfo(
            HANDLE(read as *mut core::ffi::c_void),
            None,
            None,
            Some(&mut size),
            None,
        )
    }
    .ok()
    .filter(|()| size > 0)
    .map(|()| size)
}

/// Wait until at least `at_least` bytes are waiting in the pipe whose read end is `read`, by counting
/// them again after each pause: nothing signals that a pipe has filled. `Err` says why the bound ran
/// out, or why the bytes could not be counted. The bound is the failure the caller reports; the pause
/// only paces the counting.
pub fn wait_for_pipe_pending(read: isize, at_least: u32, bound: Duration) -> Result<u32, String> {
    let deadline = std::time::Instant::now() + bound;
    loop {
        let pending = pipe_pending(read).map_err(|e| format!("counting the bytes waiting failed: {e}"))?;
        if pending >= at_least {
            return Ok(pending);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "{pending} bytes were waiting after {bound:?}, short of {at_least}"
            ));
        }
        std::thread::sleep(Duration::from_millis(5)); // sleep-ok: paces the re-count of the real condition above; the bound is the failure report and the pause is not read as state
    }
}

/// Whether the process `process` (a handle the caller keeps open for the call) has ended, waiting up
/// to `bound` for an end that was asked for and may not come: `false` if the bound ran out.
pub fn process_ended_within(process: isize, bound: Duration) -> bool {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::WaitForSingleObject;

    let millis = u32::try_from(bound.as_millis()).map_or(u32::MAX - 1, |millis| millis.min(u32::MAX - 1));
    // SAFETY: the caller keeps the process handle open for the call.
    let woke = unsafe { WaitForSingleObject(HANDLE(process as *mut core::ffi::c_void), millis) }; // sleep-ok: failure bound on a process's end, an external event; expiry is reported and is not read as state
    woke == WAIT_OBJECT_0
}

// Naming a hang -----

/// Ends the process, with a message that says where the test was, if the test is still running
/// `bound` after this was made. For a test of code that may hang: nextest ends a hung test after its
/// own limit with no more than "running for over 60 seconds". The bound is the failure surfaced to a
/// human; nothing is concluded from the time passing but that the test did not finish.
///
/// The process is aborted, not the test panicked, because the thread that hangs is the test's own and
/// no panic reaches it.
pub struct Watchdog {
    done: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    /// `what` is the test's job; `seen` says how far it got, and is called on the watchdog's thread.
    pub fn arm(what: &'static str, bound: Duration, seen: impl Fn() -> String + Send + 'static) -> Watchdog {
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // The sender is dropped when the test ends, which wakes this with `Disconnected`.
            let ended = finished.recv_timeout(bound); // sleep-ok: failure bound on a hang of the test itself
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = ended {
                eprintln!("HANG: {what} did not finish within {bound:?}. Seen: {}", seen());
                std::process::abort();
            }
        });
        Watchdog {
            done: Some(done),
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        drop(self.done.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// Logging -----

/// Run `f` and return what it logged, with its result.
pub fn logged<T>(f: impl FnOnce() -> T) -> (String, T) {
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (log, result)
}

// The lines of `install` -----

/// What was said, in order, with the stream of each line.
pub type Said = Vec<(crate::provision::Stream, String)>;

/// A sink for the tests that do not look at what is said.
pub fn silent(_: crate::provision::Stream, _: &str) {}

/// A sink that records into `said`.
pub fn recording(said: &std::cell::RefCell<Said>) -> impl FnMut(crate::provision::Stream, &str) + '_ {
    |stream, text| said.borrow_mut().push((stream, text.to_owned()))
}

/// A line the shell step prints states what happened and holds no advice: the how-to is in the README
/// ("Shell configuration"), once.
pub fn states_facts_only(text: &str) {
    for advice in [
        "run install",
        "run `install`",
        "install again",
        "next install",
        "put it",
        "replace what",
        "write the config",
        "fix ",
        "to restore",
        "so it ",
        "so this ",
        "since ",
    ] {
        assert!(!text.contains(advice), "{advice}: {text}");
    }
}

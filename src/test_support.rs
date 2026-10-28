//! Helpers shared by the Windows unit tests: reading a DACL by well-known SID alias, and a
//! stand-in profile directory.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::socket_loc::SocketLocation;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::core::{PCWSTR, PWSTR};

// Reading a DACL by SID -----

pub const FILE_ALL: u32 = 0x1f_01ff;
pub const FILE_READ_EXECUTE: u32 = 0x12_00a9;

/// The DACL of `path` as an SDDL string (`D:AI(A;OICIID;FA;;;SY)...`). Well-known SIDs print as
/// two-letter aliases, so this does not depend on the display language.
pub fn dacl_sddl(path: &Path) -> String {
    let path_w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap();
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
        .unwrap();
        let sddl = text.to_string().unwrap();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut core::ffi::c_void)));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        sddl
    }
}

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

    pub fn location(&self) -> SocketLocation {
        crate::socket_loc::for_profile(&self.0).expect("the stand-in profile path is short enough")
    }
}

impl Drop for TempProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

// Elevation -----

/// Fail loudly unless this process is an elevated administrator. For the tests that need it, so
/// they stop before they touch anything when run by hand on an ordinary host.
pub fn assert_elevated() {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: valid out-pointers; the handle is closed below.
    let elevated = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
        let mut info = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && info.TokenIsElevated != 0
    };
    assert!(
        elevated,
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

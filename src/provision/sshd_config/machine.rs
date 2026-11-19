//! provision::sshd_config::machine — the machine behind [`SshdHost`]: the `ssh` folder of ProgramData, the
//! `sshd.exe` the service runs, and the service's process. Nothing here is decided; the flow is
//! [`configure`], which is tested against a stand-in. `tests/sshd_config_windows.rs` runs this against a real
//! sshd in CI.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FileBasicInfo, GetFileInformationByHandleEx,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Services::{
    CloseServiceHandle, SC_HANDLE, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
};
use windows::Win32::System::Threading::GetProcessTimes;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::PCWSTR;

use super::configure::{ConfigFile, ConfigFiles, DropInProblem, SshdHost, config_read, configure};
use super::restart::{ServiceState, StartOutcome, StartReply, StopOutcome};
use super::{DROP_IN_DIR_NAME, DROP_IN_NAME, SshdReading};
use crate::acl;
use crate::provision::procwait::Process;
use crate::provision::{registry, system_config};

mod listening;
mod service;

/// The candidate `sshd_config`, beside the original so that the rename that replaces it stays on one volume.
const CANDIDATE_NAME: &str = "sshd_config.ssh-broker-new";
/// The files of sshd, and the program `apply` runs to check them.
struct Machine {
    ssh_dir: PathBuf,
    /// The `sshd.exe` the service runs, found from the service's own `ImagePath`.
    sshd: PathBuf,
    /// The text after the program in that `ImagePath`, when there is some.
    arguments: Option<String>,
    /// The service as the controls and waits of the restart use it, opened when the first of them is asked.
    service: Option<service::SshdService>,
}

impl Machine {
    fn find() -> anyhow::Result<Machine> {
        let image = registry::read_sshd_image_path()
            .context("read where the sshd service runs from")?
            .context("there is no sshd service")?;
        let sshd = system_config::image_program(&image).context("the sshd service's ImagePath names no program")?;
        Ok(Machine {
            ssh_dir: program_data_dir()?.join("ssh"),
            sshd: PathBuf::from(sshd),
            arguments: system_config::image_arguments(&image).map(str::to_owned),
            service: None,
        })
    }

    fn service(&mut self) -> anyhow::Result<&service::SshdService> {
        if self.service.is_none() {
            self.service = Some(service::SshdService::open()?);
        }
        Ok(self.service.as_ref().expect("opened above"))
    }

    fn config(&self) -> PathBuf {
        self.ssh_dir.join("sshd_config")
    }

    fn drop_in_dir(&self) -> PathBuf {
        self.ssh_dir.join(DROP_IN_DIR_NAME)
    }

    fn drop_in(&self) -> PathBuf {
        self.drop_in_dir().join(DROP_IN_NAME)
    }

    /// Run `sshd` with `args` and return its standard output, or what it said on the way to failing.
    fn run_sshd(&self, args: &[&OsStr]) -> anyhow::Result<String> {
        let out = Command::new(&self.sshd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {}", self.sshd.display()))?;
        anyhow::ensure!(
            out.status.success(),
            "sshd exited with {}: {}",
            out.status.code().map_or("no code".to_owned(), |code| code.to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Why `path` is not a file only SYSTEM and Administrators can write. The step never advises removing it: what
/// is in `sshd_config.d` may be an administrator's own.
fn untrusted(path: &Path, problem: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} cannot be trusted as writable only by SYSTEM and Administrators: {problem}",
        path.display()
    )
}

impl SshdHost for Machine {
    fn config_path(&self) -> PathBuf {
        self.config()
    }

    fn service_arguments(&self) -> Option<String> {
        self.arguments.clone()
    }

    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String> {
        match config {
            None => self.run_sshd(&[OsStr::new("-T")]),
            Some(file) => self.run_sshd(&[OsStr::new("-T"), OsStr::new("-f"), file.as_os_str()]),
        }
    }

    fn sshd_check(&mut self, config: &Path) -> Result<(), String> {
        self.run_sshd(&[OsStr::new("-t"), OsStr::new("-f"), config.as_os_str()])
            .map(drop)
            .map_err(|e| format!("{e:#}"))
    }

    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>> {
        match service_process()? {
            None => Ok(None),
            Some(process) => process_started(&process).map(Some),
        }
    }

    fn settled(&mut self) -> anyhow::Result<ServiceState> {
        self.service()?.settled()
    }

    fn stop(&mut self) -> anyhow::Result<StopOutcome> {
        self.service()?.stop()
    }

    fn start(&mut self) -> StartOutcome {
        match self.service() {
            Ok(service) => service.start(),
            // Not reached by the flow, which reads the state (and so opens the service) first.
            Err(e) => StartOutcome::Unreadable {
                reply: StartReply::Refused(format!("no start was sent: {e:#}")),
                cause: "the sshd service could not be opened".to_owned(),
            },
        }
    }

    fn remove_drop_in(&mut self) -> anyhow::Result<()> {
        let path = self.drop_in();
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))
    }

    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    /// The folder's time is read after its files are listed, so a file that appears meanwhile moves it.
    fn config_files(&mut self) -> anyhow::Result<ConfigFiles> {
        let mut files = vec![read_with_change_time(&self.config())?];
        let dir = self.drop_in_dir();
        let present = match std::fs::read_dir(&dir) {
            Ok(entries) => {
                let mut paths = Vec::new();
                for entry in entries {
                    let entry = entry.with_context(|| format!("list {}", dir.display()))?;
                    if !entry
                        .file_type()
                        .with_context(|| format!("look at {}", entry.path().display()))?
                        .is_dir()
                    {
                        paths.push(entry.path());
                    }
                }
                paths.sort();
                for path in paths {
                    files.push(read_with_change_time(&path)?);
                }
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| format!("list {}", dir.display())),
        };
        let folder = if present {
            Some(change_time(&open_directory(&dir)?).with_context(|| format!("read when {} changed", dir.display()))?)
        } else {
            None
        };
        Ok(ConfigFiles { folder, files })
    }

    fn ensure_drop_in_dir(&mut self) -> Result<(), DropInProblem> {
        let dir = self.drop_in_dir();
        // The folder is made as the install directory is, with its descriptor and its judgement: what must hold
        // is that only administrators can write it. One that is there and is not exactly that is left alone.
        acl::create_install_dir(&dir).map_err(|e| DropInProblem::NotMade(format!("{e:#}")))?;
        match acl::install_dir_problem(&dir) {
            Ok(None) => Ok(()),
            Ok(Some(problem)) => Err(DropInProblem::Refused(format!(
                "it is not the folder apply makes: {problem}"
            ))),
            Err(e) => Err(DropInProblem::Refused(format!("{e:#}"))),
        }
    }

    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.drop_in();
        if let Err(e) = std::fs::symlink_metadata(&path) {
            return if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e).with_context(|| format!("look at {}", path.display()))
            };
        }
        // A file others can write would let them configure sshd, and a copy with the right text would pass.
        if let Some(problem) = acl::install_dir_file_problem(&path)? {
            return Err(untrusted(&path, &problem));
        }
        Ok(Some(
            std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        ))
    }

    /// The drop-in, and the file beside it that replaces it, get no descriptor of their own and inherit their
    /// folder's permissions, because the process that serves a connection before authentication reads the
    /// included file and is not an administrator. An administrator-only drop-in makes sshd reset every
    /// connection (measured in CI on Windows Server 2025, OpenSSH 9.5).
    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()> {
        let path = self.drop_in();
        // A drop-in that is there must already be what `apply` makes: it is replaced, never written into.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                if let Some(problem) = acl::install_dir_file_problem(&path)? {
                    return Err(untrusted(&path, &problem));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("look at {}", path.display())),
        }
        // The text goes into a new file beside the drop-in, flushed, and the new file replaces the drop-in in
        // one rename: a write that fails leaves the drop-in as it was. The name does not end in `.conf`, so
        // sshd's `Include` never reads it.
        let new = self.drop_in_dir().join(format!("{DROP_IN_NAME}.ssh-broker-new"));
        match std::fs::remove_file(&new) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("remove the leftover {}", new.display()));
            }
            _ => {}
        }
        let replaced = (|| {
            write_flushed(&new, text)?;
            if let Some(problem) = acl::install_dir_file_problem(&new)? {
                return Err(untrusted(&new, &problem));
            }
            replace_file(&new, &path).with_context(|| format!("rename {} over {}", new.display(), path.display()))
        })();
        if replaced.is_err() {
            let _ = std::fs::remove_file(&new);
        }
        replaced
    }

    fn read_config(&mut self) -> anyhow::Result<Vec<u8>> {
        let path = self.config();
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf> {
        let path = self.ssh_dir.join(CANDIDATE_NAME);
        write_flushed(&path, text)?;
        Ok(path)
    }

    fn copy_security(&mut self, candidate: &Path) -> anyhow::Result<()> {
        acl::copy_file_security(&self.config(), candidate)
    }

    fn replace_config(&mut self, candidate: &Path) -> anyhow::Result<()> {
        let config = self.config();
        replace_file(candidate, &config)
            .with_context(|| format!("rename {} over {}", candidate.display(), config.display()))
    }

    fn discard_candidate(&mut self) {
        // A candidate that cannot be removed is overwritten by the next run, and is read by nothing.
        let _ = std::fs::remove_file(self.ssh_dir.join(CANDIDATE_NAME));
    }
}

// files =====

/// The file at `path`: its bytes and when it last changed, both read through one handle.
fn read_with_change_time(path: &Path) -> anyhow::Result<ConfigFile> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let changed = change_time(&file).with_context(|| format!("read when {} changed", path.display()))?;
    let mut text = Vec::new();
    file.read_to_end(&mut text)
        .with_context(|| format!("read {}", path.display()))?;
    Ok(ConfigFile {
        path: path.to_owned(),
        changed,
        text,
    })
}

/// A handle on the folder `path` that can read its times and nothing else.
fn open_directory(path: &Path) -> anyhow::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

/// When the file or folder `file` is open on last changed: its `ChangeTime`, which a write, a rename and a
/// copy that keeps the old last-write time all move.
fn change_time(file: &std::fs::File) -> std::io::Result<SystemTime> {
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: the handle is open for the call and has the right to read attributes; `info` is the size the call
    // is told.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileBasicInfo,
            (&raw mut info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(std::io::Error::from)?;
    let ticks = info.ChangeTime as u64;
    system_time(FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    })
    .map_err(std::io::Error::other)
}

/// The file `path` holds `text`, and the text is on disk when this returns. A file that is there is truncated
/// and keeps its security descriptor.
fn write_flushed(path: &Path, text: &[u8]) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    file.write_all(text)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flush {} to disk", path.display()))
}

/// Rename `from` over `to`, which is replaced, and return when the rename is on disk: a power loss after it
/// cannot leave `to` empty.
fn replace_file(from: &Path, to: &Path) -> anyhow::Result<()> {
    let wide = |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain(Some(0)).collect() };
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(Into::into)
}

/// The ProgramData folder, as Windows says where it is (OpenSSH for Windows keeps `ssh` in it).
fn program_data_dir() -> anyhow::Result<PathBuf> {
    // SAFETY: the known-folder id is a constant; the returned string is read before it is freed, once.
    unsafe {
        let path = SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None)
            .context("ask Windows where ProgramData is")?;
        let dir = PathBuf::from(OsString::from_wide(path.as_wide()));
        CoTaskMemFree(Some(path.as_ptr().cast()));
        Ok(dir)
    }
}

// the service =====

/// Closes a service handle.
struct ScHandle(SC_HANDLE);

impl ScHandle {
    /// Close the handle and say whether the service manager closed it; the drop's close discards that.
    fn close(self) -> windows::core::Result<()> {
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: the handle was opened by `OpenSCManagerW` or `OpenServiceW`; `forget` leaves this the only close.
        unsafe { CloseServiceHandle(handle) }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `OpenSCManagerW` or `OpenServiceW` and is closed once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// What the service manager says about the sshd service: its state and the id of its process.
fn query_sshd() -> anyhow::Result<SERVICE_STATUS_PROCESS> {
    let (_manager, service) = service::open_handles(SERVICE_QUERY_STATUS)?;
    service::query(&service)
}

/// The id of the process the sshd service runs in; `None` when the service has none.
fn sshd_process_id() -> anyhow::Result<Option<u32>> {
    let status = query_sshd()?;
    Ok((status.dwCurrentState != SERVICE_STOPPED && status.dwProcessId != 0).then_some(status.dwProcessId))
}

/// The service's process, held by an open handle; `None` when the service has no process. The id is read from the
/// service manager, the process opened, and the id read again: when it is the same, the handle is the service's
/// process, for an id is not given to another process while a handle to it is open. Any other answer starts
/// over: there is no count, for it settles when the service does.
fn service_process() -> anyhow::Result<Option<Process>> {
    loop {
        let Some(id) = sshd_process_id()? else {
            return Ok(None);
        };
        let Some(process) =
            Process::open(id).with_context(|| format!("open the process of the sshd service ({id})"))?
        else {
            continue;
        };
        if sshd_process_id()? == Some(id) {
            return Ok(Some(process));
        }
    }
}

/// When the process held by `process` was created.
fn process_started(process: &Process) -> anyhow::Result<SystemTime> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the handle is open with the right to query; the out-pointers are locals.
    unsafe { GetProcessTimes(process.handle(), &mut created, &mut exited, &mut kernel, &mut user) }
        .with_context(|| format!("read when the process of the sshd service ({}) started", process.pid))?;
    system_time(created)
}

/// A `FILETIME` (100 ns ticks since 1601) as a `SystemTime`.
fn system_time(filetime: FILETIME) -> anyhow::Result<SystemTime> {
    const TICKS_AT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: u64 = 10_000_000;
    let ticks = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    let since = ticks.checked_sub(TICKS_AT_UNIX_EPOCH).context("a time before 1970")?;
    Ok(UNIX_EPOCH + Duration::new(since / TICKS_PER_SECOND, (since % TICKS_PER_SECOND) as u32 * 100))
}

// this machine =====

/// `apply`'s sshd step on this machine: see [`configure`]. It never fails: what it could not do is said on
/// `say`. An sshd that has not read the change is restarted through the service manager. Whether the running
/// sshd takes the variable (or reads it when it next starts) is returned.
pub fn configure_this_machine(say: &mut dyn FnMut(&str)) -> bool {
    match Machine::find() {
        Ok(mut machine) => configure(&mut machine, say),
        Err(e) => {
            say(&format!(
                "apply: cannot find sshd, so it was not set up to accept {}: {e:#}",
                crate::protocol::ElevationPolicy::VARIABLE
            ));
            false
        }
    }
}

/// This machine's sshd as [`SshdHost`], for a caller that drives its methods itself: the CI test that measures
/// the service manager's states through `settled`, `stop` and `start`.
pub fn sshd_host_of_this_machine() -> anyhow::Result<impl SshdHost> {
    Machine::find().context("cannot find sshd")
}

/// What the `verify` row is given about sshd on this machine: `sshd -T` (which needs the rights to read sshd's
/// host keys) and whether sshd started before a file of its configuration changed, or that the service runs
/// with arguments. An error says which question could not be answered.
pub fn sshd_reading_this_machine() -> anyhow::Result<SshdReading> {
    let mut machine = Machine::find().context("cannot find sshd")?;
    if let Some(arguments) = machine.service_arguments() {
        return Ok(SshdReading::WithArguments(arguments));
    }
    let listing = machine.sshd_t(None).context("cannot ask sshd for its configuration")?;
    let read = config_read(&mut machine).context("cannot tell whether sshd has read its configuration")?;
    Ok(SshdReading::Read { listing, read })
}

//! provision::sshd_config::machine — the machine behind [`SshdHost`]: the `ssh` folder of ProgramData, the
//! `sshd.exe` the service runs, the service itself, and `net.exe`. Nothing here is decided; the flow is
//! [`configure`], which is tested against a stand-in. `tests/sshd_config_windows.rs` runs this against a real
//! sshd in CI.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
};
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{PCWSTR, w};

use super::configure::{Service, ServiceOutcome, SshdHost, configure, net_outcome, unread_file};
use super::{DROP_IN_DIR_NAME, DROP_IN_NAME, SshdReading};
use crate::acl;
use crate::provision::{registry, system_config};
use crate::winutil::OwnedHandle;

/// The candidate `sshd_config`, beside the original so that the rename that replaces it stays on one volume.
const CANDIDATE_NAME: &str = "sshd_config.ssh-broker-new";

/// The files of sshd, and the programs `apply` runs to check and restart it.
struct Machine {
    ssh_dir: PathBuf,
    /// The `sshd.exe` the service runs, found from the service's own `ImagePath`.
    sshd: PathBuf,
    /// The text after the program in that `ImagePath`, when there is some.
    arguments: Option<String>,
    /// `net.exe` in the system directory.
    net: PathBuf,
}

impl Machine {
    fn find() -> anyhow::Result<Machine> {
        let image = registry::read_sshd_image_path()
            .context("read where the sshd service runs from")?
            .context("there is no sshd service")?;
        let sshd = system_config::image_program(&image).context("the sshd service's ImagePath names no program")?;
        let system_cmd = {
            use crate::shell::Host;
            crate::shell::WindowsHost.system_cmd()?
        };
        let net = system_cmd
            .parent()
            .context("the system directory has no name")?
            .join("net.exe");
        Ok(Machine {
            ssh_dir: program_data_dir()?.join("ssh"),
            sshd: PathBuf::from(sshd),
            arguments: system_config::image_arguments(&image).map(str::to_owned),
            net,
        })
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

/// Why `path` is not private to SYSTEM and Administrators. The step never advises removing it: what is in
/// `sshd_config.d` may be an administrator's own.
fn untrusted(path: &Path, problem: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} cannot be trusted as private to SYSTEM and Administrators: {problem}",
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

    fn service(&mut self, verb: Service) -> ServiceOutcome {
        let word = match verb {
            Service::Stop => "stop",
            Service::Start => "start",
        };
        // `net` returns once the service has stopped, or once it runs.
        match Command::new(&self.net)
            .args([word, "sshd"])
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) => {
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                net_outcome(verb, out.status.code().unwrap_or(-1), &said)
            }
            Err(e) => ServiceOutcome::Failed(format!("run {}: {e}", self.net.display())),
        }
    }

    fn service_started(&mut self) -> anyhow::Result<Option<SystemTime>> {
        match sshd_process_id()? {
            None => Ok(None),
            Some(id) => process_started(id).map(Some),
        }
    }

    fn config_written(&mut self) -> anyhow::Result<(PathBuf, SystemTime)> {
        let written = |path: &Path| -> anyhow::Result<Option<SystemTime>> {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    Ok(Some(metadata.modified().with_context(|| {
                        format!("read when {} was last written", path.display())
                    })?))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).with_context(|| format!("look at {}", path.display())),
            }
        };
        let config = self.config();
        let config_time = written(&config)?.with_context(|| format!("{} is not there", config.display()))?;
        let drop_in = self.drop_in();
        Ok(match written(&drop_in)? {
            Some(drop_in_time) if drop_in_time > config_time => (drop_in, drop_in_time),
            _ => (config, config_time),
        })
    }

    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()> {
        let dir = self.drop_in_dir();
        // The folder is made as the install directory is, with its descriptor and its judgement: what must hold
        // is that only administrators can write it. One that is there and is not exactly that is left alone.
        acl::create_install_dir(&dir).with_context(|| format!("cannot make {}", dir.display()))?;
        if let Some(problem) = acl::install_dir_problem(&dir)? {
            anyhow::bail!("it is not the folder apply makes: {problem}");
        }
        Ok(())
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
        if let Some(problem) = acl::admin_only_file_problem(&path)? {
            return Err(untrusted(&path, &problem));
        }
        Ok(Some(
            std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        ))
    }

    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()> {
        let path = self.drop_in();
        // The file is made with its descriptor, and a file that is there must already be exactly that: the
        // write below keeps the descriptor.
        if let Err(e) = acl::ensure_admin_only_file(&path) {
            // Its own sentence advises removing the file, which this step never does.
            match acl::admin_only_file_problem(&path) {
                Ok(Some(problem)) => return Err(untrusted(&path, &problem)),
                Ok(None) => {}
                Err(_) => return Err(e),
            }
        }
        write_flushed(&path, text)
    }

    fn remove_drop_in(&mut self) -> anyhow::Result<()> {
        let path = self.drop_in();
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))
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

    fn discard_candidate(&mut self, candidate: &Path) {
        // A candidate that cannot be removed is overwritten by the next run, and is read by nothing.
        let _ = std::fs::remove_file(candidate);
    }
}

// files =====

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

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `OpenSCManagerW` or `OpenServiceW` and is closed once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// The id of the process the sshd service runs in; `None` when the service is not running.
fn sshd_process_id() -> anyhow::Result<Option<u32>> {
    // SAFETY: null names mean this machine and the active database; the handles are closed by their guards.
    let manager = ScHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .context("open the service manager")?,
    );
    // SAFETY: `manager` is open; the name is a NUL-terminated literal.
    let service = ScHandle(
        unsafe { OpenServiceW(manager.0, w!("sshd"), SERVICE_QUERY_STATUS) }.context("open the sshd service")?,
    );
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: the buffer is `status`, whole, and lives as long as the call.
    let queried = unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            (&raw mut status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
    };
    queried.context("ask the service manager about sshd")?;
    Ok((status.dwCurrentState != SERVICE_STOPPED && status.dwProcessId != 0).then_some(status.dwProcessId))
}

/// When the process `id` was created.
fn process_started(id: u32) -> anyhow::Result<SystemTime> {
    // SAFETY: the handle is closed by `OwnedHandle`.
    let process = OwnedHandle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, id) }
            .with_context(|| format!("open the process of the sshd service ({id})"))?,
    );
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the handle is open with the right to query; the out-pointers are locals.
    unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }
        .with_context(|| format!("read when the process of the sshd service ({id}) started"))?;
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
/// `say`. Whether the running sshd takes the variable (or reads it when it next starts) is returned.
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

/// What the `verify` row is given about sshd on this machine: `sshd -T` (which needs the rights to read sshd's
/// host keys) and whether sshd started before a file of its configuration was written, or that the service runs
/// with arguments. An error says which question could not be answered.
pub fn sshd_reading_this_machine() -> anyhow::Result<SshdReading> {
    let mut machine = Machine::find().context("cannot find sshd")?;
    if let Some(arguments) = machine.service_arguments() {
        return Ok(SshdReading::WithArguments(arguments));
    }
    let listing = machine.sshd_t(None).context("cannot ask sshd for its configuration")?;
    let unread = unread_file(&mut machine).context("cannot tell whether sshd has read its configuration")?;
    Ok(SshdReading::Read { listing, unread })
}

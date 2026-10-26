//! The orchestrator's tools: the shared directory and starting a stand-in as an account.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_broker::acl::Sid;
use ssh_broker::winutil::OwnedHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TokenPrimary};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED, CreateProcessWithTokenW, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::account::Account;
use crate::rec::{Follower, Input, fact};
use crate::win::{self, wide};
use crate::{desktop, hard_errors};

/// A directory every account can write, with a copy of this example and of `ssh-broker.exe`.
pub struct Shared {
    pub root: PathBuf,
    pub exe: PathBuf,
    pub broker: Option<PathBuf>,
}

impl Shared {
    pub fn new() -> Shared {
        let root = std::env::temp_dir().join(format!("sb-spike-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the shared directory");
        let status = desktop::status(Command::new("icacls").arg(&root).args(["/grant", "*S-1-1-0:(OI)(CI)M"]))
            .expect("run icacls");
        assert!(status.success(), "icacls on the shared directory");
        let me = std::env::current_exe().expect("current_exe");
        let exe = root.join("session_spike.exe");
        std::fs::copy(&me, &exe).expect("copy the example");
        let broker_src = me.parent().and_then(Path::parent).map(|d| d.join("ssh-broker.exe"));
        let broker = broker_src.filter(|p| p.exists()).map(|src| {
            let dest = root.join("ssh-broker.exe");
            std::fs::copy(&src, &dest).expect("copy ssh-broker.exe");
            dest
        });
        Shared { root, exe, broker }
    }

    pub fn run_dir(&self, label: &str) -> PathBuf {
        let dir = self.root.join(label);
        std::fs::create_dir_all(&dir).expect("create a run directory");
        dir
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A stand-in running as an account, in a kill-on-close job, with its results being followed.
pub struct StandIn {
    pub dir: PathBuf,
    pub label: String,
    pub process: OwnedHandle,
    pub pid: u32,
    pub job: Option<OwnedHandle>,
    follower: Option<Follower>,
    _desktop: desktop::PrivateDesktop,
}

/// Start `session_spike stand-in <dir> <scenario>` as `account`, the way sshd runs a shell: with the
/// account's network-logon token, no profile loaded, inside a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
/// job. `input` is written to `input.txt` beside the account's name, password, SID and the exe.
pub fn start_stand_in(
    shared: &Shared,
    account: &Account,
    label: &str,
    scenario: &str,
    input: &[(&str, String)],
) -> StandIn {
    let dir = shared.run_dir(label);
    let mut pairs: Vec<(&str, String)> = vec![
        ("user", account.name.clone()),
        ("password", account.password.clone()),
        ("sid", account.sid_text.clone()),
        ("exe", shared.exe.display().to_string()),
    ];
    if let Some(broker) = &shared.broker {
        pairs.push(("broker", broker.display().to_string()));
    }
    pairs.extend(input.iter().map(|(k, v)| (*k, v.clone())));
    Input::write(&dir, &pairs);
    let follower = Follower::start(label, &dir);

    let starter = Sid::current_user().unwrap().to_sddl().unwrap();
    let private = desktop::PrivateDesktop::create(&[&account.sid_text, &starter])
        .unwrap_or_else(|e| panic!("create a window station and desktop for {}: {e}", account.name));
    let network = account.network_token();
    let mut primary = HANDLE::default();
    // SAFETY: valid in/out handles.
    unsafe {
        DuplicateTokenEx(
            network.0,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    }
    .expect("duplicate the token as a primary token");
    let primary = OwnedHandle(primary);

    let mut command = wide(&format!(
        "\"{}\" stand-in \"{}\" {scenario}",
        shared.exe.display(),
        dir.display()
    ));
    let mut station_and_desktop = wide(private.name());
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(station_and_desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a local that outlives the call.
    unsafe {
        CreateProcessWithTokenW(
            primary.0,
            CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR(wide(&shared.exe.to_string_lossy()).as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            PCWSTR(wide(&dir.to_string_lossy()).as_ptr()),
            &startup,
            &mut info,
        )
    }
    .unwrap_or_else(|e| panic!("start the stand-in as {}: {e}", account.name));
    let process = OwnedHandle(info.hProcess);
    let thread = OwnedHandle(info.hThread);
    if let Err(e) = hard_errors::suppress_hard_error_boxes(process.0) {
        fact(label, "orchestrator.hard_error_boxes_off", format!("ERROR {e}"));
    }
    let job = new_kill_on_close_job();
    // SAFETY: both handles are live and owned here; the process is still suspended.
    unsafe {
        AssignProcessToJobObject(job.0, process.0).expect("put the stand-in in the job");
        assert_ne!(ResumeThread(thread.0), u32::MAX, "resume the stand-in");
    }
    StandIn {
        dir,
        label: label.to_owned(),
        process,
        pid: info.dwProcessId,
        job: Some(job),
        follower: Some(follower),
        _desktop: private,
    }
}

fn new_kill_on_close_job() -> OwnedHandle {
    // SAFETY: valid arguments; the handle is closed by `OwnedHandle`.
    unsafe {
        let job = OwnedHandle(CreateJobObjectW(None, PCWSTR::null()).expect("CreateJobObjectW"));
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .expect("SetInformationJobObject");
        job
    }
}

impl StandIn {
    /// Wait with no limit for the stand-in to exit; its exit code.
    pub fn wait(&self) -> u32 {
        win::wait_one(self.process.0);
        win::exit_code(self.process.0)
    }

    /// Close the job: the kill-on-close stands for sshd ending the session on a disconnect.
    pub fn close_job(&mut self) {
        self.job = None;
    }

    /// The process ids the job lists.
    pub fn job_pids(&self) -> Vec<usize> {
        let Some(job) = &self.job else { return Vec::new() };
        let mut buf = vec![0usize; 128];
        // SAFETY: the buffer is large enough for the header and many ids; the list is read within its count.
        unsafe {
            if windows::Win32::System::JobObjects::QueryInformationJobObject(
                Some(job.0),
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr().cast(),
                (buf.len() * std::mem::size_of::<usize>()) as u32,
                None,
            )
            .is_err()
            {
                return Vec::new();
            }
            let list = &*(buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>());
            std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), list.NumberOfProcessIdsInList as usize).to_vec()
        }
    }

    /// Whether `process` is in this stand-in's job.
    pub fn job_contains(&self, process: HANDLE) -> Option<bool> {
        let job = self.job.as_ref()?;
        let mut result = windows::core::BOOL(0);
        // SAFETY: valid handles and out-pointer.
        unsafe { windows::Win32::System::JobObjects::IsProcessInJob(process, Some(job.0), &mut result) }.ok()?;
        Some(result.as_bool())
    }

    /// Print what is left of the results and record the exit code.
    pub fn finish(mut self) {
        let code = win::exit_code(self.process.0);
        if let Some(follower) = self.follower.take() {
            follower.finish();
        }
        fact(&self.label, "stand_in_exit_code", format!("{code:#x}"));
    }
}

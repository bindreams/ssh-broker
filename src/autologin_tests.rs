//! Unit tests for `autologin`: the refusals and the order of the steps, over a fake environment
//! (no elevation, no account, no task, no console).
use super::*;
use crate::offer::AccountKind;
use crate::password_entry::{PasswordEntry, Step};
use crate::provision::session_task::{TaskState, task_name, task_xml};
use crate::vtinput::KeyEvent;

const EXE: &str = r"C:\ProgramData\ssh-broker\ssh-broker.exe";
const SECRET: &str = "hunter2-sentinel";

fn password(text: &str) -> Password {
    let key = |vk: u16, ch: u16| KeyEvent {
        virtual_key_code: vk,
        virtual_scan_code: 0,
        unicode_char: ch,
        key_down: true,
        control_key_state: 0,
        repeat_count: 1,
    };
    let mut entry = PasswordEntry::new();
    for unit in text.encode_utf16() {
        entry.key(&key(0x41, unit));
    }
    match entry.key(&key(0x0D, 0x0D)) {
        Step::Submit(p) => p,
        _ => panic!("empty"),
    }
}

fn account(name: &str, sid: &str, kind: AccountKind) -> LocalAccount {
    LocalAccount {
        name: name.into(),
        sid: sid.into(),
        kind,
    }
}

fn alice() -> LocalAccount {
    account("alice", "S-1-5-21-1-2-3-1001", AccountKind::Local)
}

/// A fake world that records what `on` and `off` did to it.
struct Fake {
    elevated: bool,
    terminal: bool,
    password: Option<&'static str>,
    batch: BatchRight,
    registered_ok: bool,
    /// What the read-back returns: the registered definition by default.
    read_back: Option<Option<TaskState>>,
    exists: bool,
    /// Deleting fails with this message.
    delete_fails: Option<&'static str>,
    calls: Vec<String>,
    said: Vec<String>,
    /// The password each step was given, as the UTF-16 units it received.
    probed: std::cell::RefCell<Vec<Vec<u16>>>,
    registered: Vec<Vec<u16>>,
    /// Whether the apply lock is held now, and how many times it was taken.
    held: std::rc::Rc<std::cell::Cell<bool>>,
    locks: u32,
    /// Taking the lock fails with this message.
    lock_fails: Option<&'static str>,
    /// The steps that ran while the lock was not held, and those that ran while it was.
    unlocked: std::cell::RefCell<Vec<&'static str>>,
    locked: std::cell::RefCell<Vec<&'static str>>,
    /// Whether the lock was held when the password was asked for.
    held_when_asked: Vec<bool>,
    /// What `off` finds the install directory to be.
    install: InstallDir,
    /// `check_install` fails with this message.
    install_problem: Option<&'static str>,
    /// Whether the lock was held at each `check_install`.
    held_when_checked: std::cell::RefCell<Vec<bool>>,
}

/// The lock a [`Fake`] hands out: held until dropped.
struct Held(std::rc::Rc<std::cell::Cell<bool>>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl Fake {
    /// Note a step that needs the lock.
    fn step(&self, name: &'static str) {
        if self.held.get() {
            self.locked.borrow_mut().push(name);
        } else {
            self.unlocked.borrow_mut().push(name);
        }
    }
}

impl Fake {
    fn new() -> Fake {
        Fake {
            elevated: true,
            terminal: true,
            password: Some(SECRET),
            batch: BatchRight::Granted,
            registered_ok: true,
            read_back: None,
            exists: true,
            delete_fails: None,
            calls: Vec::new(),
            said: Vec::new(),
            probed: Default::default(),
            registered: Vec::new(),
            held: Default::default(),
            locks: 0,
            lock_fails: None,
            unlocked: Default::default(),
            locked: Default::default(),
            held_when_asked: Vec::new(),
            install: InstallDir::Trusted,
            install_problem: None,
            held_when_checked: Default::default(),
        }
    }

    fn said(&self) -> String {
        self.said.join("\n")
    }
}

impl AutoLoginEnv for Fake {
    fn is_elevated(&self) -> anyhow::Result<bool> {
        Ok(self.elevated)
    }
    fn has_terminal(&self) -> bool {
        self.terminal
    }
    fn exe(&self) -> std::path::PathBuf {
        EXE.into()
    }
    fn lock_apply(&mut self) -> anyhow::Result<Box<dyn std::any::Any>> {
        if let Some(why) = self.lock_fails {
            anyhow::bail!(why);
        }
        self.locks += 1;
        self.held.set(true);
        Ok(Box::new(Held(self.held.clone())))
    }
    fn install_dir(&self) -> InstallDir {
        self.install.clone()
    }
    fn check_install(&self) -> anyhow::Result<()> {
        self.held_when_checked.borrow_mut().push(self.held.get());
        match self.install_problem {
            Some(why) => anyhow::bail!(why),
            None => Ok(()),
        }
    }
    fn ask_password(&mut self, _: &LocalAccount) -> anyhow::Result<Option<Password>> {
        self.held_when_asked.push(self.held.get());
        self.calls.push("ask".into());
        Ok(self.password.map(password))
    }
    fn batch_right(&self, _: &LocalAccount, password: &Password) -> BatchRight {
        self.step("batch_right");
        self.probed.borrow_mut().push(password.as_wide().to_vec());
        self.batch.clone()
    }
    fn register(&mut self, account: &LocalAccount, xml: &str, password: &Password, sddl: &str) -> anyhow::Result<()> {
        self.step("register");
        self.registered.push(password.as_wide().to_vec());
        self.calls.push(format!("register {} {}", account.sid, sddl));
        self.calls.push(format!("xml-names {}", xml.contains(&account.sid)));
        if self.registered_ok {
            Ok(())
        } else {
            anyhow::bail!("The user name or password is incorrect.")
        }
    }
    fn read_back(&self, name: &str) -> anyhow::Result<Option<TaskState>> {
        self.step("read_back");
        let sid = name.strip_prefix("ssh-broker-session-").unwrap();
        Ok(match &self.read_back {
            Some(state) => state.as_ref().map(|s| TaskState {
                xml: s.xml.clone(),
                sddl: s.sddl.clone(),
                last_result: s.last_result,
            }),
            None => Some(TaskState {
                xml: task_xml(EXE, sid),
                sddl: format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{sid})"),
                last_result: 0x0004_1303,
            }),
        })
    }
    fn delete(&mut self, name: &str) -> anyhow::Result<bool> {
        self.step("delete");
        self.calls.push(format!("delete {name}"));
        if let Some(why) = self.delete_fails {
            anyhow::bail!(why);
        }
        Ok(std::mem::replace(&mut self.exists, false))
    }
    fn run_now(&mut self, name: &str) -> anyhow::Result<()> {
        self.step("run_now");
        self.calls.push(format!("run {name}"));
        Ok(())
    }
    fn say(&mut self, line: &str) {
        self.said.push(line.to_string());
    }
}

fn error_text(result: anyhow::Result<()>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn on_refuses_a_non_elevated_shell_with_the_way_to_an_elevated_one() {
    let mut env = Fake::new();
    env.elevated = false;
    let text = error_text(on(&mut env, &alice()));
    assert!(
        text.contains("auto-login on needs an elevated administrator shell"),
        "{text}"
    );
    assert!(text.contains("A shell hosted by ssh-broker is not elevated."), "{text}");
    assert!(text.contains(&format!("run {EXE} logout")), "the full exe path: {text}");
    assert!(text.contains("press Ctrl+C at the password prompt"), "{text}");
    assert!(env.calls.is_empty(), "nothing was asked or changed: {:?}", env.calls);
}

#[test]
fn off_refuses_a_non_elevated_shell() {
    let mut env = Fake::new();
    env.elevated = false;
    let text = error_text(off(&mut env, &alice()));
    assert!(
        text.contains("auto-login off needs an elevated administrator shell"),
        "{text}"
    );
    assert!(env.calls.is_empty());
}

#[test]
fn on_needs_a_terminal() {
    let mut env = Fake::new();
    env.terminal = false;
    let text = error_text(on(&mut env, &alice()));
    assert_eq!(
        text,
        "ssh-broker: auto-login on needs a terminal to ask for the password."
    );
    assert!(env.calls.is_empty());
}

#[test]
fn on_refuses_a_non_local_account() {
    let mut env = Fake::new();
    let other = account("Zoe", "S-1-5-21-9-9-9-1001", AccountKind::NotLocal);
    let text = error_text(on(&mut env, &other));
    assert!(text.contains("Zoe is not a local account"), "{text}");
    assert!(text.contains("ssh-broker#45"), "{text}");
    assert!(
        env.calls.is_empty(),
        "no password is asked for an account that cannot be used"
    );
}

#[test]
fn on_refuses_a_missing_batch_right_naming_it() {
    let mut env = Fake::new();
    env.batch = BatchRight::Missing;
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("Log on as a batch job"), "{text}");
    assert!(text.contains("Local Security Policy"), "{text}");
    assert!(text.contains("never changes machine policy"), "{text}");
    assert!(
        !env.calls.iter().any(|call| call.starts_with("register")),
        "nothing is registered without the right: {:?}",
        env.calls
    );
}

#[test]
fn on_refuses_a_password_windows_does_not_accept_with_its_reason() {
    let mut env = Fake::new();
    env.batch = BatchRight::Refused("The user name or password is incorrect.".into());
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("The user name or password is incorrect."), "{text}");
    assert!(!env.calls.iter().any(|call| call.starts_with("register")));
}

#[test]
fn on_with_a_cancelled_prompt_changes_nothing() {
    let mut env = Fake::new();
    env.password = None;
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("cancelled"), "{text}");
    assert_eq!(env.calls, ["ask"]);
}

#[test]
fn on_registers_verifies_and_runs_the_task_once() {
    let mut env = Fake::new();
    on(&mut env, &alice()).unwrap();
    let name = task_name("S-1-5-21-1-2-3-1001");
    assert_eq!(
        env.calls,
        [
            "ask".to_string(),
            "register S-1-5-21-1-2-3-1001 D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;S-1-5-21-1-2-3-1001)".to_string(),
            "xml-names true".to_string(),
            format!("run {name}"),
        ]
    );
    assert!(env.said().contains("auto-login is on for alice"), "{}", env.said());
    let typed: Vec<u16> = SECRET.encode_utf16().collect();
    assert_eq!(
        *env.probed.borrow(),
        vec![typed.clone()],
        "the batch right is probed with the typed password"
    );
    assert_eq!(
        env.registered,
        vec![typed],
        "the task is registered with the typed password"
    );
}

#[test]
fn on_deletes_a_task_that_fails_the_read_back() {
    let mut env = Fake::new();
    let sid = "S-1-5-21-1-2-3-1001";
    env.read_back = Some(Some(TaskState {
        xml: task_xml(r"C:\evil.exe", sid),
        sddl: String::new(),
        last_result: 0,
    }));
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("does not match"), "{text}");
    assert!(text.contains("it was removed"), "{text}");
    assert!(
        env.calls.contains(&format!("delete {}", task_name(sid))),
        "{:?}",
        env.calls
    );
    assert!(!env.calls.iter().any(|call| call.starts_with("run")), "{:?}", env.calls);
}

#[test]
fn on_does_not_claim_the_task_was_removed_when_removing_it_failed() {
    let mut env = Fake::new();
    env.read_back = Some(Some(TaskState {
        xml: task_xml(r"C:\evil.exe", "S-1-5-21-1-2-3-1001"),
        sddl: String::new(),
        last_result: 0,
    }));
    env.delete_fails = Some("Access is denied.");
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("does not match"), "{text}");
    assert!(!text.contains("it was removed"), "{text}");
    assert!(text.contains("could not be removed"), "{text}");
    assert!(text.contains("Access is denied."), "{text}");
    assert!(text.contains("may still be registered"), "{text}");
}

#[test]
fn on_fails_when_the_task_is_not_there_to_read_back() {
    let mut env = Fake::new();
    env.read_back = Some(None);
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("not registered"), "{text}");
    assert!(!env.calls.iter().any(|call| call.starts_with("run")));
}

#[test]
fn on_with_a_registration_windows_refuses_leaves_no_task_and_shows_why() {
    let mut env = Fake::new();
    env.registered_ok = false;
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("The user name or password is incorrect."), "{text}");
    assert!(!env.calls.iter().any(|call| call.starts_with("run")));
}

#[test]
fn on_targets_the_named_account_not_the_caller() {
    let mut env = Fake::new();
    let bob = account("bob", "S-1-5-21-1-2-3-2002", AccountKind::Local);
    on(&mut env, &bob).unwrap();
    assert!(
        env.calls.iter().any(|call| call.contains("S-1-5-21-1-2-3-2002")),
        "{:?}",
        env.calls
    );
    assert!(
        !env.calls.iter().any(|call| call.contains("S-1-5-21-1-2-3-1001")),
        "{:?}",
        env.calls
    );
    assert!(env.said().contains("bob"), "{}", env.said());
}

#[test]
fn the_password_is_in_nothing_it_says() {
    let mut env = Fake::new();
    on(&mut env, &alice()).unwrap();
    env.batch = BatchRight::Missing;
    let error = error_text(on(&mut env, &alice()));
    assert!(!env.said().contains(SECRET));
    assert!(!error.contains(SECRET));
}

#[test]
fn off_deletes_the_task_and_says_a_running_session_continues() {
    let mut env = Fake::new();
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.calls, [format!("delete {}", task_name("S-1-5-21-1-2-3-1001"))]);
    let said = env.said();
    assert!(said.contains("auto-login is off for alice"), "{said}");
    assert!(said.contains(&format!("{EXE} logout")), "{said}");
}

#[test]
fn off_twice_is_ok() {
    let mut env = Fake::new();
    off(&mut env, &alice()).unwrap();
    env.said.clear();
    off(&mut env, &alice()).unwrap();
    assert!(env.said().contains("already off"), "{}", env.said());
}

// the apply lock -----

#[test]
fn on_holds_the_apply_lock_for_every_step_and_lets_go_at_the_end() {
    let mut env = Fake::new();
    on(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 1);
    assert_eq!(*env.unlocked.borrow(), Vec::<&str>::new(), "steps outside the lock");
    assert_eq!(
        *env.locked.borrow(),
        ["batch_right", "register", "read_back", "run_now"],
        "every step that changes the task or probes the password is under the lock"
    );
    assert!(!env.held.get(), "the lock is let go when on returns");
}

#[test]
fn on_checks_the_install_before_the_prompt_and_again_under_the_lock() {
    let mut env = Fake::new();
    on(&mut env, &alice()).unwrap();
    assert_eq!(
        *env.held_when_checked.borrow(),
        [false, true],
        "once before the password is asked for (no lock: it only reads), once under the lock (the install may have changed since)"
    );
}

#[test]
fn on_with_no_install_refuses_before_the_prompt_and_takes_no_lock() {
    let mut env = Fake::new();
    env.install_problem = Some("ssh-broker: the exe is not installed; run apply first");
    let text = error_text(on(&mut env, &alice()));
    assert!(text.contains("run apply first"), "{text}");
    assert!(env.calls.is_empty(), "no password is asked for: {:?}", env.calls);
    assert_eq!(
        env.locks, 0,
        "no lock, so no directory or lock file is made to hold one"
    );
}

#[test]
fn on_does_not_hold_the_apply_lock_while_it_asks_for_the_password() {
    let mut env = Fake::new();
    on(&mut env, &alice()).unwrap();
    assert_eq!(
        env.held_when_asked,
        [false],
        "a prompt left open must not hold up apply"
    );
}

#[test]
fn on_with_a_cancelled_prompt_takes_no_lock() {
    let mut env = Fake::new();
    env.password = None;
    on(&mut env, &alice()).unwrap_err();
    assert_eq!(env.locks, 0);
    assert!(env.locked.borrow().is_empty() && env.unlocked.borrow().is_empty());
}

#[test]
fn on_lets_go_of_the_apply_lock_when_it_fails_after_taking_it() {
    let mut env = Fake::new();
    env.batch = BatchRight::Missing;
    on(&mut env, &alice()).unwrap_err();
    assert_eq!(env.locks, 1);
    assert!(!env.held.get());
    assert!(env.unlocked.borrow().is_empty(), "{:?}", env.unlocked.borrow());
}

#[test]
fn off_holds_the_apply_lock_for_its_step_and_lets_go_at_the_end() {
    let mut env = Fake::new();
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 1);
    assert_eq!(*env.unlocked.borrow(), Vec::<&str>::new(), "steps outside the lock");
    assert_eq!(*env.locked.borrow(), ["delete"]);
    assert!(!env.held.get());
}

#[test]
fn off_deletes_the_task_without_the_lock_when_there_is_no_install_directory() {
    let mut env = Fake::new();
    env.install = InstallDir::Missing;
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 0, "no lock, and so nothing created to hold one");
    assert_eq!(env.calls, [format!("delete {}", task_name("S-1-5-21-1-2-3-1001"))]);
    assert!(env.said().contains("auto-login is off for alice"), "{}", env.said());
}

#[test]
fn off_deletes_the_task_without_the_lock_when_the_install_directory_fails_its_check_and_says_why() {
    let mut env = Fake::new();
    env.install = InstallDir::Untrusted("its owner is BUILTIN-Users, not the Administrators group".into());
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 0);
    assert_eq!(env.calls, [format!("delete {}", task_name("S-1-5-21-1-2-3-1001"))]);
    let said = env.said();
    assert!(
        said.contains("its owner is BUILTIN-Users"),
        "the reason is named: {said}"
    );
    assert!(said.contains("warning"), "{said}");
    assert!(said.contains("auto-login is off for alice"), "{said}");
}

#[test]
fn off_takes_the_lock_when_the_install_directory_passes_its_check() {
    let mut env = Fake::new();
    env.install = InstallDir::Trusted;
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 1);
    assert!(!env.said().contains("warning"), "{}", env.said());
}

#[test]
fn off_with_an_untrusted_directory_still_reports_a_task_that_cannot_be_deleted() {
    let mut env = Fake::new();
    env.install = InstallDir::Untrusted("it is not a directory".into());
    env.delete_fails = Some("Access is denied.");
    let text = error_text(off(&mut env, &alice()));
    assert!(text.contains("Access is denied."), "{text}");
}

#[test]
fn a_refusal_before_any_change_takes_no_lock() {
    let mut not_elevated = Fake::new();
    not_elevated.elevated = false;
    on(&mut not_elevated, &alice()).unwrap_err();
    off(&mut not_elevated, &alice()).unwrap_err();
    let mut no_terminal = Fake::new();
    no_terminal.terminal = false;
    on(&mut no_terminal, &alice()).unwrap_err();
    let mut not_local = Fake::new();
    on(
        &mut not_local,
        &account("Zoe", "S-1-5-21-9-9-9-1001", AccountKind::NotLocal),
    )
    .unwrap_err();
    assert_eq!(
        [not_elevated.locks, no_terminal.locks, not_local.locks],
        [0, 0, 0],
        "the lock file needs an elevated administrator and a refusal changes nothing"
    );
}

#[test]
fn a_lock_that_cannot_be_taken_stops_on_before_it_changes_anything() {
    let mut env = Fake::new();
    env.lock_fails = Some("the install directory is not ours");
    let text = error_text(on(&mut env, &alice()));
    assert_eq!(
        env.calls,
        ["ask"],
        "the password is asked for before the lock; nothing is changed"
    );
    assert!(text.contains("the install directory is not ours"), "{text}");
}

#[test]
fn off_deletes_the_task_without_the_lock_when_the_lock_cannot_be_taken_and_says_why() {
    let mut env = Fake::new();
    env.lock_fails = Some("the lock file has the wrong access");
    off(&mut env, &alice()).unwrap();
    assert_eq!(env.locks, 0);
    assert_eq!(env.calls, [format!("delete {}", task_name("S-1-5-21-1-2-3-1001"))]);
    let said = env.said();
    assert!(said.contains("warning"), "{said}");
    assert!(
        said.contains("the lock file has the wrong access"),
        "the cause is named: {said}"
    );
    assert!(said.contains("auto-login is off for alice"), "{said}");
}

#[test]
fn off_names_the_cause_of_a_lock_that_cannot_be_taken_once() {
    let mut env = Fake::new();
    env.lock_fails = Some("ssh-broker: could not take the apply lock: the-lock-path cannot be trusted");
    off(&mut env, &alice()).unwrap();
    let warning = env.said.first().expect("a warning").clone();
    assert_eq!(
        warning,
        "ssh-broker: warning: could not take the apply lock: the-lock-path cannot be trusted; deleting the task anyway."
    );
}

#[test]
fn off_with_a_lock_that_cannot_be_taken_still_reports_a_task_that_cannot_be_deleted() {
    let mut env = Fake::new();
    env.lock_fails = Some("the lock file has the wrong access");
    env.delete_fails = Some("Access is denied.");
    let text = error_text(off(&mut env, &alice()));
    assert!(text.contains("Access is denied."), "{text}");
}

// the install directory -----

/// A path under the temp dir that is removed on drop, whether it is a directory or a file.
struct TempPath(std::path::PathBuf);

impl TempPath {
    fn new(tag: &str) -> TempPath {
        TempPath(std::env::temp_dir().join(format!("sb-autologin-{tag}-{}", std::process::id())))
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}

fn state_of(path: &std::path::Path) -> InstallDir {
    install_dir_of(&crate::provision::layout::Layout {
        base: path.to_path_buf(),
    })
}

#[test]
fn an_install_directory_that_does_not_exist_is_missing_and_stays_missing() {
    let path = TempPath::new("missing");
    assert_eq!(state_of(&path.0), InstallDir::Missing);
    assert!(!path.0.exists(), "looking must create nothing");
}

#[test]
fn an_install_directory_that_is_not_the_hardened_one_is_untrusted_with_the_reason() {
    let dir = TempPath::new("plain");
    std::fs::create_dir_all(&dir.0).unwrap();
    let InstallDir::Untrusted(reason) = state_of(&dir.0) else {
        panic!("a plain temp directory is not the hardened install directory")
    };
    assert!(!reason.is_empty());

    let file = TempPath::new("file");
    std::fs::write(&file.0, b"").unwrap();
    let InstallDir::Untrusted(reason) = state_of(&file.0) else {
        panic!("a file is not an install directory")
    };
    assert!(reason.contains("not a directory"), "{reason}");
}

// the real environment -----

fn env_in(base: &std::path::Path, on_lock_wait: impl FnMut() + 'static) -> WindowsEnv {
    WindowsEnv::with_layout(
        PasswordSource::Given(None),
        crate::provision::layout::Layout {
            base: base.to_path_buf(),
        },
        on_lock_wait,
    )
}

#[test]
fn check_install_with_no_install_directory_says_run_apply_first_and_creates_nothing() {
    let dir = TempPath::new("check-missing");
    let text = format!("{:#}", env_in(&dir.0, || {}).check_install().unwrap_err());
    assert!(text.contains("is not installed; run apply first"), "{text}");
    assert!(text.contains("ssh-broker.exe"), "it names the exe: {text}");
    assert!(!dir.0.exists(), "looking must create no directory and no lock file");
}

#[test]
fn check_install_with_an_untrusted_directory_refuses_and_adds_nothing_to_it() {
    let dir = TempPath::new("check-plain");
    std::fs::create_dir_all(&dir.0).unwrap();
    let text = format!("{:#}", env_in(&dir.0, || {}).check_install().unwrap_err());
    assert!(text.contains("the install directory is not trusted"), "{text}");
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0, "no lock file was made");
}

/// What a thread tells the test about the lock it asks for.
#[derive(Debug, PartialEq, Eq)]
enum Lock {
    /// It found the lock held and is about to block.
    Waiting,
    /// It has the lock.
    Taken,
}

/// A hardened install directory under the temp dir.
fn hardened_layout(tag: &str) -> (TempPath, crate::provision::layout::Layout) {
    let dir = TempPath::new(tag);
    let layout = crate::provision::layout::Layout { base: dir.0.clone() };
    crate::provision::layout::ensure_base(&layout).unwrap();
    (dir, layout)
}

/// Elevated (CI only): the install directory must be hardened, which needs an elevated administrator.
#[test]
fn the_real_env_tells_a_missing_install_directory_from_a_trusted_one() {
    let dir = TempPath::new("env-dir");
    let env = env_in(&dir.0, || {});
    assert_eq!(env.install_dir(), InstallDir::Missing);
    crate::provision::layout::ensure_base(&crate::provision::layout::Layout { base: dir.0.clone() }).unwrap();
    assert_eq!(env.install_dir(), InstallDir::Trusted);
}

/// Elevated (CI only). The lock `auto-login on|off` take is the file `apply` takes: with another
/// holder on `apply.lock`, the real env's `lock_apply` blocks (and says so) until it lets go.
#[test]
fn the_real_env_waits_for_a_holder_of_the_apply_lock_file() {
    let (dir, layout) = hardened_layout("env-waits");
    let holder =
        crate::provision::apply_lock::acquire(&layout.apply_lock_path(), || panic!("nobody holds the lock")).unwrap();
    let (events, seen) = std::sync::mpsc::channel();
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let asker = std::thread::spawn({
        let base = dir.0.clone();
        let released = released.clone();
        move || {
            let waiting = events.clone();
            let mut env = env_in(&base, move || waiting.send(Lock::Waiting).unwrap());
            let lock = env.lock_apply().unwrap();
            let after_release = released.load(std::sync::atomic::Ordering::SeqCst);
            events.send(Lock::Taken).unwrap();
            drop(lock);
            after_release
        }
    });
    assert_eq!(
        seen.recv().expect("the asker ended without reporting"),
        Lock::Waiting,
        "lock_apply returned, or did not report a wait, while the apply lock file was held"
    );
    released.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(holder);
    assert_eq!(seen.recv().expect("the asker never got the lock"), Lock::Taken);
    assert!(
        asker.join().unwrap(),
        "lock_apply reported a wait and then returned before the holder let go"
    );
}

/// Elevated (CI only). The guard `lock_apply` returns is the lock: while it lives, a second taker
/// of `apply.lock` blocks; once it is dropped, the second gets it.
#[test]
fn the_real_env_holds_the_apply_lock_file_until_its_guard_is_dropped() {
    let (dir, layout) = hardened_layout("env-holds");
    let mut env = env_in(&dir.0, || panic!("nobody holds the lock"));
    let guard = env.lock_apply().unwrap();
    let (events, seen) = std::sync::mpsc::channel();
    let second = std::thread::spawn({
        let path = layout.apply_lock_path();
        move || {
            let waiting = events.clone();
            let lock =
                crate::provision::apply_lock::acquire(&path, move || waiting.send(Lock::Waiting).unwrap()).unwrap();
            events.send(Lock::Taken).unwrap();
            drop(lock);
        }
    });
    assert_eq!(
        seen.recv().expect("the second taker ended without reporting"),
        Lock::Waiting,
        "the lock file was free while the guard lived"
    );
    drop(guard);
    assert_eq!(seen.recv().expect("the second taker never got the lock"), Lock::Taken);
    second.join().unwrap();
}

/// A prompt that answers with a script and records what it is told to show.
struct ScriptedPrompt {
    answers: std::collections::VecDeque<Result<Step, windows::core::Error>>,
    shown: Vec<String>,
}

impl Prompt for ScriptedPrompt {
    fn read_step(&mut self) -> Result<Step, windows::core::Error> {
        self.answers.pop_front().expect("the prompt was read past its script")
    }
    fn write_text(&mut self, text: &str) {
        self.shown.push(text.to_string());
    }
}

fn scripted(answers: Vec<Result<Step, windows::core::Error>>) -> ScriptedPrompt {
    ScriptedPrompt {
        answers: answers.into(),
        shown: Vec::new(),
    }
}

#[test]
fn a_console_that_fails_to_read_says_why() {
    let cause = windows::core::Error::new(windows::core::HRESULT(0x8007_0006_u32 as i32), "the handle is invalid");
    let mut prompt = scripted(vec![Err(cause)]);
    let text = format!("{:#}", ask_until_answered(&mut prompt).expect_err("an error"));
    assert!(
        text.starts_with("ssh-broker: the console input failed; nothing was changed"),
        "{text}"
    );
    assert!(text.contains("the handle is invalid"), "the cause is carried: {text}");
}

#[test]
fn an_empty_enter_asks_again_and_the_next_password_is_the_answer() {
    let mut prompt = scripted(vec![
        Ok(Step::Empty),
        Ok(Step::Continue),
        Ok(Step::Submit(password("pw"))),
    ]);
    let answer = ask_until_answered(&mut prompt).unwrap().expect("a password");
    assert_eq!(answer.as_wide(), "pw".encode_utf16().collect::<Vec<_>>());
    assert_eq!(prompt.shown, [EMPTY_PASSWORD_LINE]);
}

#[test]
fn a_cancel_is_no_password() {
    let mut prompt = scripted(vec![Ok(Step::Cancel)]);
    assert!(ask_until_answered(&mut prompt).unwrap().is_none());
}

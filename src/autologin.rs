//! autologin: `ssh-broker auto-login on|off [<account>]`.
//!
//! `on` stores an account's password with Task Scheduler and registers a boot task that starts the
//! account's background agent, so the session exists before anyone logs in. `off` deletes the task,
//! and the stored credential goes with it (measured, spike M5(e)).
//!
//! Both are elevated commands (spike M5(a)): Task Scheduler refuses a boot trigger to any token that
//! is not an elevated administrator's, however the account is named. `on` also needs the account to
//! hold "Log on as a batch job" (M5(d)); ssh-broker checks for it with the password in hand and
//! refuses naming it, and never changes machine policy.
//!
//! The steps run over [`AutoLoginEnv`], so the refusals and their order are tested without Windows.

use std::path::PathBuf;

use anyhow::Context;

use crate::account::LocalAccount;
use crate::offer::{AccountKind, text};
use crate::password_entry::{Password, Step};
use crate::provision::session_task::{TaskState, requested_sddl, task_name, task_problem, task_xml};

/// Whether an account may log on as a batch job, checked with its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchRight {
    Granted,
    /// Windows says the right is not granted (`ERROR_LOGON_TYPE_NOT_GRANTED`).
    Missing,
    /// Windows refused for another reason, in its words: a wrong password, a disabled account.
    Refused(String),
}

/// What `on` and `off` need from the machine.
pub trait AutoLoginEnv {
    fn is_elevated(&self) -> anyhow::Result<bool>;
    /// Whether there is a terminal to ask for the password on.
    fn has_terminal(&self) -> bool;
    /// The installed exe, which the task runs and the messages name.
    fn exe(&self) -> PathBuf;
    /// Whether the install directory is trusted: the task runs the exe in it with a stored credential.
    fn check_install(&self) -> anyhow::Result<()>;
    /// Ask for `account`'s password. `None` if the user cancelled.
    fn ask_password(&mut self, account: &LocalAccount) -> anyhow::Result<Option<Password>>;
    fn batch_right(&self, account: &LocalAccount, password: &Password) -> BatchRight;
    fn register(&mut self, account: &LocalAccount, xml: &str, password: &Password, sddl: &str) -> anyhow::Result<()>;
    fn read_back(&self, name: &str) -> anyhow::Result<Option<TaskState>>;
    /// Delete the task; whether there was one.
    fn delete(&mut self, name: &str) -> anyhow::Result<bool>;
    /// Start the task now. Does not wait for it.
    fn run_now(&mut self, name: &str) -> anyhow::Result<()>;
    fn say(&mut self, line: &str);
}

fn not_elevated(verb: &str, exe: &str) -> String {
    format!(
        "ssh-broker: auto-login {verb} needs an elevated administrator shell. A shell hosted by ssh-broker is not \
         elevated. Open an elevated prompt at the PC, or over SSH run {exe} logout, reconnect, press Ctrl+C at the \
         password prompt for a plain shell, and run it there."
    )
}

fn batch_right_missing(user: &str) -> String {
    format!(
        "ssh-broker: {user} may not log on as a batch job, which Task Scheduler needs to start the session at boot. \
         An administrator can grant \"Log on as a batch job\" in Local Security Policy (User Rights Assignment). \
         ssh-broker never changes machine policy."
    )
}

/// `ssh-broker auto-login on` for `account`.
pub fn on(env: &mut dyn AutoLoginEnv, account: &LocalAccount) -> anyhow::Result<()> {
    let exe = env.exe();
    let exe_text = exe.to_string_lossy().into_owned();
    anyhow::ensure!(
        env.is_elevated().context("read the token's elevation")?,
        not_elevated("on", &exe_text)
    );
    anyhow::ensure!(
        env.has_terminal(),
        "ssh-broker: auto-login on needs a terminal to ask for the password."
    );
    anyhow::ensure!(
        account.kind == AccountKind::Local,
        text::not_local(&account.name).trim_end().to_string()
    );
    env.check_install()?;

    let password = env
        .ask_password(account)?
        .ok_or_else(|| anyhow::anyhow!("ssh-broker: cancelled; nothing was changed."))?;
    match env.batch_right(account, &password) {
        BatchRight::Granted => {}
        BatchRight::Missing => anyhow::bail!(batch_right_missing(&account.name)),
        BatchRight::Refused(reason) => {
            anyhow::bail!(
                "ssh-broker: Windows did not accept the password for {}: {reason}",
                account.name
            )
        }
    }

    let name = task_name(&account.sid);
    // Task Scheduler refuses a wrong password at registration (spike M5(c)), so the reason a
    // registration fails is its own.
    env.register(
        account,
        &task_xml(&exe_text, &account.sid),
        &password,
        &requested_sddl(&account.sid),
    )
    .with_context(|| format!("ssh-broker: could not register the task for {}", account.name))?;
    drop(password);

    // The service keeps what it was given only if it accepts it as given: read it back, and take the
    // task away again if it is not what was asked for.
    let problem = match env.read_back(&name) {
        Ok(Some(state)) => task_problem(&state, &exe_text, &account.sid),
        Ok(None) => Some("the task is not registered after registering it".to_string()),
        Err(e) => Some(format!("it could not be read back: {e:#}")),
    };
    if let Some(problem) = problem {
        let removal = match env.delete(&name) {
            Ok(true) => "it was removed".to_string(),
            Ok(false) => "it is no longer registered".to_string(),
            Err(e) => format!("it could not be removed ({e:#}) and may still be registered with the stored password"),
        };
        anyhow::bail!(
            "ssh-broker: the registered task does not match what auto-login on asked for ({problem}); {removal}."
        );
    }

    env.run_now(&name)
        .context("ssh-broker: the task is registered but could not be started")?;
    env.say(&format!(
        "ssh-broker: auto-login is on for {}. The background session starts now and at every boot.",
        account.name
    ));
    Ok(())
}

/// `ssh-broker auto-login off` for `account`. Idempotent. A running session continues until `logout`.
pub fn off(env: &mut dyn AutoLoginEnv, account: &LocalAccount) -> anyhow::Result<()> {
    let exe = env.exe().to_string_lossy().into_owned();
    anyhow::ensure!(
        env.is_elevated().context("read the token's elevation")?,
        not_elevated("off", &exe)
    );
    if env.delete(&task_name(&account.sid))? {
        env.say(&format!(
            "ssh-broker: auto-login is off for {}. A session that is running continues until {exe} logout.",
            account.name
        ));
    } else {
        env.say(&format!("ssh-broker: auto-login is already off for {}.", account.name));
    }
    Ok(())
}

// the machine -----

/// Where the password comes from.
pub enum PasswordSource {
    /// Ask at the console.
    Console,
    /// A password already in hand (for tests, which have no console).
    Given(Option<Password>),
}

/// The real machine: Task Scheduler, the console, LSA.
pub struct WindowsEnv {
    source: PasswordSource,
    /// The exe the task runs, when it is not the installed one (tests); the install is then not checked.
    exe_override: Option<PathBuf>,
}

impl WindowsEnv {
    pub fn new(source: PasswordSource) -> WindowsEnv {
        WindowsEnv {
            source,
            exe_override: None,
        }
    }

    /// For tests: the task runs `exe`, and the install directory is not examined.
    pub fn with_exe_unchecked(source: PasswordSource, exe: PathBuf) -> WindowsEnv {
        WindowsEnv {
            source,
            exe_override: Some(exe),
        }
    }
}

const EMPTY_PASSWORD_LINE: &str = "ssh-broker: empty passwords are not supported yet (ssh-broker#45). Enter a password, or press Ctrl+C to cancel.\r\n";

impl AutoLoginEnv for WindowsEnv {
    fn is_elevated(&self) -> anyhow::Result<bool> {
        crate::account::is_elevated()
    }

    fn has_terminal(&self) -> bool {
        matches!(self.source, PasswordSource::Given(_)) || crate::console_prompt::console_available()
    }

    fn exe(&self) -> PathBuf {
        self.exe_override
            .clone()
            .unwrap_or_else(crate::provision::canonical_exe)
    }

    fn check_install(&self) -> anyhow::Result<()> {
        if self.exe_override.is_some() {
            return Ok(());
        }
        let layout = crate::provision::layout::Layout::production();
        if let Err(reason) = crate::provision::layout::check_base(&layout) {
            anyhow::bail!(
                "ssh-broker: the install directory is not trusted ({reason}); the task would run from it with a \
                 stored password. Run apply, or inspect the directory"
            );
        }
        anyhow::ensure!(
            layout.canonical_exe().is_file(),
            "ssh-broker: {} is not installed; run apply first",
            layout.canonical_exe().display()
        );
        Ok(())
    }

    fn ask_password(&mut self, account: &LocalAccount) -> anyhow::Result<Option<Password>> {
        if let PasswordSource::Given(slot) = &mut self.source {
            return Ok(slot.take());
        }
        let mut prompt = crate::console_prompt::ConsolePrompt::enter()?
            .ok_or_else(|| anyhow::anyhow!("ssh-broker: auto-login on needs a terminal to ask for the password."))?;
        prompt.write_text(&format!(
            "ssh-broker: Enter the Windows password of {} to store it for auto-login. (ssh-broker hands it to Task \
             Scheduler and does not keep it.) Press Ctrl+C to cancel.\r\n",
            account.name
        ));
        ask_until_answered(&mut prompt)
    }

    fn batch_right(&self, account: &LocalAccount, password: &Password) -> BatchRight {
        crate::logon::check_batch_logon(account, password)
    }

    fn register(&mut self, account: &LocalAccount, xml: &str, password: &Password, sddl: &str) -> anyhow::Result<()> {
        let machine_user = format!("{}\\{}", crate::account::computer_name()?, account.name);
        crate::provision::taskscheduler::register_password_task(
            &task_name(&account.sid),
            xml,
            &machine_user,
            password,
            sddl,
        )
    }

    fn read_back(&self, name: &str) -> anyhow::Result<Option<TaskState>> {
        crate::provision::taskscheduler::task_state(name)
    }

    fn delete(&mut self, name: &str) -> anyhow::Result<bool> {
        crate::provision::taskscheduler::delete_task(name)
    }

    fn run_now(&mut self, name: &str) -> anyhow::Result<()> {
        crate::provision::taskscheduler::run_task(name)
    }

    fn say(&mut self, line: &str) {
        println!("{line}");
    }
}

/// What the password prompt needs from the console.
trait Prompt {
    fn read_step(&mut self) -> Result<Step, windows::core::Error>;
    fn write_text(&mut self, text: &str);
}

impl Prompt for crate::console_prompt::ConsolePrompt {
    fn read_step(&mut self) -> Result<Step, windows::core::Error> {
        crate::console_prompt::ConsolePrompt::read_step(self)
    }

    fn write_text(&mut self, text: &str) {
        crate::console_prompt::ConsolePrompt::write_text(self, text);
    }
}

/// Read until a password is submitted (`Some`) or the user cancels (`None`); an empty Enter asks again.
fn ask_until_answered(prompt: &mut dyn Prompt) -> anyhow::Result<Option<Password>> {
    loop {
        match prompt.read_step() {
            Ok(Step::Submit(password)) => return Ok(Some(password)),
            Ok(Step::Empty) => prompt.write_text(EMPTY_PASSWORD_LINE),
            Ok(Step::Cancel) => return Ok(None),
            Ok(Step::Continue) => {}
            Err(e) => {
                return Err(anyhow::Error::new(e).context("ssh-broker: the console input failed; nothing was changed"));
            }
        }
    }
}

/// `ssh-broker auto-login on|off [<account>]`.
pub fn run(args: crate::route::AutoLoginArgs) -> anyhow::Result<()> {
    use crate::route::Toggle;
    let account = match &args.account {
        Some(name) => crate::account::account_named(name)?,
        None => crate::account::current_account()?,
    };
    let mut env = WindowsEnv::new(PasswordSource::Console);
    match args.toggle {
        Toggle::On => on(&mut env, &account),
        Toggle::Off => off(&mut env, &account),
    }
}

#[cfg(test)]
#[path = "autologin_tests.rs"]
mod autologin_tests;

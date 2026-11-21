//! ssh-broker entrypoint: dispatch argv to the library.
//!
//! Everything of substance lives in the library crate; this binary only decides which
//! entry point argv selects. See `lib.rs` for the architecture.

use ssh_broker::route::Verb;
use ssh_broker::{Route, agent, cmdline, provision, route, shim};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match route(&args, &cmdline::current()) {
        Route::Shim { exec } => shim::run(exec),
        // The agent has threads that end the process too (`logout`); every end goes through one guard,
        // so that none is inside the process's exit while another begins it.
        Route::Agent(args) => match agent::run(args) {
            Ok(()) => agent::end_process(0),
            Err(e) => agent::end_on_error(&e),
        },
        Route::Usage(verb) => {
            eprintln!("{}", usage(verb));
            std::process::exit(2);
        }
        Route::Logout => logout_command(),
        Route::Elevate { terminal, command } => elevate_command(terminal, &command),
        Route::AutoLogin(None) => {
            eprintln!("usage: ssh-broker auto-login on|off [<account>]");
            std::process::exit(2);
        }
        Route::AutoLogin(Some(args)) => auto_login_command(args).map_err(|e| {
            eprintln!("{e:#}");
            std::process::exit(1)
        }),
        Route::Install => provision::install(),
        Route::InstallSshd => provision::install_sshd(),
        Route::Doctor => provision::doctor(),
        Route::DoctorProbe(link) => provision::doctor_probe(link),
        Route::ConsoleFallback { handle, login } => console_fallback_command(handle, login),
    }
}

fn usage(verb: Verb) -> &'static str {
    match verb {
        Verb::Agent => "usage: ssh-broker agent [--background [--expect-user <sid>]]",
        Verb::Logout => "usage: ssh-broker logout",
        Verb::Elevate => ssh_broker::offer::text::elevate_usage(),
        Verb::ConsoleFallback => "usage: ssh-broker console-fallback [--login] <handle> (internal)",
        Verb::InstallSshd => "usage: ssh-broker install-sshd (internal: the task that install starts runs it)",
        Verb::DoctorProbe => {
            "usage: ssh-broker doctor-probe [--make-junction <directory> | --follow <directory>] (internal)"
        }
    }
}

/// `console-fallback`: read the notice and the line from the inherited pipe `handle`, print the notice
/// on this console, start the line on it and exit with its code. The agent starts this in place of a
/// fallback shell in a pseudoconsole, because anything it writes to one ahead of the shell is cleared
/// (see `agent::launch`). `login`: the session has no command.
#[cfg(windows)]
fn console_fallback_command(handle: usize, login: bool) -> anyhow::Result<()> {
    std::process::exit(ssh_broker::shim_pty::console_fallback(handle, login))
}

#[cfg(not(windows))]
fn console_fallback_command(_handle: usize, _login: bool) -> anyhow::Result<()> {
    anyhow::bail!("console-fallback starts a shell for the agent and runs only on Windows")
}

#[cfg(windows)]
fn logout_command() -> anyhow::Result<()> {
    ssh_broker::logout::run()
}

#[cfg(not(windows))]
fn logout_command() -> anyhow::Result<()> {
    anyhow::bail!("logout ends a Windows background session and runs only on Windows")
}

#[cfg(windows)]
fn elevate_command(terminal: bool, command: &str) -> anyhow::Result<()> {
    ssh_broker::elevate::run(terminal, command)
}

#[cfg(not(windows))]
fn elevate_command(_terminal: bool, _command: &str) -> anyhow::Result<()> {
    anyhow::bail!("elevate runs a command in a Windows session and runs only on Windows")
}

#[cfg(windows)]
fn auto_login_command(args: ssh_broker::route::AutoLoginArgs) -> anyhow::Result<()> {
    ssh_broker::autologin::run(args)
}

#[cfg(not(windows))]
fn auto_login_command(_args: ssh_broker::route::AutoLoginArgs) -> anyhow::Result<()> {
    anyhow::bail!("auto-login stores a Windows password for a boot task and runs only on Windows")
}

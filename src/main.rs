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
        Route::Agent(args) => agent::run(args).map_err(|e| {
            // An agent without a console has no other way to say why it stopped.
            eprintln!("ssh-broker agent: {e:#}");
            std::process::exit(agent::exit_code_of(&e))
        }),
        Route::Usage(verb) => {
            eprintln!("{}", usage(verb));
            std::process::exit(2);
        }
        Route::Logout => logout_command(),
        Route::AutoLogin(None) => {
            eprintln!("usage: ssh-broker auto-login on|off [<account>]");
            std::process::exit(2);
        }
        Route::AutoLogin(Some(args)) => auto_login_command(args).map_err(|e| {
            eprintln!("{e:#}");
            std::process::exit(1)
        }),
        Route::Apply => provision::apply(),
        Route::Verify => provision::verify(),
        Route::VerifyProbe => provision::verify_probe(),
    }
}

fn usage(verb: Verb) -> &'static str {
    match verb {
        Verb::Agent => "usage: ssh-broker agent [--background [--expect-user <sid>]]",
        Verb::Logout => "usage: ssh-broker logout",
    }
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
fn auto_login_command(args: ssh_broker::route::AutoLoginArgs) -> anyhow::Result<()> {
    ssh_broker::autologin::run(args)
}

#[cfg(not(windows))]
fn auto_login_command(_args: ssh_broker::route::AutoLoginArgs) -> anyhow::Result<()> {
    anyhow::bail!("auto-login stores a Windows password for a boot task and runs only on Windows")
}

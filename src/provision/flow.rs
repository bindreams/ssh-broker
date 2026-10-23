//! The shape of `apply`: install, then bring agents back. Held apart from the Windows calls so
//! the failure paths can be tested with stand-ins.

/// Run `install`, then `start` the agents.
///
/// `install` receives the function that stops every agent and must call it at most once, before
/// it replaces the exe. If `install` fails after that call (or inside it, since a stop that
/// failed part-way has still stopped some agents), `start` still runs, best-effort, so a failed
/// `apply` does not leave every logged-on user without an agent. `restart_is_safe` says whether
/// the registered agent task can start one: an older single-user task cannot. The error `install`
/// returned is returned as it was.
pub fn run<T>(
    stop: impl FnOnce() -> anyhow::Result<()>,
    install: impl FnOnce(&mut dyn FnMut() -> anyhow::Result<()>) -> anyhow::Result<T>,
    restart_is_safe: impl FnOnce() -> bool,
    start: impl FnOnce(),
) -> anyhow::Result<T> {
    let mut stop = Some(stop);
    let mut attempted = false;
    let result = install(&mut || {
        attempted = true;
        stop.take().expect("the stop is called at most once")()
    });
    if result.is_ok() || (attempted && restart_is_safe()) {
        start();
    }
    result
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod flow_tests;

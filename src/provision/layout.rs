//! layout: where `apply` puts things under the install directory, and the order it touches them.
//!
//! The install directory holds the exe the agent and the self-heal task run, so nothing may be
//! read from it or written into it until [`acl::ensure_install_dir`] has made it or proved it is
//! the one this build hardened. A [`TrustedBase`] is that proof, and everything that touches the
//! directory takes one.

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::report::Check;
use super::schtasks;
use crate::acl;

/// The install directory and the paths derived from it.
#[derive(Debug)]
pub struct Layout {
    pub base: PathBuf,
}

impl Layout {
    pub fn production() -> Layout {
        Layout {
            base: PathBuf::from(super::BASE_DIR),
        }
    }

    pub fn canonical_exe(&self) -> PathBuf {
        self.base.join(super::EXE_NAME)
    }

    /// The saved account of a single-user install. No longer written or read; `apply` removes it.
    fn legacy_config_path(&self) -> PathBuf {
        self.base.join("config.toml")
    }

    /// The socket directory of a single-user install. `apply` removes it; sockets now live in
    /// each user's profile.
    fn legacy_socket_dir(&self) -> PathBuf {
        self.base.join("s")
    }
}

/// Proof that the install directory passed its ACL check. Only [`ensure_base`] and
/// [`check_base`] build one.
#[derive(Debug)]
pub struct TrustedBase<'a> {
    layout: &'a Layout,
}

impl<'a> TrustedBase<'a> {
    pub fn layout(&self) -> &'a Layout {
        self.layout
    }
}

/// The outcome of a read-only check of the install directory: the proof, or why there is none.
pub type BaseCheck<'a> = Result<TrustedBase<'a>, String>;

/// Create the install directory hardened, or prove an existing one is.
pub fn ensure_base(layout: &Layout) -> anyhow::Result<TrustedBase<'_>> {
    acl::ensure_install_dir(&layout.base)?;
    Ok(TrustedBase { layout })
}

/// Check the install directory without creating or changing anything (for `verify`).
pub fn check_base(layout: &Layout) -> BaseCheck<'_> {
    match acl::install_dir_problem(&layout.base) {
        Ok(None) => Ok(TrustedBase { layout }),
        Ok(Some(problem)) => Err(problem),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Run `action`, which reads from or runs something in the install directory, only if the
/// directory passed its ACL check.
pub fn run_if_trusted_base<T>(
    base: &BaseCheck<'_>,
    action: impl FnOnce(&TrustedBase<'_>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    match base {
        Ok(trusted) => action(trusted),
        Err(reason) => anyhow::bail!("install dir untrusted ({reason}): not running anything from it"),
    }
}

/// The `install dir ACL` row of `verify`.
pub fn install_dir_row(base: &BaseCheck<'_>) -> Check {
    match base {
        Ok(trusted) => Check::new("install dir ACL", true, trusted.layout.base.display().to_string()),
        Err(reason) => Check::new("install dir ACL", false, reason.as_str()),
    }
}

/// What a single-user install left behind: the artifacts `apply` removes or replaces.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Legacy {
    /// `config.toml`, which named the one account the agent served.
    pub config: bool,
    /// The shared `s\` socket directory.
    pub socket_dir: bool,
    /// A registered agent task that is not the group form: it names one account, and a running
    /// agent of that form holds the exe open and a machine-wide mutex.
    pub task: bool,
}

impl Legacy {
    pub fn any(&self) -> bool {
        self.config || self.socket_dir || self.task
    }

    /// What was found, for the line `apply` prints.
    pub fn describe(&self) -> String {
        let mut found = Vec::new();
        if self.task {
            found.push("the per-user agent task");
        }
        if self.config {
            found.push("config.toml");
        }
        if self.socket_dir {
            found.push("the shared socket directory");
        }
        found.join(", ")
    }
}

/// Look for the artifacts of a single-user install. `agent_task_xml` is the queried XML of the
/// registered agent task, or `None` if there is none. The install directory is only inspected
/// (never read), but it is still taken as a [`TrustedBase`]: nothing looks into an untrusted one.
pub fn legacy_artifacts(base: &TrustedBase<'_>, agent_task_xml: Option<&str>) -> Legacy {
    let exists = |path: PathBuf| path.symlink_metadata().is_ok();
    Legacy {
        config: exists(base.layout.legacy_config_path()),
        socket_dir: exists(base.layout.legacy_socket_dir()),
        task: agent_task_xml.is_some_and(|xml| !schtasks::xml_is_group_logon_task(xml)),
    }
}

/// Remove the files and directories in `legacy`. The task needs no removal: registering the new
/// one with `/F` replaces it.
pub fn remove_legacy(base: &TrustedBase<'_>, legacy: &Legacy) -> anyhow::Result<()> {
    let layout = base.layout;
    if legacy.config {
        remove_if_present(std::fs::remove_file(layout.legacy_config_path()))
            .with_context(|| format!("remove {}", layout.legacy_config_path().display()))?;
    }
    if legacy.socket_dir {
        remove_if_present(std::fs::remove_dir_all(layout.legacy_socket_dir()))
            .with_context(|| format!("remove {}", layout.legacy_socket_dir().display()))?;
    }
    Ok(())
}

fn remove_if_present(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// `apply`'s steps up to the registrations, in the only order that is safe: the base, then the
/// migration of a single-user install, then the exe. Returns the canonical exe path.
///
/// `agent_task_xml` is the queried XML of the registered agent task (`None` if there is none),
/// and `stop_agents` stops every running agent. It is called only when it has to be: a legacy
/// artifact is found, or an installed exe is about to be replaced by a different build. So
/// re-running `apply` and the boot self-heal with the installed build leave live agents alone.
/// The caller starts agents again once the tasks are registered.
pub fn prepare(
    layout: &Layout,
    current_exe: &Path,
    agent_task_xml: Option<&str>,
    stop_agents: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let base = ensure_base(layout)?;
    prepare_in(&base, current_exe, agent_task_xml, stop_agents)
}

/// [`prepare`] on a base that already passed [`ensure_base`].
pub fn prepare_in(
    base: &TrustedBase<'_>,
    current_exe: &Path,
    agent_task_xml: Option<&str>,
    stop_agents: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let legacy = legacy_artifacts(base, agent_task_xml);
    let replaces_exe = would_replace_installed_exe(base.layout, current_exe);
    if legacy.any() {
        println!("apply: replacing a single-user install ({})", legacy.describe());
    }
    if legacy.any() || replaces_exe {
        // Before the exe is copied: a running agent holds it open, and the copy would fail with a
        // sharing violation and leave the old exe under the new tasks.
        stop_agents().context("stop the running agents")?;
    }
    if legacy.any() {
        remove_legacy(base, &legacy)?;
    }
    install_self(base.layout, current_exe)
}

/// Whether installing `current` would overwrite an installed exe with a different build.
fn would_replace_installed_exe(layout: &Layout, current: &Path) -> bool {
    let canonical = layout.canonical_exe();
    current != canonical && canonical.is_file() && !files_identical(current, &canonical)
}

/// Copy `current` to the canonical path unless it is already there or identical.
///
/// A copy that fails is an error. By now every agent the logon task started has been stopped, so
/// what still holds the exe open is something else (an agent started by hand). Keeping the old exe
/// under the new tasks would report an install that did not happen.
fn install_self(layout: &Layout, current: &Path) -> anyhow::Result<PathBuf> {
    let canonical = layout.canonical_exe();
    if current != canonical && !files_identical(current, &canonical) {
        std::fs::copy(current, &canonical).with_context(|| {
            format!(
                "could not replace {}: it is in use, probably by an agent started by hand with \
                 `ssh-broker agent`; stop that agent and run apply again",
                canonical.display()
            )
        })?;
    }
    anyhow::ensure!(canonical.is_file(), "canonical exe missing after install");
    Ok(canonical)
}

fn files_identical(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;

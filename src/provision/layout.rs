//! layout: where `apply` puts things under the install directory, and the order it touches them.
//!
//! The install directory holds the exe the agent runs, so nothing may be read from it or written
//! into it until [`acl::ensure_install_dir`] has made it or proved it is the one this build
//! hardened. A [`TrustedBase`] is that proof, and everything that touches the directory takes one.

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::report::Check;
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

    /// The file whose lock lets one `apply` (or `auto-login on|off`) run at a time; see
    /// [`super::apply_lock`].
    pub fn apply_lock_path(&self) -> PathBuf {
        self.base.join("apply.lock")
    }

    /// The system layer of the shell configuration; see [`crate::shell`].
    pub fn system_config_path(&self) -> PathBuf {
        self.base.join("config.yaml")
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

/// `apply`'s steps up to the registrations, in the only order that is safe: the base, then the
/// exe. Returns the canonical exe path.
///
/// `stop_agents` stops every running agent and returns only once each has exited (the exe is
/// copied right after, and a process that is stopped but not yet gone still holds it). It is called
/// only when an installed exe is about to be replaced by a different build, so re-running `apply`
/// with the installed build leaves live agents alone. The caller starts agents again once the task
/// is registered.
///
/// `base` is the proof from [`ensure_base`].
pub fn prepare_in(
    base: &TrustedBase<'_>,
    current_exe: &Path,
    stop_agents: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    if would_replace_installed_exe(base.layout, current_exe) {
        // Before the exe is copied: a running agent holds it open, and the copy would fail with a
        // sharing violation and leave the old exe under the new task.
        stop_agents().context("stop the running agents")?;
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
/// A copy that fails is an error. By now every agent the logon task started has been stopped and
/// has exited, so a sharing violation means something else holds the exe open (an agent started
/// by hand, or the shim of an open SSH session: the exe is sshd's DefaultShell). Keeping the old exe under the new tasks would report an install that did not happen.
fn install_self(layout: &Layout, current: &Path) -> anyhow::Result<PathBuf> {
    let canonical = layout.canonical_exe();
    if current != canonical && !files_identical(current, &canonical) {
        std::fs::copy(current, &canonical).map_err(|e| anyhow::anyhow!(copy_failure(&canonical, &e)))?;
    }
    anyhow::ensure!(canonical.is_file(), "canonical exe missing after install");
    Ok(canonical)
}

/// `ERROR_SHARING_VIOLATION`: another handle on the file allows no write.
const ERROR_SHARING_VIOLATION: i32 = 32;
/// `ERROR_USER_MAPPED_FILE`: the file has a mapped section open.
const ERROR_USER_MAPPED_FILE: i32 = 1224;

/// Why replacing `canonical` failed. It says "in use" only for the codes that mean something holds
/// the file open; every other failure is named by its own error.
fn copy_failure(canonical: &Path, err: &std::io::Error) -> String {
    let in_use = matches!(
        err.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_USER_MAPPED_FILE)
    );
    if in_use {
        format!(
            "could not replace {}: {err}. It is in use although the agents of the logon task have exited: \
             either by an agent started by hand with `ssh-broker agent`, or by the shim of an open SSH \
             session (the exe is sshd's DefaultShell). Find the processes with `tasklist /fi \"imagename eq {}\"`, \
             end them or close the SSH sessions, and run apply again",
            canonical.display(),
            super::EXE_NAME
        )
    } else {
        format!("could not replace {}: {err}", canonical.display())
    }
}

fn files_identical(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;

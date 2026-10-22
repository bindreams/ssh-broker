//! layout: where `apply` puts things under the install directory, and the order it touches them.
//!
//! The install directory holds the exe the agent and the self-heal task run, so `apply` must
//! not write anything into it, or read the saved config from it, before
//! [`acl::ensure_install_dir`] has made it or proved it is the one this build hardened.
//! [`ensure_base`] is that gate; [`resolve_user`] and [`populate`] come after it.

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::config;
use crate::acl::{self, Sid};

/// The install directory and the paths derived from it.
pub struct Layout {
    pub base: PathBuf,
}

impl Layout {
    pub fn production() -> Layout {
        Layout {
            base: PathBuf::from(r"C:\ProgramData\ssh-broker"),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.base.join("config.toml")
    }

    pub fn canonical_exe(&self) -> PathBuf {
        self.base.join("ssh-broker.exe")
    }

    /// The agent's socket directory (see `afunix::socket_dir`, which the agent binds in).
    pub fn socket_dir(&self) -> PathBuf {
        self.base.join("s")
    }

    /// The shim's log directory (see `shim_pty::log_dir`). It inherits the install directory's
    /// DACL, so only SYSTEM and Administrators can write to it.
    pub fn logs_dir(&self) -> PathBuf {
        self.base.join("logs")
    }
}

/// Create the install directory hardened, or prove an existing one is. The only function here
/// allowed to touch a directory it did not make, and it only reads it.
pub fn ensure_base(layout: &Layout) -> anyhow::Result<()> {
    acl::ensure_install_dir(&layout.base)
}

/// [`ensure_base`], then the target account by name: CLI `--user` > the saved config > the
/// interactive user. The saved config is read only from a directory that passed `ensure_base`.
pub fn resolve_user(layout: &Layout, cli_user: Option<&str>, current_user: Option<&str>) -> anyhow::Result<String> {
    ensure_base(layout)?;
    let saved = std::fs::read_to_string(layout.config_path())
        .ok()
        .and_then(|s| config::Config::from_toml(&s).ok())
        .map(|c| c.target_user);
    config::resolve_target_user(cli_user, saved.as_deref(), current_user)
}

/// Fill a base that passed [`ensure_base`]: the logs directory, the exe, the hardened socket
/// directory for `sid`, and the config recording `user`. Returns the canonical exe path.
pub fn populate(layout: &Layout, current_exe: &Path, user: &str, sid: &Sid) -> anyhow::Result<PathBuf> {
    let exe = install_self(layout, current_exe)?;

    std::fs::create_dir_all(layout.logs_dir()).context("create logs dir")?;

    let sdir = layout.socket_dir();
    std::fs::create_dir_all(&sdir).context("create socket dir")?;
    acl::harden_dir(&sdir, sid).context("harden socket dir")?;
    anyhow::ensure!(
        acl::verify_dir_acl(&sdir, sid).unwrap_or(false),
        "socket dir ACL did not verify after harden"
    );

    write_config(layout, user)?;
    Ok(exe)
}

/// Copy `current` to the canonical path unless it is already there or identical.
fn install_self(layout: &Layout, current: &Path) -> anyhow::Result<PathBuf> {
    let canonical = layout.canonical_exe();
    if current != canonical
        && !files_identical(current, &canonical)
        && let Err(e) = std::fs::copy(current, &canonical)
    {
        // A running agent holds the canonical exe open (sharing violation). Don't abort
        // the whole idempotent re-apply: if a canonical exe already exists, keep it and
        // repair the rest of the state (installing a NEW build needs the agent stopped).
        anyhow::ensure!(
            canonical.is_file(),
            "copy self to {} failed and no canonical exe exists: {e}",
            canonical.display()
        );
        eprintln!(
            "apply: could not update {} ({e}); using the existing exe              — stop the agent to update the binary",
            canonical.display()
        );
    }
    anyhow::ensure!(canonical.is_file(), "canonical exe missing after install");
    Ok(canonical)
}

fn files_identical(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

fn write_config(layout: &Layout, user: &str) -> anyhow::Result<()> {
    let toml = config::Config {
        target_user: user.to_string(),
    }
    .to_toml()?;
    // Direct overwrite: config.toml is read only by apply/verify, never concurrently with
    // this write, so atomicity buys nothing — and a plain write is reliably idempotent on
    // every re-apply (a temp+rename adds a Windows replace-semantics footgun for no gain).
    std::fs::write(layout.config_path(), toml).context("write config")?;
    Ok(())
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;

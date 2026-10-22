//! layout: where `apply` puts things under the install directory, and the order it touches them.
//!
//! The install directory holds the exe the agent and the self-heal task run, so nothing may be
//! read from it or written into it until [`acl::ensure_install_dir`] has made it or proved it is
//! the one this build hardened. A [`TrustedBase`] is that proof, and everything that touches the
//! directory takes one.

use std::path::{Path, PathBuf};

use anyhow::Context;

use super::config;
use super::report::Check;
use crate::acl::{self, Sid};

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

    pub fn config_path(&self) -> PathBuf {
        self.base.join("config.toml")
    }

    pub fn canonical_exe(&self) -> PathBuf {
        self.base.join(super::EXE_NAME)
    }

    /// The agent's socket directory.
    pub fn socket_dir(&self) -> PathBuf {
        self.base.join("s")
    }

    /// The shim's log directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.base.join("logs")
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

/// The target account by name: CLI `--user` > the saved config > the interactive user. The
/// config is read only when `--user` does not settle it, so a damaged config cannot block the
/// `apply --user X` that repairs it.
pub fn resolve_user(
    base: &TrustedBase<'_>,
    cli_user: Option<&str>,
    current_user: Option<&str>,
) -> anyhow::Result<String> {
    let saved = if cli_user.is_some_and(|user| !user.is_empty()) {
        None
    } else {
        saved_user(base).with_context(|| {
            format!(
                "fix or delete {}, or pass --user <account>",
                base.layout.config_path().display()
            )
        })?
    };
    config::resolve_target_user(cli_user, saved.as_deref(), current_user)
}

/// The account recorded in the saved config, or `None` if there is no config. A config that
/// cannot be read or parsed is an error. The config lives in the install directory, hence the
/// [`TrustedBase`].
pub fn saved_user(base: &TrustedBase<'_>) -> anyhow::Result<Option<String>> {
    let path = base.layout.config_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let saved = config::Config::from_toml(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(saved.target_user))
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

/// The `socket dir ACL` row of `verify`: the socket directory verifies for the account in the
/// saved config (the agent's grantee).
pub fn socket_dir_row(base: &BaseCheck<'_>) -> Check {
    const NAME: &str = "socket dir ACL";
    let Ok(base) = base else {
        return Check::new(NAME, false, "install dir untrusted: its config is not read");
    };
    let user = match saved_user(base) {
        Ok(Some(user)) => user,
        Ok(None) => return Check::new(NAME, false, "no config target_user"),
        Err(e) => return Check::new(NAME, false, format!("{e:#}")),
    };
    let verified = Sid::lookup(&user)
        .with_context(|| format!("resolve {user:?}"))
        .and_then(|sid| acl::verify_dir_acl(&base.layout.socket_dir(), &sid).context("verify socket dir ACL"));
    match verified {
        Ok(ok) => Check::new(NAME, ok, format!("grantee={user}")),
        Err(e) => Check::new(NAME, false, format!("grantee={user}: {e:#}")),
    }
}

/// `apply`'s steps up to the registrations, in the only order that is safe: the base, then the
/// account (which reads the saved config), then everything written into it. Returns the account
/// and the canonical exe path.
pub fn prepare(
    layout: &Layout,
    current_exe: &Path,
    cli_user: Option<&str>,
    current_user: Option<&str>,
) -> anyhow::Result<(String, PathBuf)> {
    let base = ensure_base(layout)?;
    let user = resolve_user(&base, cli_user, current_user)?;
    let sid = Sid::lookup(&user).with_context(|| format!("resolving SID for {user:?}"))?;
    let exe = populate(&base, current_exe, &user, &sid)?;
    Ok((user, exe))
}

/// Fill a base that passed [`ensure_base`]. Returns the canonical exe path.
pub fn populate(base: &TrustedBase<'_>, current_exe: &Path, user: &str, sid: &Sid) -> anyhow::Result<PathBuf> {
    let layout = base.layout;
    let exe = install_self(layout, current_exe)?;

    std::fs::create_dir_all(layout.logs_dir()).context("create logs dir")?;

    let sdir = layout.socket_dir();
    std::fs::create_dir_all(&sdir).context("create socket dir")?;
    acl::harden_dir(&sdir, sid).context("harden socket dir")?;
    anyhow::ensure!(
        acl::verify_dir_acl(&sdir, sid).context("verify socket dir ACL")?,
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
            "apply: could not update {} ({e}); using the existing exe \
             — stop the agent to update the binary",
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

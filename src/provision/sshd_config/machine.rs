//! provision::sshd_config::machine — the machine behind [`SshdHost`]: `%ProgramData%\ssh`, the `sshd.exe` the
//! service runs, and `net.exe`. Nothing here is decided; the flow is [`configure`], which is tested against a
//! stand-in. `tests/sshd_config_windows.rs` runs this against a real sshd in CI.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

use super::DROP_IN_NAME;
use super::configure::{Outcome, Service, ServiceOutcome, SshdHost, configure, net_outcome};
use crate::acl;
use crate::provision::{registry, system_config};

/// sshd's configuration directory. Written the way [`crate::provision::BASE_DIR`] is: one place, no lookup.
const SSH_DIR: &str = r"C:\ProgramData\ssh";

/// The candidate `sshd_config`, beside the original so that the rename that replaces it stays on one volume.
const CANDIDATE_NAME: &str = "sshd_config.ssh-broker-new";

/// The files of sshd, and the programs `apply` runs to check and restart it.
struct Machine {
    ssh_dir: PathBuf,
    /// The `sshd.exe` the service runs, found from the service's own `ImagePath`.
    sshd: PathBuf,
    /// `net.exe` in the system directory.
    net: PathBuf,
}

impl Machine {
    fn find() -> anyhow::Result<Machine> {
        let image = registry::read_sshd_image_path()
            .context("read where the sshd service runs from")?
            .context("there is no sshd service")?;
        let sshd = system_config::image_program(&image).context("the sshd service's ImagePath names no program")?;
        let system_cmd = {
            use crate::shell::Host;
            crate::shell::WindowsHost.system_cmd()?
        };
        let net = system_cmd
            .parent()
            .context("the system directory has no name")?
            .join("net.exe");
        Ok(Machine {
            ssh_dir: PathBuf::from(SSH_DIR),
            sshd: PathBuf::from(sshd),
            net,
        })
    }

    fn config(&self) -> PathBuf {
        self.ssh_dir.join("sshd_config")
    }

    fn drop_in_dir(&self) -> PathBuf {
        self.ssh_dir.join("sshd_config.d")
    }

    fn drop_in(&self) -> PathBuf {
        self.drop_in_dir().join(DROP_IN_NAME)
    }

    /// Run `sshd` with `args` and return its standard output, or what it said on the way to failing.
    fn run_sshd(&self, args: &[&OsStr]) -> anyhow::Result<String> {
        let out = Command::new(&self.sshd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {}", self.sshd.display()))?;
        anyhow::ensure!(
            out.status.success(),
            "sshd exited with {}: {}",
            out.status.code().map_or("no code".to_owned(), |code| code.to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl SshdHost for Machine {
    fn config_path(&self) -> PathBuf {
        self.config()
    }

    fn sshd_t(&mut self, config: Option<&Path>) -> anyhow::Result<String> {
        match config {
            None => self.run_sshd(&[OsStr::new("-T")]),
            Some(file) => self.run_sshd(&[OsStr::new("-T"), OsStr::new("-f"), file.as_os_str()]),
        }
    }

    fn sshd_check(&mut self, config: &Path) -> Result<(), String> {
        self.run_sshd(&[OsStr::new("-t"), OsStr::new("-f"), config.as_os_str()])
            .map(drop)
            .map_err(|e| format!("{e:#}"))
    }

    fn service(&mut self, verb: Service) -> ServiceOutcome {
        let word = match verb {
            Service::Stop => "stop",
            Service::Start => "start",
        };
        // `net` returns once the service has stopped, or once it runs.
        match Command::new(&self.net)
            .args([word, "sshd"])
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) => {
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                net_outcome(verb, out.status.code().unwrap_or(-1), &said)
            }
            Err(e) => ServiceOutcome::Failed(format!("run {}: {e}", self.net.display())),
        }
    }

    fn ensure_drop_in_dir(&mut self) -> anyhow::Result<()> {
        acl::ensure_admin_only_dir(&self.drop_in_dir())
    }

    fn read_drop_in(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.drop_in();
        if let Err(e) = std::fs::symlink_metadata(&path) {
            return if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e).with_context(|| format!("look at {}", path.display()))
            };
        }
        // A file others can write would let them configure sshd, and a copy with the right text would pass.
        if let Some(problem) = acl::admin_only_file_problem(&path)? {
            anyhow::bail!(
                "{} cannot be trusted as private to SYSTEM and Administrators: {problem}. Inspect it, remove it, \
                 and run `apply` again",
                path.display()
            );
        }
        Ok(Some(
            std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        ))
    }

    fn write_drop_in(&mut self, text: &[u8]) -> anyhow::Result<()> {
        let path = self.drop_in();
        // The file is made with its descriptor, and a file that is there must already be exactly that: the
        // write below keeps the descriptor.
        acl::ensure_admin_only_file(&path)?;
        std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))
    }

    fn remove_drop_in(&mut self) -> anyhow::Result<()> {
        let path = self.drop_in();
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))
    }

    fn read_config(&mut self) -> anyhow::Result<Vec<u8>> {
        let path = self.config();
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    fn write_candidate(&mut self, text: &[u8]) -> anyhow::Result<PathBuf> {
        let path = self.ssh_dir.join(CANDIDATE_NAME);
        std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    fn copy_security(&mut self, candidate: &Path) -> anyhow::Result<()> {
        acl::copy_file_security(&self.config(), candidate)
    }

    fn replace_config(&mut self, candidate: &Path) -> anyhow::Result<()> {
        let config = self.config();
        std::fs::rename(candidate, &config)
            .with_context(|| format!("rename {} over {}", candidate.display(), config.display()))
    }

    fn discard_candidate(&mut self, candidate: &Path) {
        // A candidate that cannot be removed is overwritten by the next run, and is read by nothing.
        let _ = std::fs::remove_file(candidate);
    }
}

/// `apply`'s sshd step on this machine: see [`configure`]. It never fails: what it could not do is said on
/// `say`.
pub fn configure_this_machine(say: &mut dyn FnMut(&str)) -> Outcome {
    match Machine::find() {
        Ok(mut machine) => configure(&mut machine, say),
        Err(e) => {
            say(&format!(
                "apply: cannot find sshd, so it was not set up to accept {}: {e:#}",
                crate::protocol::ElevationPolicy::VARIABLE
            ));
            Outcome {
                accepts: false,
                restarted: false,
            }
        }
    }
}

/// `sshd -T` on this machine: sshd's effective configuration. Needs the rights to read sshd's host keys.
pub fn sshd_t_this_machine() -> anyhow::Result<String> {
    Machine::find()?.sshd_t(None)
}

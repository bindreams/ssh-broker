//! The file that hands a fallback shell's notice and line to the hidden `console-fallback` verb.
//!
//! A pseudoconsole clears the screen after anything written ahead of the shell, so the agent starts
//! the verb, which prints the notice from inside it and then starts the line. A command line takes
//! 32,767 UTF-16 units, so the line cannot travel as an argument beside the verb's own name; it goes
//! in a file, and the verb is given the file's path.
//!
//! The file is made in the user's private folder (`socket_loc::SocketLocation::dir`), whose
//! inheritable owner-only ACEs the file is born with. The verb starts the line the file holds, so
//! [`take`] reads only a file in that folder, and only if the caller's check finds its ACL private.
//! The file lives from [`stage`] until the verb has read it, or until the agent's spawn fails. An
//! agent killed in between leaves it behind; [`sweep`] removes such files when an agent starts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;

const NAME_PREFIX: &str = "console-fallback-";

/// A file written by [`stage`]. Removed when dropped, unless it was handed over to the verb.
#[derive(Debug)]
pub struct Staged {
    path: Option<PathBuf>,
}

impl Staged {
    /// The path to give the verb.
    pub fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("a staged file has its path until it is handed over")
    }

    /// The verb is running and owns the file now: it removes it after reading.
    pub fn hand_over(mut self) {
        self.path = None;
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some(path) = self.path.take()
            && let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("could not remove {}: {e}", path.display());
        }
    }
}

/// Write `notice` and `line` to a new file in `dir`, which must exist. The file appears whole under
/// its final name, by a rename from a name nothing reads.
pub fn stage(dir: &Path, notice: &str, line: &str) -> std::io::Result<Staged> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let bytes = postcard::to_stdvec(&(notice, line)).map_err(std::io::Error::other)?;
    loop {
        let name = format!(
            "{NAME_PREFIX}{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let (made, final_path) = (dir.join(format!("{name}.tmp")), dir.join(&name));
        let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&made) {
            Ok(file) => file,
            // A file of an agent that died with this process id: the next name is free.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let written = file.write_all(&bytes).and_then(|()| file.flush());
        drop(file);
        let renamed = written.and_then(|()| std::fs::rename(&made, &final_path));
        if let Err(e) = renamed {
            let _ = std::fs::remove_file(&made);
            return Err(e);
        }
        return Ok(Staged { path: Some(final_path) });
    }
}

/// The pid in the name of a file [`stage`] makes (or of the `.tmp` file it renames).
fn writer_of(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(NAME_PREFIX)?;
    let rest = rest.strip_suffix(".tmp").unwrap_or(rest);
    let (pid, n) = rest.split_once('-')?;
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    (digits(pid) && digits(n) && n.parse::<u64>().is_ok())
        .then(|| pid.parse().ok())
        .flatten()
}

/// Remove the files in `dir` whose writer is gone: an agent killed after [`stage`] and before its
/// verb read the file leaves one behind.
///
/// `is_live` says whether a process with the writer's pid is the writer (a pid is reused, so it must
/// tell a running agent from another program that has the number). A file whose writer it cannot
/// check stays, since nothing shows it is an orphan; the next sweep asks again. Names that [`stage`]
/// does not make are left alone and their writers are not asked about.
pub fn sweep(dir: &Path, mut is_live: impl FnMut(u32) -> anyhow::Result<bool>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(writer_of) else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        match is_live(pid) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = std::fs::remove_file(entry.path())
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!("could not remove {}: {e}", entry.path().display());
                }
            }
            Err(e) => tracing::warn!(
                "left {} in place: could not tell if process {pid} is still running: {e:#}",
                entry.path().display()
            ),
        }
    }
    Ok(())
}

/// The notice and the line `file` holds, and the file removed.
///
/// `file` must be directly in `dir` (the user's private folder, from the token) and `private` must
/// find its ACL private; a file that is not is removed unread. A file outside `dir` is refused and
/// left alone.
pub fn take(
    file: &Path,
    dir: &Path,
    private: impl FnOnce(&Path) -> anyhow::Result<bool>,
) -> anyhow::Result<(String, String)> {
    anyhow::ensure!(
        file.parent() == Some(dir),
        "{} is not in the private folder {}",
        file.display(),
        dir.display()
    );
    let read = || -> anyhow::Result<(String, String)> {
        anyhow::ensure!(
            private(file).with_context(|| format!("check the ACL of {}", file.display()))?,
            "{} is not private to this account",
            file.display()
        );
        let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
        postcard::from_bytes(&bytes).with_context(|| format!("{} does not hold a notice and a line", file.display()))
    };
    let result = read();
    // A file that stays is no worse than one that was never read: nothing reads it again.
    if let Err(e) = std::fs::remove_file(file)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("could not remove {}: {e}", file.display());
    }
    result
}

#[cfg(test)]
#[path = "fallback_file_tests.rs"]
pub(crate) mod fallback_file_tests;

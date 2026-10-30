//! A table-driven [`Host`] for the unit tests: it answers from stated facts and models nothing.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::Host;

/// What a path holds.
#[derive(Clone)]
pub enum Entry {
    File(Vec<u8>),
    Dir,
    /// Reading it fails with this message (access denied, a sharing violation).
    Unreadable(&'static str),
}

pub const SYSTEM_CMD: &str = r"C:\Windows\System32\cmd.exe";
pub const SYSTEM_CONFIG: &str = r"C:\ProgramData\ssh-broker\config.yaml";
pub const PROFILE: &str = r"C:\Users\me";
pub const USER_CONFIG: &str = r"C:\Users\me\.config\ssh-broker\config.yaml";

pub struct TestHost {
    pub env: HashMap<String, OsString>,
    pub profile: Option<PathBuf>,
    pub entries: HashMap<PathBuf, Entry>,
    /// Bare name to the file `find_program` returns.
    pub path: HashMap<String, PathBuf>,
    /// Paths that are the system `cmd.exe` by identity (besides [`SYSTEM_CMD`] itself).
    pub system_cmd_aliases: Vec<PathBuf>,
    /// Every path `read_file` was asked for, in order.
    pub reads: Mutex<Vec<PathBuf>>,
}

impl TestHost {
    /// A machine with the system `cmd.exe` and a profile, and no config files.
    pub fn new() -> Self {
        let mut host = TestHost {
            env: HashMap::new(),
            profile: Some(PathBuf::from(PROFILE)),
            entries: HashMap::new(),
            path: HashMap::new(),
            system_cmd_aliases: Vec::new(),
            reads: Mutex::new(Vec::new()),
        };
        host.entries
            .insert(PathBuf::from(SYSTEM_CMD), Entry::File(b"MZ".to_vec()));
        host
    }

    pub fn with_file(mut self, path: &str, contents: &str) -> Self {
        self.entries
            .insert(PathBuf::from(path), Entry::File(contents.as_bytes().to_vec()));
        self
    }

    pub fn with_bytes(mut self, path: &str, contents: &[u8]) -> Self {
        self.entries.insert(PathBuf::from(path), Entry::File(contents.to_vec()));
        self
    }

    pub fn with_entry(mut self, path: &str, entry: Entry) -> Self {
        self.entries.insert(PathBuf::from(path), entry);
        self
    }

    /// A program file at `path`, found on `PATH` as `name`.
    pub fn with_program(mut self, name: &str, path: &str) -> Self {
        self.entries.insert(PathBuf::from(path), Entry::File(b"MZ".to_vec()));
        self.path.insert(name.to_string(), PathBuf::from(path));
        self
    }

    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_string(), OsString::from(value));
        self
    }

    pub fn with_user_config(self, contents: &str) -> Self {
        self.with_file(USER_CONFIG, contents)
    }

    pub fn with_system_config(self, contents: &str) -> Self {
        self.with_file(SYSTEM_CONFIG, contents)
    }

    pub fn read_log(&self) -> Vec<PathBuf> {
        self.reads.lock().unwrap().clone()
    }
}

impl Host for TestHost {
    fn env(&self, name: &str) -> Option<OsString> {
        self.env.get(name).cloned()
    }

    fn profile_dir(&self) -> anyhow::Result<PathBuf> {
        self.profile
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the account has no profile directory"))
    }

    fn read_file(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        self.reads.lock().unwrap().push(path.to_path_buf());
        match self.entries.get(path) {
            None => Ok(None),
            Some(Entry::File(bytes)) => Ok(Some(bytes.clone())),
            Some(Entry::Dir) => Err(io::Error::other("Access is denied. (os error 5)")),
            Some(Entry::Unreadable(message)) => Err(io::Error::other(*message)),
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        matches!(self.entries.get(path), Some(Entry::File(_)))
    }

    fn find_program(&self, name: &str) -> Option<PathBuf> {
        self.path.get(name).cloned()
    }

    fn is_system_cmd(&self, path: &Path) -> io::Result<bool> {
        if !self.entries.contains_key(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "The system cannot find the file specified.",
            ));
        }
        Ok(path == Path::new(SYSTEM_CMD) || self.system_cmd_aliases.iter().any(|a| a == path))
    }

    fn system_cmd(&self) -> PathBuf {
        PathBuf::from(SYSTEM_CMD)
    }

    fn system_config_path(&self) -> PathBuf {
        PathBuf::from(SYSTEM_CONFIG)
    }
}

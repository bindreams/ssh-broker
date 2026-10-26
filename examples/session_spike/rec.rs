//! Result files and the live log.
//!
//! Every process of the spike writes `key=value` lines to its own `<name>.res` file in the run
//! directory. The orchestrator follows the directory and prints each new line as
//! `SPIKE <run>.<name>.<key>=<value>`, so a hang or a kill still leaves every earlier line in the
//! job log. Lines also go to the job summary when `GITHUB_STEP_SUMMARY` is set.

use std::collections::HashMap;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::win::{self, DirWatch, Event};

/// One writer of `key=value` lines.
pub struct Rec {
    path: PathBuf,
}

impl Rec {
    pub fn create(dir: &Path, name: &str) -> Rec {
        Rec {
            path: dir.join(format!("{name}.res")),
        }
    }

    pub fn put(&self, key: &str, value: impl Display) {
        let value = value.to_string().replace(['\r', '\n'], " ");
        let line = format!("{key}={value}\n");
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
        if let Err(e) = written {
            eprintln!("cannot record {key} in {}: {e}", self.path.display());
        }
    }

    /// A Windows error under `key`: its code and message.
    pub fn err(&self, key: &str, e: &windows::core::Error) {
        self.put(key, format!("ERROR {}", win::describe(e)));
    }

    /// The value of the last `key=` line already recorded in the file, if any.
    pub fn read_back(dir: &Path, name: &str, key: &str) -> Option<String> {
        let text = std::fs::read_to_string(dir.join(format!("{name}.res"))).ok()?;
        text.lines()
            .rev()
            .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_owned))
    }
}

// Input ----------------------------------------------------------------------------------------

/// What the orchestrator tells a stand-in: `key=value` lines in `input.txt`. The file holds the
/// throwaway accounts' passwords and is never printed.
pub struct Input(Vec<(String, String)>);

impl Input {
    pub fn write(dir: &Path, pairs: &[(&str, String)]) {
        let text: String = pairs.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        std::fs::write(dir.join("input.txt"), text).expect("write input.txt");
    }

    pub fn read(dir: &Path) -> Input {
        let text = std::fs::read_to_string(dir.join("input.txt")).expect("read input.txt");
        Input(
            text.lines()
                .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn req(&self, key: &str) -> &str {
        self.get(key).unwrap_or_else(|| panic!("input.txt has no {key}"))
    }

    pub fn all(&self, key: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

// Output ---------------------------------------------------------------------------------------

static SUMMARY: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// Open the job summary, if there is one, for [`emit`].
pub fn open_summary() {
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(b"\n");
            *SUMMARY.lock().unwrap() = Some(file);
        }
    }
}

/// One line to the job log and the job summary.
pub fn emit(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
    if let Some(file) = SUMMARY.lock().unwrap().as_mut() {
        let _ = writeln!(file, "    {line}");
    }
}

/// `SPIKE <label>.<key>=<value>` for a fact the orchestrator itself found.
pub fn fact(label: &str, key: &str, value: impl Display) {
    emit(&format!(
        "SPIKE {label}.{key}={}",
        value.to_string().replace(['\r', '\n'], " ")
    ));
}

// Following a run directory ----------------------------------------------------------------------

/// Prints the new lines of every `*.res` file in a directory as they appear.
pub struct Follower {
    stop: std::sync::Arc<Event>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Follower {
    pub fn start(label: &str, dir: &Path) -> Follower {
        let stop = std::sync::Arc::new(Event::unnamed());
        let watch = DirWatch::new(dir, false).expect("watch the run directory");
        let (label, dir, thread_stop) = (label.to_owned(), dir.to_owned(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut offsets: HashMap<PathBuf, usize> = HashMap::new();
            loop {
                scan(&label, &dir, &mut offsets);
                let woken = win::wait_any(&[watch.handle(), thread_stop.handle()]);
                if woken == 1 {
                    break;
                }
                watch.rearm();
            }
            scan(&label, &dir, &mut offsets);
        });
        Follower {
            stop,
            thread: Some(thread),
        }
    }

    /// Print what is left and stop.
    pub fn finish(mut self) {
        self.stop.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn scan(label: &str, dir: &Path, offsets: &mut HashMap<PathBuf, usize>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "res"))
        .collect();
    files.sort();
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let seen = offsets.entry(path.clone()).or_insert(0);
        let Some(end) = bytes.iter().rposition(|&b| b == b'\n') else {
            continue;
        };
        if end < *seen {
            continue;
        }
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        for line in String::from_utf8_lossy(&bytes[*seen..=end]).lines() {
            emit(&format!("SPIKE {label}.{stem}.{line}"));
        }
        *seen = end + 1;
    }
}

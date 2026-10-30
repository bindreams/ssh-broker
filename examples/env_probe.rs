//! Spike probe (M7, never merged). Writes the environment it was started with to stdout and, whole and
//! renamed into place, to `<this exe>.env`. sshd starts it as the `DefaultShell`; the logon and the task
//! start it where the agent would be.

use std::io::Write as _;

fn main() {
    let exe = std::env::current_exe().expect("own path");
    let mut vars: Vec<(String, String)> = std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    vars.sort_by_key(|(name, _)| name.to_uppercase());
    let mut text = String::new();
    for (name, value) in &vars {
        text.push_str(&format!("{name}={value}\n"));
    }
    let _ = write!(std::io::stdout(), "{text}");

    let mut path = exe.into_os_string();
    path.push(".env");
    let path = std::path::PathBuf::from(path);
    let staging = path.with_extension("env.staging");
    std::fs::write(&staging, text).expect("write the environment");
    std::fs::rename(&staging, &path).expect("publish the environment");
}

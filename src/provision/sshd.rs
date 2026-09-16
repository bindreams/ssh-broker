//! provision::sshd — reading the EFFECTIVE sshd configuration (pure; host-testable).
//!
//! The shim is sshd's `DefaultShell`, so both an `exec` request and a `subsystem` request reach
//! it as the same thing: one command string. sshd's own distinction — the client names a
//! subsystem by KEY (`sftp`) and sshd maps it to a binary through `sshd_config` — is destroyed
//! before we see it, and no environment variable carries it (checked against `session.c`: the
//! child gets `USER`, `HOME`, `SSH_CLIENT`, `SSH_CONNECTION` and friends; nothing identifies a
//! subsystem, and `SSH_ORIGINAL_COMMAND` is set only when a *forced command* overrode the
//! request).
//!
//! What survives is the DECLARATION itself, and that is the thing worth trusting: sshd's trust
//! anchor for which binary runs is `sshd_config`, never anything on the wire. So instead of
//! inspecting a client-chosen string, compare it against what the administrator declared.
//!
//! **Why `sshd -T` and not the config file.** `sshd_config` holds the raw line; what reaches the
//! shim is `subsystem_args`, which sshd builds by splitting the line (`argv_split`), taking the
//! first token as the command, and RE-ASSEMBLING it (`argv_assemble`, which backslash-escapes
//! `\`, `'` and `"` and quotes any token containing whitespace). Reconstructing that here would
//! mean reimplementing two OpenSSH functions and keeping them in step forever. `sshd -T` prints
//! the resolved value directly — `dump_config` does
//! `printf("subsystem %s %s\n", subsystem_name[i], subsystem_args[i])` — so it hands us sshd's
//! own answer, byte for byte, for the cost of parsing one line shape.

/// One `Subsystem` declaration, as sshd resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsystem {
    /// The key a client names in a subsystem request, e.g. `sftp`.
    pub name: String,
    /// The command string sshd will hand to the login shell — i.e. exactly what the shim
    /// receives. This is `subsystem_args`, already split and re-assembled by sshd.
    pub command_line: String,
}

/// Parse the `subsystem` declarations out of `sshd -T` output.
///
/// Tolerant of the surrounding dump: `sshd -T` prints a hundred-odd unrelated directives, and
/// their order is not contractual. Unknown or malformed lines are skipped rather than erroring —
/// a future sshd adding a directive must not break provisioning. A `subsystem` line with no
/// argument after the name is skipped too: it cannot match anything, and admitting it would let
/// an empty declaration match an empty command.
pub fn parse_subsystems(dump: &str) -> Vec<Subsystem> {
    dump.lines()
        .filter_map(|line| {
            // `dump_config` emits the keyword lowercased and unindented, but accept leading
            // whitespace so a caller may hand us output that has been through a pipeline.
            let rest = line.trim_start().strip_prefix("subsystem ")?;
            let (name, command_line) = rest.split_once(' ')?;
            let (name, command_line) = (name.trim(), command_line.trim());
            if name.is_empty() || command_line.is_empty() {
                return None;
            }
            Some(Subsystem {
                name: name.to_string(),
                command_line: command_line.to_string(),
            })
        })
        .collect()
}

/// Whether `command` is one of the declared subsystem command lines.
///
/// An exact, whole-string comparison — deliberately not a prefix, basename or token match. The
/// string sshd hands the shim for a subsystem request IS `subsystem_args` verbatim, so anything
/// looser would start inferring again, which is the class of bug this replaces.
///
/// An `exec` request can of course send a byte-identical string. That is harmless: an identical
/// string launches an identical binary — the administrator's own declared helper — so the client
/// gains nothing it could not get by requesting the subsystem legitimately.
pub fn matches_declaration(command: &str, declared: &[Subsystem]) -> bool {
    declared.iter().any(|s| s.command_line == command)
}

#[cfg(test)]
#[path = "sshd_tests.rs"]
mod sshd_tests;

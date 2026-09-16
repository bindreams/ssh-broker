//! Host tests for parsing `sshd -T` output.
use super::{Subsystem, matches_declaration, parse_subsystems};

/// A realistic slice of `sshd -T`: the subsystem lines sit among unrelated directives, and their
/// position is not contractual, so the parser must find them by shape rather than by offset.
const DUMP: &str = "\
port 22
permitrootlogin prohibit-password
logingracetime 120
subsystem sftp sftp-server.exe
maxstartups 10:30:100
";

#[test]
fn finds_a_subsystem_among_unrelated_directives() {
    assert_eq!(
        parse_subsystems(DUMP),
        vec![Subsystem {
            name: "sftp".into(),
            command_line: "sftp-server.exe".into(),
        }]
    );
}

/// The whole remainder of the line is the command, spaces and all. This is the case the old
/// argv[0]-based detection got wrong: an unquoted spaced path in `sshd_config` reaches the shim
/// as `C:\\Program Files\\OpenSSH\\sftp-server.exe` (sshd's `argv_assemble` escapes each `\`),
/// whose argv[0] tokenizes to `C:\\Program` and whose basename is `Program` — a miss. Matching
/// the DECLARATION sidesteps tokenizing the path at all, so the administrator is not required to
/// quote anything.
#[test]
fn the_command_is_the_whole_remainder_including_spaces_and_escapes() {
    let dump = r"subsystem sftp C:\\Program Files\\OpenSSH\\sftp-server.exe";
    let got = parse_subsystems(dump);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].command_line, r"C:\\Program Files\\OpenSSH\\sftp-server.exe");
    // And that is exactly what the shim would be asked to classify.
    assert!(matches_declaration(
        r"C:\\Program Files\\OpenSSH\\sftp-server.exe",
        &got
    ));
}

#[test]
fn several_subsystems_are_all_returned() {
    let dump = "subsystem sftp sftp-server.exe\nsubsystem backup C:\\tools\\backup.exe --now\n";
    let got = parse_subsystems(dump);
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].name, "backup");
    assert_eq!(got[1].command_line, r"C:\tools\backup.exe --now");
}

/// Matching is exact and whole-string. A prefix, a basename or a differing argument must all
/// fail: anything looser would be inferring from the command again, which is what this replaces.
#[test]
fn matching_is_exact_and_not_a_prefix_or_basename() {
    let declared = parse_subsystems(DUMP);
    assert!(matches_declaration("sftp-server.exe", &declared));
    assert!(
        !matches_declaration("sftp-server.exe -l ERROR", &declared),
        "a suffix must not match"
    );
    assert!(
        !matches_declaration("sftp-server", &declared),
        "a prefix must not match"
    );
    assert!(
        !matches_declaration(r"C:\evil\sftp-server.exe", &declared),
        "a matching basename must not match — that is the heuristic this removes"
    );
    assert!(!matches_declaration("", &declared), "an empty command must never match");
}

/// Unknown or malformed lines are skipped, not fatal: a future sshd adding a directive must not
/// break provisioning. An argument-less `subsystem` line is dropped too, or an empty declaration
/// would match an empty command.
#[test]
fn malformed_and_argument_less_lines_are_skipped() {
    assert!(parse_subsystems("").is_empty());
    assert!(parse_subsystems("subsystem\n").is_empty());
    assert!(parse_subsystems("subsystem sftp\n").is_empty(), "no command to match");
    assert!(
        parse_subsystems("subsystemsftp foo\n").is_empty(),
        "keyword needs its space"
    );
    assert!(parse_subsystems("port 22\nmaxstartups 10:30:100\n").is_empty());
    // A declaration still parses when it follows a malformed neighbour.
    assert_eq!(parse_subsystems("subsystem\nsubsystem sftp ok.exe\n").len(), 1);
}

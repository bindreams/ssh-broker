//! Host tests for the pure parts of `provision::sshd_config`: the text edit, the `sshd -T` reader, the
//! `verify` row. The flow is in `configure_tests`.
use super::*;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// The stock Windows file, in the parts that matter: an `AcceptEnv`-free global section and a `Match` block.
const STOCK: &str = "# This is the sshd server system-wide configuration file.\r\n\
#Port 22\r\n\
\r\n\
#AcceptEnv LANG LC_*\r\n\
Subsystem\tsftp\tsftp-server.exe\r\n\
\r\n\
Match Group administrators\r\n\
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n";

fn edited(text: &[u8]) -> String {
    String::from_utf8(with_include(text).unwrap()).unwrap()
}

// with_include ====================================================================

#[test]
fn with_include_puts_the_line_above_the_first_match() {
    assert_eq!(
        edited(STOCK.as_bytes()),
        STOCK.replace(
            "Match Group administrators",
            &format!("{INCLUDE_LINE}\r\nMatch Group administrators")
        )
    );
}

#[test]
fn with_include_puts_the_line_at_the_end_when_there_is_no_match() {
    assert_eq!(
        edited(b"Port 22\r\nSubsystem sftp x\r\n"),
        format!("Port 22\r\nSubsystem sftp x\r\n{INCLUDE_LINE}\r\n")
    );
    // A last line with no terminator gets one before the inserted line, and the file still ends as it did.
    assert_eq!(edited(b"Port 22"), format!("Port 22\r\n{INCLUDE_LINE}"));
    assert_eq!(edited(b"Port 22\n"), format!("Port 22\n{INCLUDE_LINE}\n"));
    assert_eq!(edited(b""), format!("{INCLUDE_LINE}\r\n"));
}

#[test]
fn with_include_puts_the_line_above_only_the_first_of_two_matches() {
    let text = "Port 22\nMatch User a\nX 1\nMatch User b\nX 2\n";
    let out = edited(text.as_bytes());
    assert_eq!(
        out,
        format!("Port 22\n{INCLUDE_LINE}\nMatch User a\nX 1\nMatch User b\nX 2\n")
    );
    assert_eq!(out.matches(INCLUDE_LINE).count(), 1);
}

#[test]
fn with_include_keeps_crlf_and_lf_and_a_bom() {
    assert_eq!(
        edited(b"Port 22\r\nMatch All\r\n"),
        "Port 22\r\nInclude sshd_config.d/*.conf\r\nMatch All\r\n"
    );
    assert_eq!(
        edited(b"Port 22\nMatch All\n"),
        "Port 22\nInclude sshd_config.d/*.conf\nMatch All\n"
    );
    // The first line break decides.
    assert_eq!(
        edited(b"Port 22\nPort 23\r\nMatch All\n"),
        "Port 22\nPort 23\r\nInclude sshd_config.d/*.conf\nMatch All\n"
    );
    // A BOM stays first, also when the Match is the first line.
    let with_bom = [BOM, b"Port 22\r\nMatch All\r\n"].concat();
    assert_eq!(
        with_include(&with_bom).unwrap(),
        [BOM, b"Port 22\r\nInclude sshd_config.d/*.conf\r\nMatch All\r\n"].concat()
    );
    let match_first = [BOM, b"Match All\r\nX 1\r\n"].concat();
    assert_eq!(
        with_include(&match_first).unwrap(),
        [BOM, b"Include sshd_config.d/*.conf\r\nMatch All\r\nX 1\r\n"].concat()
    );
}

#[test]
fn with_include_is_refused_for_utf16_and_for_a_nul() {
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("Port 22\r\n".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    assert!(with_include(&utf16).is_err());
    let utf16_be: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain("Port 22\r\n".encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    assert!(with_include(&utf16_be).is_err());
    assert!(with_include(b"Port 22\0\r\n").is_err());
    assert!(with_include(b"Port \xFF22\r\n").is_err(), "not UTF-8");
    // A lone CR is a line break that a CRLF or LF file does not have: where the lines are is not known.
    assert!(with_include(b"Port 22\rMatch All\r").is_err());
    let why = with_include(&utf16).unwrap_err().to_string();
    assert!(why.contains("UTF-16"), "{why}");
}

#[test]
fn with_include_ignores_match_inside_a_comment_and_matches_without_regard_to_case() {
    assert_eq!(
        edited(b"# Match User x\r\n  # match all\r\nPort 22\r\n"),
        format!("# Match User x\r\n  # match all\r\nPort 22\r\n{INCLUDE_LINE}\r\n")
    );
    assert_eq!(
        edited(b"Port 22\r\n\t mAtCh User x\r\nX 1\r\n"),
        format!("Port 22\r\n{INCLUDE_LINE}\r\n\t mAtCh User x\r\nX 1\r\n")
    );
    // A keyword that only starts with the word is not a Match line.
    assert_eq!(edited(b"Matcher 1\r\n"), format!("Matcher 1\r\n{INCLUDE_LINE}\r\n"));
}

#[test]
fn with_include_changes_no_other_byte() {
    let fixtures: [&[u8]; 8] = [
        STOCK.as_bytes(),
        b"",
        b"Port 22",
        b"Port 22\n",
        b"Match All",
        b"Match All\nX 1",
        b"\xEF\xBB\xBFPort 22\r\nMatch User a\r\nX 1\r\n",
        b"a\nb\r\nMatch x\r\n\r\n\r\nMatch y\n",
    ];
    for input in fixtures {
        let out = with_include(input).unwrap();
        let line = INCLUDE_LINE.as_bytes();
        let added = out.len() - input.len();
        // The output is the input with one run of bytes put in: the line, with the break of the file's kind
        // after it (before a Match, or at the end of a file that ends in one) or before it (at the end of a
        // file that does not).
        let one_insertion = (0..=input.len()).any(|at| {
            let put = &out[at..at + added];
            out[..at] == input[..at]
                && out[at + added..] == input[at..]
                && (put == [line, b"\r\n"].concat()
                    || put == [line, b"\n"].concat()
                    || put == [b"\r\n", line].concat()
                    || put == [b"\n", line].concat()
                    || put == line)
        });
        assert!(
            one_insertion,
            "{:?} -> {:?}",
            String::from_utf8_lossy(input),
            String::from_utf8_lossy(&out)
        );
    }
}

// the drop-in ====================================================================

#[test]
fn the_drop_in_text_is_exactly_the_one_line() {
    assert_eq!(
        DROP_IN_TEXT,
        format!("AcceptEnv {}\r\n", crate::protocol::ElevationPolicy::VARIABLE)
    );
    assert_eq!(DROP_IN_NAME, "10-ssh-broker.conf");
    assert_eq!(INCLUDE_LINE, "Include sshd_config.d/*.conf");
}

// the `sshd -T` reader ====================================================================

const NAME: &str = "SSH_BROKER_ELEVATION";

#[test]
fn accepts_reads_the_acceptenv_lines_and_wildcards() {
    assert!(accepts(
        "port 22\nacceptenv SSH_BROKER_ELEVATION\nsubsystem sftp x\n",
        NAME
    ));
    assert!(
        accepts("acceptenv LANG\r\nacceptenv SSH_BROKER_ELEVATION\r\n", NAME),
        "CRLF lines"
    );
    assert!(accepts("acceptenv *\n", NAME));
    assert!(accepts("acceptenv SSH_*\n", NAME));
    assert!(accepts("acceptenv SSH_BROKER_ELEVATIO?\n", NAME));
    assert!(
        accepts("acceptenv LANG SSH_BROKER_ELEVATION\n", NAME),
        "two patterns on a line"
    );
    assert!(!accepts("acceptenv LANG\nacceptenv LC_*\n", NAME));
    assert!(!accepts("", NAME));
    assert!(!accepts("port 22\n", NAME));
    assert!(
        !accepts("acceptenv ssh_broker_elevation\n", NAME),
        "patterns are case-sensitive"
    );
    assert!(!accepts("acceptenv SSH_BROKER\n", NAME), "a prefix is not a match");
    assert!(!accepts("acceptenv ?\n", NAME), "? is one character");
    assert!(
        !accepts("setenv SSH_BROKER_ELEVATION=never\n", NAME),
        "another keyword with the name in it"
    );
    assert!(!accepts("  acceptenv-not SSH_BROKER_ELEVATION\n", NAME));
}

#[test]
fn pinned_reads_a_global_setenv_line_for_the_name_and_no_other() {
    assert_eq!(
        pinned("setenv SSH_BROKER_ELEVATION=never\n", NAME).as_deref(),
        Some("never")
    );
    assert_eq!(
        pinned("port 22\r\nsetenv A=b SSH_BROKER_ELEVATION=auto-approve\r\n", NAME).as_deref(),
        Some("auto-approve")
    );
    assert_eq!(
        pinned("setenv \"SSH_BROKER_ELEVATION=always\"\n", NAME).as_deref(),
        Some("always")
    );
    assert_eq!(pinned("setenv A=b\nsetenv SSH_BROKER_ELEVATION_X=never\n", NAME), None);
    assert_eq!(pinned("acceptenv SSH_BROKER_ELEVATION\n", NAME), None);
    assert_eq!(pinned("", NAME), None);
    // The last assignment is the one the session gets.
    assert_eq!(
        pinned(
            "setenv SSH_BROKER_ELEVATION=never\nsetenv SSH_BROKER_ELEVATION=always\n",
            NAME
        )
        .as_deref(),
        Some("always")
    );
}

// the verify row ====================================================================

const ROW_NAME: &str = "sshd accepts SSH_BROKER_ELEVATION";

#[test]
fn the_sshd_row_below_high_is_informational_and_passes_without_asking_sshd() {
    let row = accepts_row(Integrity::Medium, || panic!("sshd -T must not be asked below High"));
    assert_eq!(row.name, ROW_NAME);
    assert!(row.pass);
    assert_eq!(
        row.detail,
        "not checked here: sshd's configuration is read by an elevated `verify`"
    );
}

#[test]
fn the_sshd_row_at_high_passes_when_the_variable_is_accepted_or_pinned_by_the_server() {
    let accepted = accepts_row(Integrity::High, || Ok("acceptenv SSH_BROKER_ELEVATION\n".into()));
    assert!(accepted.pass, "{}", accepted.detail);
    assert_eq!(accepted.name, ROW_NAME);
    assert_eq!(accepted.detail, "sshd accepts SSH_BROKER_ELEVATION from clients");

    let pinned = accepts_row(Integrity::High, || Ok("setenv SSH_BROKER_ELEVATION=never\n".into()));
    assert!(pinned.pass, "{}", pinned.detail);
    assert_eq!(pinned.detail, "pinned by the server to never");
}

#[test]
fn the_sshd_row_at_high_fails_naming_the_include_line_and_says_elevate_works_without_it() {
    let row = accepts_row(Integrity::High, || Ok("port 22\nacceptenv LANG\n".into()));
    assert!(!row.pass);
    assert_eq!(
        row.detail,
        "sshd does not accept SSH_BROKER_ELEVATION from clients; add the line `Include sshd_config.d/*.conf` \
         above the first `Match` in sshd_config and restart sshd. `ssh-broker elevate` works without it."
    );
    let broken = accepts_row(Integrity::High, || Err(anyhow::anyhow!("sshd.exe did not start")));
    assert!(!broken.pass);
    assert!(
        broken.detail.contains("cannot ask sshd") && broken.detail.contains("sshd.exe did not start"),
        "{}",
        broken.detail
    );
}

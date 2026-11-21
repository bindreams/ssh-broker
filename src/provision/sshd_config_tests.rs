//! Host tests for the pure parts of `provision::sshd_config`: the text edit, the `sshd -T` reader, the
//! `doctor` row. The flow is in `configure_tests`.
use super::*;
use std::path::PathBuf;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// The two lines `install` puts into `sshd_config`: the `Include` of the drop-ins, or the `AcceptEnv` itself when
/// the folder cannot be used. The edit is the same for both.
const LINES: [&str; 2] = [INCLUDE_LINE, ACCEPT_LINE];

/// The stock Windows file, in the parts that matter: an `AcceptEnv`-free global section and a `Match` block.
const STOCK: &str = "# This is the sshd server system-wide configuration file.\r\n\
#Port 22\r\n\
\r\n\
#AcceptEnv LANG LC_*\r\n\
Subsystem\tsftp\tsftp-server.exe\r\n\
\r\n\
Match Group administrators\r\n\
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n";

fn edited(text: &[u8], line: &str) -> String {
    String::from_utf8(with_line(text, line).unwrap()).unwrap()
}

// with_line ====================================================================

#[test]
fn with_line_puts_the_line_above_the_first_match() {
    for line in LINES {
        assert_eq!(
            edited(STOCK.as_bytes(), line),
            STOCK.replace(
                "Match Group administrators",
                &format!("{line}\r\nMatch Group administrators")
            )
        );
    }
}

#[test]
fn with_line_puts_the_line_at_the_end_when_there_is_no_match() {
    for line in LINES {
        assert_eq!(
            edited(b"Port 22\r\nSubsystem sftp x\r\n", line),
            format!("Port 22\r\nSubsystem sftp x\r\n{line}\r\n")
        );
        // A last line with no terminator gets one before the inserted line, and the file still ends as it did.
        assert_eq!(edited(b"Port 22", line), format!("Port 22\r\n{line}"));
        assert_eq!(edited(b"Port 22\n", line), format!("Port 22\n{line}\n"));
        assert_eq!(edited(b"", line), format!("{line}\r\n"));
    }
}

#[test]
fn with_line_puts_the_line_above_only_the_first_of_two_matches() {
    let text = "Port 22\nMatch User a\nX 1\nMatch User b\nX 2\n";
    for line in LINES {
        let out = edited(text.as_bytes(), line);
        assert_eq!(out, format!("Port 22\n{line}\nMatch User a\nX 1\nMatch User b\nX 2\n"));
        assert_eq!(out.matches(line).count(), 1);
    }
}

#[test]
fn with_line_keeps_crlf_and_lf_and_a_bom() {
    for line in LINES {
        assert_eq!(
            edited(b"Port 22\r\nMatch All\r\n", line),
            format!("Port 22\r\n{line}\r\nMatch All\r\n")
        );
        assert_eq!(
            edited(b"Port 22\nMatch All\n", line),
            format!("Port 22\n{line}\nMatch All\n")
        );
        // The first line break decides.
        assert_eq!(
            edited(b"Port 22\nPort 23\r\nMatch All\n", line),
            format!("Port 22\nPort 23\r\n{line}\nMatch All\n")
        );
        // A BOM stays first, also when the Match is the first line.
        let with_bom = [BOM, b"Port 22\r\nMatch All\r\n"].concat();
        assert_eq!(
            with_line(&with_bom, line).unwrap(),
            [BOM, format!("Port 22\r\n{line}\r\nMatch All\r\n").as_bytes()].concat()
        );
        let match_first = [BOM, b"Match All\r\nX 1\r\n"].concat();
        assert_eq!(
            with_line(&match_first, line).unwrap(),
            [BOM, format!("{line}\r\nMatch All\r\nX 1\r\n").as_bytes()].concat()
        );
    }
}

#[test]
fn with_line_is_refused_for_utf16_and_for_a_nul() {
    for line in LINES {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("Port 22\r\n".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert!(with_line(&utf16, line).is_err());
        let utf16_be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain("Port 22\r\n".encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        assert!(with_line(&utf16_be, line).is_err());
        assert!(with_line(b"Port 22\0\r\n", line).is_err());
        assert!(with_line(b"Port \xFF22\r\n", line).is_err(), "not UTF-8");
        // A lone CR is a line break that a CRLF or LF file does not have: where the lines are is not known.
        assert!(with_line(b"Port 22\rMatch All\r", line).is_err());
        let why = with_line(&utf16, line).unwrap_err().to_string();
        assert!(why.contains("UTF-16"), "{why}");
    }
}

#[test]
fn with_line_ignores_match_inside_a_comment_and_matches_without_regard_to_case() {
    for line in LINES {
        assert_eq!(
            edited(b"# Match User x\r\n  # match all\r\nPort 22\r\n", line),
            format!("# Match User x\r\n  # match all\r\nPort 22\r\n{line}\r\n")
        );
        assert_eq!(
            edited(b"Port 22\r\n\t mAtCh User x\r\nX 1\r\n", line),
            format!("Port 22\r\n{line}\r\n\t mAtCh User x\r\nX 1\r\n")
        );
        // A keyword that only starts with the word is not a Match line.
        assert_eq!(edited(b"Matcher 1\r\n", line), format!("Matcher 1\r\n{line}\r\n"));
    }
}

#[test]
fn with_line_finds_a_match_that_sshd_tokenises_as_one() {
    for line in LINES {
        assert_eq!(
            edited(b"Port 22\r\nMatch=User foo\r\nX 1\r\n", line),
            format!("Port 22\r\n{line}\r\nMatch=User foo\r\nX 1\r\n")
        );
        assert_eq!(
            edited(b"Port 22\r\nMatch =all\r\nX 1\r\n", line),
            format!("Port 22\r\n{line}\r\nMatch =all\r\nX 1\r\n")
        );
        assert_eq!(
            edited(b"Port 22\r\n\x0cMatch All\r\n", line),
            format!("Port 22\r\n{line}\r\n\x0cMatch All\r\n")
        );
    }
}

#[test]
fn with_line_changes_no_other_byte() {
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
    for text in LINES {
        for input in fixtures {
            let out = with_line(input, text).unwrap();
            let line = text.as_bytes();
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
}

// the tokeniser ====================================================================

#[test]
fn keyword_ends_at_white_space_or_an_equals_sign_after_the_blanks_sshd_skips() {
    let cases: [(&str, Option<(&str, &str)>); 16] = [
        ("Port 22", Some(("Port", "22"))),
        ("Port 22\r\n", Some(("Port", "22"))),
        ("Port", Some(("Port", ""))),
        (" \t Port\t22  \r\n", Some(("Port", "22"))),
        ("Match=User foo", Some(("Match", "User foo"))),
        ("Match =all", Some(("Match", "all"))),
        ("Match = all", Some(("Match", "all"))),
        ("\rMatch All", Some(("Match", "All"))),
        ("\x0cMatch All", Some(("Match", "All"))),
        ("\r\x0c \tMatch All", Some(("Match", "All"))),
        (r"Include=D:\x\*.conf", Some(("Include", r"D:\x\*.conf"))),
        ("AcceptEnv A B", Some(("AcceptEnv", "A B"))),
        ("#Include x", None),
        ("  # Match All", None),
        ("", None),
        ("   \r\n", None),
    ];
    for (line, expected) in cases {
        assert_eq!(keyword(line), expected, "{line:?}");
    }
}

#[test]
fn an_include_of_another_location_is_found_and_ours_alone_is_not() {
    let ours = format!("Port 22\r\n{INCLUDE_LINE}\r\nMatch All\r\n");
    assert_eq!(include_elsewhere(ours.as_bytes()), None);
    assert_eq!(include_elsewhere(STOCK.as_bytes()), None);
    assert_eq!(include_elsewhere(b""), None);
    assert_eq!(include_elsewhere(format!("  {INCLUDE_LINE}  \r\n").as_bytes()), None);
    assert_eq!(
        include_elsewhere(format!("include {}\r\n", &INCLUDE_LINE["Include ".len()..]).as_bytes()),
        None,
        "the keyword is compared without regard to case"
    );
    assert_eq!(include_elsewhere(b"#Include x\r\n"), None);
    assert_eq!(include_elsewhere(b"  # Include D:\\x\\*.conf\r\n"), None);

    for (text, line) in [
        (r"Include=D:\x\*.conf", r"Include=D:\x\*.conf"),
        (r"Include D:\x\*.conf", r"Include D:\x\*.conf"),
        (r"include D:\x\*.conf", r"include D:\x\*.conf"),
        (r#"Include "sshd_config.d/*.conf""#, r#"Include "sshd_config.d/*.conf""#),
        (
            r"Include sshd_config.d/*.conf D:\x\*.conf",
            r"Include sshd_config.d/*.conf D:\x\*.conf",
        ),
        ("Include", "Include"),
    ] {
        assert_eq!(
            include_elsewhere(format!("Port 22\r\n  {text}  \r\nMatch All\r\n").as_bytes()).as_deref(),
            Some(line),
            "{text}"
        );
    }
    // An argument that does not survive decoding is another one, and a BOM is not part of a keyword.
    assert!(include_elsewhere(b"Include \xFF\r\n").is_some());
    assert!(include_elsewhere(&[BOM, b"Include D:\\x\r\n"].concat()).is_some());
    assert_eq!(
        include_elsewhere(&[BOM, format!("{INCLUDE_LINE}\r\n").as_bytes()].concat()),
        None
    );
}

#[test]
fn the_first_include_of_another_location_is_the_one_found() {
    let text = format!("{INCLUDE_LINE}\r\nInclude D:\\a\r\nInclude D:\\b\r\n");
    assert_eq!(include_elsewhere(text.as_bytes()).as_deref(), Some("Include D:\\a"));
}

// the lines and the drop-in ====================================================================

#[test]
fn the_drop_in_text_is_exactly_the_one_line() {
    assert_eq!(
        ACCEPT_LINE,
        format!("AcceptEnv {}", crate::protocol::ElevationPolicy::VARIABLE)
    );
    assert_eq!(drop_in_text(), format!("{ACCEPT_LINE}\r\n"));
    assert_eq!(DROP_IN_NAME, "10-ssh-broker.conf");
    assert_eq!(DROP_IN_DIR_NAME, "sshd_config.d");
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

#[test]
fn a_variable_accepted_or_pinned_is_in_force_by_one_judgement() {
    assert!(in_force("acceptenv SSH_BROKER_ELEVATION\n"));
    assert!(in_force("setenv SSH_BROKER_ELEVATION=never\n"));
    assert!(!in_force("port 22\nacceptenv LANG\n"));
}

// the doctor row ====================================================================

const ROW_NAME: &str = "sshd accepts SSH_BROKER_ELEVATION";

fn read(listing: &str) -> anyhow::Result<SshdReading> {
    Ok(SshdReading::Read {
        listing: listing.into(),
        read: ConfigRead::Read,
    })
}

const NOT_CHECKED_HERE: &str = "not checked here: sshd's configuration is read by an administrator's elevated `doctor`";

#[test]
fn the_sshd_row_of_an_administrator_that_is_not_elevated_is_informational_and_passes_without_asking_sshd() {
    let row = accepts_row(&Ok(Elevation::Filtered), || {
        panic!("sshd must not be asked of an administrator that is not elevated")
    });
    assert_eq!(row.name, ROW_NAME);
    assert!(row.pass);
    assert_eq!(row.detail, NOT_CHECKED_HERE);
}

#[test]
fn the_sshd_row_of_an_account_that_is_not_an_administrator_passes_without_asking_sshd() {
    // `Standard` is a non-administrator's token, at High or not (a Backup Operators account's `always` session is
    // at High).
    let row = accepts_row(&Ok(Elevation::Standard), || {
        panic!("sshd must not be asked by an account that is not an administrator")
    });
    assert_eq!(row.name, ROW_NAME);
    assert!(row.pass);
    assert_eq!(row.detail, NOT_CHECKED_HERE);
}

#[test]
fn the_sshd_row_fails_with_the_shared_clause_when_the_elevation_cannot_be_read() {
    let row = accepts_row(&Err(anyhow::anyhow!("the token cannot be opened")), || {
        panic!("sshd must not be asked when the elevation is not known")
    });
    assert_eq!(row.name, ROW_NAME);
    assert!(!row.pass);
    assert_eq!(
        row.detail,
        format!(
            "{}, so whether sshd accepts SSH_BROKER_ELEVATION is not known",
            crate::offer::text::elevation_unreadable_clause("the token cannot be opened")
        )
    );
}

#[test]
fn the_sshd_row_of_an_elevated_administrator_passes_when_the_variable_is_accepted_or_pinned_by_the_server() {
    let accepted = accepts_row(&Ok(Elevation::Full), || read("acceptenv SSH_BROKER_ELEVATION\n"));
    assert!(accepted.pass, "{}", accepted.detail);
    assert_eq!(accepted.name, ROW_NAME);
    assert_eq!(accepted.detail, "sshd accepts SSH_BROKER_ELEVATION from clients");

    let pinned = accepts_row(&Ok(Elevation::Full), || read("setenv SSH_BROKER_ELEVATION=never\n"));
    assert!(pinned.pass, "{}", pinned.detail);
    assert_eq!(pinned.detail, "pinned by the server to never");
}

#[test]
fn the_sshd_row_of_an_elevated_administrator_fails_when_sshd_does_not_accept_and_says_install_sets_it_up() {
    let row = accepts_row(&Ok(Elevation::Full), || read("port 22\nacceptenv LANG\n"));
    assert!(!row.pass);
    assert_eq!(
        row.detail,
        "sshd does not accept SSH_BROKER_ELEVATION from clients; `ssh-broker install` sets it up, and says what it \
         could not do. `ssh-broker elevate` works without it."
    );
    assert!(!row.detail.contains("Include"), "{}", row.detail);
    let broken = accepts_row(&Ok(Elevation::Full), || Err(anyhow::anyhow!("sshd.exe did not start")));
    assert!(!broken.pass);
    assert!(broken.detail.contains("sshd.exe did not start"), "{}", broken.detail);
}

#[test]
fn the_sshd_row_fails_when_sshd_started_before_its_configuration_was_written() {
    for listing in [
        "acceptenv SSH_BROKER_ELEVATION\n",
        "setenv SSH_BROKER_ELEVATION=never\n",
    ] {
        let row = accepts_row(&Ok(Elevation::Full), || {
            Ok(SshdReading::Read {
                listing: listing.into(),
                read: ConfigRead::Unread(PathBuf::from("sshd_config.d").join("10-ssh-broker.conf")),
            })
        });
        assert!(!row.pass);
        assert_eq!(
            row.detail,
            format!(
                "sshd was started before {} was last changed and has not read it; `ssh-broker install` restarts it, or \
                 restart the sshd service",
                PathBuf::from("sshd_config.d").join("10-ssh-broker.conf").display()
            )
        );
    }
    // A configuration sshd does not accept fails for that, whether or not it was read.
    let row = accepts_row(&Ok(Elevation::Full), || {
        Ok(SshdReading::Read {
            listing: "port 22\n".into(),
            read: ConfigRead::Unread(PathBuf::from("sshd_config")),
        })
    });
    assert!(!row.pass);
    assert!(row.detail.contains("does not accept"), "{}", row.detail);
}

#[test]
fn the_sshd_row_passes_and_says_so_when_a_files_time_is_ahead_of_the_clock() {
    // What the row says of the variable, then the clause about the clock.
    for (listing, said) in [
        (
            "acceptenv SSH_BROKER_ELEVATION\n",
            "sshd accepts SSH_BROKER_ELEVATION from clients",
        ),
        ("setenv SSH_BROKER_ELEVATION=never\n", "pinned by the server to never"),
    ] {
        let row = accepts_row(&Ok(Elevation::Full), || {
            Ok(SshdReading::Read {
                listing: listing.into(),
                read: ConfigRead::AheadOfClock(PathBuf::from("sshd_config")),
            })
        });
        assert!(row.pass, "{}", row.detail);
        assert_eq!(
            row.detail,
            format!(
                "{said}; sshd_config's change time is ahead of the clock, so whether the running sshd has read \
                 it cannot be told (`ssh-broker install` restarts it to be sure, or restart the sshd service)"
            )
        );
    }
    // A configuration sshd does not accept fails for that.
    let row = accepts_row(&Ok(Elevation::Full), || {
        Ok(SshdReading::Read {
            listing: "port 22\n".into(),
            read: ConfigRead::AheadOfClock(PathBuf::from("sshd_config")),
        })
    });
    assert!(!row.pass);
    assert!(row.detail.contains("does not accept"), "{}", row.detail);
}

#[test]
fn the_sshd_row_passes_with_a_note_when_sshd_includes_another_location() {
    for (listing, said) in [
        (
            "acceptenv SSH_BROKER_ELEVATION\n",
            "sshd accepts SSH_BROKER_ELEVATION from clients",
        ),
        ("setenv SSH_BROKER_ELEVATION=never\n", "pinned by the server to never"),
    ] {
        let row = accepts_row(&Ok(Elevation::Full), || {
            Ok(SshdReading::Read {
                listing: listing.into(),
                read: ConfigRead::IncludesOther {
                    file: PathBuf::from("sshd_config"),
                    line: r"Include D:\x\*.conf".into(),
                },
            })
        });
        assert!(row.pass, "{}", row.detail);
        assert_eq!(
            row.detail,
            format!(
                "{said}; sshd_config has `Include D:\\x\\*.conf`, so whether the running sshd has read its \
                 configuration cannot be told (`ssh-broker install` restarts it to be sure, or restart the sshd \
                 service)"
            )
        );
    }
    // A configuration sshd does not accept fails for that.
    let row = accepts_row(&Ok(Elevation::Full), || {
        Ok(SshdReading::Read {
            listing: "port 22\n".into(),
            read: ConfigRead::IncludesOther {
                file: PathBuf::from("sshd_config"),
                line: r"Include D:\x\*.conf".into(),
            },
        })
    });
    assert!(!row.pass);
    assert!(row.detail.contains("does not accept"), "{}", row.detail);
}

#[test]
fn the_sshd_row_passes_as_it_does_for_a_read_configuration_when_sshd_is_not_running() {
    let row = accepts_row(&Ok(Elevation::Full), || {
        Ok(SshdReading::Read {
            listing: "acceptenv SSH_BROKER_ELEVATION\n".into(),
            read: ConfigRead::NotRunning,
        })
    });
    assert!(row.pass, "{}", row.detail);
    assert_eq!(row.detail, "sshd accepts SSH_BROKER_ELEVATION from clients");
}

#[test]
fn the_sshd_row_is_informational_when_the_service_has_arguments() {
    let row = accepts_row(&Ok(Elevation::Full), || {
        Ok(SshdReading::WithArguments(r"-f D:\conf\sshd_config".into()))
    });
    assert!(row.pass, "{}", row.detail);
    assert_eq!(
        row.detail,
        "not checked: the sshd service runs with arguments (`-f D:\\conf\\sshd_config`), which can name another \
         configuration file"
    );
}

//! Host tests for the report the verb writes and `install` reads. The order of the hand-over is `hand_over_tests`;
//! the real Task Scheduler is measured by `tests/sshd_config_windows.rs`, which CI runs.
use super::*;

// what a line of the report is =====

#[test]
fn a_warning_is_told_from_a_note_by_its_prefix_in_the_report() {
    assert_eq!(WARNING_PREFIX, "warning: ");
    assert_eq!(render(LineKind::Note, "sshd restarted"), "sshd restarted");
    assert_eq!(
        render(LineKind::Warning, "sshd is NOT running"),
        "warning: sshd is NOT running"
    );
}

#[test]
fn every_line_of_a_warning_that_has_several_is_a_warning_in_the_report() {
    assert_eq!(
        render(LineKind::Warning, "sshd rejects it: line 1\nline 2"),
        "warning: sshd rejects it: line 1\nwarning: line 2"
    );
    assert_eq!(render(LineKind::Note, "line 1\nline 2"), "line 1\nline 2");
}

#[test]
fn an_empty_text_is_rendered_as_one_empty_line_of_its_kind() {
    assert_eq!(render(LineKind::Note, ""), "");
    assert_eq!(render(LineKind::Warning, ""), "warning: ");
}

/// A note whose line begins with the prefix gets one more space in front, which `read_line` takes off: the
/// line cannot be read as a warning, and renders in the report as a plain line.
#[test]
fn a_note_that_begins_like_a_warning_is_rendered_with_one_space_more_and_read_line_takes_it_off() {
    assert_eq!(render(LineKind::Note, "warning: x"), " warning: x");
    assert_eq!(render(LineKind::Note, " warning: x"), "  warning: x");
    assert_eq!(render(LineKind::Note, "a\nwarning: b"), "a\n warning: b");
    for text in ["warning: x", " warning: x", "warning: ", "plain", "  indented", ""] {
        assert_eq!(
            read_line(&render(LineKind::Note, text)),
            (LineKind::Note, text),
            "{text:?}"
        );
        assert_eq!(
            read_line(&render(LineKind::Warning, text)),
            (LineKind::Warning, text),
            "{text:?}"
        );
    }
}

#[test]
fn a_reported_text_is_read_as_its_lines_and_their_kinds() {
    let parsed = Report::parse("a note\r\nwarning: a warning\r\nanother note\r\n");
    assert_eq!(
        parsed.lines,
        [
            ReportLine {
                kind: LineKind::Note,
                text: "a note".into()
            },
            ReportLine {
                kind: LineKind::Warning,
                text: "a warning".into()
            },
            ReportLine {
                kind: LineKind::Note,
                text: "another note".into()
            },
        ]
    );
    assert_eq!(parsed.warnings().collect::<Vec<_>>(), ["a warning"]);
    assert_eq!(Report::parse("a\nb").lines.len(), 2);
    assert!(Report::parse("").lines.is_empty());
    assert!(!Report::parse("").complete);
}

#[test]
fn a_line_that_is_written_is_read_back_as_it_was_said() {
    let said = [
        (LineKind::Note, "sshd restarted; it accepts SSH_BROKER_ELEVATION"),
        (LineKind::Warning, "sshd is NOT running: start it"),
        (LineKind::Warning, "line 1\nline 2"),
    ];
    let mut out = Vec::new();
    write_lines(&mut out, |say| {
        for (kind, text) in said {
            say(kind, text);
        }
    })
    .unwrap();
    let parsed = Report::parse(&String::from_utf8(out).unwrap());
    assert!(parsed.complete);
    assert_eq!(
        parsed.warnings().collect::<Vec<_>>(),
        ["sshd is NOT running: start it", "line 1", "line 2"]
    );
    assert_eq!(parsed.lines.len(), 4);
    assert_eq!(parsed.lines[0].kind, LineKind::Note);
}

/// What `Report::parse` reads of `said` after the verb has written it: every line with its kind and text.
fn written_and_read(said: &[(LineKind, &str)]) -> Vec<(LineKind, String)> {
    let mut out = Vec::new();
    write_lines(&mut out, |say| {
        for (kind, text) in said {
            say(*kind, text);
        }
    })
    .unwrap();
    let parsed = Report::parse(&String::from_utf8(out).unwrap());
    assert!(parsed.complete);
    parsed.lines.into_iter().map(|line| (line.kind, line.text)).collect()
}

/// A note that begins with the warning's prefix is written so that `parse` reads it back as a note, and as the text
/// it was: it cannot become a warning, which `install` would show.
#[test]
fn a_note_that_begins_with_the_warning_prefix_is_read_back_as_that_note() {
    for text in [
        "warning: this is a note",
        " warning: one space is a space of the note",
        "  warning: two",
        "warning: ",
    ] {
        assert_eq!(
            written_and_read(&[(LineKind::Note, text)]),
            [(LineKind::Note, text.to_owned())],
            "{text:?}"
        );
    }
}

#[test]
fn a_note_of_several_lines_one_of_which_begins_with_the_warning_prefix_stays_a_note() {
    assert_eq!(
        written_and_read(&[(LineKind::Note, "first\nwarning: second\nthird")]),
        [
            (LineKind::Note, "first".to_owned()),
            (LineKind::Note, "warning: second".to_owned()),
            (LineKind::Note, "third".to_owned()),
        ]
    );
}

#[test]
fn a_warning_whose_text_begins_like_a_warning_is_one_warning_with_that_text() {
    assert_eq!(
        written_and_read(&[
            (LineKind::Warning, "warning: twice"),
            (LineKind::Warning, " warning: spaced")
        ]),
        [
            (LineKind::Warning, "warning: twice".to_owned()),
            (LineKind::Warning, " warning: spaced".to_owned()),
        ]
    );
}

/// An empty text is one empty line of its kind, as every line was written before kinds.
#[test]
fn an_empty_text_is_one_empty_line_of_its_kind() {
    assert_eq!(
        written_and_read(&[(LineKind::Note, ""), (LineKind::Warning, "")]),
        [(LineKind::Note, String::new()), (LineKind::Warning, String::new())]
    );
}

#[test]
fn a_text_with_crlf_line_breaks_is_read_back_as_its_lines_with_their_kinds() {
    assert_eq!(
        written_and_read(&[
            (LineKind::Note, "first\r\nwarning: second\r\n"),
            (LineKind::Warning, "one\r\ntwo"),
        ]),
        [
            (LineKind::Note, "first".to_owned()),
            (LineKind::Note, "warning: second".to_owned()),
            (LineKind::Warning, "one".to_owned()),
            (LineKind::Warning, "two".to_owned()),
        ]
    );
}

#[test]
fn a_report_that_ends_with_the_closing_line_is_complete_and_the_closing_line_is_not_a_line() {
    let parsed = Report::parse(&format!("a\r\nb\r\n{REPORT_END}\r\n"));
    assert!(parsed.complete);
    assert_eq!(
        parsed.lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );

    let parsed = Report::parse("a\r\nb\r\n");
    assert!(!parsed.complete);
    assert_eq!(parsed.lines.len(), 2);
}

// the report file =====

#[test]
fn the_report_file_holds_notes_and_warnings_as_plain_lines_and_no_line_begins_with_the_verb() {
    let dir = std::env::temp_dir().join(format!("sb-report-plain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("install-sshd.log");

    write_report(&path, |say| {
        say(LineKind::Note, "restarting sshd");
        say(LineKind::Warning, "sshd is NOT running");
        say(LineKind::Note, "sshd restarted");
    })
    .unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        raw,
        format!("restarting sshd\r\nwarning: sshd is NOT running\r\nsshd restarted\r\n{REPORT_END}\r\n")
    );
    for line in raw.lines() {
        let first = line.split(|c: char| !c.is_alphanumeric()).next().unwrap_or_default();
        assert!(
            !first.eq_ignore_ascii_case("install") && !line.starts_with("install-sshd:"),
            "{line}"
        );
    }
}

#[test]
fn the_verb_writes_each_line_to_the_report_whole_before_it_goes_on() {
    let dir = std::env::temp_dir().join(format!("sb-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("install-sshd.log");
    std::fs::write(&path, "left from an earlier run\r\n").unwrap();

    let mut seen_by_a_reader = Vec::new();
    write_report(&path, |say| {
        say(LineKind::Note, "first");
        seen_by_a_reader.push(std::fs::read_to_string(&path).unwrap());
        say(LineKind::Warning, "second");
        seen_by_a_reader.push(std::fs::read_to_string(&path).unwrap());
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        seen_by_a_reader,
        ["first\r\n", "first\r\nwarning: second\r\n"],
        "a line is in the file when `say` returns, and the earlier run's text is gone"
    );
}

#[test]
fn the_closing_line_is_written_only_after_the_step_has_returned() {
    let dir = std::env::temp_dir().join(format!("sb-report-end-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("install-sshd.log");

    let mut inside = None;
    write_report(&path, |say| {
        say(LineKind::Warning, "first");
        inside = Some(Report::parse(&std::fs::read_to_string(&path).unwrap()));
    })
    .unwrap();
    let after = Report::parse(&std::fs::read_to_string(&path).unwrap());
    let raw = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let inside = inside.unwrap();
    assert!(
        !inside.complete,
        "while the step runs the file does not say that it is whole"
    );
    assert_eq!(inside.warnings().collect::<Vec<_>>(), ["first"]);
    assert!(after.complete);
    assert_eq!(after.warnings().collect::<Vec<_>>(), ["first"]);
    assert_eq!(
        raw,
        format!("warning: first\r\n{REPORT_END}\r\n"),
        "the last line of the file"
    );
}

/// A writer that takes the first `accepts` writes and fails every one after them.
struct Failing {
    accepts: usize,
    written: Vec<u8>,
}

impl std::io::Write for Failing {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.accepts == 0 {
            return Err(std::io::Error::other("the disk is full"));
        }
        self.accepts -= 1;
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_line_that_cannot_be_written_leaves_the_report_without_a_closing_line_and_is_the_error() {
    let mut out = Failing {
        accepts: 1,
        written: Vec::new(),
    };
    let mut said = Vec::new();
    let err = write_lines(&mut out, |say| {
        say(LineKind::Note, "first");
        say(LineKind::Warning, "second");
        say(LineKind::Note, "third");
        said.push("the step ran to its end");
    })
    .unwrap_err();
    assert_eq!(err.to_string(), "the disk is full");
    assert_eq!(
        said,
        ["the step ran to its end"],
        "the step is not cut short by a failed line"
    );
    assert_eq!(
        String::from_utf8(out.written).unwrap(),
        "first\r\n",
        "no closing line follows a failed one: the report says it is not whole"
    );
}

#[test]
fn a_closing_line_that_cannot_be_written_is_the_error() {
    let mut out = Failing {
        accepts: 1,
        written: Vec::new(),
    };
    let err = write_lines(&mut out, |say| say(LineKind::Note, "first")).unwrap_err();
    assert_eq!(err.to_string(), "the disk is full");
    let text = String::from_utf8(out.written).unwrap();
    assert!(!text.contains(REPORT_END), "{text}");
}

#[test]
fn a_report_that_cannot_be_written_is_an_error_and_the_step_does_not_run() {
    let missing = std::env::temp_dir()
        .join(format!("sb-no-such-dir-{}", std::process::id()))
        .join("install-sshd.log");
    let mut ran = false;
    let err = write_report(&missing, |_| ran = true).unwrap_err();
    assert!(
        !ran,
        "no report to write to, so nothing is run that nobody could read about"
    );
    assert!(format!("{err:#}").contains("install-sshd.log"), "{err:#}");
}

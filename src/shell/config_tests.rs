//! Host tests for the `config.yaml` schema (pure; runs on any platform).

use super::{ShellBlock, parse, render_file};
use crate::shell::Escaping;

fn block(text: &str) -> ShellBlock {
    parse(text.as_bytes())
        .unwrap_or_else(|e| panic!("{text:?} does not parse: {e}"))
        .unwrap_or_else(|| panic!("{text:?} has no shell block"))
}

fn start(program: &str) -> ShellBlock {
    ShellBlock {
        start: vec![program.to_string()],
        ..ShellBlock::default()
    }
}

#[test]
fn all_three_shorthands_parse_to_the_same_block() {
    let want = start("pwsh.exe");
    assert_eq!(block("shell: pwsh.exe"), want);
    assert_eq!(block("shell: {start: pwsh.exe}"), want);
    assert_eq!(block("shell: {start: [pwsh.exe]}"), want);
    assert_eq!(block("shell:\n  start:\n    - pwsh.exe\n"), want);
}

#[test]
fn a_string_is_one_argument_never_split() {
    let text = r"shell: C:\Program Files\PowerShell\7\pwsh.exe -NoLogo";
    assert_eq!(block(text).start, [r"C:\Program Files\PowerShell\7\pwsh.exe -NoLogo"]);
    assert_eq!(
        block(r#"shell: {start: "pwsh.exe -NoLogo"}"#).start,
        ["pwsh.exe -NoLogo"]
    );
}

#[test]
fn the_canonical_form_round_trips() {
    let text = "\
shell:
  start: [pwsh.exe]
  append:
    without-command: []
    with-command: [-c]
  escaping: msvc        # cmd | msvc; later msys, powershell-base64
";
    assert_eq!(
        block(text),
        ShellBlock {
            start: vec!["pwsh.exe".into()],
            without_command: Some(vec![]),
            with_command: Some(vec!["-c".into()]),
            escaping: Some(Escaping::Msvc),
        }
    );
}

#[test]
fn an_empty_list_is_kept_distinct_from_an_absent_one() {
    let with_empty = block("shell: {start: x, append: {with-command: []}}");
    assert_eq!(with_empty.with_command, Some(vec![]));
    assert_eq!(with_empty.without_command, None);
    let absent = block("shell: {start: x, append: {}}");
    assert_eq!(absent.with_command, None);
    assert_eq!(block("shell: x").with_command, None);
}

#[test]
fn append_values_are_lists_of_arguments() {
    let b = block(r#"shell: {start: [pwsh.exe, -NoLogo], append: {with-command: ["-Command", "-"]}}"#);
    assert_eq!(b.start, ["pwsh.exe", "-NoLogo"]);
    assert_eq!(b.with_command, Some(vec!["-Command".to_string(), "-".to_string()]));
}

/// Each of these is a broken config (D5): the reason must say what was wrong, so the one
/// warning the user gets is enough to fix the file.
#[test]
fn unknown_keys_and_bad_values_are_errors_naming_the_value() {
    for (text, names) in [
        ("shell: {start: x, escaping: msys}", "msys"),
        ("shell: {strt: x}", "strt"),
        ("shell: {start: []}", "start"),
        ("shell: {start: 3}", "start"),
        ("shell: {start: [a, 3]}", "string"),
        ("shell: {start: x, append: {with-comand: [-c]}}", "with-comand"),
        ("shell: {start: x, append: {with-command: -c}}", "with-command"),
        ("shell: {escaping: cmd}", "start"),
        ("shell: [a, b]", "shell"),
        ("shell:", "shell"),
        ("shell: 3", "shell"),
        ("shel: x", "shel"),
        ("shell: x\nshell: y\n", "shell"),
        ("shell: {start: x, start: y}", "start"),
        ("shell: {start: x}\nextra: 1\n", "extra"),
        ("- shell: x\n", "sequence"),
        ("shell: {start: x, escaping: [cmd]}", "escaping"),
    ] {
        let error = parse(text.as_bytes()).expect_err(text);
        assert!(
            error.reason.contains(names),
            "{text:?}: the reason {:?} does not name {names:?}",
            error.reason
        );
    }
}

#[test]
fn a_file_without_shell_is_none_and_an_empty_or_comment_only_file_too() {
    for text in ["", "\n", "# only a comment\n", "---\n", "---\n# c\n...\n", "  \n\n"] {
        assert_eq!(parse(text.as_bytes()).expect(text), None, "{text:?}");
    }
}

/// Review Focus 1: a config saved by Notepad or PowerShell parses, or is one error; it never panics.
#[test]
fn editor_encodings_parse() {
    let text = "shell:\r\n  start: [pwsh.exe]\r\n  append:\r\n    with-command: [-c]";
    let want = ShellBlock {
        start: vec!["pwsh.exe".into()],
        with_command: Some(vec!["-c".into()]),
        ..ShellBlock::default()
    };

    let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
    utf8_bom.extend_from_slice(text.as_bytes());
    let mut utf16le = vec![0xFF, 0xFE];
    utf16le.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let mut utf16be = vec![0xFE, 0xFF];
    utf16be.extend(text.encode_utf16().flat_map(u16::to_be_bytes));

    for (name, bytes) in [
        ("utf-8", text.as_bytes().to_vec()),
        ("utf-8 bom", utf8_bom),
        ("utf-16le bom", utf16le),
        ("utf-16be bom", utf16be),
        ("lf only", text.replace("\r\n", "\n").into_bytes()),
    ] {
        assert_eq!(
            parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}")),
            Some(want.clone()),
            "{name}"
        );
    }
}

#[test]
fn a_non_ascii_program_survives_every_editor_encoding() {
    let text = "shell: C:\\Users\\Ünï cödé\\bin\\pwsh.exe\r\n";
    let want = start("C:\\Users\\Ünï cödé\\bin\\pwsh.exe");
    let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
    utf8_bom.extend_from_slice(text.as_bytes());
    let mut utf16le = vec![0xFF, 0xFE];
    utf16le.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    for bytes in [text.as_bytes().to_vec(), utf8_bom, utf16le] {
        assert_eq!(parse(&bytes).unwrap(), Some(want.clone()));
    }
}

#[test]
fn bytes_that_are_not_text_are_an_error_not_a_panic() {
    for bytes in [
        &b"\xFF\xFE\x00"[..],
        b"shell: \xC3\x28",
        b"\x00\x00\x00",
        b"\xFE\xFF\x00",
        b"shell: \xFF",
    ] {
        parse(bytes).expect_err(&format!("{bytes:?}"));
    }
}

/// Review Focus 6: an editor may leave half a file; whatever prefix is read, it is a block or an error.
#[test]
fn a_torn_file_is_an_error_not_a_panic() {
    let text = "shell:\n  start: [pwsh.exe, \"-NoLogo\"]\n  append:\n    without-command: []\n    with-command: [-c]\n  escaping: msvc\n";
    for end in 0..=text.len() {
        if !text.is_char_boundary(end) {
            continue;
        }
        let _ = parse(&text.as_bytes()[..end]);
    }
    // The whole file is fine, and a prefix cut inside a quoted string or a flow list is not.
    assert!(parse(text.as_bytes()).unwrap().is_some());
    assert!(parse(&text.as_bytes()[..28]).is_err());
}

#[test]
fn an_error_says_where_it_is() {
    let error = parse(b"shell:\n  start: [a,\n").expect_err("an unterminated list");
    assert!(error.reason.contains("line"), "{}", error.reason);
}

fn round_trips(block: ShellBlock) {
    let text = render_file(&block).expect("a block renders");
    let back = parse(text.as_bytes())
        .unwrap_or_else(|e| panic!("{text}\ndoes not parse: {e}"))
        .unwrap_or_else(|| panic!("{text}\nhas no shell block"));
    assert_eq!(back, block, "{text}");
}

#[test]
fn a_serialized_block_parses_back_equal() {
    round_trips(ShellBlock {
        start: vec!["pwsh.exe".into()],
        without_command: Some(vec!["-NoLogo".into()]),
        with_command: Some(vec!["-Command".into()]),
        escaping: Some(Escaping::Cmd),
    });
    round_trips(start("pwsh.exe"));
    round_trips(ShellBlock {
        start: vec!["x".into()],
        without_command: Some(vec![]),
        ..ShellBlock::default()
    });
    round_trips(ShellBlock {
        start: vec!["x".into()],
        with_command: Some(vec![]),
        escaping: Some(Escaping::Msvc),
        ..ShellBlock::default()
    });
    for program in [
        r"C:\Program Files (x86)\PowerShell\pwsh.exe",
        r#"C:\a "quoted" dir\pwsh.exe"#,
        "C:\\Users\\Ünï cödé\\bin\\pwsh.exe",
        "x: y",
        "- z",
        "#not a comment",
        "'single'",
        "yes",
        "null",
        "3",
        "~",
        "",
        " lead and trail ",
        "line\nbreak",
    ] {
        round_trips(ShellBlock {
            start: vec![program.into(), program.into()],
            without_command: Some(vec![program.into()]),
            with_command: Some(vec![program.into()]),
            escaping: None,
        });
    }
}

#[test]
fn the_rendered_file_is_the_canonical_nested_form() {
    let text = render_file(&ShellBlock {
        start: vec!["pwsh.exe".into()],
        with_command: Some(vec!["-c".into()]),
        escaping: Some(Escaping::Msvc),
        ..ShellBlock::default()
    })
    .unwrap();
    assert_eq!(
        text,
        "shell:\n  start:\n  - pwsh.exe\n  append:\n    with-command:\n    - -c\n  escaping: msvc\n"
    );
}

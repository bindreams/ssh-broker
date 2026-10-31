use super::{decode, encode};

#[test]
fn the_notice_and_the_line_come_back_exactly() {
    for (notice, line) in [
        ("", ""),
        ("a notice", r#""C:\a b\cmd.exe" /c echo "x" \"#),
        ("héllo ✓\r\n", "echo a\r\nb\t"),
        ("n", &"x".repeat(32_766)),
    ] {
        let bytes = encode(notice, line).unwrap();
        assert_eq!(decode(&bytes).unwrap(), (notice.to_owned(), line.to_owned()));
    }
}

/// An agent that died mid-write leaves a prefix; reading it as a shorter line would start the wrong command.
#[test]
fn a_hand_off_cut_short_is_an_error_at_every_length() {
    let bytes = encode("a notice", "cmd.exe /c echo hi").unwrap();
    for len in 0..bytes.len() {
        assert!(decode(&bytes[..len]).is_err(), "a prefix of {len} bytes was read");
    }
}

/// Bytes after the notice and the line are not part of a hand-off: a stream that holds more than
/// was written is not the one the agent wrote.
#[test]
fn bytes_after_the_line_are_an_error() {
    let mut bytes = encode("a notice", "cmd.exe /c echo hi").unwrap();
    bytes.push(0);
    assert!(decode(&bytes).is_err());
    let doubled = [encode("n", "l").unwrap(), encode("n", "l").unwrap()].concat();
    assert!(decode(&doubled).is_err());
}

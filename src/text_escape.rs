//! The rule by which text is shown as escapes, for the places that must not let a character act or two texts look
//! alike: a comment in the config file ([`crate::shell::config::comment_text`]) and the consent question's text
//! ([`crate::offer::text::display`]).

/// `text` with every character `escape` has an escape for written as that escape, and every backslash that would
/// read as the start of one doubled, so that no two texts show alike: a newline and the text `\n` stay different. Any
/// other backslash is left, so a path reads as it is. A backslash reads as the start of an escape when `rest` (what
/// follows it) begins with a character that is itself escaped, with a backslash (the doubling this writes), or with
/// what `starts_escape` says an escape's own text begins with.
pub fn escape_text(
    text: &str,
    escape: impl Fn(char) -> Option<String>,
    starts_escape: impl Fn(&[char]) -> bool,
) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (at, &c) in chars.iter().enumerate() {
        if let Some(escaped) = escape(c) {
            out.push_str(&escaped);
            continue;
        }
        if c == '\\' {
            let rest = &chars[at + 1..];
            let reads_as_escape =
                rest.first().is_some_and(|&next| next == '\\' || escape(next).is_some()) || starts_escape(rest);
            if reads_as_escape {
                out.push('\\');
            }
        }
        out.push(c);
    }
    out
}

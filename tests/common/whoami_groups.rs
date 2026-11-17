//! What `whoami /groups` says of a token, for the tests that start a program with a token they chose.
#![allow(dead_code)]

/// What `whoami /groups` shows of a token: its mandatory label (`High`, `Medium`) and what it says of
/// `BUILTIN\Administrators` (`enabled`, `deny-only`, `absent`).
#[derive(Debug, PartialEq, Eq)]
pub struct TokenShown {
    pub label: String,
    pub administrators: &'static str,
}

impl TokenShown {
    pub fn new(label: &str, administrators: &'static str) -> TokenShown {
        TokenShown {
            label: label.to_owned(),
            administrators,
        }
    }
}

/// The token `whoami /groups` printed in `text`. Read without lines, so that it serves what a terminal showed too
/// (a terminal's text has its line ends removed): the label is the word before ` Mandatory Level`, and the
/// state of Administrators is read from what follows its SID, up to the SID of the next group.
pub fn token_shown(text: &str) -> TokenShown {
    let label_at = text.find(r"Mandatory Label\").unwrap_or_else(|| {
        panic!(
            "no mandatory label in the output of whoami /groups:
{text}"
        )
    });
    let rest = &text[label_at + r"Mandatory Label\".len()..];
    let label = rest.split(" Mandatory Level").next().unwrap().to_owned();
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    let administrators = match text.find(ADMINISTRATORS) {
        None => "absent",
        Some(at) => {
            let row = &text[at + ADMINISTRATORS.len()..];
            let row = &row[..row.find("S-1-").unwrap_or(row.len())];
            if row.contains("deny only") {
                "deny-only"
            } else {
                "enabled"
            }
        }
    };
    TokenShown { label, administrators }
}

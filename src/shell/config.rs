//! The `config.yaml` schema and its parser.
//!
//! Strict: an unknown key anywhere is an error, so a typo is a warning instead of being ignored.

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::Escaping;

/// The `shell` block, as written. `None` fields are the defaults, which depend on the program;
/// `Some(vec![])` is an explicit "none".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShellBlock {
    /// Program, then its leading arguments. Never empty after [`parse`].
    pub start: Vec<String>,
    pub without_command: Option<Vec<String>>,
    pub with_command: Option<Vec<String>>,
    pub escaping: Option<Escaping>,
}

/// Why a config file is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What is wrong: the offending key or value and, when the parser gave one, the line.
    pub reason: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ParseError {}

/// The `shell` block of a config file's bytes. `Ok(None)`: a valid file with no `shell` (empty,
/// or only comments).
///
/// Editors save UTF-8 (with or without a BOM) or UTF-16 with a BOM; the BOM decides.
pub fn parse(bytes: &[u8]) -> Result<Option<ShellBlock>, ParseError> {
    let (text, _, malformed) = encoding_rs::UTF_8.decode(bytes);
    if malformed {
        return Err(ParseError {
            reason: "the file is not valid UTF-8 or UTF-16 text".into(),
        });
    }
    let file: Option<File> = yaml_serde::from_str(&text).map_err(|e| ParseError { reason: e.to_string() })?;
    let Some(raw) = file.and_then(|f| f.shell) else {
        return Ok(None);
    };
    let block = ShellBlock::from(raw);
    if block.start.is_empty() {
        return Err(ParseError {
            reason: "invalid `shell`: `start` is required and must not be empty".into(),
        });
    }
    refuse_nul(&block)?;
    Ok(Some(block))
}

/// `CreateProcessW` ends the line at the first NUL, so a NUL in any configured string would start
/// the shell with part of its arguments dropped. The file is broken instead, and its reason names
/// the key.
fn refuse_nul(block: &ShellBlock) -> Result<(), ParseError> {
    let lists = [
        ("start", Some(&block.start)),
        ("with-command", block.with_command.as_ref()),
        ("without-command", block.without_command.as_ref()),
    ];
    for (key, list) in lists {
        if list.is_some_and(|items| items.iter().any(|item| item.contains('\0'))) {
            return Err(ParseError {
                reason: format!("invalid `shell`: `{key}` holds a NUL character, which a command line cannot carry"),
            });
        }
    }
    Ok(())
}

/// A config file holding `block`, in the canonical nested form.
pub fn render_file(block: &ShellBlock) -> Result<String, ParseError> {
    render_annotated(block, &Notes::default())
}

/// A comment for the line of each key [`render_annotated`] writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct Notes<'a> {
    pub start: Option<&'a str>,
    pub without_command: Option<&'a str>,
    pub with_command: Option<&'a str>,
    pub escaping: Option<&'a str>,
}

/// [`render_file`] with a comment after each key that has a note. The YAML library renders every
/// value; the keys, their nesting and the comments are all that is written here, so any string
/// reads back as itself.
pub fn render_annotated(block: &ShellBlock, notes: &Notes<'_>) -> Result<String, ParseError> {
    let mut out = String::from("shell:\n");
    entry(&mut out, 2, "start", &block.start, notes.start)?;
    if block.without_command.is_some() || block.with_command.is_some() {
        out.push_str("  append:\n");
        if let Some(list) = &block.without_command {
            entry(&mut out, 4, "without-command", list, notes.without_command)?;
        }
        if let Some(list) = &block.with_command {
            entry(&mut out, 4, "with-command", list, notes.with_command)?;
        }
    }
    if let Some(escaping) = &block.escaping {
        entry(&mut out, 2, "escaping", escaping, notes.escaping)?;
    }
    Ok(out)
}

/// One `key: value` of the block at `indent` columns. A list goes under its key, at the key's own
/// indent, as a sequence under a mapping key may; any other value, and an empty list, follows the key.
fn entry<T: Serialize>(
    out: &mut String,
    indent: usize,
    key: &str,
    value: &T,
    note: Option<&str>,
) -> Result<(), ParseError> {
    let rendered = yaml_serde::to_string(value).map_err(|e| ParseError { reason: e.to_string() })?;
    let pad = " ".repeat(indent);
    // A control character in a note (a path can hold one) would end the comment early.
    let note = note.map_or(String::new(), |n| {
        let shown: String = n
            .chars()
            .flat_map(|c| {
                if c.is_control() {
                    c.escape_default().collect()
                } else {
                    vec![c]
                }
            })
            .collect();
        format!("  # {shown}")
    });
    let value = rendered.trim_end_matches('\n');
    if value.contains('\n') || value.starts_with("- ") {
        out.push_str(&format!("{pad}{key}:{note}\n"));
        for line in value.lines() {
            out.push_str(&format!("{pad}{line}\n"));
        }
    } else {
        out.push_str(&format!("{pad}{key}: {value}{note}\n"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default, deserialize_with = "shell_field")]
    shell: Option<RawShell>,
}

/// Present means a block: `shell:` with nothing after it is a mistake, not "no shell".
fn shell_field<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<RawShell>, D::Error> {
    RawShell::deserialize(deserializer).map(Some)
}

/// `shell:` as written: a program, or a mapping.
struct RawShell(RawBlock);

impl<'de> Deserialize<'de> for RawShell {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = yaml_serde::Value::deserialize(deserializer)?;
        match value {
            yaml_serde::Value::String(program) => Ok(RawShell(RawBlock {
                start: Some(Args(vec![program])),
                append: None,
                escaping: None,
            })),
            yaml_serde::Value::Mapping(_) => yaml_serde::from_value(value)
                .map(RawShell)
                .map_err(|e| D::Error::custom(format!("invalid `shell`: {e}"))),
            _ => Err(D::Error::custom("invalid `shell`: expected a program or a mapping")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawBlock {
    #[serde(default, deserialize_with = "start")]
    start: Option<Args>,
    append: Option<RawAppend>,
    #[serde(default, deserialize_with = "escaping")]
    escaping: Option<Escaping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawAppend {
    #[serde(default, deserialize_with = "without_command")]
    without_command: Option<List>,
    #[serde(default, deserialize_with = "with_command")]
    with_command: Option<List>,
}

// A present key must hold a valid value (`key:` with nothing is a mistake), and the error names
// the key, which `from_value` cannot locate. One wrapper per key because `deserialize_with`
// takes no arguments.
fn named<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D, key: &str) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer)
        .map(Some)
        .map_err(|e| D::Error::custom(format!("`{key}`: {e}")))
}

fn start<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Args>, D::Error> {
    named(deserializer, "start")
}

fn escaping<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Escaping>, D::Error> {
    named(deserializer, "escaping")
}

fn without_command<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<List>, D::Error> {
    named(deserializer, "without-command")
}

fn with_command<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<List>, D::Error> {
    named(deserializer, "with-command")
}

/// A list of arguments (strings only: a number or a boolean is a mistake, not a coercion).
struct List(Vec<String>);

impl<'de> Deserialize<'de> for List {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = yaml_serde::Value::deserialize(deserializer)?;
        let yaml_serde::Value::Sequence(items) = value else {
            return Err(D::Error::custom("expected a list of strings"));
        };
        items
            .into_iter()
            .map(|item| match item {
                yaml_serde::Value::String(s) => Ok(s),
                other => Err(D::Error::custom(format!(
                    "expected a string in the list, found {other:?}"
                ))),
            })
            .collect::<Result<_, _>>()
            .map(List)
    }
}

/// `start`: one program (a string is exactly one argument, never split), or a list.
struct Args(Vec<String>);

impl<'de> Deserialize<'de> for Args {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = yaml_serde::Value::deserialize(deserializer)?;
        match value {
            yaml_serde::Value::String(program) => Ok(Args(vec![program])),
            yaml_serde::Value::Sequence(_) => yaml_serde::from_value::<List>(value)
                .map(|list| Args(list.0))
                .map_err(|e| D::Error::custom(e.to_string())),
            other => Err(D::Error::custom(format!(
                "expected a program or a list of strings, found {other:?}"
            ))),
        }
    }
}

impl From<RawShell> for ShellBlock {
    fn from(raw: RawShell) -> Self {
        let RawBlock {
            start,
            append,
            escaping,
        } = raw.0;
        let (without_command, with_command) = match append {
            Some(a) => (a.without_command.map(|l| l.0), a.with_command.map(|l| l.0)),
            None => (None, None),
        };
        ShellBlock {
            start: start.map(|s| s.0).unwrap_or_default(),
            without_command,
            with_command,
            escaping,
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

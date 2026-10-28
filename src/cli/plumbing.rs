//! Plumbing mode: one JSON object per command on stdout, and everything else on stderr.
//!
//! For automation, which reads what happened rather than how it was said: the human output
//! of every command moves to stderr, where the log already is, and stdout carries only the
//! reports. Nothing prompts in plumbing mode, and a confirmation has to be given with `--yes`.

use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The original stdout, where the reports go once fd 1 points at stderr
static REPORTS: Mutex<Option<File>> = Mutex::new(None);

/// Whether plumbing mode is on
pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Turn plumbing mode on: keep stdout for the reports and send everything else to stderr
pub(super) fn enable() -> Result<()> {
    if active() {
        return Ok(());
    }
    std::io::stdout().flush()?;
    // SAFETY: plain descriptor calls on the process's own standard streams; the duplicate is
    // owned by the `File` from here on and never closed elsewhere
    let reports = unsafe {
        let copy = libc::dup(1);
        if copy < 0 || libc::dup2(2, 1) < 0 {
            bail!("Cannot set up plumbing mode: {}", std::io::Error::last_os_error());
        }
        File::from_raw_fd(copy)
    };
    *REPORTS.lock().expect("never poisoned") = Some(reports);
    ACTIVE.store(true, Ordering::Relaxed);
    Ok(())
}

/// A JSON value, as much of JSON as a report needs
pub(super) enum Json {
    Null,
    Bool(bool),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    /// A string, or null where there is none
    pub(super) fn maybe(text: Option<&str>) -> Json {
        text.map_or(Json::Null, |text| Json::Str(text.to_string()))
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Json::Str(text) => out.push_str(&json_string(text)),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&json_string(name));
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// What the running command found, for its report: a field name and its value each
static FOUND: Mutex<Vec<(&'static str, Json)>> = Mutex::new(Vec::new());

/// Add what a command found to its report, where plumbing is on
pub(super) fn attach(name: &'static str, value: Json) {
    if active() {
        FOUND.lock().expect("never poisoned").push((name, value));
    }
}

/// Report one command's outcome as a JSON object on its own line, with what it found
pub(super) fn report(command: &str, result: &Result<()>) {
    let mut fields = vec![("command", Json::Str(command.to_string()))];
    match result {
        Ok(()) => fields.push(("ok", Json::Bool(true))),
        Err(err) => {
            fields.push(("ok", Json::Bool(false)));
            fields.push(("error", Json::Str(format!("{err:#}"))));
        }
    }
    fields.extend(std::mem::take(&mut *FOUND.lock().expect("never poisoned")));
    let mut line = String::new();
    Json::Object(fields).write(&mut line);
    line.push('\n');
    if let Some(reports) = REPORTS.lock().expect("never poisoned").as_mut() {
        let _ = reports.write_all(line.as_bytes());
        let _ = reports.flush();
    }
}

/// A JSON string literal
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_nest() {
        let mut out = String::new();
        Json::Object(vec![
            ("cards", Json::Array(vec![Json::Null, Json::Bool(false)])),
            ("name", Json::maybe(Some("a\"b"))),
        ])
        .write(&mut out);
        assert_eq!(out, "{\"cards\":[null,false],\"name\":\"a\\\"b\"}");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(json_string("a \"b\"\n\\c\u{1}"), "\"a \\\"b\\\"\\n\\\\c\\u0001\"");
    }
}

//! Tab completion in the interactive session: verbs, a verb's options, their values, and the
//! names `set` and `unset` take.
//!
//! Everything offered comes from the session's command and the option table, never from the
//! history or anything typed before: the options a line cannot change are hidden there, the
//! seed phrase and the passwords among them, a seed flag a line gives bare to ask is offered
//! without a value, and an option that takes a secret has no values to offer, so a completion
//! can neither name nor echo one.

use super::config;

use clap::{Arg, Command};

use rustyline::Context;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

/// The line editor's helper: the session's completion, and no hints, colour or validation
pub(super) struct LineHelper {
    command: Command,
    settings: Vec<String>,
}

impl LineHelper {
    pub(super) fn new() -> LineHelper {
        let mut command = super::session_command();
        command.build();
        let settings = config::option_names(&command).into_iter().collect();
        LineHelper { command, settings }
    }

    /// The completions of the word that ends at `pos`, and where that word starts
    fn candidates(&self, line: &str, pos: usize) -> (usize, Vec<String>) {
        // A cursor inside a character completes nothing rather than cut the line there
        let Some(before) = line.get(..pos) else {
            return (pos, Vec::new());
        };
        // The word starts after the last whitespace, which may take more than one byte (a
        // no-break space typed with AltGr), so the cut is after that character, not its first
        // byte
        let start = before
            .char_indices()
            .rfind(|(_, ch)| ch.is_whitespace())
            .map_or(0, |(at, ch)| at + ch.len_utf8());
        let word = &before[start..];
        let words: Vec<&str> = before[..start].split_whitespace().collect();
        let candidates = match words.first() {
            None => self.verbs(word),
            Some(&"help") if words.len() == 1 => self.verbs(word),
            Some(&verb @ ("set" | "unset")) if !word.starts_with('-') => {
                self.settings(word, verb == "set")
            }
            Some(verb) => match self.command.find_subcommand(verb) {
                Some(verb) => options(verb, words.last().copied(), word),
                None => Vec::new(),
            },
        };
        (start, candidates)
    }

    /// The verbs a line can start with
    fn verbs(&self, word: &str) -> Vec<String> {
        self.command
            .get_subcommands()
            .filter(|verb| !verb.is_hide_set())
            .map(|verb| verb.get_name())
            .filter(|name| name.starts_with(word))
            .map(|name| format!("{name} "))
            .collect()
    }

    /// The names `set` and `unset` take, as `name=` for `set`, and after `name=` its values
    fn settings(&self, word: &str, set: bool) -> Vec<String> {
        if let (true, Some((key, value))) = (set, word.split_once('=')) {
            let name = key
                .strip_prefix("piv.")
                .or_else(|| key.strip_prefix("pgp."))
                .unwrap_or(key);
            let arg = std::iter::once(&self.command)
                .chain(self.command.get_subcommands())
                .flat_map(Command::get_arguments)
                .find(|arg| arg.get_long() == Some(name));
            return arg
                .map(|arg| values(arg, value, true))
                .unwrap_or_default()
                .into_iter()
                .map(|value| format!("{key}={value}"))
                .collect();
        }
        let (table, name) = match word.split_once('.') {
            Some((table @ ("piv" | "pgp"), name)) => (format!("{table}."), name),
            _ => (String::new(), word),
        };
        self.settings
            .iter()
            .filter(|setting| setting.starts_with(name))
            .map(|setting| format!("{table}{setting}{}", if set { "=" } else { " " }))
            .collect()
    }
}

/// A verb's long options, as a line may give them, or the values of the one before the word
fn options(verb: &Command, previous: Option<&str>, word: &str) -> Vec<String> {
    let visible = || {
        verb.get_arguments()
            .filter(|arg| !arg.is_hide_set() && !arg.is_positional())
    };
    // `--policy=st`, the option and its value in one word
    if let Some((flag, value)) = word.split_once('=')
        && let Some(arg) = visible().find(|arg| long_of(arg).as_deref() == Some(flag))
    {
        return values(arg, value, false)
            .into_iter()
            .map(|value| format!("{flag}={value}"))
            .collect();
    }
    if word.starts_with('-') {
        return visible()
            .filter_map(long_of)
            .filter(|flag| flag.starts_with(word))
            .map(|flag| format!("{flag} "))
            .collect();
    }
    // The value of the option before, where it takes one of a few
    let taking = previous.and_then(|previous| {
        visible().find(|arg| {
            long_of(arg).as_deref() == Some(previous)
                || arg
                    .get_short()
                    .is_some_and(|short| previous == format!("-{short}"))
        })
    });
    taking.map_or_else(Vec::new, |arg| values(arg, word, false))
}

/// An option's long spelling, `--name`
fn long_of(arg: &Arg) -> Option<String> {
    arg.get_long().map(|long| format!("--{long}"))
}

/// The values an option takes that complete `word`: its value enum, each item of a list
/// after the last comma, and `true` or `false` for a flag where a setting gives it a value
fn values(arg: &Arg, word: &str, setting: bool) -> Vec<String> {
    let (done, item) = match arg.get_value_delimiter() {
        Some(delimiter) => word
            .rfind(delimiter)
            .map_or(("", word), |at| word.split_at(at + delimiter.len_utf8())),
        None => ("", word),
    };
    let names: Vec<String> = if !arg.get_action().takes_values() {
        if setting {
            vec!["true".into(), "false".into()]
        } else {
            Vec::new()
        }
    } else {
        arg.get_possible_values()
            .iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| value.get_name().to_string())
            .collect()
    };
    // A list goes on after a comma; any other value ends its word
    let end = if arg.get_value_delimiter().is_some() {
        ""
    } else {
        " "
    };
    names
        .into_iter()
        .filter(|name| name.starts_with(item))
        .map(|name| format!("{done}{name}{end}"))
        .collect()
}

impl Completer for LineHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let (start, candidates) = self.candidates(line, pos);
        Ok((
            start,
            candidates
                .into_iter()
                .map(|candidate| Pair {
                    display: candidate.trim_end().into(),
                    replacement: candidate,
                })
                .collect(),
        ))
    }
}

impl Hinter for LineHelper {
    type Hint = String;
}

impl Highlighter for LineHelper {}

impl Validator for LineHelper {}

impl rustyline::Helper for LineHelper {}

/// The completions of a session line typed up to `pos`, and where the word they replace
/// starts, as the session's tab key offers them
pub fn complete(line: &str, pos: usize) -> (usize, Vec<String>) {
    LineHelper::new().candidates(line, pos)
}

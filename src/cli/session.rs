//! The session: the seeds and defaults that outlive one command, the interactive line editor,
//! and the questions only a session asks.

use super::completion::LineHelper;
use super::config::Defaults;
use super::generate::generate;
use super::seeds::{SeedBook, Source};
use super::verbs;
use super::{Cli, SeedArgs, Verb, ceremony, plumbing};
use crate::mnemonic;
use crate::prompt;

use std::io::{self, BufRead, IsTerminal};

use anyhow::{Result, anyhow, bail};

use clap::FromArgMatches;
use clap::parser::ValueSource;

use rustyline::config::Config;
use rustyline::error::ReadlineError;
use rustyline::history::MemHistory;

/// Whether the session keeps going after a line
pub(super) enum Flow {
    Continue,
    Quit,
}

/// What a line's words parse to: a verb with the line's own seeds, or what clap shows in its
/// place, help, the version or a usage error
enum Parsed {
    Verb(Box<(SeedArgs, Verb)>),
    Shown(clap::Error),
}

/// The state of one invocation, interactive session or ceremony: the seeds, resolved at most
/// once, and the defaults every command starts from
///
/// Deliberately not `Debug`, like [`Cli`] and for the same reason.
pub(super) struct Session {
    seeds: SeedBook,
    pub(super) defaults: Defaults,
    /// Whether this session may prompt at all: true only when stdin is a terminal and no
    /// plumbing was asked for. Otherwise it keeps the one-shot contract: errors and warnings,
    /// never a prompt a script would hang on.
    pub(super) interactive: bool,
    /// Whether every command reports itself as one JSON object
    plumbing: bool,
}

impl Session {
    /// A session from the command line's seeds and the loaded defaults
    pub(super) fn new(seeds: SeedArgs, mut defaults: Defaults, plumbing: bool) -> Result<Session> {
        if plumbing {
            plumbing::enable()?;
        }
        // Taken in once: a session's lines are parsed without the environment, so that a
        // variable read again on every line can never undo a `set`
        defaults.absorb_environment()?;
        Ok(Session {
            seeds: SeedBook::from_args(seeds),
            defaults,
            interactive: false,
            plumbing,
        })
    }

    /// Run one verb, reporting it as plumbing asks; `views` are the command parsed again for
    /// each applet, where the config has a table for one
    pub(super) fn run_verb(&mut self, verb: Verb, views: Option<(Verb, Verb)>) -> Result<()> {
        let name = verb.name().to_string();
        let result = self.execute(verb, SeedArgs::default(), views).map(drop);
        if self.plumbing {
            plumbing::report(&name, &result);
        }
        result
    }

    /// Run one verb in this session, with a line's own seeds where it gives them
    fn execute(&mut self, verb: Verb, line: SeedArgs, views: Option<(Verb, Verb)>) -> Result<Flow> {
        match verb {
            Verb::Quit => return Ok(Flow::Quit),
            Verb::Set { settings, .. } if settings.is_empty() => self.show(),
            Verb::Set { settings, save: false } => self.defaults.set(&settings)?,
            Verb::Set { settings, save: true } => self.defaults.save(&settings)?,
            Verb::Unset { names, save: false } => self.defaults.unset(&names)?,
            Verb::Unset { names, save: true } => self.defaults.unsave(&names)?,
            Verb::Run { recipe, ceremony: file, record, dry_run, check } => ceremony::run(
                self,
                recipe.as_deref(),
                file.as_deref(),
                record.as_deref(),
                dry_run,
                check,
            )?,
            Verb::Generate => self.generate()?,
            verb => {
                verbs::preflight(&verb, views.as_ref())?;
                let overrides = line.card_seed.is_some() || line.key_seed.is_some();
                let mut book = self.seeds.overridden(line);
                let roots = book.roots(verb.seed_use(), self.interactive)?;
                // What the session's own seeds resolved to is kept; a line's override is
                // that line's alone
                if overrides {
                    self.seeds.seed = book.seed;
                } else {
                    self.seeds = book;
                }
                verbs::dispatch(verb, views, roots, self.interactive)?;
            }
        }
        Ok(Flow::Continue)
    }

    /// Show the config files consulted, the state of the seeds (never a seed itself) and the
    /// defaults, each behind the layer it comes from
    fn show(&self) {
        println!("Config files:");
        for file in self.defaults.describe_files() {
            println!("  {file}");
        }
        // Only a person at a terminal is ever asked; anywhere else a seed is given or missing
        let asked = if self.interactive {
            "asked for when needed"
        } else {
            "not given, and only an interactive session asks"
        };
        let state = |source: &Source, fallback: &str| match source {
            Source::Absent => fallback.to_string(),
            Source::Given(..) => "given".into(),
            Source::Resolved(_) => "loaded".into(),
            Source::Ask => asked.into(),
        };
        println!("Seeds:");
        println!("  seed       {}", state(&self.seeds.seed, asked));
        println!("  card seed  {}", state(&self.seeds.card, "the seed"));
        println!("  key seed   {}", state(&self.seeds.key, "the seed"));
        println!("Defaults:");
        let defaults = self.defaults.describe();
        if defaults.is_empty() {
            println!("  no defaults set");
        }
        for default in defaults {
            println!("  {default}");
        }
    }

    /// Mint a seed, and keep it for the rest of the session
    ///
    /// Replacing a seed the session already holds gets the same ceremony as a card wipe: one
    /// typo must not silently re-point every later command.
    fn generate(&mut self) -> Result<()> {
        if self.plumbing {
            bail!("`generate` shows a phrase to a person, which plumbing has none of");
        }
        let in_session = self.interactive;
        if in_session && self.seeds.has_seed() {
            verbs::ask(
                "The session already holds a seed; generate will replace it for every later \
                 command.",
            )?;
        } else if self.seeds.has_seed() {
            bail!("The session already holds a seed; a piped session cannot replace it");
        }
        let seed = generate(in_session)?;
        let seed = if in_session {
            match prompt::read_optional_secret("Password (empty for none): ")? {
                Some(password) => seed.with_password(&password),
                None => seed,
            }
        } else {
            seed
        };
        // Public, and what `check` shows later: written down with the phrase, it tells a
        // mistyped phrase or password from the right one before anything trusts it
        println!(
            "Seed id: {} (write it down with the phrase; `check` shows it again)",
            super::seeds::seed_id(&seed.seed())
        );
        if in_session {
            self.seeds.adopt(seed);
        }
        Ok(())
    }

    /// Parse and run one line, returning what went wrong rather than reporting it
    pub(super) fn run_line(&mut self, line: &str, ceremony: bool) -> Result<Flow> {
        let result = self.interpret(line, ceremony);
        // Plumbing hears of every line, the ones refused before they ran included, named by
        // their first word, which is the verb of every line that parses
        if self.plumbing
            && let Some(first) = line.split_whitespace().next()
        {
            plumbing::report(first, &result.as_ref().map(drop).map_err(|err| anyhow!("{err:#}")));
        }
        result
    }

    /// Parse and run one line
    fn interpret(&mut self, line: &str, ceremony: bool) -> Result<Flow> {
        let Some(tokens) = shlex::split(line) else {
            bail!("Unbalanced quotes in the command line");
        };
        if tokens.is_empty() {
            return Ok(Flow::Continue);
        }
        // Answered as `set` answers a secret, and kept out of the history all the same
        if let Some(name) = secret_setting(&tokens) {
            bail!(
                "`{name}` is a secret, and secrets are never defaults; the line was kept out \
                 of the history"
            );
        }
        if let Some(secret) = names_a_secret(&tokens, ceremony) {
            bail!(
                "{secret} is fixed for the session{}: a line never carries it, so it cannot \
                 end up in the history{}",
                if ceremony {
                    " and never written in a ceremony"
                } else {
                    ""
                },
                if ceremony {
                    " or the file"
                } else {
                    "; a command that needs it asks"
                }
            );
        }

        let mut parsed = match self.parse(&tokens)? {
            Parsed::Verb(parsed) => *parsed,
            // Help and the version are what the line asked for; a usage error is not
            Parsed::Shown(err) => {
                let _ = err.print();
                if err.use_stderr() {
                    bail!("The line was not run");
                }
                return Ok(Flow::Continue);
            }
        };
        if self.interactive && !ceremony && self.ask_identity(&parsed)? {
            let Parsed::Verb(again) = self.parse(&tokens)? else {
                bail!("The line no longer parses with the answers as defaults");
            };
            parsed = *again;
        }
        let (seeds, mut verb) = parsed;
        if self.interactive {
            ask_pins(&mut verb)?;
        }
        let views = self.views(&tokens)?;
        self.execute(verb, seeds, views)
    }

    /// Parse a line's words with the session's defaults, which take the place of the
    /// environment: the session read that once at its start
    ///
    /// What clap shows instead of a verb is handed back unprinted, so that a line parsed twice,
    /// once to judge whether it may enter the history, is shown once.
    fn parse(&self, tokens: &[String]) -> Result<Parsed> {
        let matches = match self
            .defaults
            .apply_to(super::session_command(), false)
            .try_get_matches_from(tokens)
        {
            Ok(matches) => matches,
            // clap repeats an unexpected argument in its error, so a line that most likely
            // carries a secret is answered without echoing it
            Err(_) if mnemonic::looks_like_phrase(tokens) => bail!(
                "That looks like a seed phrase; it was neither stored nor echoed. A command \
                 that needs it asks for it on a hidden prompt"
            ),
            Err(err) => return Ok(Parsed::Shown(err)),
        };
        for process in super::PROCESS_OPTIONS {
            if matches.value_source(process) == Some(ValueSource::CommandLine) {
                bail!("--{} is fixed when the program starts", process.replace('_', "-"));
            }
        }
        let cli = Cli::from_arg_matches(&matches)?;
        let verb = cli
            .verb
            .ok_or_else(|| anyhow!("A line starts with a verb; `help` lists them"))?;
        Ok(Parsed::Verb(Box::new((cli.seeds, verb))))
    }

    /// A line parsed once for each applet with that applet's defaults, PIV's first, where the
    /// defaults have a table for one; without, both halves take the line as parsed
    fn views(&self, tokens: &[String]) -> Result<Option<(Verb, Verb)>> {
        if !self.defaults.has_tables() {
            return Ok(None);
        }
        let parse = |app| -> Result<Verb> {
            let matches = self
                .defaults
                .for_app(app)
                .apply_to(super::session_command(), false)
                .try_get_matches_from(tokens)?;
            Cli::from_arg_matches(&matches)?
                .verb
                .ok_or_else(|| anyhow!("A line starts with a verb"))
        };
        Ok(Some((parse(super::App::Piv)?, parse(super::App::Pgp)?)))
    }

    /// Ask for the name and emails a command will demand, and keep the answers as defaults;
    /// true when there was something to ask
    ///
    /// The session's version of `set`: only the two inputs without a default get this,
    /// everything else has a deliberate one.
    fn ask_identity(&mut self, (seeds, verb): &(SeedArgs, Verb)) -> Result<bool> {
        let identity = match verb {
            Verb::Check { identity, .. }
            | Verb::Upload { identity, .. }
            | Verb::Rotate { identity, .. }
            | Verb::Publish { identity, .. }
            | Verb::Ungap { identity, .. }
            | Verb::Revoke { identity, .. } => identity,
            _ => return Ok(false),
        };
        let _ = seeds;
        let mut settings = Vec::new();
        if identity.name.is_none() {
            let name = prompt::read_public("Common name: ")?;
            if !name.is_empty() {
                settings.push(format!("name={name}"));
            }
        }
        if identity.emails.is_empty() && !matches!(verb, Verb::Revoke { .. }) {
            let emails = prompt::read_public("Emails (comma separated, empty for none): ")?;
            let emails: Vec<_> = emails
                .split(',')
                .map(str::trim)
                .filter(|email| !email.is_empty())
                .collect();
            if !emails.is_empty() {
                settings.push(format!("emails={}", emails.join(",")));
            }
        }
        let asked = !settings.is_empty();
        self.defaults.set(&settings)?;
        Ok(asked)
    }
}

/// Ask for the pins a command sets or changes, on the terminal with no echo
///
/// The new pin twice, since a typo would set a pin nobody knows; the current one once, which
/// the card checks itself. An `init` without a pin may keep the factory pin, which deserves a
/// deliberate answer rather than a default.
fn ask_pins(verb: &mut Verb) -> Result<()> {
    match verb {
        Verb::Init { pin, write, .. } if pin.pin.is_none() && !write.dry_run => {
            pin.pin = prompt::read_optional_secret("User pin (empty keeps the factory pin): ")?;
        }
        Verb::Pin { pin, current_pin, reset, write, .. } if !write.dry_run => {
            if !*reset && current_pin.is_none() {
                *current_pin = Some(prompt::read_secret("Current user pin: ")?);
            }
            if pin.is_none() {
                let new = prompt::read_secret("New user pin: ")?;
                if *prompt::read_secret("New user pin again: ")? != *new {
                    bail!("The two entries differ; the pin was not changed");
                }
                *pin = Some(new);
            }
        }
        _ => {}
    }
    Ok(())
}

/// The secret a `set` or `unset` line names as a default, `set seed=<phrase>` among them:
/// refused as a default, and a line that would hold the phrase itself
fn secret_setting(tokens: &[String]) -> Option<&str> {
    if !matches!(tokens.first().map(String::as_str), Some("set" | "unset")) {
        return None;
    }
    tokens[1..]
        .iter()
        .filter(|word| !word.starts_with('-'))
        .map(|word| word.split_once('=').map_or(word.as_str(), |(name, _)| name))
        .find(|name| super::config::is_secret(name))
}

/// The secret a line names, if it names one
///
/// The seeds and passwords are fixed for the session, and allowing them on a line would put a
/// secret into the line editor's history; a bare `--card-seed` or `--key-seed` asks for that
/// seed instead, which is allowed. `-s` and `-p` cover clap's attached short-value forms; no
/// other flag starts with either letter. A ceremony file is a file, so it may not hold a pin
/// either, and no line holds a secret as a default.
pub(super) fn names_a_secret(tokens: &[String], ceremony: bool) -> Option<&'static str> {
    if secret_setting(tokens).is_some() {
        return Some("A secret");
    }
    let named = |token: &str, flag: &str| token == flag || token.starts_with(&format!("{flag}="));
    let valued = |token: &str, flag: &str| {
        token
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(|value| !value.trim().is_empty())
    };
    // A bare seed flag takes no value, so a word after it is a phrase given with a space
    // instead of `=`, which clap would otherwise echo back as an unexpected argument
    let seed_flags = ["--card-seed", "--key-seed", "--from-key-seed"];
    if tokens
        .windows(2)
        .any(|pair| seed_flags.contains(&pair[0].as_str()) && !pair[1].starts_with('-'))
    {
        return Some("A seed");
    }
    for token in tokens {
        let short = |letter: char| {
            !token.starts_with("--") && token.starts_with('-') && token[1..].starts_with(letter)
        };
        if named(token, "--seed") || short('s') {
            return Some("The seed");
        }
        if named(token, "--password")
            || named(token, "--card-password")
            || named(token, "--key-password")
            || named(token, "--from-key-password")
            || short('p')
        {
            return Some("A password");
        }
        if valued(token, "--card-seed")
            || valued(token, "--key-seed")
            || valued(token, "--from-key-seed")
        {
            return Some("A seed");
        }
        if ceremony && (named(token, "--pin") || named(token, "--current-pin") || short('i')) {
            return Some("A pin");
        }
    }
    None
}

/// The live image's start: its ceremony, then the session, which keeps the seeds the
/// ceremony asked for
///
/// A failing ceremony is reported rather than fatal, so the session is there to look into it.
pub(super) fn image(mut session: Session) -> Result<()> {
    session.interactive = io::stdin().is_terminal();
    if let Err(err) = ceremony::run(&mut session, None, None, None, false, false) {
        log::error!("{err:#}");
    }
    repl(session)
}

/// The interactive session: the seeds are entered once and every command reuses them
///
/// Reading commands and reading secrets never overlap: the line editor holds no terminal
/// state between lines, and the secret prompts talk to `/dev/tty` through `rpassword`, so a
/// command may prompt mid-session without confusing either.
pub(super) fn repl(mut session: Session) -> Result<()> {
    // Piped input gets a plain reader: no banner, no prompt, no editor, so scripted
    // sessions and tests see nothing but their own output
    if !io::stdin().is_terminal() || session.plumbing {
        let mut failed = 0;
        for line in io::stdin().lock().lines() {
            match session.run_line(&line?, false) {
                Ok(Flow::Quit) => break,
                Ok(Flow::Continue) => {}
                // Plumbing stops at the first error, as a script would want
                Err(err) if session.plumbing => return Err(err),
                Err(err) => {
                    log::error!("{err:#}");
                    failed += 1;
                }
            }
        }
        // Every line was tried, and the status says whether all of them went through, so
        // that `mind-the-gap < steps && ...` can be trusted
        if failed > 0 {
            bail!("{failed} of the session's lines failed");
        }
        return Ok(());
    }

    session.interactive = true;

    println!("mind-the-gap interactive session");
    println!("The first command that needs a seed phrase asks for it on a hidden prompt;");
    println!("it is kept only in memory and gone on exit.");
    println!("Commands match the command line; `help` lists them, `quit` or Ctrl-D leaves.");

    let mut editor: rustyline::Editor<LineHelper, MemHistory> = rustyline::Editor::with_history(
        Config::builder().auto_add_history(false).build(),
        MemHistory::new(),
    )?;
    editor.set_helper(Some(LineHelper::new()));

    loop {
        match editor.readline("mtg> ") {
            Ok(line) => {
                // Only commands become recallable. A rejected secret-naming line must not be
                // one arrow press away, and neither may anything that does not parse: a seed
                // phrase typed at the prompt, or an unbalanced quote around half of one
                if let Some(tokens) = shlex::split(&line)
                    && !tokens.is_empty()
                    && names_a_secret(&tokens, false).is_none()
                    && session.parse(&tokens).is_ok_and(|parsed| match parsed {
                        Parsed::Verb(..) => true,
                        Parsed::Shown(err) => !err.use_stderr(),
                    })
                {
                    let _ = editor.add_history_entry(&line);
                }
                match session.run_line(&line, false) {
                    Ok(Flow::Quit) => return Ok(()),
                    Ok(Flow::Continue) => {}
                    Err(err) => log::error!("{err:#}"),
                }
            }
            // Ctrl-C abandons the current line, not the session
            Err(ReadlineError::Interrupted) => continue,
            // Ctrl-D leaves like `quit`
            Err(ReadlineError::Eof) => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
}

/// The verbs a ceremony may hand `--dry-run` to, being the ones that write
pub(super) fn takes_dry_run(verb: &str) -> bool {
    matches!(verb, "init" | "upload" | "rotate" | "pin" | "wipe" | "revoke")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        shlex::split(line).unwrap()
    }

    #[test]
    fn secrets_never_ride_on_a_line() {
        for line in [
            "check --seed 'abandon abandon'",
            "check -sabandon",
            "check --password=x",
            "upload --key-seed='abandon art'",
            "rotate --date 2027-01-01 --from-key-seed=abandon",
            "check -px",
        ] {
            assert!(names_a_secret(&words(line), false).is_some(), "{line}");
        }
        // Asking for a seed is fine, and so is a pin typed in a session
        for line in [
            "upload --key-seed",
            "upload --card-seed --key-seed=",
            "init --pin 123456",
        ] {
            assert!(names_a_secret(&words(line), false).is_none(), "{line}");
        }
        // A ceremony is a file, and holds no pin
        assert!(names_a_secret(&words("init --pin 123456"), true).is_some());
        assert!(names_a_secret(&words("init -i123456"), true).is_some());
    }

    /// A default that names a secret names it on the line: `set seed=<phrase>` carries the
    /// phrase, so the line is kept out of the history as any other that holds a secret
    #[test]
    fn a_secret_set_as_a_default_names_a_secret() {
        for line in [
            "set seed='abandon abandon art'",
            "set --save seed=abandon",
            "set name=Jane pgp.pin=123456",
            "set piv.password=x",
            "unset key-password",
            "set current-pin=1234",
        ] {
            assert!(names_a_secret(&words(line), false).is_some(), "{line}");
        }
        for line in [
            "set name=Jane",
            "set --save subkey=seed",
            "unset pinentry",
            "set",
        ] {
            assert!(names_a_secret(&words(line), false).is_none(), "{line}");
        }
        assert_eq!(secret_setting(&words("set name=x seed=y")), Some("seed"));
    }
}

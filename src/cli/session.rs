//! The interactive session: the line editor, the sticky defaults and the secrets it asks
//! for once.

use super::{
    Backend, Identity, confirm_destruction, dispatch,
    generate::generate,
    parse_date, parse_duration,
    pgp_commands::{PGPCommand, PGPOptions},
    piv_commands::{PIVCommand, PIVOptions},
    spelled,
};
use crate::mnemonic::{self, MnemonicSeed};
use crate::pgp;
use crate::piv;
use crate::policy::Policy;
use crate::prompt;
use crate::seed::Algorithm;

use std::time::Duration;

use std::io;
use std::io::{BufRead, IsTerminal};

use anyhow::{Result, bail};

use chrono::{DateTime, Utc};

use clap::{ArgGroup, Parser, Subcommand};

use rustyline::config::Config;
use rustyline::error::ReadlineError;
use rustyline::history::MemHistory;

use zeroize::Zeroizing;

/// The state of one invocation or interactive session: secrets are resolved at most
/// once, the identity fields entered once and overridable per command
///
/// Deliberately not `Debug`, like [`CLI`](super::CLI) and for the same reason.
pub(super) struct Session {
    /// The seed with the derivation password folded in, once resolved
    pub(super) seed: Option<MnemonicSeed>,
    /// The resolved derivation password, kept to fold into a later adopted seed
    pub(super) password: Option<Zeroizing<String>>,
    /// Seed text from the command line or environment, consumed on first resolution
    pub(super) pending_seed: Option<Zeroizing<String>>,
    /// The password argument as parsed, consumed on first resolution
    pub(super) pending_password: Option<Zeroizing<String>>,
    /// Whether the session already asked for the password; an empty answer resolves to
    /// no password but must still count as answered, or a later `generate` would ask
    /// the same question twice
    pub(super) password_asked: bool,
    /// Whether the password came from the command line or environment rather than a prompt
    pub(super) password_supplied: bool,
    /// Whether this session may prompt at all: true only when stdin is a terminal.
    /// The piped path keeps the one-shot contract: errors and warnings, never a
    /// prompt a script would hang on.
    pub(super) interactive: bool,
    pub(super) subkey: Option<String>,
    pub(super) name: Option<String>,
    pub(super) emails: Vec<String>,
    /// Backend defaults stored with `set`, applied where a line omits them
    pub(super) defaults: Stickies,
}

/// Session-stored defaults for the backend options a fleet workflow repeats: a line's
/// own value always wins, these fill the gaps
#[derive(Default)]
pub(super) struct Stickies {
    pub(super) date: Option<DateTime<Utc>>,
    pub(super) validity: Option<Duration>,
    pub(super) shared_pgp: Vec<pgp::SharedKey>,
    pub(super) shared_piv: Vec<piv::SharedSlot>,
    pub(super) legacy: bool,
    pub(super) intermediate: bool,
    pub(super) no_msroots: bool,
    pub(super) org: Option<String>,
    pub(super) unit: Option<String>,
    pub(super) country: Option<String>,
    pub(super) policy: Option<Policy>,
    pub(super) algorithm: Option<Algorithm>,
    pub(super) management_key: Option<piv::ManagementKeyArg>,
}

/// What `unset` can forget: the subkey id and every default `set` stores, spelled like
/// `set`'s own flags
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(super) enum Setting {
    Subkey,
    Date,
    Validity,
    SharedPgp,
    SharedPiv,
    Legacy,
    Intermediate,
    NoMsroots,
    Org,
    Unit,
    Country,
    Policy,
    Algorithm,
    ManagementAlgorithm,
}

/// Per-command overrides of the session's non-secret identity fields
#[derive(Default)]
pub(super) struct Overrides {
    pub(super) subkey: Option<String>,
    pub(super) name: Option<String>,
    pub(super) emails: Vec<String>,
}

impl Session {
    /// Resolve the derivation password at most once, from the argument alone: a
    /// one-shot invocation never prompts for it, so its presence is always visible in
    /// the invocation that supplied it (the interactive session asks alongside the
    /// seed instead, through [`Self::ask_password_once`])
    fn resolve_password(&mut self) -> Option<Zeroizing<String>> {
        if self.password.is_none() {
            self.password = self.pending_password.take();

            if self.password.is_some() {
                log::info!("Using the supplied root seed password");
            }
        }

        self.password.clone()
    }

    /// Ask for the optional password on the terminal, once, with an empty answer
    /// meaning none
    ///
    /// Only the interactive entry points call this, right where the seed itself is
    /// obtained: the password belongs to the seed, so the session asks for both in one
    /// ceremony instead of growing a separate command that is easy to forget. A
    /// password supplied as an argument wins and suppresses the question.
    fn ask_password_once(&mut self) -> Result<()> {
        if !self.password_asked && self.password.is_none() && self.pending_password.is_none() {
            self.password = prompt::read_optional_secret("Password (empty for none): ")?;
            self.password_asked = true;
        }
        Ok(())
    }

    /// Resolve the seed at most once: supplied text, or a terminal prompt in the
    /// interactive session (a one-shot invocation without a seed is rejected before
    /// this is reached, so the prompt can only fire mid-session)
    ///
    /// A seed is never invented behind the user's back: minting a fresh one is what
    /// `generate` is for, and it does not let go until the phrase is written down. The
    /// supplied phrase is never echoed back, since it would linger in scrollback next
    /// to everything derived from it.
    fn resolve_seed(&mut self) -> Result<MnemonicSeed> {
        if let Some(seed) = &self.seed {
            return Ok(seed.clone());
        }

        let mut seed: MnemonicSeed = match self.pending_seed.take() {
            Some(text) => text.trim().parse()?,
            None if self.interactive => {
                // A typo is reported before anything else is asked, and costs only the
                // phrase: the password belongs to the seed, so it follows in the same
                // breath, once the phrase is known to be valid
                let seed = loop {
                    let text = prompt::read_secret("Seed phrase: ")?;
                    match text.trim().parse() {
                        Ok(seed) => break seed,
                        Err(err) => log::error!("{err}; try again, or Ctrl-C to abort"),
                    }
                };
                self.ask_password_once()?;
                seed
            }
            None => bail!(
                "No seed phrase given. A piped session never prompts; pass --seed \
                 (or MIND_THE_SEED) when starting it."
            ),
        };

        if let Some(password) = self.resolve_password() {
            seed = seed.with_password(&password);
        }

        self.seed = Some(seed.clone());
        Ok(seed)
    }

    /// Adopt a freshly minted seed for the rest of the session, folding in the password
    ///
    /// Only the session calls this, right after the `generate` ceremony, so the
    /// password question belongs here as much as at the seed prompt.
    fn adopt(&mut self, seed: MnemonicSeed) -> Result<()> {
        self.pending_seed = None;
        self.ask_password_once()?;
        self.seed = Some(match self.resolve_password() {
            Some(password) => seed.with_password(&password),
            None => seed,
        });
        Ok(())
    }

    /// Assemble the identity for one command, resolving the seed if the command needs one
    pub(super) fn identity(&mut self, needs_seed: bool, overrides: Overrides) -> Result<Identity> {
        let seed = if needs_seed {
            Some(self.resolve_seed()?)
        } else {
            None
        };
        let subkey = overrides.subkey.or_else(|| self.subkey.clone());

        // The subkey id is public by design -- it ends up in every certificate -- so
        // echoing it is harmless and confirms which card is being derived.
        if needs_seed && let Some(subkey) = subkey.as_ref() {
            log::info!("Subkey derivation identifier: {}", subkey.as_str());
        }

        Ok(Identity {
            seed,
            subkey,
            name: overrides.name.or_else(|| self.name.clone()),
            emails: if overrides.emails.is_empty() {
                self.emails.clone()
            } else {
                overrides.emails
            },
        })
    }
}

// One line of the interactive session, parsed like a tiny argv.
//
// Deliberately not `Debug`, like [`CLI`] and for the same reason. There are no seed or
// password arguments here: the secrets are session state, and any line naming them is
// rejected before parsing so a secret can never reach the in-memory history. The identity
// overrides carry no `env` bindings either: the session captured the `MIND_THE_...`
// variables once at startup, and a per-line re-read would silently resurrect values that
// `set` changed away. The options *inside* the backends keep their env fallbacks; the
// process environment cannot change mid-session, so they resolve to the same values as a
// one-shot invocation.
#[derive(Parser)]
#[command(
    name = "mtg",
    bin_name = "mtg",
    disable_version_flag = true,
    about = "Commands of the interactive session: the command line's, minus the secrets"
)]
pub(super) struct ReplLine {
    /// Override the session subkey id for this command only
    #[arg(short = 'k', long, global = true)]
    subkey: Option<String>,

    /// Override the session common name for this command only
    #[arg(short, long, global = true)]
    name: Option<String>,

    /// Override the session email addresses for this command only
    #[arg(short = 'm', long, value_delimiter = ',', global = true)]
    emails: Vec<String>,

    #[command(subcommand)]
    command: ReplCommand,
}

/// The verbs available at the session prompt
#[derive(Subcommand)]
pub(super) enum ReplCommand {
    /// The regular backends, exactly as on the one-shot command line
    #[command(flatten)]
    Backend(Backend),

    /// Show the session identity: name, emails, subkey id, never the seed
    Session,

    /// Change the session identity or stored backend defaults for the rest of the
    /// session; a command line's own options always win over a stored default
    #[command(group = ArgGroup::new("fields").required(true).multiple(true)
        .args(["subkey", "name", "emails", "date", "validity", "shared_pgp",
               "shared_piv", "legacy", "intermediate", "no_msroots", "org", "unit",
               "country", "policy", "algorithm", "management_key"]))]
    Set {
        /// New session subkey id
        #[arg(short = 'k', long)]
        subkey: Option<String>,

        /// New session common name
        #[arg(short, long)]
        name: Option<String>,

        /// New session email addresses
        #[arg(short = 'm', long, value_delimiter = ',')]
        emails: Vec<String>,

        /// Default creation date for both backends
        #[arg(short, long, value_name = "YYYY-MM-DD", value_parser = parse_date)]
        date: Option<DateTime<Utc>>,

        /// Default validity duration for both backends
        #[arg(short, long, value_name = "DURATION", value_parser = parse_duration)]
        validity: Option<Duration>,

        /// Default PGP keys to derive without the subkey id
        #[arg(long, value_name = "KEYS", value_delimiter = ',')]
        shared_pgp: Vec<pgp::SharedKey>,

        /// Default PIV slots to derive without the subkey id
        #[arg(long, value_name = "SLOTS", value_delimiter = ',')]
        shared_piv: Vec<piv::SharedSlot>,

        /// Default to the original derivation labels (`unset legacy` clears it)
        #[arg(long)]
        legacy: bool,

        /// Default to an intermediate issuing CA (`unset intermediate` clears it)
        #[arg(long)]
        intermediate: bool,

        /// Default to skipping the msroots object (`unset no-msroots` clears it)
        #[arg(long)]
        no_msroots: bool,

        /// Default organization (O) for PIV subjects
        #[arg(long, value_name = "ORG")]
        org: Option<String>,

        /// Default organizational unit (OU) for PIV subjects
        #[arg(long, value_name = "UNIT")]
        unit: Option<String>,

        /// Default country (C) for PIV subjects
        #[arg(long, value_name = "CC")]
        country: Option<String>,

        /// Default pin and touch policy for both backends' uploads
        #[arg(long, value_enum)]
        policy: Option<Policy>,

        /// Default algorithm for both backends
        #[arg(long, value_enum)]
        algorithm: Option<Algorithm>,

        /// Default management key algorithm for PIV uploads
        #[arg(long = "management-algorithm", value_enum)]
        management_key: Option<piv::ManagementKeyArg>,
    },

    /// Forget session settings that `set` stored, back to the command line's defaults
    Unset {
        /// The settings to forget
        #[arg(value_enum, required = true)]
        settings: Vec<Setting>,
    },

    /// Reopen the one-time password question; the derived identifiers change with it
    Password,

    /// Show the tool name and version
    Version,

    /// Leave the session
    Quit,
}

/// Whether the session loop keeps going after a line
pub(super) enum Flow {
    Continue,
    Quit,
}

/// Tokens that would name a secret on a session line
///
/// The seed and password are fixed for the whole session, and allowing them here would
/// put a secret into the line editor's history. `-s.../-p...` cover clap's attached
/// short-value forms; no other flag in the tree starts with either letter.
fn names_a_secret(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        token == "--seed"
            || token.starts_with("--seed=")
            || token == "--password"
            || token.starts_with("--password=")
            || (token.starts_with("-s") && !token.starts_with("--"))
            || (token.starts_with("-p") && !token.starts_with("--"))
    })
}

/// The interactive session: the identity is entered once and every command reuses it
///
/// Reading commands and reading secrets never overlap: the line editor holds no
/// terminal state between lines, and the seed and password prompts talk to `/dev/tty`
/// through `rpassword`, so a command may prompt mid-session without confusing either.
pub(super) fn repl(mut session: Session) -> Result<()> {
    // Piped input gets a plain reader: no banner, no prompt, no editor, so scripted
    // sessions and tests see nothing but their own output
    if !io::stdin().is_terminal() {
        for line in io::stdin().lock().lines() {
            if let Flow::Quit = handle_line(&mut session, &line?)? {
                break;
            }
        }
        return Ok(());
    }

    session.interactive = true;

    println!("mind-the-gap interactive session");
    println!("The first command that needs the seed phrase asks for it on a hidden prompt;");
    println!("it is kept only in memory and gone on exit.");
    println!("Commands match the command line; `help` lists them, `quit` or Ctrl-D leaves.");

    let mut editor: rustyline::Editor<(), MemHistory> = rustyline::Editor::with_history(
        Config::builder().auto_add_history(false).build(),
        MemHistory::new(),
    )?;

    loop {
        match editor.readline("mtg> ") {
            Ok(line) => {
                // Only commands become recallable. A rejected secret-naming line must not
                // be one arrow press away, and neither may anything that does not parse:
                // a seed phrase typed at the prompt, a password after `password`, or an
                // unbalanced quote around half of either
                if let Some(tokens) = shlex::split(&line)
                    && !names_a_secret(&tokens)
                    && ReplLine::try_parse_from(std::iter::once("mtg".into()).chain(tokens)).is_ok()
                {
                    let _ = editor.add_history_entry(&line);
                }
                if let Flow::Quit = handle_line(&mut session, &line)? {
                    return Ok(());
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

/// Ask for a missing upload pin on the terminal, the session's way of taking secrets
///
/// Only `upload` gets this: there a missing pin means the card keeps the well-known
/// factory pin, which deserves a deliberate answer rather than a default. An empty
/// answer keeps the factory pin, and the upload handler warns about it the same way a
/// one-shot invocation does. Every other command treats a missing pin as "skip what
/// needs one", which stays as typed.
fn ask_upload_pin(backend: &mut Backend) -> Result<()> {
    let pin = match backend {
        Backend::PGP { command: PGPCommand::Upload { pin, .. }, .. } => pin,
        Backend::PIV { command: PIVCommand::Upload { pin, .. }, .. } => pin,
        _ => return Ok(()),
    };
    if pin.is_none() {
        *pin = prompt::read_optional_secret("User pin (empty keeps the factory pin): ")?;
    }
    Ok(())
}

/// Reopen the one-time password question and re-fold the session's seed
///
/// `MnemonicSeed::with_password` keeps the mnemonic, so folding a new password over a
/// resolved seed is safe; everything derived afterwards changes with it, which is the
/// point and gets said out loud.
fn ask_password_again(session: &mut Session) -> Result<()> {
    if !session.interactive {
        bail!("A piped session never prompts; start the session with --password instead");
    }
    let password = prompt::read_optional_secret("Password (empty for none): ")?;
    session.password_asked = true;
    if let Some(seed) = session.seed.take() {
        session.seed = Some(seed.with_password(password.as_deref().map_or("", |p| p.as_str())));
        log::warn!("The password changed: every identifier and key derived from now on differs");
    }
    session.password = password;
    Ok(())
}

/// Fill a command's omitted backend options from the session's stored defaults
///
/// A line's own value always wins; the stored default only covers what was left out.
fn merge_defaults(backend: &mut Backend, d: &Stickies) {
    match backend {
        Backend::PGP {
            options: PGPOptions { date, validity, shared, legacy, algorithm, policy, .. },
            ..
        } => {
            *policy = policy.or(d.policy);
            *date = date.or(d.date);
            *validity = validity.or(d.validity);
            if shared.is_empty() {
                shared.clone_from(&d.shared_pgp);
            }
            *legacy |= d.legacy;
            // `set --algorithm p384` is meant for PIV, the one backend that has it
            *algorithm = algorithm.or(d.algorithm.filter(|sticky| *sticky != Algorithm::P384));
        }
        Backend::PIV {
            options:
                PIVOptions {
                    date,
                    validity,
                    intermediate,
                    shared,
                    org,
                    unit,
                    country,
                    policy,
                    no_msroots,
                    algorithm,
                    management_key,
                    ..
                },
            ..
        } => {
            *date = date.or(d.date);
            *validity = validity.or(d.validity);
            *intermediate |= d.intermediate;
            if shared.is_empty() {
                shared.clone_from(&d.shared_piv);
            }
            *no_msroots |= d.no_msroots;
            if org.is_none() {
                org.clone_from(&d.org);
            }
            if unit.is_none() {
                unit.clone_from(&d.unit);
            }
            if country.is_none() {
                country.clone_from(&d.country);
            }
            *policy = policy.or(d.policy);
            *algorithm = algorithm.or(d.algorithm);
            *management_key = management_key.or(d.management_key);
        }
        Backend::Generate => {}
    }
}

/// Ask for missing identity fields the command will demand, and keep the answers
///
/// The session's version of `set`: only the two required-without-default inputs get
/// this, everything else has a deliberate default. The clap parsers stay untouched;
/// this runs before dispatch, like the upload pin question.
fn ask_identity(session: &mut Session, backend: &Backend) -> Result<()> {
    if !backend.needs_seed() {
        return Ok(());
    }
    if session.name.is_none() {
        let name = prompt::read_public("Common name: ")?;
        if !name.is_empty() {
            session.name = Some(name);
        }
    }
    let wants_emails = matches!(backend, Backend::PGP { command, .. } if command.mints_uids());
    if wants_emails && session.emails.is_empty() {
        let emails = prompt::read_public("Emails (comma separated): ")?;
        if !emails.is_empty() {
            session.emails = emails.split(',').map(|e| e.trim().to_string()).collect();
        }
    }
    Ok(())
}

/// Parse and run one session line; errors are reported, never fatal to the session
pub(super) fn handle_line(session: &mut Session, line: &str) -> Result<Flow> {
    let Some(tokens) = shlex::split(line) else {
        log::error!("Unbalanced quotes in the command line");
        return Ok(Flow::Continue);
    };
    if tokens.is_empty() {
        return Ok(Flow::Continue);
    }

    if names_a_secret(&tokens) {
        log::error!("The seed and password are fixed for the session; restart to change them");
        return Ok(Flow::Continue);
    }

    // The parser wants a program name in front, mirroring the prompt
    let line =
        match ReplLine::try_parse_from(std::iter::once("mtg".into()).chain(tokens.iter().cloned()))
        {
            Ok(line) => line,
            // clap repeats an unexpected argument in its error, so the two lines that most
            // likely carry a secret are answered without echoing it
            Err(_) if mnemonic::looks_like_phrase(&tokens) => {
                log::error!(
                    "That looks like a seed phrase; it was neither stored nor echoed. A command \
                 that needs it asks for it on a hidden prompt"
                );
                return Ok(Flow::Continue);
            }
            Err(_) if tokens[0] == "password" => {
                log::error!("`password` takes no argument, it asks on a hidden prompt");
                return Ok(Flow::Continue);
            }
            Err(err) => {
                // clap errors carry their own formatting, including help and usage output
                let _ = err.print();
                return Ok(Flow::Continue);
            }
        };

    let overrides = Overrides { subkey: line.subkey, name: line.name, emails: line.emails };

    // The identity overrides only mean something in front of a backend command; on the
    // other verbs they would be accepted and silently ignored. `set` is exempt: its own
    // flags are the same names on purpose, and clap's global propagation hands their
    // values to both levels.
    if matches!(
        line.command,
        ReplCommand::Session
            | ReplCommand::Quit
            | ReplCommand::Unset { .. }
            | ReplCommand::Backend(Backend::Generate)
    ) && (overrides.subkey.is_some() || overrides.name.is_some() || !overrides.emails.is_empty())
    {
        log::error!(
            "Identity options do not apply to this command; use `set` to change the session"
        );
        return Ok(Flow::Continue);
    }

    let result = match line.command {
        ReplCommand::Quit => return Ok(Flow::Quit),
        ReplCommand::Session => {
            let show = |label: &str, value: Option<&str>| {
                println!("  {label}: {}", value.unwrap_or("(not set)"));
            };
            show("name", session.name.as_deref());
            show(
                "emails",
                (!session.emails.is_empty())
                    .then(|| session.emails.join(", "))
                    .as_deref(),
            );
            show("subkey", session.subkey.as_deref());
            show(
                "seed",
                Some(if session.seed.is_some() {
                    "loaded"
                } else {
                    "not loaded"
                }),
            );
            // State only, never the value: the password has no checksum, so whether
            // one is in effect is the only feedback a user can get
            show(
                "password",
                Some(if session.password.is_some() {
                    "set"
                } else if session.password_asked || session.seed.is_some() {
                    "none"
                } else {
                    "not asked yet"
                }),
            );
            let d = &session.defaults;
            let mut stored: Vec<String> = Vec::new();
            if let Some(date) = d.date {
                stored.push(format!("date={}", date.format("%Y-%m-%d")));
            }
            if let Some(validity) = d.validity {
                stored.push(format!("validity={}", humantime::format_duration(validity)));
            }
            if !d.shared_pgp.is_empty() {
                stored.push(format!("shared-pgp={:?}", d.shared_pgp));
            }
            if !d.shared_piv.is_empty() {
                stored.push(format!("shared-piv={:?}", d.shared_piv));
            }
            for (flag, on) in [
                ("legacy", d.legacy),
                ("intermediate", d.intermediate),
                ("no-msroots", d.no_msroots),
            ] {
                if on {
                    stored.push(flag.into());
                }
            }
            for (key, value) in [("org", &d.org), ("unit", &d.unit), ("country", &d.country)] {
                if let Some(value) = value {
                    stored.push(format!("{key}={value}"));
                }
            }
            if let Some(policy) = d.policy {
                stored.push(format!("policy={}", spelled(&policy)));
            }
            if let Some(algorithm) = d.algorithm {
                stored.push(format!("algorithm={algorithm:?}"));
            }
            if let Some(algorithm) = d.management_key {
                stored.push(format!("management-key={algorithm:?}"));
            }
            show("defaults", (!stored.is_empty()).then(|| stored.join(", ")).as_deref());
            Ok(())
        }
        ReplCommand::Set {
            subkey,
            name,
            emails,
            date,
            validity,
            shared_pgp,
            shared_piv,
            legacy,
            intermediate,
            no_msroots,
            org,
            unit,
            country,
            policy,
            algorithm,
            management_key,
        } => {
            if let Some(subkey) = subkey {
                session.subkey = Some(subkey);
            }
            if let Some(name) = name {
                session.name = Some(name);
            }
            if !emails.is_empty() {
                session.emails = emails;
            }
            let d = &mut session.defaults;
            d.date = date.or(d.date);
            d.validity = validity.or(d.validity);
            if !shared_pgp.is_empty() {
                d.shared_pgp = shared_pgp;
            }
            if !shared_piv.is_empty() {
                d.shared_piv = shared_piv;
            }
            d.legacy |= legacy;
            d.intermediate |= intermediate;
            d.no_msroots |= no_msroots;
            d.org = org.or(d.org.take());
            d.unit = unit.or(d.unit.take());
            d.country = country.or(d.country.take());
            d.policy = policy.or(d.policy);
            d.algorithm = algorithm.or(d.algorithm);
            d.management_key = management_key.or(d.management_key);
            Ok(())
        }
        ReplCommand::Unset { settings } => {
            let d = &mut session.defaults;
            for setting in settings {
                match setting {
                    Setting::Subkey => session.subkey = None,
                    Setting::Date => d.date = None,
                    Setting::Validity => d.validity = None,
                    Setting::SharedPgp => d.shared_pgp.clear(),
                    Setting::SharedPiv => d.shared_piv.clear(),
                    Setting::Legacy => d.legacy = false,
                    Setting::Intermediate => d.intermediate = false,
                    Setting::NoMsroots => d.no_msroots = false,
                    Setting::Org => d.org = None,
                    Setting::Unit => d.unit = None,
                    Setting::Country => d.country = None,
                    Setting::Policy => d.policy = None,
                    Setting::Algorithm => d.algorithm = None,
                    Setting::ManagementAlgorithm => d.management_key = None,
                }
            }
            Ok(())
        }
        ReplCommand::Password => ask_password_again(session),
        ReplCommand::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        // The session keeps a freshly minted seed, so provisioning can follow directly.
        // Replacing a seed the session already holds gets the same ceremony as a card
        // wipe: one typo must not silently re-point every later upload.
        ReplCommand::Backend(Backend::Generate) => (|| {
            if session.seed.is_some() || session.pending_seed.is_some() {
                if !session.interactive {
                    bail!("The session already holds a seed; a piped session cannot replace it");
                }
                confirm_destruction(
                    "The session already holds a seed; generate will replace it \
                     for every later command.",
                )?;
                // A password answered at the prompt belonged to the old phrase, so the new
                // one asks again; one from the invocation is the user's standing choice
                if session.password_supplied {
                    log::info!("The password from the command line applies to the new phrase");
                } else {
                    session.password = None;
                    session.password_asked = false;
                }
            }
            generate(true).and_then(|seed| session.adopt(seed))
        })(),
        ReplCommand::Backend(mut backend) => {
            let needs_seed = backend.needs_seed();
            merge_defaults(&mut backend, &session.defaults);
            // The seed and its password come first: a mistyped phrase is reported before
            // anything else is asked, and nothing typed later can land in the wrong prompt
            let prep = if session.interactive {
                let seed = if needs_seed {
                    session.resolve_seed().map(drop)
                } else {
                    Ok(())
                };
                seed.and_then(|()| ask_identity(session, &backend))
                    .and_then(|()| ask_upload_pin(&mut backend))
            } else {
                Ok(())
            };
            prep.and_then(|()| session.identity(needs_seed, overrides))
                .and_then(|identity| dispatch(backend, identity))
        }
    };

    if let Err(err) = result {
        log::error!("{err:#}");
    }
    Ok(Flow::Continue)
}

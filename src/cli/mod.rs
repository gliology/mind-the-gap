//! The clap command line: argument types, the subcommand tree, and the run loop.
//!
//! Secret-bearing arguments are `Zeroizing<String>`. A one-shot invocation takes them
//! from flags or `MIND_THE_...` variables and fails when the seed is missing; only the
//! interactive session prompts, once, so a script can never hang on a hidden prompt.
//! The handlers wire the seed layer to the [`pgp`](crate::pgp) and [`piv`](crate::piv) builders.

mod generate;
mod pgp_commands;
mod piv_commands;
mod session;

use generate::generate;
use pgp_commands::{PGPCommand, PGPOptions, run_pgp};
use piv_commands::{PIVCommand, PIVOptions, run_piv};
use session::{Overrides, ReplLine, Session, Stickies, repl};

use crate::common;
use crate::mnemonic::MnemonicSeed;
use crate::prompt;
use crate::seed::Algorithm;

use std::io::Write;
use std::{fs, io};

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use humantime::parse_duration;

use anyhow::{Result, anyhow, bail};

use clap::{Command, CommandFactory, Parser, Subcommand};

use zeroize::Zeroizing;

/// The parsed command line, global arguments plus the subcommand
// Deliberately not `Debug`: the struct carries the seed phrase, password and pins, and a
// stray `{:?}` must not be able to print them.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct CLI {
    /// Mnemonic seed phrase of root secret
    ///
    /// Required for any command that derives keys: a one-shot invocation fails without
    /// it rather than stopping on a prompt, and no command ever invents a seed on its
    /// own. Use `generate` to mint one, or run without any subcommand for an
    /// interactive session, which asks for the phrase once and keeps it off the
    /// command line entirely.
    #[arg(help_heading = "Identity", short, long, global = true, env = "MIND_THE_SEED")]
    seed: Option<Zeroizing<String>>,

    /// Optional password to use in root entropy derivation
    ///
    /// A password has no checksum, so a typo silently derives different keys. The
    /// interactive session asks for it right after the seed phrase, with an empty
    /// answer meaning none, and lets the derived identifiers be compared against a
    /// known card before anything is written.
    #[arg(help_heading = "Identity", short, long, global = true, env = "MIND_THE_PASSWORD")]
    password: Option<Zeroizing<String>>,

    /// Optional identifier to include in subkey derivation.
    ///
    /// Public by design, it ends up in every certificate, so it is deliberately not
    /// treated as a secret anywhere.
    #[arg(help_heading = "Identity", short = 'k', long, global = true, env = "MIND_THE_SUBKEY")]
    subkey: Option<String>,

    /// Common name to use on certs or smartcards
    #[arg(help_heading = "Identity", short, long, global = true, env = "MIND_THE_NAME")]
    name: Option<String>,

    /// Email addresses to use on certs or smartcards, comma separated
    #[arg(
        help_heading = "Identity",
        short = 'm',
        long,
        value_delimiter = ',',
        global = true,
        env = "MIND_THE_EMAILS"
    )]
    emails: Vec<String>,

    /// Logging filter, like MIND_THE_LOG_LEVEL (the flag wins)
    ///
    /// Same grammar as env_logger, e.g. `info` or `mind_the_gap=debug`. Applied when the
    /// process starts, so a session keeps the level it started with. Card traffic, which
    /// carries pins and key bytes, is never logged above info.
    #[arg(long, global = true, value_name = "FILTER", env = "MIND_THE_LOG_LEVEL")]
    log_level: Option<String>,

    /// The backend and subcommand to run; omitted, an interactive session starts
    #[command(subcommand)]
    backend: Option<Backend>,
}

#[derive(Subcommand)]
// PGP and PIV are the established names of these backends and of the subcommands they map to;
// spelling them `Pgp`/`Piv` would read worse in a domain where both are always capitalised.
#[allow(clippy::upper_case_acronyms)]
enum Backend {
    /// Generate a new seed phrase and confirm it was written down
    ///
    /// The only place this tool mints key material: no command ever invents a seed on its
    /// own. The phrase stays on screen until its transcription is verified word by word,
    /// then the screen is wiped so it survives only on paper.
    Generate,

    /// Generate and export PGP keys and certs
    PGP {
        #[command(flatten)]
        options: PGPOptions,

        #[command(subcommand)]
        command: PGPCommand,
    },
    /// Generate and export PIV keys and certs
    PIV {
        #[command(flatten)]
        options: PIVOptions,

        #[command(subcommand)]
        command: PIVCommand,
    },
}

impl Backend {
    /// Determine if selected backend and command needs secret seed data
    // Kept as a match so both backends line up symmetrically; the `!matches!(..)` form clippy
    // suggests hides the shared shape behind a negation.
    #[allow(clippy::match_like_matches_macro)]
    fn needs_seed(&self) -> bool {
        match self {
            Backend::Generate => false,
            Backend::PGP { command: PGPCommand::Status, .. } => false,
            Backend::PIV { command: PIVCommand::Status, .. } => false,
            _ => true,
        }
    }
}

/// Write key material or another secret-bearing file, readable by its owner alone.
///
/// `fs::write` would create the file world-readable under the usual umask and follow a
/// symlink already sitting at the path. Creating with `O_EXCL` and mode 0600 does neither;
/// an existing regular file is removed first so exports stay overwritable. The permissions
/// are set at creation, so there is no window in which another user can open the file.
fn write_sensitive(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;

    Ok(())
}

/// Ask before `upload` wipes `card`, the card's own description taken from its preflight
fn confirm(application: &str, card: &str) -> Result<()> {
    confirm_destruction(&format!(
        "Uploading resets the {application} application of\n  {card}\n\
         Every key and certificate it holds is erased."
    ))
}

/// Ask a destructive yes/no question, without side effects on the data channels
///
/// The warning and the question go to stderr: stdout may be carrying certificates.
/// Answers come from stdin only when stdin is a terminal; when it is piped (a session
/// script, a redirect) the answer is read from the controlling terminal instead, so a
/// script's next line can never be consumed as a yes. With no terminal either, there
/// is nobody to ask and --yes is the way to say it in advance.
fn confirm_destruction(warning: &str) -> Result<()> {
    eprintln!("{warning}");
    match prompt::confirm("Continue?") {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Aborted, nothing was changed"),
        Err(_) => bail!("Refusing to continue without confirmation, use --yes"),
    }
}

/// Return clap command for testing and documentation
pub fn command() -> Command {
    CLI::command()
}

/// Return the interactive session's clap command, for testing
pub fn repl_command() -> Command {
    ReplLine::command()
}

/// Parse the command line and run: a single subcommand, or the interactive session
pub fn run() -> Result<()> {
    let CLI { seed, password, subkey, name, emails, log_level: _, backend } = CLI::parse();

    let mut session = Session {
        seed: None,
        password: None,
        pending_seed: seed,
        password_supplied: password.is_some(),
        pending_password: password,
        password_asked: false,
        interactive: false,
        subkey,
        name,
        emails,
        defaults: Stickies::default(),
    };

    match backend {
        None => repl(session),
        Some(backend) => {
            // A one-shot invocation is scriptable or it is nothing: a missing seed is
            // an error, not a prompt a script would hang on. Only the interactive
            // session asks, and it asks once.
            if backend.needs_seed() && session.pending_seed.is_none() {
                bail!(
                    "No seed phrase given. Pass --seed (or MIND_THE_SEED), mint one \
                     with `generate`, or run without a subcommand for an interactive \
                     session that asks for it once."
                );
            }

            let identity = session.identity(backend.needs_seed(), Overrides::default())?;
            dispatch(backend, identity)
        }
    }
}

/// Run one parsed backend invocation against a resolved identity
fn dispatch(backend: Backend, identity: Identity) -> Result<()> {
    match backend {
        // The seed generation ceremony needs no other input; the one-shot path drops the
        // minted seed, which lives on paper now, while the session path adopts it
        Backend::Generate => generate(false).map(|_| ()),
        Backend::PGP { options, command } => run_pgp(identity, options, command),
        Backend::PIV { options, command } => run_piv(identity, options, command),
    }
}

/// The resolved identity arguments shared by both backends
struct Identity {
    seed: Option<MnemonicSeed>,
    subkey: Option<String>,
    name: Option<String>,
    emails: Vec<String>,
}

/// Warn when `algorithm` asks for more strength than the phrase can give it
///
/// A key is never stronger than the secret it comes from: RSA-4096 from a 12 word phrase
/// costs the larger key's price for the phrase's 128 bits. Only a warning, since the keys
/// are still sound and a password may well make up the difference.
fn warn_if_phrase_is_weaker(seed: &MnemonicSeed, algorithm: Algorithm) {
    let (entropy, strength) = (seed.entropy_bits(), algorithm.strength_bits());
    if entropy < strength {
        log::warn!(
            "{} keys aim at about {strength} bits of strength, but the phrase carries {entropy} \
             bits of entropy (a password adds what it adds, which cannot be measured here)",
            algorithm.name()
        );
    }
}

/// The command-line spelling of a value, for messages that echo an option back
fn spelled<T: clap::ValueEnum>(value: &T) -> String {
    value
        .to_possible_value()
        .map_or_else(String::new, |value| value.get_name().to_string())
}

/// The command-line spelling of a list of values, as the flag takes it
fn spelled_all<T: clap::ValueEnum>(values: &[T]) -> String {
    values.iter().map(spelled).collect::<Vec<_>>().join(",")
}

/// Parse a `--date`: midnight UTC of the given day
///
/// The date is read as midnight UTC, never local time: derivation inputs must not depend
/// on the timezone of the machine they are typed on.
fn parse_date(input: &str) -> Result<DateTime<Utc>> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|e| anyhow!(e))
        .map(|date| Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).expect("Static valid values")))
}

/// Warn when a provisioned card keeps the well-known factory user pin
///
/// A warning rather than a refusal: scripts stay in charge of their own flags, and the
/// interactive session asks for the pin before this is reached.
fn warn_factory_pin(missing: bool) {
    if missing {
        log::warn!(
            "No pin supplied: the card keeps the factory user pin ({}), usable by anyone who finds it; pass --pin to set one",
            common::FACTORY_USER_PIN
        );
    }
}

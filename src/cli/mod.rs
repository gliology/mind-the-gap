//! The clap command line: argument types, the subcommand tree, and the run loop.
//!
//! Secret-bearing arguments are `Zeroizing<String>`. A one-shot invocation takes them
//! from flags or `MIND_THE_...` variables and fails when the seed is missing; only the
//! interactive session prompts, once, so a script can never hang on a hidden prompt.
//! The handlers wire the seed layer to the [`pgp`] and [`piv`] builders.

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
use crate::pgp;
use crate::piv;
use crate::seed::Algorithm;

use std::time::Duration;

use std::io::{IsTerminal, Write};
use std::{fs, io};

use anyhow::{Result, anyhow, bail};

use chrono::{DateTime, Utc};

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
    #[arg(short, long, global = true, env = "MIND_THE_SEED")]
    seed: Option<Zeroizing<String>>,

    /// Optional password to use in root entropy derivation
    ///
    /// A password has no checksum, so a typo silently derives different keys. The
    /// interactive session asks for it right after the seed phrase, with an empty
    /// answer meaning none, and lets the derived identifiers be compared against a
    /// known card before anything is written.
    #[arg(short, long, global = true, env = "MIND_THE_PASSWORD")]
    password: Option<Zeroizing<String>>,

    /// Optional identifier to include in subkey derivation.
    ///
    /// Public by design, it ends up in every certificate, so it is deliberately not
    /// treated as a secret anywhere.
    #[arg(short = 'k', long, global = true, env = "MIND_THE_SUBKEY")]
    subkey: Option<String>,

    /// Common name to use on certs or smartcards
    #[arg(short, long, global = true, env = "MIND_THE_NAME")]
    name: Option<String>,

    /// Email addresses to use on certs or smartcards
    #[arg(short = 'm', long, value_delimiter = ',', global = true, env = "MIND_THE_EMAILS")]
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
        /// Creation date of the primary key
        #[arg(short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Creation date of the subkeys
        #[arg(long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_SUBDATE", value_parser = common::parse_date)]
        subdate: Option<DateTime<Utc>>,

        /// Validity duration of the subkeys
        #[arg(short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        /// Subkeys to derive without the subkey id, so every card gets the same one
        #[arg(
            long,
            value_name = "KEYS",
            value_delimiter = ',',
            global = true,
            env = "MIND_THE_PGP_SHARED"
        )]
        shared: Vec<pgp::SharedKey>,

        /// Use the original derivation labels, for cards provisioned before the scheme changed
        #[arg(long, global = true, env = "MIND_THE_LEGACY")]
        legacy: bool,

        /// Algorithm to derive every key with (Curve25519 by default; p384 is PIV-only)
        #[arg(long, value_enum, global = true, env = "MIND_THE_ALGORITHM")]
        algorithm: Option<Algorithm>,

        #[command(subcommand)]
        command: PGPCommand,
    },
    /// Generate and export PIV keys and certs
    PIV {
        /// Creation date of certificates (unix epoch by default)
        #[arg(short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Validity duration of the slot certificates (infinite by default)
        #[arg(short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        /// Insert an intermediate issuing CA between the root and the slot certificates
        #[arg(long, global = true, env = "MIND_THE_INTERMEDIATE")]
        intermediate: bool,

        /// Slots to derive without the subkey id, so every card gets the same key
        #[arg(
            long,
            value_name = "SLOTS",
            value_delimiter = ',',
            global = true,
            env = "MIND_THE_PIV_SHARED"
        )]
        shared: Vec<piv::SharedSlot>,

        /// Superseded subkey ids whose key management key to archive, newest first
        #[arg(long = "retire", value_name = "SUBKEY", global = true, env = "MIND_THE_RETIRE")]
        retired: Vec<String>,

        /// Organization (O) to include in all certificate subjects
        #[arg(long, value_name = "ORG", global = true, env = "MIND_THE_ORG")]
        org: Option<String>,

        /// Organizational unit (OU) to include in all certificate subjects
        #[arg(long, value_name = "UNIT", global = true, env = "MIND_THE_UNIT")]
        unit: Option<String>,

        /// Two-letter ISO country code (C) to include in all certificate subjects
        #[arg(long, value_name = "CC", global = true, env = "MIND_THE_COUNTRY")]
        country: Option<String>,

        /// Override the per-slot pin policy (ignored for the card authentication slot)
        #[arg(long, value_enum, global = true, env = "MIND_THE_PIN_POLICY")]
        pin_policy: Option<piv::PinPolicyArg>,

        /// Override the per-slot touch policy (ignored for the card authentication slot)
        #[arg(long, value_enum, global = true, env = "MIND_THE_TOUCH_POLICY")]
        touch_policy: Option<piv::TouchPolicyArg>,

        /// Do not store the certificate authorities in the card's msroots object
        #[arg(long, global = true, env = "MIND_THE_NO_MSROOTS")]
        no_msroots: bool,

        /// Algorithm to derive every key with, authorities included (P-256 by default)
        #[arg(long, value_enum, global = true, env = "MIND_THE_ALGORITHM")]
        algorithm: Option<Algorithm>,

        /// Algorithm of the management key upload installs (auto picks by firmware)
        #[arg(long, value_enum, global = true, env = "MIND_THE_PIV_MANAGEMENT_KEY")]
        management_key: Option<piv::ManagementKeyArg>,

        /// Whether management access demands a touch after upload (always by default)
        #[arg(long, value_enum, global = true, env = "MIND_THE_PIV_MANAGEMENT_KEY_TOUCH")]
        management_key_touch: Option<piv::ManagementTouchArg>,

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

    let stdin_is_tty = io::stdin().is_terminal();
    let mut tty_in = if stdin_is_tty {
        None
    } else {
        Some(std::io::BufReader::new(
            fs::File::open("/dev/tty")
                .map_err(|_| anyhow!("Refusing to continue without confirmation, use --yes"))?,
        ))
    };

    // "yes" proceeds, "no" aborts, and anything else asks again: a typo should cost one
    // more keystroke, not the whole invocation.
    loop {
        eprint!("Continue? [yes/no] ");

        let mut input = String::new();
        let read = match tty_in.as_mut() {
            Some(reader) => std::io::BufRead::read_line(reader, &mut input)?,
            None => io::stdin().read_line(&mut input)?,
        };
        if read == 0 {
            bail!("Refusing to continue without confirmation, use --yes")
        }
        match input.trim() {
            "yes" => return Ok(()),
            "no" => bail!("Aborted, the card was not touched"),
            _ => continue,
        }
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
        // ... then command
        Backend::PGP { date, subdate, validity, shared, legacy, algorithm, command } => run_pgp(
            identity,
            PGPOptions { date, subdate, validity, shared, legacy, algorithm },
            command,
        ),
        // ... then command
        Backend::PIV {
            date,
            validity,
            intermediate,
            shared,
            retired,
            org,
            unit,
            country,
            pin_policy,
            touch_policy,
            no_msroots,
            algorithm,
            management_key,
            management_key_touch,
            command,
        } => run_piv(
            identity,
            PIVOptions {
                date,
                validity,
                intermediate,
                shared,
                retired,
                org,
                unit,
                country,
                pin_policy,
                touch_policy,
                no_msroots,
                algorithm,
                management_key,
                management_key_touch,
            },
            command,
        ),
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

//! The clap command line: argument types, the subcommand tree, and the run loop.
//!
//! Secret-bearing arguments are `Zeroizing<String>`. A one-shot invocation takes them
//! from flags or `MIND_THE_...` variables and fails when the seed is missing; only the
//! interactive session prompts, once, so a script can never hang on a hidden prompt.
//! The handlers wire the seed layer to the [`pgp`] and [`piv`] builders.

// Import helper to add shared commands
use crate::common;
use crate::mnemonic::MnemonicSeed;
use crate::pgp::{self, CertificateKind, VerificationKind};
use crate::piv;
use crate::prompt;
use crate::qr;

use std::{path::PathBuf, time::Duration};

use std::io::{BufRead, IsTerminal, Write};
use std::{fs, io};

use anyhow::{Result, anyhow, bail};

use chrono::{DateTime, Utc};

use clap::{ArgGroup, Command, CommandFactory, Parser, Subcommand};

use der::Encode;
use sha2::{Digest, Sha256};

use sequoia_openpgp::armor;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;

use rustyline::config::Config;
use rustyline::error::ReadlineError;
use rustyline::history::MemHistory;

use zeroize::Zeroizing;

/// The parsed command line, global arguments plus the subcommand
///
/// Deliberately not `Debug`: the struct carries the seed phrase, password and pins, and a
/// stray `{:?}` must not be able to print them.
#[derive(Parser)]
#[command(author, version, about)]
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
    /// Same grammar as env_logger, e.g. `info` or `mind_the_gap=debug`. Applied when
    /// the process starts, so it cannot be changed from inside a session; the card
    /// stacks stay clamped to info either way, see main.rs.
    #[arg(long, global = true, value_name = "FILTER")]
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

#[derive(Subcommand, Clone, PartialEq)]
enum PGPCommand {
    /// Display current status
    Status,

    /// Check validity of smartcard
    Check {
        /// User pin to check
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card to check
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,
    },

    /// Adjust a provisioned card's settings, authenticated by the derived admin pin
    ///
    /// Upload writes sensible defaults; this changes them to your liking afterwards
    /// without reprovisioning anything. Only the options given are touched. (The PIV
    /// backend has no counterpart: its pin and touch policies are fixed when a key is
    /// imported -- set them with `piv upload`'s --pin-policy and --touch-policy.)
    #[command(group = ArgGroup::new("settings").required(true).multiple(true)
        .args(["touch", "lang", "url", "login", "sign_pin"]))]
    Config {
        /// Serial number of smart card to adjust
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,

        /// Touch policy per key, as `<key>=<policy>`
        ///
        /// Keys are signing, decryption and authentication; policies are off, on, fixed,
        /// cached and cached-fixed. The fixed variants lock the setting until the key is
        /// replaced. Example: --touch signing=on,decryption=cached
        #[arg(long, value_name = "KEY=POLICY", value_delimiter = ',', value_parser = parse_touch)]
        touch: Vec<(pgp::SubkeyRole, pgp::TouchPolicyArg)>,

        /// Cardholder language preferences (ISO 639-1), most preferred first
        #[arg(long, value_name = "LANG", value_delimiter = ',', value_parser = parse_lang)]
        lang: Vec<[u8; 2]>,

        /// URL where the public certificate can be fetched
        #[arg(long, value_name = "URL")]
        url: Option<String>,

        /// Login data, conventionally an account or user name
        #[arg(long, value_name = "LOGIN")]
        login: Option<String>,

        /// Whether one pin entry signs once (the card default) or for the whole session
        #[arg(long, value_enum, value_name = "MODE")]
        sign_pin: Option<pgp::SignPinValidity>,
    },

    /// Export key to smartcard
    Upload {
        /// Pin to protect exported keys on smartcards
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card target
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,

        /// Accept potentially dangerous operations
        #[arg(short, long)]
        yes: bool,

        /// Optional output path of public cert
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show output as QR code on terminal
        #[arg(short, long)]
        qr: bool,
    },

    /// Export primary-signed certificates for uids and subkeys
    Certify {
        /// Type of certificate to generate
        #[arg(short = 't', long, value_enum, default_value_t)]
        kind: CertificateKind,

        /// Public certificate output path (QR code shown when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export secret keys to file
    #[command(group(ArgGroup::new("dest").required(true).args(["output", "qr"])))]
    Export {
        /// Pin to protect exported keys in file
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Secret key output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show output as QR code on terminal
        #[arg(short, long)]
        qr: bool,
    },

    /// Generate revocation certificate
    Revoke {
        /// Revocation certificate output path (QR code shown when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// What the revocation covers
        #[arg(short = 't', long, value_enum, default_value_t)]
        kind: pgp::RevocationKind,

        /// Numeric revocation reason code (RFC 4880)
        ///
        /// Long-only on purpose: `-c` means the card everywhere else, and this is typed
        /// about once per revocation.
        #[arg(long, default_value_t = 0)]
        code: u8,

        /// Human-readable revocation reason
        #[arg(long, default_value = "Unspecified")]
        reason: String,
    },

    /// Export primary-signed certificates of external keys
    Trust {
        /// External certificate to sign
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Level of verification to certify
        #[arg(short = 't', long, value_enum, default_value_t)]
        kind: VerificationKind,

        /// Public certificate output path (QR code shown when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Clone, PartialEq)]
enum PIVCommand {
    /// Display current status
    Status,

    /// Export the derived certificate chain
    Certify {
        /// Which part of the chain to export
        #[arg(short = 't', long, value_enum, default_value_t)]
        kind: piv::CertificateKind,

        /// Public certificate output path (QR code shown when omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Check validity of smartcard
    Check {
        /// Pin to protect exported keys on smartcards
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card target
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,
    },

    /// Export key to smartcard
    Upload {
        /// Pin to protect exported keys on smartcards
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card target
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,

        /// Accept potentially dangerous operations
        #[arg(short, long)]
        yes: bool,

        /// Certificate chain output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show the root certificate as a QR code
        #[arg(short, long)]
        qr: bool,
    },
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

/// Parse one `<key>=<policy>` pair for `pgp configure --touch`
fn parse_touch(s: &str) -> Result<(pgp::SubkeyRole, pgp::TouchPolicyArg), String> {
    use clap::ValueEnum;

    let (key, policy) = s
        .split_once('=')
        .ok_or_else(|| format!("'{s}' is not <key>=<policy>, e.g. signing=on"))?;

    Ok((pgp::SubkeyRole::from_str(key, true)?, pgp::TouchPolicyArg::from_str(policy, true)?))
}

/// Parse one ISO 639-1 language code for `pgp configure --lang`
fn parse_lang(s: &str) -> Result<[u8; 2], String> {
    match s.as_bytes() {
        [a, b] if a.is_ascii_lowercase() && b.is_ascii_lowercase() => Ok([*a, *b]),
        _ => Err(format!("'{s}' is not a two-letter ISO 639-1 code, e.g. en")),
    }
}

fn confirm(backend: &str) -> Result<()> {
    confirm_destruction(&format!(
        "Uploading new keys will reset the {backend} smartcard.\n\
         This will clear any existing keys or data on the card!"
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

/// Ignore SIGINT and SIGQUIT for a guard's lifetime, restoring the old handlers after
///
/// Death by signal skips every `Drop`, so a Ctrl-C while a secret is on the alternate
/// screen would strand the terminal with the secret still showing. During a ceremony
/// the keys simply do nothing; leaving is what the prompts are for.
#[cfg(unix)]
struct IgnoreInterrupts(libc::sighandler_t, libc::sighandler_t);

#[cfg(unix)]
impl IgnoreInterrupts {
    fn install() -> Self {
        unsafe {
            Self(
                libc::signal(libc::SIGINT, libc::SIG_IGN),
                libc::signal(libc::SIGQUIT, libc::SIG_IGN),
            )
        }
    }
}

#[cfg(unix)]
impl Drop for IgnoreInterrupts {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.0);
            libc::signal(libc::SIGQUIT, self.1);
        }
    }
}

/// Mint a new seed phrase and hold it on screen until the user proves it is written down
///
/// Returns the minted seed so an interactive session can adopt it; the one-shot path
/// drops it, since a fresh phrase is only useful once it exists on paper anyway.
fn generate() -> Result<MnemonicSeed> {
    let seed = MnemonicSeed::generate()?;
    let words = seed.words();

    // The whole ceremony happens on the alternate screen of the controlling terminal,
    // never stdout: under `generate > file` a stdout phrase would land on disk, and on
    // the main screen it would survive in scrollback. The RAII guard restores a clean
    // display on every exit path, errors included, and Ctrl-C is ignored throughout
    // because a signal death would skip that restoration.
    #[cfg(unix)]
    let _guard = IgnoreInterrupts::install();
    let mut screen = qr::Screen::enter_cooked()?;

    loop {
        // Show the phrase, numbered for transcription
        writeln!(screen.tty)?;
        writeln!(screen.tty, "This is your new seed phrase. Write it down now, on paper:")?;
        writeln!(screen.tty)?;
        for (index, word) in words.iter().enumerate() {
            write!(screen.tty, "  {:>2}. {:<12}", index + 1, word)?;
            if (index + 1) % 4 == 0 {
                writeln!(screen.tty)?;
            }
        }
        writeln!(screen.tty)?;

        prompt::read_ack("Press enter once it is written down... ")?;

        // Wipe before the quiz, so answers come from paper and not from the screen
        screen.wipe()?;

        // Prove the copy is complete and readable before letting go of the phrase
        if quiz(&mut screen.tty, &words)? {
            break;
        }

        writeln!(
            screen.tty,
            "That did not match your phrase, compare your copy against the original:"
        )?;
    }

    // Leave the alternate screen before the parting words: they hold no secret and
    // should stay readable, while everything above vanishes with the screen
    drop(screen);

    let mut tty = prompt::tty()?;
    writeln!(tty, "Seed phrase confirmed.")?;
    writeln!(tty, "Pass it with --seed where a script needs it.")?;
    writeln!(tty)?;
    writeln!(tty, "To provision several cards in one sitting without retyping it, run")?;
    writeln!(tty, "mind-the-gap without arguments: the interactive session asks for the")?;
    writeln!(tty, "phrase once and keeps it in memory until you leave.")?;

    Ok(seed)
}

/// Ask for a few randomly chosen words of the phrase
fn quiz(tty: &mut impl Write, words: &[String]) -> Result<bool> {
    writeln!(tty, "Confirm your copy by answering from it below.")?;
    writeln!(tty)?;

    // Sampled from the OS generator like the phrase itself; rejection keeps them distinct
    let mut indices: Vec<usize> = Vec::new();
    while indices.len() < 3 {
        let index = getrandom::u32()
            .map_err(|err| anyhow!("Operating system entropy source failed: {err}"))?
            as usize
            % words.len();
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices.sort_unstable();

    for index in indices {
        // An accidental empty Enter re-asks instead of aborting the whole ceremony
        let answer = loop {
            match prompt::read_optional_secret(&format!("Word {}: ", index + 1))? {
                Some(answer) => break answer,
                None => continue,
            }
        };
        if answer.trim() != words[index] {
            return Ok(false);
        }
    }

    Ok(true)
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

/// The state of one invocation or interactive session: secrets are resolved at most
/// once, the identity fields entered once and overridable per command
///
/// Deliberately not `Debug`, like [`CLI`] and for the same reason.
struct Session {
    /// The seed with the derivation password folded in, once resolved
    seed: Option<MnemonicSeed>,
    /// The resolved derivation password, kept to fold into a later adopted seed
    password: Option<Zeroizing<String>>,
    /// Seed text from the command line or environment, consumed on first resolution
    pending_seed: Option<Zeroizing<String>>,
    /// The password argument as parsed, consumed on first resolution
    pending_password: Option<Zeroizing<String>>,
    /// Whether the session already asked for the password; an empty answer resolves to
    /// no password but must still count as answered, or a later `generate` would ask
    /// the same question twice
    password_asked: bool,
    /// Whether this session may prompt at all: true only when stdin is a terminal.
    /// The piped path keeps the one-shot contract: errors and warnings, never a
    /// prompt a script would hang on.
    interactive: bool,
    subkey: Option<String>,
    name: Option<String>,
    emails: Vec<String>,
    /// Backend defaults stored with `set`, applied where a line omits them
    defaults: Stickies,
}

/// Session-stored defaults for the backend options a fleet workflow repeats: a line's
/// own value always wins, these fill the gaps
#[derive(Default)]
struct Stickies {
    date: Option<DateTime<Utc>>,
    validity: Option<Duration>,
    shared_pgp: Vec<pgp::SharedKey>,
    shared_piv: Vec<piv::SharedSlot>,
    legacy: bool,
    intermediate: bool,
    no_msroots: bool,
    org: Option<String>,
    unit: Option<String>,
    country: Option<String>,
    pin_policy: Option<piv::PinPolicyArg>,
    touch_policy: Option<piv::TouchPolicyArg>,
}

/// Per-command overrides of the session's non-secret identity fields
#[derive(Default)]
struct Overrides {
    subkey: Option<String>,
    name: Option<String>,
    emails: Vec<String>,
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

        let text = match self.pending_seed.take() {
            Some(text) => text,
            None if self.interactive => {
                // The password belongs to the seed, so an interactively entered seed
                // comes with the password question in the same breath; a seed supplied
                // as an argument keeps its password on the argument side too
                let text = prompt::read_secret("Seed phrase: ")?;
                self.ask_password_once()?;
                text
            }
            None => bail!(
                "No seed phrase given. A piped session never prompts; pass --seed \
                 (or MIND_THE_SEED) when starting it."
            ),
        };
        let mut seed: MnemonicSeed = text.trim().parse()?;

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
    fn identity(&mut self, needs_seed: bool, overrides: Overrides) -> Result<Identity> {
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

/// Run one parsed backend invocation against a resolved identity
fn dispatch(backend: Backend, identity: Identity) -> Result<()> {
    match backend {
        // The seed generation ceremony needs no other input; the one-shot path drops the
        // minted seed, which lives on paper now, while the session path adopts it
        Backend::Generate => generate().map(|_| ()),
        // ... then command
        Backend::PGP { date, subdate, validity, shared, legacy, command } => {
            run_pgp(identity, PGPOptions { date, subdate, validity, shared, legacy }, command)
        }
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
            },
            command,
        ),
    }
}

/// One line of the interactive session, parsed like a tiny argv
///
/// Deliberately not `Debug`, like [`CLI`] and for the same reason. There are no seed or
/// password arguments here: the secrets are session state, and any line naming them is
/// rejected before parsing so a secret can never reach the in-memory history. The
/// identity overrides carry no `env` bindings either: the session captured the
/// `MIND_THE_...` variables once at startup, and a per-line re-read would silently
/// resurrect values that `set` changed away. The options *inside* the backends keep
/// their env fallbacks; the process environment cannot change mid-session, so they
/// resolve to the same values as a one-shot invocation.
#[derive(Parser)]
#[command(name = "mtg", bin_name = "mtg", disable_version_flag = true)]
struct ReplLine {
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
enum ReplCommand {
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
               "country", "pin_policy", "touch_policy"]))]
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
        #[arg(short, long, value_name = "YYYY-MM-DD", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Default validity duration for both backends
        #[arg(short, long, value_name = "DURATION", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        /// Default PGP keys to derive without the subkey id
        #[arg(long, value_name = "KEYS", value_delimiter = ',')]
        shared_pgp: Vec<pgp::SharedKey>,

        /// Default PIV slots to derive without the subkey id
        #[arg(long, value_name = "SLOTS", value_delimiter = ',')]
        shared_piv: Vec<piv::SharedSlot>,

        /// Default to the original derivation labels (cannot be unset; restart to clear)
        #[arg(long)]
        legacy: bool,

        /// Default to an intermediate issuing CA (cannot be unset; restart to clear)
        #[arg(long)]
        intermediate: bool,

        /// Default to skipping the msroots object (cannot be unset; restart to clear)
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

        /// Default per-slot pin policy for PIV uploads
        #[arg(long, value_enum)]
        pin_policy: Option<piv::PinPolicyArg>,

        /// Default per-slot touch policy for PIV uploads
        #[arg(long, value_enum)]
        touch_policy: Option<piv::TouchPolicyArg>,
    },

    /// Reopen the one-time password question; the derived identifiers change with it
    Password,

    /// Show the tool name and version
    Version,

    /// Leave the session
    #[command(alias = "quit")]
    Exit,
}

/// Whether the session loop keeps going after a line
enum Flow {
    Continue,
    Exit,
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
fn repl(mut session: Session) -> Result<()> {
    // Piped input gets a plain reader: no banner, no prompt, no editor, so scripted
    // sessions and tests see nothing but their own output
    if !io::stdin().is_terminal() {
        for line in io::stdin().lock().lines() {
            if let Flow::Exit = handle_line(&mut session, &line?)? {
                break;
            }
        }
        return Ok(());
    }

    session.interactive = true;

    println!("mind-the-gap interactive session");
    println!("The seed phrase is asked for once, kept only in memory, and gone on exit.");
    println!("Commands match the command line; `help` lists them, `exit` or Ctrl-D leaves.");

    let mut editor: rustyline::Editor<(), MemHistory> = rustyline::Editor::with_history(
        Config::builder().auto_add_history(false).build(),
        MemHistory::new(),
    )?;

    loop {
        match editor.readline("mtg> ") {
            Ok(line) => {
                // Only clean lines become recallable: a rejected secret-naming line
                // must not be one arrow press away, and a line the splitter cannot
                // parse (an unbalanced quote around, say, half a seed phrase) has to
                // count as secret-bearing rather than slip through unsplit
                if let Some(tokens) = shlex::split(&line)
                    && !names_a_secret(&tokens)
                {
                    let _ = editor.add_history_entry(&line);
                }
                if let Flow::Exit = handle_line(&mut session, &line)? {
                    return Ok(());
                }
            }
            // Ctrl-C abandons the current line, not the session
            Err(ReadlineError::Interrupted) => continue,
            // Ctrl-D leaves like `exit`
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
        Backend::PGP { date, validity, shared, legacy, .. } => {
            *date = date.or(d.date);
            *validity = validity.or(d.validity);
            if shared.is_empty() {
                shared.clone_from(&d.shared_pgp);
            }
            *legacy |= d.legacy;
        }
        Backend::PIV {
            date,
            validity,
            intermediate,
            shared,
            org,
            unit,
            country,
            pin_policy,
            touch_policy,
            no_msroots,
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
            *pin_policy = pin_policy.or(d.pin_policy);
            *touch_policy = touch_policy.or(d.touch_policy);
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
    let wants_emails = matches!(
        backend,
        Backend::PGP {
            command: PGPCommand::Certify { .. }
                | PGPCommand::Upload { .. }
                | PGPCommand::Export { .. },
            ..
        }
    );
    if wants_emails && session.emails.is_empty() {
        let emails = prompt::read_public("Emails (comma separated): ")?;
        if !emails.is_empty() {
            session.emails = emails.split(',').map(|e| e.trim().to_string()).collect();
        }
    }
    Ok(())
}

/// Parse and run one session line; errors are reported, never fatal to the session
fn handle_line(session: &mut Session, line: &str) -> Result<Flow> {
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
    let line = match ReplLine::try_parse_from(std::iter::once("mtg".into()).chain(tokens)) {
        Ok(line) => line,
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
        ReplCommand::Session | ReplCommand::Exit | ReplCommand::Backend(Backend::Generate)
    ) && (overrides.subkey.is_some() || overrides.name.is_some() || !overrides.emails.is_empty())
    {
        log::error!(
            "Identity options do not apply to this command; use `set` to change the session"
        );
        return Ok(Flow::Continue);
    }

    let result = match line.command {
        ReplCommand::Exit => return Ok(Flow::Exit),
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
            if let Some(policy) = d.pin_policy {
                stored.push(format!("pin-policy={policy:?}"));
            }
            if let Some(policy) = d.touch_policy {
                stored.push(format!("touch-policy={policy:?}"));
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
            pin_policy,
            touch_policy,
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
            d.pin_policy = pin_policy.or(d.pin_policy);
            d.touch_policy = touch_policy.or(d.touch_policy);
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
                session.password_asked = false;
            }
            generate().and_then(|seed| session.adopt(seed))
        })(),
        ReplCommand::Backend(mut backend) => {
            let needs_seed = backend.needs_seed();
            merge_defaults(&mut backend, &session.defaults);
            let prep = if session.interactive {
                ask_upload_pin(&mut backend).and_then(|()| ask_identity(session, &backend))
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

/// The resolved identity arguments shared by both backends
struct Identity {
    seed: Option<MnemonicSeed>,
    subkey: Option<String>,
    name: Option<String>,
    emails: Vec<String>,
}

/// The PGP backend's certificate options, as parsed
struct PGPOptions {
    date: Option<DateTime<Utc>>,
    subdate: Option<DateTime<Utc>>,
    validity: Option<Duration>,
    shared: Vec<pgp::SharedKey>,
    legacy: bool,
}

/// The PIV backend's certificate options, as parsed
struct PIVOptions {
    date: Option<DateTime<Utc>>,
    validity: Option<Duration>,
    intermediate: bool,
    shared: Vec<piv::SharedSlot>,
    retired: Vec<String>,
    org: Option<String>,
    unit: Option<String>,
    country: Option<String>,
    pin_policy: Option<piv::PinPolicyArg>,
    touch_policy: Option<piv::TouchPolicyArg>,
    no_msroots: bool,
}

/// Run one PGP subcommand, assembling the certificate builder on demand
fn run_pgp(identity: Identity, options: PGPOptions, command: PGPCommand) -> Result<()> {
    let Identity { seed, subkey, name, emails } = identity;
    let PGPOptions { date, subdate, validity, shared, legacy } = options;

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    // Only the commands that mint user ids need emails; check compares keys, revoke
    // retires them, config touches card data -- none of them builds a uid
    let needs_emails = matches!(
        command,
        PGPCommand::Certify { .. } | PGPCommand::Upload { .. } | PGPCommand::Export { .. }
    );

    let builder = move || -> Result<pgp::SeededSmartcard> {
        let name = name.ok_or_else(|| anyhow!("No name given, pass --name (or MIND_THE_NAME)"))?;

        if needs_emails && emails.is_empty() {
            bail!("No email given, pass --emails (or MIND_THE_EMAILS)");
        }

        // Prepare pgp cert
        log::info!("Initializing PGP certificate for '{}'", name);

        let scheme = if legacy {
            log::warn!("Using the legacy derivation scheme");
            pgp::Scheme::Legacy
        } else {
            pgp::Scheme::Current
        };

        let seed = seed
            .as_ref()
            .expect("resolved above when the command needs a seed");
        let mut builder = pgp::SeededSmartcard::with_scheme(&seed.seed(), subkey, name, scheme);

        // Add user identities
        for address in emails.into_iter() {
            log::info!("Adding userid for email: {}", address);
            builder = builder.add_email(&address)?;
        }

        // Set creation date
        if let Some(date) = date {
            log::info!("Setting certificate creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_creation_time(date.into());
        }

        if let Some(date) = subdate {
            log::info!("Setting subkey creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_subkey_creation_time(date.into());
        }

        if !shared.is_empty() {
            log::info!("Deriving without the subkey id: {:?}", shared);
            builder = builder.with_shared(shared.clone());
        }

        // Set validity period
        if let Some(validity) = validity {
            log::info!(
                "Setting subkey validity duration: {}",
                humantime::format_duration(validity)
            );
            builder = builder.with_subkey_validity(validity);
        }

        Ok(builder)
    };

    match command {
        PGPCommand::Status => pgp::status(),
        PGPCommand::Check { pin, card } => {
            let mut builder = builder()?;

            // Apply pin to smartcard
            if let Some(pin) = pin.as_ref() {
                log::info!("Verifying the supplied user pin");
                builder = builder.with_pin(pin.clone());
            }

            // Show info about target card
            if let Some(serial) = card.as_ref() {
                log::info!("Checking keys on smartcard: {}", serial);
            }

            builder.check(card)
        }
        PGPCommand::Config { card, touch, lang, url, login, sign_pin } => {
            // The parser's ArgGroup already demands at least one setting
            let settings = pgp::CardSettings { touch, lang, url, login, sign_pin };

            let builder = builder()?;

            if let Some(serial) = card.as_ref() {
                log::info!("Configuring smartcard: {}", serial);
            }

            builder.configure(card, settings)
        }
        PGPCommand::Upload { pin, card, yes, output, qr: show_qr } => {
            common::warn_factory_pin(pin.is_none());

            // The OpenPGP card spec requires at least 6 characters for the user pin
            if let Some(pin) = pin.as_ref()
                && pin.chars().count() < 6
            {
                bail!("OpenPGP user pin needs at least 6 characters")
            }

            let mut builder = builder()?;

            // No warning for a missing --date on purpose: creation times default to a
            // fixed epoch value, so an upload without dates is deterministic and is
            // exactly the configuration the hardware suite provisions with

            // Apply pin to smartcard and cert
            if let Some(pin) = pin.as_ref() {
                log::info!("Protecting card and keys with the supplied pin");
                builder = builder.with_pin(pin.clone());
            }

            // Show info about target card
            if let Some(serial) = card.as_ref() {
                log::info!("Exporting secret key to smartcard: {}", serial);
            }

            // Check user confirmation
            if !yes {
                confirm("PGP")?;
            }

            // Generate and save result
            let cert = builder.upload(card)?;
            log::info!("Uploaded PGP certificate '{}'", cert);

            let armored = cert.armored().to_vec()?;
            if let Some(path) = output {
                log::info!("Saving certificate to file: {}", path.display());
                fs::write(path, &armored)?;
            }
            if show_qr {
                qr::show_qr(&armored, false)?;
            }

            Ok(())
        }
        PGPCommand::Certify { kind, output } => {
            let builder = builder()?;

            // Generate public certificate and save result
            log::info!("Certifying uids and seeded keys: {:?}", kind);
            let cert = builder.certify(kind)?;

            log::info!("Generated PGP certificate '{}'", cert);
            let armored = cert.armored().to_vec()?;

            if let Some(path) = output {
                log::info!("Saving certificate to file: {}", path.display());
                fs::write(path, &armored)?;
            } else {
                qr::show_qr(&armored, false)?;
            }

            Ok(())
        }
        PGPCommand::Export { pin, output, qr: show_qr } => {
            let mut builder = builder()?;

            // Apply pin to private keys
            if let Some(pin) = pin.as_ref() {
                log::info!("Protecting exported keys with the supplied pin");
                builder = builder.with_pin(pin.clone());
            } else {
                log::warn!(
                    "Exporting secret keys UNENCRYPTED, pass --pin to protect them; the file itself is readable only by you"
                );
            }

            // Generate secret keys and save result
            let cert = builder.export()?;
            log::info!("Generated PGP secret keys for {}", cert);

            let tsk_bytes = Zeroizing::new(cert.as_tsk().armored().to_vec()?);
            if let Some(path) = output {
                log::info!("Saving secret keys to file: {}", path.display());
                write_sensitive(&path, &tsk_bytes)?;
            }
            if show_qr {
                qr::show_qr(&tsk_bytes, true)?;
                log::warn!(
                    "Secret keys were rendered on the terminal, clear the scrollback once transferred (e.g. `clear && printf '\\e[3J'`)"
                );
            }

            Ok(())
        }
        PGPCommand::Revoke { output, kind, code, reason } => {
            let builder = builder()?;

            // Generate rev cert and save result
            let raw = builder.revoke(kind, code, &reason)?;
            log::info!("Generated PGP revocation: {:?}", kind);

            // Armor the revocation packet (gnupg convention: Kind::PublicKey)
            let mut armored = Vec::new();
            {
                let mut w = armor::Writer::new(&mut armored, armor::Kind::PublicKey)?;
                w.write_all(&raw)?;
                w.finalize()?;
            }
            if let Some(path) = output {
                log::info!("Saving revocation certificate to file: {}", path.display());
                // A revocation certificate is a capability: anyone holding it can
                // retire the identity, so it gets the same treatment as key material
                write_sensitive(&path, &armored)?;
            } else {
                // A revocation certificate is a capability, so its QR gets the same
                // no-stdout discipline as key material
                qr::show_qr(&armored, true)?;
                log::warn!(
                    "The revocation certificate was rendered on the terminal, treat the scrollback accordingly"
                );
            }

            Ok(())
        }
        PGPCommand::Trust { input, kind, output } => {
            let builder = builder()?;

            // Generate public certificate and save result
            log::info!("Certifying certificate in file: {}", input.display());
            let other = Cert::from_file(input)?;

            log::info!("Certifying certificate with id: {}", other);
            let cert = builder.trust(other, kind)?;

            log::info!("Generated PGP certificate '{}'", cert);
            let armored = cert.armored().to_vec()?;

            if let Some(path) = output {
                log::info!("Saving certificate to file: {}", path.display());
                fs::write(path, &armored)?;
            } else {
                qr::show_qr(&armored, false)?;
            }

            Ok(())
        }
    }
}

/// Run one PIV subcommand, assembling the certificate builder on demand
fn run_piv(identity: Identity, options: PIVOptions, command: PIVCommand) -> Result<()> {
    let Identity { seed, subkey, name, emails } = identity;
    let emails_empty = emails.is_empty();
    let PIVOptions {
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
    } = options;

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    let builder = move || -> Result<piv::SeededSmartcard> {
        let name = name.ok_or_else(|| anyhow!("No name given, pass --name (or MIND_THE_NAME)"))?;

        // Configure and run backend
        log::info!("Generating PIV certificates for '{}'", name);
        let seed = seed
            .as_ref()
            .expect("resolved above when the command needs a seed");
        let mut builder = piv::SeededSmartcard::new(&seed.seed(), subkey, name);

        for address in emails.iter() {
            log::info!("Adding SAN for email: {}", address);
            builder = builder.add_email(address)?;
        }

        // Distinguished name attributes shared by every tier of the chain
        if let Some(org) = org {
            log::info!("Setting certificate organization: {}", org);
            builder = builder.with_org(org);
        }
        if let Some(unit) = unit {
            log::info!("Setting certificate organizational unit: {}", unit);
            builder = builder.with_org_unit(unit);
        }
        if let Some(country) = country {
            log::info!("Setting certificate country: {}", country);
            builder = builder.with_country(country);
        }
        if intermediate {
            log::info!("Inserting an intermediate issuing certificate authority");
            builder = builder.with_intermediate(true);
        }

        if !shared.is_empty() {
            log::info!("Deriving without the subkey id: {:?}", shared);
            builder = builder.with_shared(shared.clone());
        }

        if !retired.is_empty() {
            log::info!("Archiving key management keys of: {:?}", retired);
            builder = builder.with_retired(retired.clone());
        }

        // Policy overrides only affect the user slots, never card authentication
        if let Some(policy) = pin_policy {
            log::info!("Setting slot pin policy: {:?}", policy);
            builder = builder.with_pin_policy(policy.into());
        }
        if let Some(policy) = touch_policy {
            log::info!("Setting slot touch policy: {:?}", policy);
            builder = builder.with_touch_policy(policy.into());
        }

        if no_msroots {
            log::info!("Not storing certificate authorities in msroots");
            builder = builder.with_msroots(false);
        }

        // Applied here rather than per command so that certify, check and upload all
        // derive the very same chain
        // Without --date the creation time stays at the unix epoch, silently: the
        // deterministic default is the documented design, same as the PGP backend
        if let Some(date) = date {
            log::info!("Setting certificate creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_creation_time(date.into());
        }

        if let Some(validity) = validity {
            log::info!(
                "Setting certificate validity duration: {}",
                humantime::format_duration(validity)
            );
            builder = builder.with_validity_duration(validity);
        }

        Ok(builder)
    };

    match command {
        PIVCommand::Status => piv::status(),
        PIVCommand::Certify { kind, output } => {
            let builder = builder()?;

            // Generate the chain and report what it contains
            log::info!("Generating PIV certificate chain: {:?}", kind);
            let chain = builder.certify(kind.clone())?;
            let selected = chain.select(kind.clone())?;

            for cert in selected.iter() {
                log::info!(
                    "{}: {:x}",
                    cert.tbs_certificate().subject(),
                    Sha256::digest(cert.to_der()?)
                );
            }

            // Export certificates in PEM format
            let encoded = chain.to_pem(kind)?;
            if let Some(path) = output {
                log::info!("Saving certificates to file: {}", path.display());
                fs::write(path, encoded.as_bytes())?;
            } else if selected.len() == 1 {
                qr::show_qr(encoded.as_bytes(), false)?;
            } else {
                bail!(
                    "Refusing to render {} certificates as a QR code, use --output or --kind root",
                    selected.len()
                )
            }

            Ok(())
        }
        PIVCommand::Check { pin, card } => {
            // A chain derived without emails carries no SANs; against a card that was
            // provisioned with them, every slot would "mismatch" for the wrong reason
            if emails_empty {
                log::warn!(
                    "No --emails given: if the card was provisioned with emails, every \
                     certificate will mismatch; pass them exactly as at provisioning"
                );
            }

            let mut builder = builder()?;

            if let Some(pin) = pin.as_ref() {
                log::info!("Verifying the supplied user pin");
                builder = builder.with_pin(pin.clone());
            }

            // Show info about target card
            if let Some(serial) = card.as_ref() {
                log::info!("Checking keys on smartcard: {}", serial);
            }

            builder.check(card)
        }
        PIVCommand::Upload { pin, card, yes, output, qr: show_qr } => {
            common::warn_factory_pin(pin.is_none());

            // Verify user inputs further. Counted in characters, not bytes: the card takes
            // up to 8 bytes, but a multi-byte character miscounted here would produce an
            // off-by-N error message rather than a wrong length on the card.
            if let Some(pin) = pin.as_ref() {
                let length = pin.chars().count();
                if !(6..=8).contains(&length) || !pin.is_ascii() {
                    bail!("PIV pin needs to be between 6 and 8 ASCII characters")
                }
            }

            let mut builder = builder()?;

            if let Some(pin) = pin.as_ref() {
                log::info!("Setting the smartcard user pin");
                builder = builder.with_pin(pin.clone());
            }

            // Show info about target card
            if let Some(serial) = card.as_ref() {
                log::info!("Upload keys to smartcard: {}", serial);
            }

            // Check confirmation
            if !yes {
                confirm("PIV")?;
            }

            // Generate, upload and save result
            let chain = builder.upload(card)?;
            log::info!(
                "Uploaded PIV certificate chain under '{}'",
                chain.root.tbs_certificate().subject()
            );

            if let Some(path) = output {
                log::info!("Saving certificates to file: {}", path.display());
                fs::write(path, chain.to_pem(piv::CertificateKind::Chain)?.as_bytes())?;
            }
            if show_qr {
                qr::show_qr(chain.to_pem(piv::CertificateKind::Root)?.as_bytes(), false)?;
            }

            Ok(())
        }
    }
}

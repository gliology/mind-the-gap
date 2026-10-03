//! The clap command line: argument types, the subcommand tree, and the run loop.
//!
//! Secret-bearing arguments are `Zeroizing<String>` and are prompted for when omitted --
//! values on the command line leak through `ps` and shell history, so the prompt is the
//! preferred entry and the `MIND_THE_...` environment variables cover only the public
//! parameters. The handlers wire the seed layer to the [`pgp`] and [`piv`] builders.

// Import helper to add shared commands
use crate::common;
use crate::mnemonic::MnemonicSeed;
use crate::pgp::{self, CertificateKind, VerificationKind};
use crate::piv;
use crate::prompt;
use crate::qr;

use rand_core::{OsRng, TryRngCore};

use std::{path::PathBuf, time::Duration};

use std::io::Write;
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
    /// Prompted for on the terminal when omitted, which is the preferred way to enter it:
    /// arguments are visible in `ps` and shell history, environment variables in /proc,
    /// while the prompt echoes nothing and leaves no trace. Use `generate` to mint one.
    #[arg(short, long, global = true, env = "MIND_THE_SEED")]
    seed: Option<Zeroizing<String>>,

    /// Optional password to use in root entropy derivation
    ///
    /// Takes its value only in the equals form, `--password=<PASSWORD>`. Passing the bare
    /// flag instead prompts for the password on the terminal, asking twice without echoing:
    /// a password has no checksum, and a typo would silently derive different keys.
    #[arg(
        short,
        long,
        global = true,
        env = "MIND_THE_PASSWORD",
        num_args = 0..=1,
        require_equals = true
    )]
    password: Option<Option<Zeroizing<String>>>,

    /// Optional identifier to include in subkey derivation.
    ///
    /// Public by design -- it ends up in every certificate -- so it is deliberately not
    /// treated as a secret anywhere.
    #[arg(short = 'k', long, global = true, env = "MIND_THE_SUBKEY")]
    subkey: Option<String>,

    /// Common name to use on certs or smartcards
    #[arg(short, long, global = true, env = "MIND_THE_NAME")]
    name: Option<String>,

    /// Email addresses to use on certs or smartcards
    #[arg(short = 'm', long, value_delimiter = ',', global = true, env = "MIND_THE_EMAILS")]
    emails: Vec<String>,

    /// The backend and subcommand to run
    #[command(subcommand)]
    backend: Option<Backend>,
}

#[derive(Subcommand, Clone)]
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
            env = "MIND_THE_SHARED"
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
            env = "MIND_THE_SHARED"
        )]
        shared: Vec<piv::SharedSlot>,

        /// Superseded subkey ids whose key management key to archive, newest first
        #[arg(long = "retire", value_name = "SUBKEY", global = true, env = "MIND_THE_RETIRE")]
        retired: Vec<String>,

        /// Organization (O) to include in all certificate subjects
        #[arg(long, value_name = "ORG", global = true, env = "MIND_THE_ORG")]
        org: Option<String>,

        /// Organizational unit (OU) to include in all certificate subjects
        #[arg(long, value_name = "UNIT", global = true, env = "MIND_THE_OU")]
        ou: Option<String>,

        /// Two-letter ISO country code (C) to include in all certificate subjects
        #[arg(long, value_name = "CC", global = true, env = "MIND_THE_COUNTRY")]
        country: Option<String>,

        /// Card identifier used in the card authentication subject (derived by default)
        #[arg(long, value_name = "ID", global = true, env = "MIND_THE_CARD_ID")]
        card_id: Option<String>,

        /// Override the per-slot pin policy (ignored for the card authentication slot)
        #[arg(long, value_enum, global = true, env = "MIND_THE_PIN_POLICY")]
        pin_policy: Option<piv::PinPolicyArg>,

        /// Override the per-slot touch policy (ignored for the card authentication slot)
        #[arg(long, value_enum, global = true, env = "MIND_THE_TOUCH_POLICY")]
        touch_policy: Option<piv::TouchPolicyArg>,

        /// Do not store the certificate authorities in the card's msroots object
        #[arg(long, global = true)]
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
    fn needs_seed(self) -> bool {
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
    Configure {
        /// Serial number of smart card to configure
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
        #[arg(long, value_enum, value_name = "VALIDITY")]
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

        /// Leave the factory user pin (123456) on the card when --pin is omitted
        ///
        /// Without this, upload refuses to provision a card that would still answer to the
        /// well-known factory pin.
        #[arg(long)]
        keep_factory_pin: bool,

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
        #[arg(short = 't', long, default_value = "generic")]
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
        ///
        /// No short form: `-t` is already the reason text on this subcommand.
        #[arg(long, value_enum, default_value_t)]
        kind: pgp::RevocationKind,

        /// Reason code of revocation
        #[arg(short, long, default_value = "0")]
        code: u8,

        /// Reason string of revocation
        #[arg(short, long, default_value = "Unspecified")]
        text: String,
    },

    /// Export primary-signed certificates of external keys
    Trust {
        /// External certificate to sign
        #[arg(short, long)]
        input: PathBuf,

        /// Level of verification to certify
        #[arg(short = 't', long, default_value = "generic")]
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
        #[arg(short = 't', long, value_enum, default_value = "chain")]
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

        /// Leave the factory user pin (123456) on the card when --pin is omitted
        ///
        /// Without this, upload refuses to provision a card that would still answer to the
        /// well-known factory pin.
        #[arg(long)]
        keep_factory_pin: bool,

        /// Certificate chain output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show the root certificate as a QR code
        #[arg(short = 'q', long = "qr")]
        show_qr: bool,
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
    println!("Uploading new keys will reset the {backend} smartcard.");
    println!("This will clear any existing keys or data on the card!");

    // "yes" proceeds, "no" aborts, and anything else asks again: a typo should cost one
    // more keystroke, not the whole invocation.
    loop {
        print!("Continue? [yes/no] ");
        io::stdout().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            bail!("Refusing to continue without confirmation on stdin, use --yes")
        }
        match input.trim() {
            "yes" => return Ok(()),
            "no" => bail!("Aborted, the card was not touched"),
            _ => continue,
        }
    }
}

/// Mint a new seed phrase and hold it on screen until the user proves it is written down
fn generate() -> Result<()> {
    let seed = MnemonicSeed::generate()?;
    let words = seed.words();

    // The whole ceremony talks to the controlling terminal, never stdout: under
    // `generate > file` a stdout phrase would land on disk while the wipe below scrubbed
    // only the file, with nothing to notice it by
    let mut tty = prompt::tty()?;

    loop {
        // Show the phrase, numbered for transcription
        writeln!(tty)?;
        writeln!(tty, "This is your new seed phrase. Write it down now, on paper:")?;
        writeln!(tty)?;
        for (index, word) in words.iter().enumerate() {
            write!(tty, "  {:>2}. {:<12}", index + 1, word)?;
            if (index + 1) % 4 == 0 {
                writeln!(tty)?;
            }
        }
        writeln!(tty)?;

        prompt::read_ack("Press enter once it is written down... ")?;

        // Wipe screen *and* scrollback, so the phrase survives only on paper
        write!(tty, "\x1b[2J\x1b[3J\x1b[H")?;
        tty.flush()?;

        // Prove the copy is complete and readable before letting go of the phrase
        if quiz(&mut tty, &words)? {
            break;
        }

        writeln!(tty, "That did not match your phrase, compare your copy against the original:")?;
    }

    write!(tty, "\x1b[2J\x1b[3J\x1b[H")?;
    tty.flush()?;

    writeln!(tty, "Seed phrase confirmed.")?;
    writeln!(tty, "Enter it at the prompt of any command that is run without --seed.")?;

    Ok(())
}

/// Ask for a few randomly chosen words of the phrase
fn quiz(tty: &mut std::fs::File, words: &[String]) -> Result<bool> {
    writeln!(tty, "Confirm your copy by answering from it below.")?;
    writeln!(tty)?;

    // Sampled from the OS generator like the phrase itself; rejection keeps them distinct
    let mut indices: Vec<usize> = Vec::new();
    while indices.len() < 3 {
        let index = OsRng
            .try_next_u32()
            .map_err(|err| anyhow!("Operating system entropy source failed: {err}"))?
            as usize
            % words.len();
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices.sort_unstable();

    for index in indices {
        let answer = prompt::read_secret(&format!("Word {}: ", index + 1))?;
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

/// Parse and run clap command line ui
pub fn run() -> Result<()> {
    let CLI { seed, password, subkey, name, emails, backend } = CLI::parse();

    // A command that derives keys needs the seed; one that only reads a card does not, and
    // `generate` mints its own. Checked before anything prompts, so `status` never asks.
    let needs_seed = backend.clone().map(Backend::needs_seed).unwrap_or(false);

    // Prompt for the seed when it is needed and was not supplied. A seed is never invented
    // behind the user's back: minting a fresh one is what `generate` is for, and it does not
    // let go until the phrase is written down. The supplied phrase is never echoed back --
    // it would linger in scrollback next to everything derived from it.
    let seed: Option<MnemonicSeed> = match (seed, needs_seed) {
        (Some(text), true) => Some(text.trim().parse()?),
        (None, true) => Some(prompt::read_secret("Seed phrase: ")?.trim().parse()?),
        (_, false) => None,
    };

    // A bare `--password` asks on the terminal instead of taking a value
    let password = match password {
        Some(Some(password)) => Some(password),
        Some(None) if needs_seed => {
            Some(prompt::read_confirmed("Password: ", "Repeat password: ")?)
        }
        _ => None,
    };

    // Prepare root seed phrase and password
    let seed = match (seed, password.as_ref()) {
        (Some(seed), Some(password)) => Some(seed.with_password(password)),
        (seed, _) => seed,
    };

    if needs_seed {
        if password.is_some() {
            log::info!("Using the supplied root seed password");
        }

        // The subkey id is public by design -- it ends up in every certificate -- so echoing
        // it is harmless and confirms which card is being derived.
        if let Some(subkey) = subkey.as_ref() {
            log::info!("Subkey derivation identifier: {}", subkey.as_str());
        }
    }

    // Match backend ...
    match backend {
        // ... starting with the seed generation ceremony, which needs no other input
        Some(Backend::Generate) => generate(),
        // ... then command
        Some(Backend::PGP { date, subdate, validity, shared, legacy, command }) => run_pgp(
            Identity { seed, subkey, name, emails },
            PGPOptions { date, subdate, validity, shared, legacy },
            command,
        ),
        // ... then command
        Some(Backend::PIV {
            date,
            validity,
            intermediate,
            shared,
            retired,
            org,
            ou,
            country,
            card_id,
            pin_policy,
            touch_policy,
            no_msroots,
            command,
        }) => run_piv(
            Identity { seed, subkey, name, emails },
            PIVOptions {
                date,
                validity,
                intermediate,
                shared,
                retired,
                org,
                ou,
                country,
                card_id,
                pin_policy,
                touch_policy,
                no_msroots,
            },
            command,
        ),
        None => Ok(CLI::command().print_long_help()?),
    }
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
    ou: Option<String>,
    country: Option<String>,
    card_id: Option<String>,
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
    let builder = move || -> Result<pgp::SeededSmartcard> {
        let name = name.ok_or(anyhow!("Requires name to be specified"))?;

        if emails.is_empty() {
            bail!("Requires at least one email to be specified");
        }

        // Prepare pgp cert
        log::info!("Initializing PGP certificate for '{}'", name);

        let scheme = if legacy {
            log::warn!("Using the legacy derivation scheme");
            pgp::Scheme::Legacy
        } else {
            pgp::Scheme::Current
        };

        let seed = seed.as_ref().expect("prompted for above when missing");
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
        PGPCommand::Configure { card, touch, lang, url, login, sign_pin } => {
            let settings = pgp::CardSettings { touch, lang, url, login, sign_pin };
            if settings.is_empty() {
                bail!(
                    "Nothing to configure: pass at least one of --touch, --lang, --url, \
                     --login or --sign-pin"
                );
            }

            let builder = builder()?;

            if let Some(serial) = card.as_ref() {
                log::info!("Configuring smartcard: {}", serial);
            }

            builder.configure(card, settings)
        }
        PGPCommand::Upload { pin, card, yes, keep_factory_pin, output, qr: show_qr } => {
            if pin.is_none() && !keep_factory_pin {
                bail!(
                    "No --pin supplied: the card would keep the factory user pin \
                     (123456), usable by anyone who finds it. Pass --pin, or \
                     --keep-factory-pin to accept that deliberately."
                );
            }

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
                qr::print_qr(&armored)?;
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
                qr::print_qr(&armored)?;
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
                qr::print_qr(&tsk_bytes)?;
                log::warn!(
                    "Secret keys were rendered on the terminal, clear the scrollback once transferred (e.g. `clear && printf '\\e[3J'`)"
                );
            }

            Ok(())
        }
        PGPCommand::Revoke { output, kind, code, text } => {
            let builder = builder()?;

            // Generate rev cert and save result
            let raw = builder.revoke(kind, code, &text)?;
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
                qr::print_qr(&armored)?;
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
                qr::print_qr(&armored)?;
            }

            Ok(())
        }
    }
}

/// Run one PIV subcommand, assembling the certificate builder on demand
fn run_piv(identity: Identity, options: PIVOptions, command: PIVCommand) -> Result<()> {
    let Identity { seed, subkey, name, emails } = identity;
    let PIVOptions {
        date,
        validity,
        intermediate,
        shared,
        retired,
        org,
        ou,
        country,
        card_id,
        pin_policy,
        touch_policy,
        no_msroots,
    } = options;

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    let builder = move || -> Result<piv::SeededSmartcard> {
        let name = name.ok_or(anyhow!("Requires name to be specified"))?;

        // Configure and run backend
        log::info!("Generating PIV certificates for '{}'", name);
        let seed = seed.as_ref().expect("prompted for above when missing");
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
        if let Some(unit) = ou {
            log::info!("Setting certificate organizational unit: {}", unit);
            builder = builder.with_org_unit(unit);
        }
        if let Some(country) = country {
            log::info!("Setting certificate country: {}", country);
            builder = builder.with_country(country);
        }
        if let Some(id) = card_id {
            log::info!("Setting card identifier: {}", id);
            builder = builder.with_card_id(id);
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
        if let Some(date) = date {
            log::info!("Setting certificate creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_creation_time(date.into());
        } else {
            log::warn!("No creation date given, using the unix epoch");
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
                qr::print_qr(encoded.as_bytes())?;
            } else {
                bail!(
                    "Refusing to render {} certificates as a QR code, use --output or --kind root",
                    selected.len()
                )
            }

            Ok(())
        }
        PIVCommand::Check { pin, card } => {
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
        PIVCommand::Upload { pin, card, yes, keep_factory_pin, output, show_qr } => {
            if pin.is_none() && !keep_factory_pin {
                bail!(
                    "No --pin supplied: the card would keep the factory user pin \
                     (123456), usable by anyone who finds it. Pass --pin, or \
                     --keep-factory-pin to accept that deliberately."
                );
            }

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
                qr::print_qr(chain.to_pem(piv::CertificateKind::Root)?.as_bytes())?;
            }

            Ok(())
        }
    }
}

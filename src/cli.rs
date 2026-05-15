// Import helper to add shared commands
use crate::common;
use crate::mnemonic::{MnemonicSeed, MnemonicSource};
use crate::pgp::{self, CertificateKind, VerificationKind};
use crate::piv;
use crate::qr;

use std::{path::PathBuf, time::Duration};

use std::io::Write;
use std::{fs, io};

use anyhow::{anyhow, bail, Result};

use chrono::{DateTime, Utc};

use clap::{ArgGroup, Command, CommandFactory, Parser, Subcommand};

use sequoia_openpgp::armor;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;

use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct CLI {
    /// Mnemonic seed phrase of root secret
    #[arg(short, long, global = true, env = "MIND_THE_SEED")]
    seed: Option<MnemonicSeed>,

    /// Optional password to use in root entropy derivation
    #[arg(short, long, global = true, env = "MIND_THE_PASSWORD")]
    password: Option<Zeroizing<String>>,

    /// Optional identifier to include in subkey derivation
    #[arg(short = 'k', long, global = true, env = "MIND_THE_SUBKEY")]
    subkey: Option<Zeroizing<String>>,

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

#[derive(Subcommand, Clone, Debug)]
enum Backend {
    /// Generate and export PGP keys and certs
    PGP {
        /// Creation date of the primary key
        #[arg(short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Creation date of the subkeys
        #[arg(long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_SUBDATE")]
        subdate: Option<DateTime<Utc>>,

        /// Validity duration of the subkeys
        #[arg(short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        #[command(subcommand)]
        command: PGPCommand,
    },
    /// Generate and export PIV keys and certs
    PIV {
        /// Creation date of certificates (current timestamp by default)
        #[arg(short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Validity duration of certificates (infinite by default)
        #[arg(short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        #[command(subcommand)]
        command: PIVCommand,
    },
}

impl Backend {
    /// Determine if selected backend and command needs secret seed data
    fn needs_seed(self) -> bool {
        match self {
            Backend::PGP { command: PGPCommand::Status, ..} => false,
            Backend::PIV { command: PIVCommand::Status, ..} => false,
            _ => true,
        }
    }
}

#[derive(Subcommand, Clone, PartialEq, Debug)]
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

#[derive(Subcommand, Clone, PartialEq, Debug)]
enum PIVCommand {
    /// Display current status
    Status,

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
    },
}

fn confirm(backend: &str) -> Result<()> {
    println!("Uploading new keys will reset the {backend} smartcard.");
    println!("This will clear any existing keys or data on the card!");

    loop {
        print!("Continue? [yes] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim() == "yes" {
            break;
        }
    }

    Ok(())
}

/// Return clap command for testing and documentation
pub fn command() -> Command {
    CLI::command()
}

/// Parse and run clap command line ui
pub fn run() -> Result<()> {
    let CLI {
        seed,
        password,
        subkey,
        name,
        emails,
        backend,
    } = CLI::parse();

    // Prepare root seed phrase and password
    let mut seed = seed.unwrap_or(MnemonicSeed::new());
    if let Some(password) = password.as_ref() {
        seed = seed.with_password(password);
    }

    // Print root secret information if used by backend
    if backend.clone().map(Backend::needs_seed).unwrap_or(false) {
        // - Root seed and source
        match seed.source() {
            MnemonicSource::Random => log::warn!("Random root seed: {}", seed.phrase()),
            MnemonicSource::Phrase => log::info!("Root seed phrase: {}", seed.phrase()),
        };

        // - Optional key identifier or password used in primary derivation
        if let Some(password) = password.as_ref() {
            log::info!("Root seed password: {}", password.as_str());
        }

        // - Optional subkey derivation identifier
        if let Some(subkey) = subkey.as_ref() {
            log::info!("Subkey derivation identifier: {}", subkey.as_str());
        }
    }

    // Match backend ...
    match backend {
        // ... then command
        Some(Backend::PGP { date, subdate, validity, command }) => {
            let builder = if command != PGPCommand::Status {

                let name = name.ok_or(anyhow!("Requires name to be specified"))?;

                if emails.is_empty() {
                    bail!("Requires at least one email to be specified");
                }

                // Prepare pgp cert
                log::info!("Initializing PGP certificate for '{}'", name);

                let mut builder = pgp::SeededSmartcard::new(seed.seed(), subkey, name);

                // Add user identities
                for address in emails.into_iter() {
                    log::info!("Adding userid for email: {}", address);
                    builder = builder.add_email(&address);
                }

                // Set creation date
                if let Some(date) = date {
                    log::info!(
                        "Setting certificate creation time: {}",
                        date.format("%Y-%m-%d %T")
                    );
                    builder = builder.with_creation_time(date.into());
                }

                if let Some(date) = subdate {
                    log::info!(
                        "Setting subkey creation time: {}",
                        date.format("%Y-%m-%d %T")
                    );
                    builder = builder.with_subkey_creation_time(date.into());
                }

                // Set validity period
                if let Some(validity) = validity {
                    log::info!(
                        "Setting subkey validity duration: {}",
                        humantime::format_duration(validity)
                    );
                    builder = builder.with_subkey_validity(validity);
                }

                Some(builder)
            } else {
                None
            };

            match command {
                PGPCommand::Status => pgp::status(),
                PGPCommand::Check { pin, card } => {
                    // Retrieve initialized builder
                    let mut builder = builder.unwrap();

                    // Apply pin to smartcard
                    if let Some(ref pin) = pin.as_ref() {
                        log::info!("Checking protection pin: {}", pin.as_str());
                        builder = builder.with_pin((*pin).clone());
                    }

                    // Show info about target card
                    if let Some(serial) = card.as_ref() {
                        log::info!("Checking keys on smartcard: {}", serial);
                    }

                    builder.check(card)
                }
                PGPCommand::Upload { pin, card, yes, output, qr: show_qr } => {
                    // Retrieve initialized builder
                    let mut builder = builder.unwrap();

                    //TODO: Investigate or document better
                    if date.is_none() && subdate.is_none() {
                        log::warn!("Key upload might fail if date is not set!");
                    }

                    // Apply pin to smartcard and cert
                    if let Some(ref pin) = pin.as_ref() {
                        log::info!("Setting protection pin: {}", pin.as_str());
                        builder = builder.with_pin((*pin).clone());
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
                    // Retrieve initialized builder
                    let builder = builder.unwrap();

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
                    // Retrieve initialized builder
                    let mut builder = builder.unwrap();

                    // Apply pin to private keys
                    if let Some(ref pin) = pin.as_ref() {
                        log::info!("Setting protection pin of export: {}", pin.as_str());
                        builder = builder.with_pin((*pin).clone());
                    }

                    // Generate secret keys and save result
                    let cert = builder.export()?;
                    log::info!("Generated PGP secret keys for {}", cert);

                    let tsk_bytes = cert.as_tsk().armored().to_vec()?;
                    if let Some(path) = output {
                        log::info!("Saving secret keys to file: {}", path.display());
                        fs::write(path, &tsk_bytes)?;
                    }
                    if show_qr {
                        qr::print_qr(&tsk_bytes)?;
                    }

                    Ok(())
                }
                PGPCommand::Revoke { output, code, text } => {
                    // Retrieve initialized builder
                    let builder = builder.unwrap();

                    // Generate rev cert and save result
                    let cert = builder.revoke(code, &text)?;
                    log::info!("Generated PGP revocation certificate");

                    // Armor the revocation packet (gnupg convention: Kind::PublicKey)
                    let raw = cert.to_vec()?;
                    let mut armored = Vec::new();
                    {
                        let mut w = armor::Writer::new(&mut armored, armor::Kind::PublicKey)?;
                        w.write_all(&raw)?;
                        w.finalize()?;
                    }
                    if let Some(path) = output {
                        log::info!("Saving revocation certificate to file: {}", path.display());
                        fs::write(path, &armored)?;
                    } else {
                        qr::print_qr(&armored)?;
                    }

                    Ok(())
                }
                PGPCommand::Trust { input, kind, output } => {
                    // Retrieve initialized builder
                    let builder = builder.unwrap();

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
        // ... then command
        Some(Backend::PIV { date, validity, command }) => {
            let builder = if command != PIVCommand::Status {
                let name = name.ok_or(anyhow!("Requires name to be specified"))?;

                // Configure and run backend
                log::info!("Generating PIV certificates for '{}'", name);
                let mut builder = piv::SeededSmartcard::new(seed.seed(), subkey, name);

                for address in emails.into_iter() {
                    log::info!("Adding SAN for email: {}", address);
                    builder = builder.add_email(address);
                }

                Some(builder)
            } else {
                None
            };

            match command {
                PIVCommand::Status => piv::status(),
                PIVCommand::Check { pin, card } => {
                    let mut builder = builder.unwrap();

                    if let Some(ref pin) = pin.as_ref() {
                        log::info!("Checking protection pin: {}", pin.as_str());
                        builder = builder.with_pin((*pin).clone());
                    }

                    // Show info about target card
                    if let Some(serial) = card.as_ref() {
                        log::info!("Checking keys on smartcard: {}", serial);
                    }

                    builder.check(card)
                },
                PIVCommand::Upload { pin, card, yes } => {
                    // Verify user inputs further
                    if let Some(ref pin) = pin.as_ref() {
                        if pin.len() < 6 || pin.len() > 8 {
                            bail!("PIV pin needs to be between 6 and 8 characters")
                        }
                    }

                    let mut builder = builder.unwrap();

                    if let Some(ref pin) = pin.as_ref() {
                        log::info!("Setting smartcard user pin: {}", pin.as_str());
                        builder = builder.with_pin((*pin).clone());
                    }

                    // Set validity period
                    if let Some(date) = date {
                        log::info!(
                            "Setting certificate creation time: {}",
                            date.format("%Y-%m-%d %T")
                        );
                        builder = builder.with_creation_time(date.into());
                    }

                    // Set validity period
                    if let Some(validity) = validity {
                        log::info!(
                            "Setting certificate validity duration: {}",
                            humantime::format_duration(validity)
                        );
                        builder = builder.with_validity_duration(validity);
                    }

                    // Show info about target card
                    if let Some(serial) = card.as_ref() {
                        log::info!("Upload keys to smartcard: {}", serial);
                    }

                    // Check confirmation
                    if !yes {
                        confirm("PIV")?;
                    }

                    builder.upload(card)
                }
            }
        }
        None => Ok(CLI::command().print_long_help()?),
    }
}

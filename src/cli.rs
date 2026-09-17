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

use sha2::{Digest, Sha256};
use der::Encode;

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
// PGP and PIV are the established names of these backends and of the subcommands they map to;
// spelling them `Pgp`/`Piv` would read worse in a domain where both are always capitalised.
#[allow(clippy::upper_case_acronyms)]
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
        /// Creation date of certificates (unix epoch by default)
        #[arg(short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = common::parse_date)]
        date: Option<DateTime<Utc>>,

        /// Validity duration of the slot certificates (infinite by default)
        #[arg(short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = common::parse_duration)]
        validity: Option<Duration>,

        /// Insert an intermediate issuing CA between the root and the slot certificates
        #[arg(long, global = true, env = "MIND_THE_INTERMEDIATE")]
        intermediate: bool,

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

        /// Certificate chain output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show the root certificate as a QR code
        #[arg(short = 'q', long = "qr")]
        show_qr: bool,
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
                    if let Some(pin) = pin.as_ref() {
                        log::info!("Checking protection pin: {}", pin.as_str());
                        builder = builder.with_pin(pin.clone());
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
                    if let Some(pin) = pin.as_ref() {
                        log::info!("Setting protection pin: {}", pin.as_str());
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
                    if let Some(pin) = pin.as_ref() {
                        log::info!("Setting protection pin of export: {}", pin.as_str());
                        builder = builder.with_pin(pin.clone());
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
        Some(Backend::PIV {
            date,
            validity,
            intermediate,
            org,
            ou,
            country,
            card_id,
            pin_policy,
            touch_policy,
            no_msroots,
            command,
        }) => {
            let builder = if command != PIVCommand::Status {
                let name = name.ok_or(anyhow!("Requires name to be specified"))?;

                // Configure and run backend
                log::info!("Generating PIV certificates for '{}'", name);
                let mut builder = piv::SeededSmartcard::new(seed.seed(), subkey, name);

                for address in emails.iter() {
                    log::info!("Adding SAN for email: {}", address);
                    builder = builder.add_email(address);
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
                    log::info!(
                        "Setting certificate creation time: {}",
                        date.format("%Y-%m-%d %T")
                    );
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

                Some(builder)
            } else {
                None
            };

            match command {
                PIVCommand::Status => piv::status(),
                PIVCommand::Certify { kind, output } => {
                    // Retrieve initialized builder
                    let builder = builder.unwrap();

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
                        bail!("Refusing to render {} certificates as a QR code, use --output or --kind root", selected.len())
                    }

                    Ok(())
                }
                PIVCommand::Check { pin, card } => {
                    let mut builder = builder.unwrap();

                    if let Some(pin) = pin.as_ref() {
                        log::info!("Checking protection pin: {}", pin.as_str());
                        builder = builder.with_pin(pin.clone());
                    }

                    // Show info about target card
                    if let Some(serial) = card.as_ref() {
                        log::info!("Checking keys on smartcard: {}", serial);
                    }

                    builder.check(card)
                },
                PIVCommand::Upload { pin, card, yes, output, show_qr } => {
                    // Verify user inputs further
                    if let Some(pin) = pin.as_ref() {
                        if pin.len() < 6 || pin.len() > 8 {
                            bail!("PIV pin needs to be between 6 and 8 characters")
                        }
                    }

                    let mut builder = builder.unwrap();

                    if let Some(pin) = pin.as_ref() {
                        log::info!("Setting smartcard user pin: {}", pin.as_str());
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
        None => Ok(CLI::command().print_long_help()?),
    }
}

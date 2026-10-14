//! The `pgp` subcommands and their handler.

use super::{
    Identity, confirm, parse_date, parse_duration, spelled, spelled_all, warn_factory_pin,
    warn_if_phrase_is_weaker, write_sensitive,
};
use crate::pgp::{self, CertificateKind, VerificationKind};
use crate::qr;
use crate::seed::Algorithm;

use std::{path::PathBuf, time::Duration};

use std::fs;
use std::io::Write;

use anyhow::{Result, bail};

use chrono::{DateTime, Utc};

use clap::{ArgGroup, Subcommand};

use sequoia_openpgp::armor;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;

use zeroize::Zeroizing;

#[derive(Subcommand, Clone, PartialEq)]
pub(super) enum PGPCommand {
    /// List the attached OpenPGP cards and the keys they hold (needs no seed)
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
        /// Keys are signing, decryption and authentication; policies are never, always,
        /// always-fixed, cached and cached-fixed, as for PIV.
        /// The fixed variants lock the setting until the key is replaced.
        /// Example: --touch signing=always,decryption=cached
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

    /// Reset the card and import the derived subkeys
    ///
    /// Erases the card's OpenPGP application. Then sets the user pin and an admin pin derived
    /// from the phrase and the subkey id, which `check` and `config` re-derive, and imports
    /// the three subkeys. A forgotten pin is recovered by running upload again. Asks before
    /// the reset and names the card.
    Upload {
        /// User pin to set on the card (the factory 123456 when omitted)
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card target
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,

        /// Reset the card without asking first
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

        /// What the revocation covers: `subkeys` retires this card's keys, `certificate` the
        /// whole identity and every card with it
        // Required on purpose: the one choice here that cannot be taken back has no default
        #[arg(short = 't', long, value_enum)]
        kind: pgp::RevocationKind,

        /// Revocation reason: 0 unspecified, 1 superseded, 2 compromised, 3 retired
        ///
        /// A lost or stolen card is 2 if the pin may be known, else 3.
        // Long-only on purpose: `-c` means the card everywhere else, and this is typed about
        // once per revocation
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
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

/// Parse one `<key>=<policy>` pair for `pgp configure --touch`
fn parse_touch(s: &str) -> Result<(pgp::SubkeyRole, pgp::TouchPolicyArg), String> {
    use clap::ValueEnum;

    let (key, policy) = s
        .split_once('=')
        .ok_or_else(|| format!("'{s}' is not <key>=<policy>, e.g. signing=always"))?;

    Ok((pgp::SubkeyRole::from_str(key, true)?, pgp::TouchPolicyArg::from_str(policy, true)?))
}

/// Parse one ISO 639-1 language code for `pgp configure --lang`
fn parse_lang(s: &str) -> Result<[u8; 2], String> {
    match s.as_bytes() {
        [a, b] if a.is_ascii_lowercase() && b.is_ascii_lowercase() => Ok([*a, *b]),
        _ => Err(format!("'{s}' is not a two-letter ISO 639-1 code, e.g. en")),
    }
}

/// The options every `pgp` subcommand shares, given before the subcommand or after it
#[derive(clap::Args, Clone, Default)]
pub(super) struct PGPOptions {
    /// Creation date of the primary key (the unix epoch by default, so re-runs match)
    #[arg(help_heading = "Certificate", short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = parse_date)]
    pub(super) date: Option<DateTime<Utc>>,

    /// Creation date of the subkeys (the primary's by default)
    #[arg(help_heading = "Certificate", long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_PGP_SUBDATE", value_parser = parse_date)]
    pub(super) subdate: Option<DateTime<Utc>>,

    /// Validity duration of the subkeys, e.g. 2y or 18months (unlimited by default)
    #[arg(help_heading = "Certificate", short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = parse_duration)]
    pub(super) validity: Option<Duration>,

    /// Subkeys to derive without the subkey id, so every card gets the same one
    #[arg(
        help_heading = "Derivation",
        long,
        value_name = "KEYS",
        value_delimiter = ',',
        global = true,
        env = "MIND_THE_PGP_SHARED"
    )]
    pub(super) shared: Vec<pgp::SharedKey>,

    /// Use the original derivation labels, for cards provisioned before the scheme changed
    #[arg(help_heading = "Derivation", long, global = true, env = "MIND_THE_PGP_LEGACY")]
    pub(super) legacy: bool,

    /// Algorithm to derive every key with (Curve25519 by default; p384 is PIV-only)
    #[arg(
        help_heading = "Derivation",
        long,
        value_enum,
        global = true,
        env = "MIND_THE_ALGORITHM"
    )]
    pub(super) algorithm: Option<Algorithm>,
}

impl PGPCommand {
    /// Whether the command builds user ids, and so needs a name and emails
    pub(super) fn mints_uids(&self) -> bool {
        matches!(
            self,
            PGPCommand::Certify { .. } | PGPCommand::Upload { .. } | PGPCommand::Export { .. }
        )
    }
}

/// Run one PGP subcommand, assembling the certificate builder on demand
pub(super) fn run_pgp(identity: Identity, options: PGPOptions, command: PGPCommand) -> Result<()> {
    let Identity { seed, subkey, name, emails } = identity;
    let PGPOptions { date, subdate, validity, shared, legacy, algorithm } = options;

    // Refused before the seed is stretched, which takes argon2 seconds per derivation level
    if algorithm == Some(Algorithm::P384) {
        bail!(pgp::P384_REFUSED);
    }
    // The legacy scheme derives the primary under the label 0x01 and a subkey id under its
    // own bytes, so this one id would hand the card the primary key itself
    if legacy && subkey.as_deref() == Some("\u{1}") {
        bail!("Subkey id 0x01 collides with the primary key under --legacy; pick another");
    }

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    // Only the commands that mint user ids need emails; check compares keys, revoke
    // retires them, config touches card data -- none of them builds a uid
    let needs_emails = command.mints_uids();

    let builder = move || -> Result<pgp::SeededSmartcard> {
        // Everything missing at once, so a script is fixed in one round
        let mut missing = Vec::new();
        if name.is_none() {
            missing.push("--name (or MIND_THE_NAME)");
        }
        if needs_emails && emails.is_empty() {
            missing.push("--emails (or MIND_THE_EMAILS)");
        }
        if !missing.is_empty() {
            bail!("Missing {}; in a session, `set` them", missing.join(" and "));
        }
        let name = name.expect("checked above");

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

        // Applied before anything else derives: the algorithm is part of every key's label
        if let Some(algorithm) = algorithm {
            log::info!("Deriving {algorithm} keys");
            warn_if_phrase_is_weaker(seed, algorithm);
            builder = builder.with_algorithm(algorithm)?;
        }

        for address in emails.into_iter() {
            log::info!("Adding userid for email: {}", address);
            builder = builder.add_email(&address)?;
        }

        if let Some(date) = date {
            log::info!("Setting certificate creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_creation_time(date.into());
        }

        if let Some(date) = subdate {
            log::info!("Setting subkey creation time: {}", date.format("%Y-%m-%d %T"));
            builder = builder.with_subkey_creation_time(date.into());
        }

        if !shared.is_empty() {
            log::info!("Deriving without the subkey id: {}", spelled_all(&shared));
            builder = builder.with_shared(shared.clone());
        }

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

            if let Some(pin) = pin.as_ref() {
                log::info!("Verifying the supplied user pin");
                builder = builder.with_pin(pin.clone());
            }

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
            warn_factory_pin(pin.is_none());

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

            if let Some(pin) = pin.as_ref() {
                log::info!("Protecting card and keys with the supplied pin");
                builder = builder.with_pin(pin.clone());
            }

            // Opened before the question, so that it names the card and an unfit card is
            // refused while still intact
            let target = builder.preflight(card.clone())?;
            if !yes {
                confirm("OpenPGP", &target)?;
            }

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

            log::info!("Certifying the {} certificate", spelled(&kind));
            let cert = builder.certify(kind)?;

            log::info!("Generated PGP certificate '{}'", cert);
            let armored = cert.armored().to_vec()?;

            emit_public(&armored, output)
        }
        PGPCommand::Export { pin, output, qr: show_qr } => {
            let mut builder = builder()?;

            if let Some(pin) = pin.as_ref() {
                log::info!("Protecting exported keys with the supplied pin");
                builder = builder.with_pin(pin.clone());
            } else {
                log::warn!(
                    "Exporting secret keys UNENCRYPTED, pass --pin to protect them; the file itself is readable only by you"
                );
            }

            let cert = builder.export()?;
            log::info!("Generated PGP secret keys for {}", cert);

            let tsk_bytes = Zeroizing::new(cert.as_tsk().armored().to_vec()?);
            if let Some(path) = output {
                log::info!("Saving secret keys to file: {}", path.display());
                write_sensitive(&path, &tsk_bytes)?;
            }
            if show_qr {
                qr::show_qr(&tsk_bytes, true)?;
            }

            Ok(())
        }
        PGPCommand::Revoke { output, kind, code, reason } => {
            let builder = builder()?;

            let raw = builder.revoke(kind, code, &reason)?;
            log::info!("Generated a revocation of the {}", spelled(&kind));

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
            }

            Ok(())
        }
        PGPCommand::Trust { input, kind, output } => {
            let builder = builder()?;

            log::info!("Certifying certificate in file: {}", input.display());
            let other = Cert::from_file(input)?;

            log::info!("Certifying certificate with id: {}", other);
            let cert = builder.trust(other, kind)?;

            log::info!("Generated PGP certificate '{}'", cert);
            let armored = cert.armored().to_vec()?;

            emit_public(&armored, output)
        }
    }
}

/// Write a public certificate to `output`, or show it as a QR code when there is none
fn emit_public(armored: &[u8], output: Option<PathBuf>) -> Result<()> {
    match output {
        Some(path) => {
            log::info!("Saving certificate to file: {}", path.display());
            fs::write(path, armored)?;
            Ok(())
        }
        None => qr::show_qr(armored, false),
    }
}

//! The `piv` subcommands and their handler.

use super::{
    Identity, confirm, parse_date, parse_duration, spelled, spelled_all, warn_factory_pin,
    warn_if_phrase_is_weaker, warn_policy,
};
use crate::piv;
use crate::policy::Policy;
use crate::qr;
use crate::seed::Algorithm;

use std::{path::PathBuf, time::Duration};

use std::fs;

use anyhow::{Result, anyhow, bail};

use chrono::{DateTime, Utc};

use clap::Subcommand;

use der::pem::LineEnding;
use der::{Encode, EncodePem};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

#[derive(Subcommand, Clone, PartialEq)]
pub(super) enum PIVCommand {
    /// List the attached PIV cards and what their slots hold (needs no seed)
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
        /// User pin, for slots whose keys need it to prove themselves
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// Serial number of smart card target
        #[arg(short, long, env = "MIND_THE_CARD")]
        card: Option<String>,
    },

    /// Reset the card and provision the derived chain
    ///
    /// Erases the card's PIV application: every key and certificate on it. Then installs the
    /// derived management key, sets the user pin and blocks the puk, so a forgotten pin is
    /// recovered by running upload again from the phrase, not by a puk. Asks before the reset
    /// and names the card.
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

        /// Write the provisioned chain, the authorities and every slot certificate, to this file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show the provisioned chain as QR codes, one certificate after another
        #[arg(short, long)]
        qr: bool,
    },
}

/// The options every `piv` subcommand shares, given before the subcommand or after it
#[derive(clap::Args, Clone, Default)]
pub(super) struct PIVOptions {
    /// Creation date of certificates (unix epoch by default)
    #[arg(help_heading = "Certificate", short, long, value_name = "YYYY-MM-DD", global = true, env = "MIND_THE_DATE", value_parser = parse_date)]
    pub(super) date: Option<DateTime<Utc>>,

    /// Validity duration of the slot certificates, e.g. 5y (unlimited by default)
    #[arg(help_heading = "Certificate", short, long, value_name = "DURATION", global = true, env = "MIND_THE_VALIDITY", value_parser = parse_duration)]
    pub(super) validity: Option<Duration>,

    /// Insert an intermediate issuing CA between the root and the slot certificates
    #[arg(help_heading = "Certificate", long, global = true, env = "MIND_THE_PIV_INTERMEDIATE")]
    pub(super) intermediate: bool,

    /// Slots to derive without the subkey id, so every card gets the same key
    #[arg(
        help_heading = "Derivation",
        long,
        value_name = "SLOTS",
        value_delimiter = ',',
        global = true,
        env = "MIND_THE_PIV_SHARED"
    )]
    pub(super) shared: Vec<piv::SharedSlot>,

    /// Superseded subkey ids whose key management key to archive, newest first
    #[arg(
        help_heading = "Derivation",
        long = "retire",
        value_name = "SUBKEY",
        global = true,
        env = "MIND_THE_PIV_RETIRE"
    )]
    pub(super) retired: Vec<String>,

    /// Organization (O) to include in all certificate subjects
    #[arg(
        help_heading = "Certificate",
        long,
        value_name = "ORG",
        global = true,
        env = "MIND_THE_PIV_ORG"
    )]
    pub(super) org: Option<String>,

    /// Organizational unit (OU) to include in all certificate subjects
    #[arg(
        help_heading = "Certificate",
        long,
        value_name = "UNIT",
        global = true,
        env = "MIND_THE_PIV_UNIT"
    )]
    pub(super) unit: Option<String>,

    /// Two-letter ISO country code (C) to include in all certificate subjects
    #[arg(
        help_heading = "Certificate",
        long,
        value_name = "CC",
        global = true,
        env = "MIND_THE_PIV_COUNTRY"
    )]
    pub(super) country: Option<String>,

    /// Pin and touch requirements upload gives the keys and management access (relaxed by
    /// default; see the policies chapter of the book)
    #[arg(help_heading = "Card", long, value_enum, global = true, env = "MIND_THE_POLICY")]
    pub(super) policy: Option<Policy>,

    /// Do not store the certificate authorities in the card's msroots object
    #[arg(help_heading = "Card", long, global = true, env = "MIND_THE_PIV_NO_MSROOTS")]
    pub(super) no_msroots: bool,

    /// Algorithm to derive every key with, authorities included (P-256 by default)
    #[arg(
        help_heading = "Derivation",
        long,
        value_enum,
        global = true,
        env = "MIND_THE_ALGORITHM"
    )]
    pub(super) algorithm: Option<Algorithm>,

    /// Algorithm of the management key upload installs (auto picks by firmware)
    #[arg(
        help_heading = "Card",
        long = "management-algorithm",
        value_name = "ALGORITHM",
        value_enum,
        global = true,
        env = "MIND_THE_PIV_MANAGEMENT_ALGORITHM"
    )]
    pub(super) management_key: Option<piv::ManagementKeyArg>,
}

/// Run one PIV subcommand, assembling the certificate builder on demand
pub(super) fn run_piv(identity: Identity, options: PIVOptions, command: PIVCommand) -> Result<()> {
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
        policy,
        no_msroots,
        algorithm,
        management_key,
    } = options;

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    let builder = move || -> Result<piv::SeededSmartcard> {
        let name = name
            .ok_or_else(|| anyhow!("Missing --name (or MIND_THE_NAME); in a session, `set` it"))?;

        log::info!("Generating PIV certificates for '{}'", name);
        let seed = seed
            .as_ref()
            .expect("resolved above when the command needs a seed");
        let mut builder = piv::SeededSmartcard::new(&seed.seed(), subkey, name);

        if let Some(algorithm) = algorithm {
            log::info!("Deriving {algorithm} keys");
            warn_if_phrase_is_weaker(seed, algorithm);
            builder = builder.with_algorithm(algorithm);
        }

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
            log::info!("Deriving without the subkey id: {}", spelled_all(&shared));
            builder = builder.with_shared(shared.clone());
        }

        if !retired.is_empty() {
            log::info!("Archiving key management keys of: {}", retired.join(", "));
            builder = builder.with_retired(retired.clone());
        }

        if let Some(policy) = policy {
            log::info!("Setting pin and touch policy: {}", spelled(&policy));
            builder = builder.with_policy(policy);
        }

        if no_msroots {
            log::info!("Not storing certificate authorities in msroots");
            builder = builder.with_msroots(false);
        }

        if let Some(algorithm) = management_key {
            log::info!("Setting management key algorithm: {}", spelled(&algorithm));
            builder = builder.with_management_key(algorithm);
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

            log::info!("Generating the PIV certificates: {}", spelled(&kind));
            let chain = builder.certify(kind)?;
            let selected = chain.select(kind)?;

            for cert in selected.iter() {
                let name = chain.name_of(cert);
                log::info!("{name}: SHA-256 {:x}", Sha256::digest(cert.to_der()?));
            }

            match output {
                Some(path) => {
                    log::info!("Saving certificates to file: {}", path.display());
                    fs::write(path, chain.to_pem(kind)?.as_bytes())?;
                    Ok(())
                }
                None => show_chain(&chain, kind),
            }
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

            if let Some(serial) = card.as_ref() {
                log::info!("Checking keys on smartcard: {}", serial);
            }

            builder.check(card)
        }
        PIVCommand::Upload { pin, card, yes, output, qr: show_qr } => {
            warn_factory_pin(pin.is_none());
            warn_policy(policy.unwrap_or_default(), false);

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

            // Opened before the question, so that it names the card and an unfit card is
            // refused while still intact
            let target = builder.preflight(card.clone())?;
            if !yes {
                confirm("PIV", &target)?;
            }

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
                show_chain(&chain, piv::CertificateKind::Chain)?;
            }

            Ok(())
        }
    }
}

/// Show the selected certificates as QR codes, one per certificate and each named: the
/// codes carry what `--output` would write, in pieces a code can hold
fn show_chain(chain: &piv::CertChain, kind: piv::CertificateKind) -> Result<()> {
    let pems = chain
        .select(kind)?
        .into_iter()
        .map(|cert| Ok((chain.name_of(cert), cert.to_pem(LineEnding::default())?)))
        .collect::<Result<Vec<_>>>()?;
    let pages: Vec<_> = pems
        .iter()
        .map(|(name, pem)| qr::QrPage { title: Some(name.clone()), data: pem.as_bytes() })
        .collect();
    qr::show_qr_pages(&pages, false)
}

//! The `piv` subcommands and their handler.

use super::{Identity, confirm, spelled, spelled_all, warn_if_phrase_is_weaker};
use crate::common;
use crate::piv;
use crate::qr;
use crate::seed::Algorithm;

use std::{path::PathBuf, time::Duration};

use std::fs;

use anyhow::{Result, anyhow, bail};

use chrono::{DateTime, Utc};

use clap::Subcommand;

use der::Encode;
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

        /// Certificate chain output path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show the root certificate as a QR code
        #[arg(short, long)]
        qr: bool,
    },
}

/// The PIV backend's certificate options, as parsed
pub(super) struct PIVOptions {
    pub(super) date: Option<DateTime<Utc>>,
    pub(super) validity: Option<Duration>,
    pub(super) intermediate: bool,
    pub(super) shared: Vec<piv::SharedSlot>,
    pub(super) retired: Vec<String>,
    pub(super) org: Option<String>,
    pub(super) unit: Option<String>,
    pub(super) country: Option<String>,
    pub(super) pin_policy: Option<piv::PinPolicyArg>,
    pub(super) touch_policy: Option<piv::TouchPolicyArg>,
    pub(super) no_msroots: bool,
    pub(super) algorithm: Option<Algorithm>,
    pub(super) management_key: Option<piv::ManagementKeyArg>,
    pub(super) management_key_touch: Option<piv::ManagementTouchArg>,
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
        pin_policy,
        touch_policy,
        no_msroots,
        algorithm,
        management_key,
        management_key_touch,
    } = options;

    // Built lazily, so a command that needs no builder -- status today, anything later --
    // simply never calls it; the closure moves the identity in and can run at most once
    let builder = move || -> Result<piv::SeededSmartcard> {
        let name = name
            .ok_or_else(|| anyhow!("Missing --name (or MIND_THE_NAME); in a session, `set` it"))?;

        // Configure and run backend
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

        // Policy overrides only affect the user slots, never card authentication
        if let Some(policy) = pin_policy {
            log::info!("Setting slot pin policy: {}", spelled(&policy));
            builder = builder.with_pin_policy(policy.into());
        }
        if let Some(policy) = touch_policy {
            log::info!("Setting slot touch policy: {}", spelled(&policy));
            builder = builder.with_touch_policy(policy.into());
        }

        if no_msroots {
            log::info!("Not storing certificate authorities in msroots");
            builder = builder.with_msroots(false);
        }

        if let Some(algorithm) = management_key {
            log::info!("Setting management key algorithm: {}", spelled(&algorithm));
            builder = builder.with_management_key(algorithm);
        }
        if let Some(touch) = management_key_touch {
            log::info!("Setting management key touch: {}", spelled(&touch));
            builder = builder.with_management_touch(touch);
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
            log::info!("Generating the PIV certificates: {}", spelled(&kind));
            let chain = builder.certify(kind.clone())?;
            let selected = chain.select(kind.clone())?;

            // The person slots share a subject, so a leaf is named by its slot
            for cert in selected.iter() {
                let slot = chain
                    .leaves
                    .iter()
                    .find(|(_, leaf)| std::ptr::eq(leaf, *cert));
                let name = match slot {
                    Some((slot, _)) => format!("{slot:?} slot"),
                    None => cert.tbs_certificate().subject().to_string(),
                };
                log::info!("{name}: SHA-256 {:x}", Sha256::digest(cert.to_der()?));
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

            // Opened before the question, so that it names the card and an unfit card is
            // refused while still intact
            let target = builder.preflight(card.clone())?;
            if !yes {
                confirm("PIV", &target)?;
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

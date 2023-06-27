use crate::cli::common::MindTheMatches;
use crate::openpgp;

use clap::{ArgMatches, Command};

use anyhow::Result;

use openpgp_card_pcsc::PcscBackend;
use openpgp_card::{Error as CardError, SmartcardError};
use openpgp_card_sequoia::{state::Open, types::KeyType, Card};

use sha2::{Digest, Sha256};
use yubikey::reader::Context;

/// Status subcommand definition
pub fn subcmd() -> Command {
    Command::new("status").about("Show current status of hardware and config")
}

///Parse common commands and list all supported cards
pub fn subrun(matches: &ArgMatches) -> Result<()> {
    let (_seed, _subkey) = matches.parse_common();

    //FIXME: Relate seed/subkey to current hardware

    status_openpgp()?;

    status_piv()?;

    Ok(())
}

///Print list of currently available OpenPGP cards
fn status_openpgp() ->Result<()> {

    println!("Available OpenPGP cards:");

    let cards = match PcscBackend::cards(None) {
        //Ignore missing reader and return empty list instead
        Err(CardError::Smartcard(SmartcardError::NoReaderFoundError)) =>Ok(Vec::<PcscBackend>::new()),
        other => other,
    }?;

    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for backend in cards {
        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        println!(" - Card {}", transaction.application_identifier()?.ident(),);

        if let Some(name) = transaction.cardholder_name()? {
            println!("   Cardholder: {}", name);
        }

        for kt in openpgp::DEFAULT_KEY_TYPES {
            if let Some(sign) = transaction.public_key(KeyType::Signing)? {
                println!("   {:?} key: {}", kt, sign.fingerprint());
            }
        }

        println!();
    }

    Ok(())
}

///Print list of currently available PIV cards
fn status_piv() ->Result<()> {

    println!("Available PIV cards:");

    let mut context = Context::open()?;
    let cards: Vec<_> = context.iter()?.collect();

    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for reader in cards {
        println!(" - Reader '{}'", reader.name());

        let mut token = reader.open()?;
        println!("   Serial: {}", token.serial());

        for key in token.piv_keys()? {
            let cert = key.certificate();

            // Fingerprint is SHA256 hash of certificate
            let mut hasher = Sha256::new();
            hasher.update(cert.clone().into_buffer());
            let fingerprint = hasher.finalize();

            println!(
                "   {} key: {:x} ({})",
                key.slot(),
                fingerprint,
                cert.subject()
            );
        }

        println!();
    }

    Ok(())
}


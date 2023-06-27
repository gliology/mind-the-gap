use crate::cli::common::{MindTheCommand, MindTheMatches};

use crate::piv;

use clap::{ArgMatches, Command};

use anyhow::{bail, Result};

/// Generate the command line interface for the piv subcommand
pub fn subcmd() -> Command {
    Command::new("piv")
        .about("Initialize PIV smart card from mnemonic seed")
        .add_common_args()
        .add_backend_args()
}

pub fn subrun(matches: &ArgMatches) -> Result<()> {
    // Parse seed and subkey
    let (seed, subkey) = matches.parse_common();

    // Parse user name, emails and pin
    let (name, emails, pin, card) = matches.parse_backend();

    // Verify user inputs further
    if let Some(ref pin) = pin.as_ref() {
        if pin.len() < 6 || pin.len() > 8 {
            bail!("PIV pin needs to be between 6 and 8 characters")
        }
    }

    // Configure and run backend
    println!("Generating P256 PIV certificates...");
    let mut builder = piv::SeededSmartcard::new(
        seed.derive(Some(b"piv")),
        subkey,
        name,
    );

    for address in emails.into_iter() {
        println!("- Adding SAN for email: {}", address);
        builder = builder.add_email(address);
    }

    if let Some(ref pin) = pin.as_ref() {
        builder = builder.with_pin((*pin).clone());
    }

    if let Some(ref card) = card.as_ref() {
        builder = builder.to_smartcard(card);
    }

    builder.generate()?;

    Ok(())
}

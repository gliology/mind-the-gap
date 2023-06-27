use crate::mnemonic::{MnemonicSeed, MnemonicSource};

use clap::{Arg, ArgAction, ArgMatches, Command};

use chrono::{DateTime, LocalResult, NaiveDate, TimeZone, Utc};

use zeroize::Zeroizing;

use anyhow::{anyhow, Result};

///Trait to easily extend clap
pub trait MindTheCommand {
    fn add_common_args(self) -> Command;
    fn add_backend_args(self) -> Command;
}

///Standardized command line interfaces
impl MindTheCommand for Command {
    ///Add default argument for most commands
    fn add_common_args(self) -> Command {
        self
            // Optional parameter to seed root secret
            .arg(
                Arg::new("mnemonic")
                    .short('s')
                    .long("seed")
                    .env("MIND_THE_SEED")
                    .value_parser(MnemonicSeed::from_phrase)
                    .help("Mnemonic seed phrase of root secret"),
            )
            .arg(
                Arg::new("password")
                    .short('p')
                    .long("password")
                    .env("MIND_THE_PASSWORD")
                    .help("Password to protect mnemonic seed phrase"),
            )
            // Optional parameter to derive subkeys
            .arg(
                Arg::new("subkey")
                    .short('k')
                    .long("subkey")
                    .env("MIND_THE_SUBKEY")
                    .help("Identifier to use in subkey derivation"),
            )
    }

    ///Add default arguments for backend commands
    fn add_backend_args(self) -> Command {
        self
            // Mandatory arguments
            .arg(
                Arg::new("name")
                    .short('n')
                    .long("name")
                    .required(true)
                    .env("MIND_THE_NAME")
                    .help("Name to use on the cert and smartcard"),
            )
            .arg(
                Arg::new("email")
                    .short('m')
                    .long("email")
                    .num_args(1..)
                    .value_delimiter(',')
                    .required(true)
                    .env("MIND_THE_EMAILS")
                    .action(ArgAction::Append)
                    .help("Email addresses to add to cert, allows multiple"),
            )
            // Optional pin to protect exported secrets
            .arg(
                Arg::new("pin")
                    .short('i')
                    .long("pin")
                    .env("MIND_THE_PIN")
                    .help("Pin to protect smartcards and exported keys"),
            )
            // Optional target smart card by serial number
            .arg(
                Arg::new("card")
                    .short('c')
                    .long("card")
                    .env("MIND_THE_CARD")
                    .help("Serial number of smart card target")
            )
    }
}

// Helpers to parse duration
pub(crate) use humantime::parse_duration;

// Helpers to parse date
pub(crate) fn parse_date(input: &str) -> Result<DateTime<Utc>> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|e| anyhow!(e))
        .and_then(|dt| match Utc.from_local_datetime(&dt.and_hms_opt(0, 0, 0).expect("Static valid values")) {
            LocalResult::None => Err(anyhow!("No such local time")),
            LocalResult::Single(t) => Ok(t),
            LocalResult::Ambiguous(t1, t2) => Err(anyhow!(
                "Ambiguous local time, ranging from {:?} to {:?}",
                t1, t2
            )),
        })
}

/// Trait to easily extend clap matches
pub trait MindTheMatches {
    fn parse_common(&self) -> (MnemonicSeed, Option<Zeroizing<String>>);
    fn parse_backend(&self) -> (String, Vec<String>, Option<Zeroizing<String>>, Option<String>);
}

/// Standardized command line interfaces
impl MindTheMatches for ArgMatches {
    fn parse_common(&self) -> (MnemonicSeed, Option<Zeroizing<String>>) {
        // Use provided seed or generate new one
        let mut seed = if let Some(provided) = self.get_one::<MnemonicSeed>("mnemonic") {
            provided.clone()
        } else {
            MnemonicSeed::new()
        };

        match seed.source() {
            MnemonicSource::Random =>println!("- New random root seed: {}", seed.phrase()),
            MnemonicSource::Phrase =>println!("- Root seed from phrase: {}", seed.phrase()),
        };

        //Apply optional password
        if let Some(password) = self.get_one::<String>("password") {
            println!("- Root seed password: {}", password.as_str());
            seed = seed.with_password(password);
        }

        //Parse optional subkey
        let subkey: Option<Zeroizing<String>> = self.get_one::<String>("subkey").cloned().map(Into::into);
        if let Some(ref id) = subkey.as_ref() {
            println!("- Subkey derivation identifier: {}", id.as_str());
        }

        println!();

        (seed, subkey)
    }

    fn parse_backend(&self) -> (String, Vec<String>, Option<Zeroizing<String>>, Option<String>) {
        // Parse user name and emails
        let name = self.get_one::<String>("name").expect("Required argument").clone();
        let emails = self
            .get_many::<String>("email")
            .expect("Required argument")
            .cloned()
            .collect();

        // Parse export pin and card
        let pin = self.get_one::<String>("pin").cloned().map(Into::into);

        let card = self.get_one::<String>("card").cloned();

        (name, emails, pin, card)
    }
}

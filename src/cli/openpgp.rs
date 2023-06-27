use crate::cli::common::{parse_date, parse_duration, MindTheCommand, MindTheMatches};

use crate::openpgp;

use std::fs;

use clap::{Arg, ArgMatches, Command};

use anyhow::Result;

use chrono::{DateTime, Utc};
use std::time::Duration;

use sequoia_openpgp::serialize::SerializeInto;

pub fn subcmd() -> Command {
    Command::new("openpgp")
        .about("Initialize OpenPGP Smartcard from mnemonic seed")
        // Optional config flags for certificate generation
        .arg(
            Arg::new("date")
                .short('d')
                .long("date")
                .value_name("YYYY-MM-DD")
                .number_of_values(1)
                .value_parser(parse_date)
                .help("Creation date of the primary key"),
        )
        .arg(
            Arg::new("subdate")
                .long("subdate")
                .value_name("YYYY-MM-DD")
                .number_of_values(1)
                .value_parser(parse_date)
                .help("Creation date of the subkeys"),
        )
        .arg(
            Arg::new("validity")
                .short('v')
                .long("validity")
                .value_name("DURATION")
                .value_parser(parse_duration)
                .help("Validity duration of the subkeys"),
        )
        // Optional config flags for file output
        .arg(
            Arg::new("output-public")
                .long("output-public")
                .value_name("FILEPATH")
                .default_value("public.asc")
                .help("File path of public key output"),
        )
        .arg(
            Arg::new("output-secret")
                .long("output-secret")
                .value_name("FILEPATH")
                .default_value("secret.asc")
                .help("File path of secret key output"),
        )
        .arg(
            Arg::new("output-revcert")
                .long("output-revcert")
                .value_name("FILEPATH")
                .default_value("revcert.asc")
                .help("File path of revocation cert output"),
        )
        .add_common_args()
        .add_backend_args()
}

pub fn subrun(matches: &ArgMatches) -> Result<()> {
    // Parse creation dates
    let date = matches.get_one::<DateTime<Utc>>("date");
    let subdate = matches.get_one::<DateTime<Utc>>("subdate");

    if date.is_none() && subdate.is_none() {
        //TODO: Investigate or document better
        println!("WARNING: Key upload might fail if date is not set!");
    }

    // Parse validity duration
    let validity = matches.get_one::<Duration>("validity");

    // Parse output paths
    let output_public = matches
        .get_one::<String>("output-public")
        .expect("Default value provided");
    let output_secret = matches
        .get_one::<String>("output-secret")
        .expect("Default value provided");
    let output_revcert = matches
        .get_one::<String>("output-revcert")
        .expect("Default value provided");

    // Prepare root seed phrase and pasword
    println!("Preparing root seed...");

    // Parse phrase, password and subkey id
    let (seed, subkey) = matches.parse_common();

    let (name, emails, pin, card) = matches.parse_backend();

    // Prepare openpgp cert
    println!(
        "Generating OpenPGP Ed/Cv25519 certificate for '{}' ...",
        name
    );
    let mut builder = openpgp::SeededSmartcard::new(seed.derive(Some(b"openpgp")), subkey, name);

    // Add user identities
    for address in emails.into_iter() {
        println!("- Adding userid for email: {}", address);
        builder = builder.add_email(&address);
    }

    // Set creation date
    if let Some(date) = date {
        println!(
            "- Setting certificate creation time: {}",
            date.format("%Y-%m-%d %T")
        );
        builder = builder.with_creation_time((*date).into());
    }

    if let Some(date) = subdate {
        println!(
            "- Setting subkey creation time: {}",
            date.format("%Y-%m-%d %T")
        );
        builder = builder.with_subkey_creation_time((*date).into());
    }

    // Set validity period
    if let Some(validity) = validity {
        println!(
            "- Setting subkey validity duration: {}",
            humantime::format_duration(*validity)
        );
        builder = builder.with_subkey_validity(*validity);
    }

    // Apply pin to smartcard and cert
    if let Some(ref pin) = pin.as_ref() {
        println!("- Setting protection pin: {}", pin.as_str());
        builder = builder.with_pin((*pin).clone());
    }

    // Apply smartcard filter
    let card_target = match card {
        Some(ref serial) => match serial.as_str() {
            "off" | "disabled" | "none" => None,
            value => Some(value),
        },
        None => Some("auto"),
    };
    builder = builder.to_smartcard(card_target);

    // Display to which we export the secret keys
    println!();

    if let Some(serial) = card_target {
        println!("-> Exporting secret key to smartcard: {}", serial);
    } else {
        println!("-> Exporting secret key to file: {}", output_secret);
    }

    // This row is intentionally left blank.
    println!();

    // Generate and safe result
    let (cert, rev) = builder.generate()?;
    println!("New certificate generated: {}", cert);

    println!("- Saving public key file: {}", output_public);
    fs::write(output_public, cert.armored().to_vec()?)?;

    if card_target.is_none() {
        println!("- Saving secret key file: {}", output_secret);
        fs::write(output_secret, cert.as_tsk().armored().to_vec()?)?;
    }

    // TODO: Armor revocation certificate
    println!("- Saving revocation certificate: {}", output_revcert);
    fs::write(output_revcert, rev.to_vec()?)?;

    Ok(())
}

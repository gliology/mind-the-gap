use mind_the_gap::mnemonic::MnemonicSeed;
use mind_the_gap::openpgp::SeededEd25519Cert;

use std::fs;

use sequoia_openpgp::serialize::SerializeInto;

use chrono::{NaiveDate, Utc, LocalResult, TimeZone, DateTime };

use clap::{App, Arg};

// Helper trait for simple error reporting
trait ResultErrToString<T> {
    fn map_err_to_string(self) -> Result<T, String>;
}

impl<T, E: ToString> ResultErrToString<T> for Result<T, E> {
    fn map_err_to_string(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

// Helpers to parse duration
use humantime::parse_duration;

fn is_valid_duration(value: String) -> Result<(), String> {
    parse_duration(&value).map(|_| ()).map_err_to_string()
}


// Helpers to parse date
fn parse_date(input: &str) -> Result<DateTime<Utc>, String> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err_to_string()
        .and_then(|dt| {
            match Utc.from_local_datetime(&dt.and_hms(0,0,0)) {
                LocalResult::None => Err(String::from("No such local time")),
                LocalResult::Single(t) => Ok(t),
                LocalResult::Ambiguous(t1, t2) => {
                    Err(format!("Ambiguous local time, ranging from {:?} to {:?}", t1, t2))
                }
            }
        })
}

fn is_valid_date(value: String) -> Result<(), String> {
    parse_date(&value).map(|_| ())
}


/// Command line parse and execute
fn main() -> Result<(), String> {

    let matches = App::new("Mnemonic2PGP")
        .version("0.1.0")
        .author("Florian Franzen <florian@gli.al>")
        .about("Convert mnemonic key phrases to OpenPGP user certificates")

        .arg(Arg::with_name("phrase")
            .long("phrase")
            .short("1")
            .value_name("MNEMONIC")
            .number_of_values(1)
            .help("Mnemonic phrase for primary key"))
        .arg(Arg::with_name("subphrase")
            .long("subphrase")
            .short("2")
            .value_name("MNEMONIC")
            .number_of_values(1)
            .help("Mnemonic phrase for subkeys"))
        .arg(Arg::with_name("password")
             .short("p")
             .long("password")
             .value_name("PASSWORD")
             .number_of_values(1)
             .help("Password to protect primary key mnemonic"))
        .arg(Arg::with_name("subpassword")
             .long("subpassword")
             .value_name("PASSWORD")
             .number_of_values(1)
             .help("Password to protect subkey mnemonic"))

        .arg(Arg::with_name("name")
            .short("n")
            .long("name")
            .value_name("FIRST M. LAST")
            .number_of_values(1)
            .required(true)
            .help("Name to use on the cert and smartcard"))
          .arg(Arg::with_name("email")
            .short("m")
            .long("email")
            .value_name("FIRST.LAST@DOMAIN.COM")
            .number_of_values(1)
            .required(true)
            .multiple(true)
            .help("Email addresses to add to cert, allows multiple"))
       .arg(Arg::with_name("date")
             .short("d")
             .long("date")
             .value_name("YYYY-MM-DD")
             .number_of_values(1)
             .validator(is_valid_date)
             .help("Creation date of the primary key"))
        .arg(Arg::with_name("subdate")
             .long("subdate")
             .value_name("YYYY-MM-DD")
             .number_of_values(1)
             .validator(is_valid_date)
             .help("Creation date of the subkeys"))
         .arg(Arg::with_name("validity")
             .short("v")
             .long("validity")
             .value_name("DURATION")
             .number_of_values(1)
             .validator(is_valid_duration)
             .help("Validity duration of the subkeys"))

        .arg(Arg::with_name("output-card")
             .long("output-card")
             .value_name("ON|OFF|SERIAL")
             .number_of_values(1)
             .default_value("on")
             .help("If and to which smartcard to export the secret keys"))
        .arg(Arg::with_name("output-password")
             .long("output-password")
             .value_name("PASSWORD")
             .number_of_values(1)
             .help("Password with which to protect secret key output"))
        .arg(Arg::with_name("output-public")
             .long("output-public")
             .value_name("FILEPATH")
             .number_of_values(1)
             .default_value("public.asc")
             .help("File path of public key output"))
        .arg(Arg::with_name("output-secret")
             .long("output-secret")
             .value_name("FILEPATH")
             .number_of_values(1)
             .default_value("secret.asc")
             .help("File path of secret key output"))
        .arg(Arg::with_name("output-revcert")
             .long("output-revcert")
             .value_name("FILEPATH")
             .number_of_values(1)
             .default_value("revcert.asc")
             .help("File path of revocation cert output"))
        .get_matches();


    // Parse phrase and subphrase
    let phrase = matches.value_of("phrase");
    let subphrase = matches.value_of("subphrase");

    // Parse password and subpassword
    let password = matches.value_of("password");
    let subpassword = matches.value_of("subpassword");


    // Parse user identifier
    let name = matches.value_of("name").expect("Required argument");
    let emails = matches.values_of("email").expect("Required argument");

    // Parse creation dates
    let date = matches.value_of("date")
        .map(|d| parse_date(d).expect("Validator specified"));

    let subdate = matches.value_of("subdate")
        .map(|d| parse_date(d).expect("Validator specified"));

    // Parse validity duration
    let validity = matches.value_of("validity")
        .map(|d| parse_duration(d).expect("Validator specified"));


    // Parse output password
    let output_password = matches.value_of("output-password");

    // Parse output smartcard
    let output_card = matches.value_of("output-card").
        expect("Default value provided");

    // Parse output paths
    let output_public = matches.value_of("output-public")
        .expect("Default value provided");
    let output_secret = matches.value_of("output-secret")
        .expect("Default value provided");
    let output_revcert = matches.value_of("output-revcert")
        .expect("Default value provided");


    println!("Preparing mnemonic seeds...");

    // Prepare primary seed phrase and pasword
    let mut seed = if let Some(phrase) = phrase {
        MnemonicSeed::from_phrase(phrase).map_err_to_string()?
    } else {
        MnemonicSeed::new()
    };
    println!("- Primary key seed phrase: {}", seed.phrase());

    if let Some(password) = password {
        println!("- Primary key seed password: {}", password);
        seed = seed.with_password(password);
    }

    // Prepare subkey seed phrase and password
    let mut subseed = if let Some(subphrase) = subphrase {
        MnemonicSeed::from_phrase(subphrase).map_err_to_string()?
    } else {
        MnemonicSeed::new()
    };
    println!("- Subkey seed phrase: {}", subseed.phrase());

    if let Some(password) = subpassword {
        println!("- Subkey seed password: {}", password);
        subseed = subseed.with_password(password);
    }

    println!();


    // Prepare openpgp cert
    println!("Generating OpenPGP Ed/Cv25519 certificate for '{}' ...", name);
    let mut builder = SeededEd25519Cert::new(seed, name, subseed);

    // Set creation date
    if let Some(date) = date {
        println!("- Setting certificate creation time: {}", date.format("%Y-%m-%d %T"));
        builder = builder.with_creation_time(date.into());
    }

    if let Some(date) = subdate {
        println!("- Setting subkey creation time: {}", date.format("%Y-%m-%d %T"));
        builder = builder.with_subkey_creation_time(date.into());
    }

    // Set validity period
    if let Some(validity) = validity {
        println!("- Setting subkey validity duration: {}", humantime::format_duration(validity));
        builder = builder.with_subkey_validity(validity);
    }

    // Add user identities
    for address in emails.into_iter() {
        println!("- Adding email identifier: {}", address);
        builder = builder.add_email(address);
    }

    // Apply password to cert
    if let Some(password) = output_password {
        println!("- Adding password protection: {}", password);
        builder = builder.with_password(password);
    }

    // Apply smartcard filter
    let card_target = match output_card {
        "on" => Some("auto"),
        "ON" => Some("auto"),
        "off" => None,
        "OFF" => None,
        value => Some(value),
    };
    builder = builder.to_smartcard(card_target);

    println!();

    if let Some(serial) = card_target {
        println!("-> Exporting secret key to smartcard: {}", serial);
    } else {
        println!("-> Exporting secret key to file: {}", output_secret);
    }

    // This row is intentionally left blank.
    println!();

    // Generate and safe result
    let (cert, rev) = builder.generate().map_err_to_string()?;
    println!("New certificate generated: {}", cert);

    println!("- Saving public key file: {}", output_public);
    fs::write(output_public,
              cert.armored().to_vec().map_err_to_string()?
    ).map_err_to_string()?;

    if card_target.is_none() {
        println!("- Saving secret key file: {}", output_secret);
        fs::write(output_secret,
              cert.as_tsk().armored().to_vec().map_err_to_string()?
        ).map_err_to_string()?;
    }

    // TODO: Armor revocation certificate
    println!("- Saving revocation certificate: {}", output_revcert);
    fs::write(output_revcert,
              rev.to_vec().map_err_to_string()?
    ).map_err_to_string()?;

    Ok(())
}

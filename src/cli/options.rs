//! The one option table: every option a command takes, declared once.
//!
//! Each option is a field of one of the groups below, and its long name is also its config
//! key, its `set` name in a session or ceremony, and, upper-cased behind `MIND_THE_`, its
//! environment variable. A verb flattens the groups it takes, so an option means the same
//! wherever it appears. Secrets are options too, for scripts, but never config keys.

use crate::pgp;
use crate::piv;
use crate::policy::Policy;
use crate::role::KeyRole;
use crate::seed::{Algorithm, KeyPath};
use crate::target::CardTarget;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use chrono::{Days, Months, NaiveDate};

use clap::Args;

use zeroize::Zeroizing;

/// An applet a card carries
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum App {
    /// The PIV application: X.509 certificates, smart card logon, S/MIME
    Piv,
    /// The OpenPGP application
    Pgp,
}

impl App {
    /// The name messages use for the applet
    pub(super) fn name(self) -> &'static str {
        match self {
            App::Piv => "PIV",
            App::Pgp => "OpenPGP",
        }
    }
}

/// Which applet a command acts on
#[derive(Args, Clone, Default)]
pub(super) struct AppArgs {
    /// The applet to act on; both where omitted, each where the card carries it
    #[arg(help_heading = "Card", long, value_enum, env = "MIND_THE_APP")]
    pub app: Option<App>,
}

impl AppArgs {
    /// The applets chosen, and whether they were named rather than defaulted
    pub(super) fn apps(&self) -> (Vec<App>, bool) {
        match self.app {
            Some(app) => (vec![app], true),
            None => (vec![App::Piv, App::Pgp], false),
        }
    }
}

/// Which card a command addresses
#[derive(Args, Clone, Default)]
pub(super) struct CardArgs {
    /// Card to address: a PIV serial, an OpenPGP identifier (MMMM:SSSSSSSS) or a reader
    /// name, as `list` shows them; the one attached card where omitted
    #[arg(help_heading = "Card", short, long, value_name = "CARD", env = "MIND_THE_CARD")]
    pub card: Option<CardTarget>,
}

/// How keys are derived, whichever key seed they come from
#[derive(Args, Clone, Default)]
pub(super) struct DeriveArgs {
    /// Algorithm every key is derived with: P-256 for PIV and Curve25519 for OpenPGP where
    /// omitted; p384 is PIV only
    #[arg(help_heading = "Derivation", long, value_enum, env = "MIND_THE_ALGORITHM")]
    pub algorithm: Option<Algorithm>,

    /// Derive OpenPGP keys and the admin pin under the legacy scheme (mtg0), from one seed,
    /// for cards provisioned before 1.0
    #[arg(help_heading = "Derivation", long, env = "MIND_THE_LEGACY")]
    pub legacy: bool,
}

/// Where the usable keys sit under the key seed
#[derive(Args, Clone, Default)]
pub(super) struct PathArgs {
    /// The device or application the keys are bound to: a step of the derivation, no secret,
    /// and named in no certificate
    #[arg(help_heading = "Derivation", short = 'k', long, env = "MIND_THE_SUBKEY")]
    pub subkey: Option<String>,

    /// The key generation: a step of the derivation, and the day its keys and certificates
    /// were created (the identity date where omitted, or none, created at the epoch)
    #[arg(
        help_heading = "Derivation",
        short,
        long,
        value_name = "YYYY-MM-DD",
        env = "MIND_THE_DATE",
        value_parser = parse_date
    )]
    pub date: Option<NaiveDate>,
}

impl PathArgs {
    /// The key path these options name
    pub(super) fn path(&self) -> KeyPath {
        KeyPath { subkey: self.subkey.clone(), date: self.date }
    }
}

/// Who the identity is, as its certificates name it
#[derive(Args, Clone, Default)]
pub(super) struct IdentityArgs {
    /// Common name of the identity, on every certificate and as the cardholder; at most 40
    /// characters where PIV's certificates carry it
    #[arg(help_heading = "Identity", short, long, env = "MIND_THE_NAME")]
    pub name: Option<String>,

    /// Email addresses of the identity, comma separated: OpenPGP user ids, PIV alternative
    /// names
    #[arg(
        help_heading = "Identity",
        short = 'm',
        long,
        value_delimiter = ',',
        env = "MIND_THE_EMAILS",
        value_parser = parse_email
    )]
    pub emails: Vec<String>,

    /// Organization (O) of the PIV certificate subjects, at most 64 characters
    #[arg(help_heading = "Identity", long, env = "MIND_THE_ORG")]
    pub org: Option<String>,

    /// Organizational unit (OU) of the PIV certificate subjects, at most 64 characters
    #[arg(help_heading = "Identity", long, env = "MIND_THE_UNIT")]
    pub unit: Option<String>,

    /// ISO country code (C) of the PIV certificate subjects, two uppercase letters such as DE
    #[arg(help_heading = "Identity", long, value_name = "CC", env = "MIND_THE_COUNTRY")]
    pub country: Option<String>,

    /// When the identity was created: the OpenPGP primary key and the PIV root authority,
    /// whose fingerprints it is part of, and the generation of keys without a --date (the
    /// epoch where omitted)
    #[arg(
        help_heading = "Identity",
        long,
        value_name = "YYYY-MM-DD",
        env = "MIND_THE_IDENTITY_DATE",
        value_parser = parse_date
    )]
    pub identity_date: Option<NaiveDate>,

    /// How long the keys' certificates are valid, counted on the calendar from the day the
    /// keys were created: days, weeks, months or years, as 730d, 2w, 6mo or 2y (unlimited
    /// where omitted)
    #[arg(
        help_heading = "Identity",
        long,
        value_name = "PERIOD",
        env = "MIND_THE_VALIDITY",
        value_parser = parse_validity
    )]
    pub validity: Option<Validity>,

    /// Where the PIV revocation lists are published, as a URL ending in a list's name with
    /// .crl: each list is published beside it, under that name with the root's algorithm
    /// added and an issuing authority's tag after it (alice.crl names alice-p256.crl and
    /// alice-p256-issuing-9b3e5d17.crl), and every certificate names its issuer's list (none
    /// where omitted)
    #[arg(help_heading = "Identity", long, value_name = "URL", env = "MIND_THE_CRL_URL")]
    pub crl_url: Option<String>,

    /// Insert an intermediate issuing authority between the PIV root and the slot
    /// certificates, one per device and generation
    #[arg(help_heading = "Identity", long, env = "MIND_THE_INTERMEDIATE")]
    pub intermediate: bool,
}

/// Which usable keys a command acts on
#[derive(Args, Clone, Default)]
pub(super) struct KeyArgs {
    /// The keys to act on, comma separated (all three where omitted)
    #[arg(help_heading = "Keys", long, value_enum, value_delimiter = ',', env = "MIND_THE_KEY")]
    pub key: Vec<KeyRole>,

    /// The PIV slot the decryption key goes to instead of 9d: a retired slot from 82 to 95,
    /// to keep a previous or another identity's key
    #[arg(
        help_heading = "Keys",
        long,
        value_name = "SLOT",
        env = "MIND_THE_SLOT",
        value_parser = parse_slot
    )]
    pub slot: Option<u8>,
}

/// The pin and touch requirements, and what else administers a card
#[derive(Args, Clone, Default)]
pub(super) struct PolicyArgs {
    /// Pin and touch requirements of the keys, and of PIV management access (relaxed where
    /// omitted; see the policies chapter of the book)
    #[arg(help_heading = "Card", long, value_enum, env = "MIND_THE_POLICY")]
    pub policy: Option<Policy>,

    /// Make the OpenPGP touch requirement unchangeable but by replacing the key, where the
    /// card offers it (YubiKeys)
    #[arg(help_heading = "Card", long, env = "MIND_THE_FIXED_TOUCH")]
    pub fixed_touch: bool,

    /// Algorithm of the PIV management key `init` installs (auto picks by firmware)
    #[arg(
        help_heading = "Card",
        long,
        value_name = "ALGORITHM",
        value_enum,
        env = "MIND_THE_MANAGEMENT_ALGORITHM"
    )]
    pub management_algorithm: Option<piv::ManagementKeyArg>,

    /// Whether OpenPGP `init` makes the card take hashed pins through its KDF data object
    /// (auto: on a Gnuk, which depends on it)
    #[arg(help_heading = "Card", long, value_enum, env = "MIND_THE_KDF")]
    pub kdf: Option<pgp::Kdf>,

    /// Do not store the PIV certificate authorities in the card's msroots object
    #[arg(help_heading = "Card", long, env = "MIND_THE_NO_MSROOTS")]
    pub no_msroots: bool,
}

/// OpenPGP cardholder data, written only when given
#[derive(Args, Clone, Default)]
pub(super) struct CardDataArgs {
    /// Cardholder language preferences (ISO 639-1), most preferred first; where omitted,
    /// `init` writes English and `upload` leaves the card's as they are
    #[arg(
        help_heading = "Card",
        long,
        value_name = "LANG",
        value_delimiter = ',',
        env = "MIND_THE_LANG",
        value_parser = parse_lang
    )]
    pub lang: Vec<[u8; 2]>,

    /// URL where the public certificate can be fetched
    #[arg(help_heading = "Card", long, env = "MIND_THE_URL")]
    pub url: Option<String>,

    /// Login data, conventionally an account or user name
    #[arg(help_heading = "Card", long, env = "MIND_THE_LOGIN")]
    pub login: Option<String>,
}

impl CardDataArgs {
    pub(super) fn data(&self) -> crate::pgp::CardData {
        crate::pgp::CardData {
            lang: self.lang.clone(),
            url: self.url.clone(),
            login: self.login.clone(),
        }
    }
}

/// What every command that writes to a card takes
#[derive(Args, Clone, Default)]
pub(super) struct WriteArgs {
    /// Write without asking first
    #[arg(help_heading = "Writing", short, long)]
    pub yes: bool,

    /// Only show what would be written
    #[arg(help_heading = "Writing", long)]
    pub dry_run: bool,
}

/// What a command that writes files only takes: it asks nothing, as nothing it writes
/// replaces what is on a card
#[derive(Args, Clone, Default)]
pub(super) struct DryRunArgs {
    /// Only show what would be written
    #[arg(help_heading = "Writing", long)]
    pub dry_run: bool,
}

/// Where material leaving the gap goes
#[derive(Args, Clone, Default)]
pub(super) struct OutputArgs {
    /// Where the material goes: a file, a directory for several pieces, or `-` for stdout
    /// (never for a secret); QR codes on the terminal where omitted
    #[arg(help_heading = "Writing", short = 'o', long, value_name = "PATH")]
    pub to: Option<PathBuf>,
}

/// The user pin a command sets, checks or protects an export with
#[derive(Args, Clone, Default)]
pub(super) struct PinArgs {
    /// User pin (a session asks for it where it matters)
    #[arg(short = 'i', long, env = "MIND_THE_PIN")]
    pub pin: Option<Zeroizing<String>>,
}

/// How long certificates are valid: a count of calendar units from the day the keys were
/// created
///
/// Calendar units only, because a certificate's validity is planned in them: a fixed-length
/// year would end a `2y` validity at noon two days off its anniversary, and minutes or hours
/// are no period a key is used for, while `24m` read as minutes once issued certificates that
/// expired during the ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Validity {
    count: u32,
    unit: CalendarUnit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CalendarUnit {
    Days,
    Weeks,
    Months,
    Years,
}

impl CalendarUnit {
    /// The unit as a validity spells it
    fn suffix(self) -> &'static str {
        match self {
            CalendarUnit::Days => "d",
            CalendarUnit::Weeks => "w",
            CalendarUnit::Months => "mo",
            CalendarUnit::Years => "y",
        }
    }
}

impl std::fmt::Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.count, self.unit.suffix())
    }
}

impl Validity {
    /// The day the validity ends on, at its midnight, for keys created on `created`
    ///
    /// Months and years count as a calendar does: the same day of the month that many months
    /// on, or the month's last day where it is shorter, so a month from January 31st ends on
    /// the last day of February, and a year from February 29th on February 28th.
    pub(super) fn end(self, created: NaiveDate) -> Result<NaiveDate> {
        let end = match self.unit {
            CalendarUnit::Days => created.checked_add_days(Days::new(self.count.into())),
            CalendarUnit::Weeks => created.checked_add_days(Days::new(u64::from(self.count) * 7)),
            CalendarUnit::Months => created.checked_add_months(Months::new(self.count)),
            CalendarUnit::Years => self
                .count
                .checked_mul(12)
                .and_then(|months| created.checked_add_months(Months::new(months))),
        };
        // OpenPGP counts an expiry in unsigned 32-bit seconds, which wrap past the last day a
        // key can be created on: a later end would read as a day long gone
        match end {
            Some(end) if end <= LAST_DAY => Ok(end),
            _ => bail!(
                "A validity of {self} from {created} ends after {LAST_DAY}, the last day a \
                 certificate's end can be told on; give a shorter one, or leave --validity out \
                 for certificates without an end"
            ),
        }
    }

    /// The validity as the builders take it: from midnight of the day the keys were created
    /// to midnight of the day it ends
    pub(super) fn duration_from(self, created: NaiveDate) -> Result<Duration> {
        let end = self.end(created)?;
        Ok(crate::seed::midnight(end)
            .duration_since(crate::seed::midnight(created))
            .expect("a validity ends after it starts"))
    }
}

/// Parse a `--validity`: a count and a calendar unit, `d`, `w`, `mo` or `y`
fn parse_validity(input: &str) -> Result<Validity> {
    let units = "a validity is counted in days, weeks, months or years, as 730d, 2w, 6mo or 2y";
    let digits = input.len() - input.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let (count, suffix) = input.split_at(digits);
    if count.is_empty() {
        bail!("'{input}' is no period: {units}");
    }
    let unit = match suffix {
        "d" => CalendarUnit::Days,
        "w" => CalendarUnit::Weeks,
        "mo" => CalendarUnit::Months,
        "y" => CalendarUnit::Years,
        "m" => bail!("'{input}' would be minutes: {units}, so months are `mo`"),
        "" => bail!("'{input}' has no unit: {units}"),
        _ => bail!("'{input}' is not in calendar units: {units}"),
    };
    let count: u32 = count
        .parse()
        .map_err(|_| anyhow!("'{input}' counts more than a validity can: {units}"))?;
    if count == 0 {
        bail!("'{input}' is no validity at all: {units}");
    }
    Ok(Validity { count, unit })
}

/// The last day a key can be created on, or a validity end on: OpenPGP keeps both times in
/// unsigned 32-bit seconds, which run out on it
const LAST_DAY: NaiveDate = NaiveDate::from_ymd_opt(2106, 2, 7).expect("a valid date");

/// Parse a `--date`: a day, which every derivation reads as midnight UTC
fn parse_date(input: &str) -> Result<NaiveDate> {
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|err| anyhow!("'{input}' is not a date as YYYY-MM-DD: {err}"))?;
    // The day is also the keys' creation time, which OpenPGP keeps as unsigned 32-bit
    // seconds: outside that range it would not read back as the generation it names
    let first = NaiveDate::from_ymd_opt(1970, 1, 1).expect("a valid date");
    if !(first..=LAST_DAY).contains(&date) {
        bail!("'{input}' is outside the days a key can be created on, {first} to {LAST_DAY}");
    }
    Ok(date)
}

/// Parse one address of `--emails`, without the spaces a list typed as `a@x, b@x` leaves
fn parse_email(input: &str) -> Result<String> {
    Ok(input.trim().to_string())
}

/// Parse a `--slot`: two hex digits
fn parse_slot(input: &str) -> Result<u8> {
    u8::from_str_radix(input.trim_start_matches("0x"), 16)
        .map_err(|_| anyhow!("'{input}' is not a slot number such as 9d or 82"))
}

/// Parse one ISO 639-1 language code
fn parse_lang(s: &str) -> Result<[u8; 2], String> {
    match s.as_bytes() {
        [a, b] if a.is_ascii_lowercase() && b.is_ascii_lowercase() => Ok([*a, *b]),
        _ => Err(format!("'{s}' is not a two-letter ISO 639-1 code, e.g. en")),
    }
}

//! The clap command line: the verbs, the seeds, and the run loop.
//!
//! One grammar for everything: a one-shot invocation, a line of the interactive session and
//! a step of a ceremony are all parsed by [`command`], verb first, with the applet an option.
//! Secret-bearing arguments are `Zeroizing<String>`. A one-shot invocation takes them from
//! flags or `MIND_THE_...` variables and fails when one is missing; only the interactive
//! session prompts, so a script can never hang on a hidden prompt.

mod ceremony;
mod completion;
mod config;
mod generate;
mod logging;
mod options;
mod output;
mod plumbing;
mod reference;
mod seeds;
mod session;
mod verbs;

pub use completion::complete;
pub use logging::install_logger;
use options::{
    App, AppArgs, CardArgs, CardDataArgs, DeriveArgs, DryRunArgs, IdentityArgs, KeyArgs,
    OutputArgs, PathArgs, PinArgs, PolicyArgs, WriteArgs,
};
pub use reference::{REGENERATE, reference};
use session::Session;

use crate::pgp;
use crate::revocation::RevocationKind;

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Result, bail};

use clap::{Args, Command, CommandFactory, FromArgMatches, Parser, Subcommand};

use zeroize::Zeroizing;

/// The parsed command line: the seeds, the process options and the verb
// Deliberately not `Debug`: the struct carries the seed phrases, passwords and pins, and a
// stray `{:?}` must not be able to print them. The process options are declared before the
// seeds because clap orders a verb's help headings as their options are declared, and the
// seeds come last there.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Logging filter, like MIND_THE_LOG_LEVEL (the flag wins)
    ///
    /// Same grammar as env_logger, e.g. `info` or `mind_the_gap=debug`. Applied when the
    /// process starts, so a session keeps the level it started with. Card traffic, which
    /// carries pins and key bytes, is never logged above info.
    #[arg(
        help_heading = "Process",
        long,
        global = true,
        value_name = "FILTER",
        env = "MIND_THE_LOG_LEVEL"
    )]
    log_level: Option<String>,

    /// Plumbing mode for automation: never prompt, report one JSON object per command on
    /// stdout, and stop at the first error
    #[arg(help_heading = "Process", long, global = true, env = "MIND_THE_PLUMBING")]
    plumbing: bool,

    /// Config file to read defaults from, in place of the user's,
    /// $XDG_CONFIG_HOME/mind-the-gap/config.toml (~/.config/mind-the-gap/config.toml by
    /// default); `set` alone shows the files read
    #[arg(
        help_heading = "Process",
        long,
        global = true,
        value_name = "FILE",
        env = "MIND_THE_CONFIG"
    )]
    config: Option<PathBuf>,

    #[command(flatten)]
    seeds: SeedArgs,

    /// The verb to run; omitted, an interactive session starts, or on the image the default
    /// ceremony
    #[command(subcommand)]
    verb: Option<Verb>,
}

/// The seeds, each a phrase and its password
///
/// One seed is both the card seed and the key seed. Either may be given apart from it: the
/// card seed administers cards, the key seed derives an identity and its keys. Without a
/// value, `--card-seed` and `--key-seed` ask for that seed in a session.
#[derive(Args, Clone, Default)]
struct SeedArgs {
    /// Mnemonic seed phrase: the card seed and the key seed, where neither is given apart
    ///
    /// Required for any command that derives: a one-shot invocation fails without it rather
    /// than stopping on a prompt, and no command ever invents a seed on its own. Use
    /// `generate` to mint one, or run without a verb for an interactive session, which asks
    /// for the phrase once and keeps it off the command line entirely.
    #[arg(help_heading = "Seeds", short, long, global = true, env = "MIND_THE_SEED")]
    pub seed: Option<Zeroizing<String>>,

    /// Password of the seed phrase; a typo derives other keys, so `check` shows the seed id
    #[arg(help_heading = "Seeds", short, long, global = true, env = "MIND_THE_PASSWORD")]
    pub password: Option<Zeroizing<String>>,

    /// Card seed phrase, which administers cards, apart from the seed (asked for in a
    /// session when given without a value)
    #[arg(
        help_heading = "Seeds",
        long,
        global = true,
        env = "MIND_THE_CARD_SEED",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        value_name = "PHRASE"
    )]
    pub card_seed: Option<Zeroizing<String>>,

    /// Password of the card seed phrase
    #[arg(help_heading = "Seeds", long, global = true, env = "MIND_THE_CARD_PASSWORD")]
    pub card_password: Option<Zeroizing<String>>,

    /// Key seed phrase, which derives the identity and its keys, apart from the seed (asked
    /// for in a session when given without a value)
    #[arg(
        help_heading = "Seeds",
        long,
        global = true,
        env = "MIND_THE_KEY_SEED",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        value_name = "PHRASE"
    )]
    pub key_seed: Option<Zeroizing<String>>,

    /// Password of the key seed phrase
    #[arg(help_heading = "Seeds", long, global = true, env = "MIND_THE_KEY_PASSWORD")]
    pub key_password: Option<Zeroizing<String>>,
}

/// The verbs, one per action
#[derive(Subcommand, Clone)]
enum Verb {
    /// Mint a new seed phrase and confirm it was written down
    ///
    /// The only place this tool mints key material: no command ever invents a seed on its
    /// own. The phrase stays on screen until its transcription is verified word by word,
    /// then the screen is wiped so it survives only on paper.
    Generate,

    /// List the attached cards, their applets and keys; with a seed, whose they are
    ///
    /// Reads only what the cards show without a pin, and leaves every card as it was found,
    /// so it is safe with any number of cards attached, in use or not.
    List {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        keys: KeyArgs,
    },

    /// Show what the seeds derive, and compare a card with it
    ///
    /// The seed ids and the identity's fingerprints first, to compare with a record kept with
    /// the phrase; then, with a card attached, whether the card seed initialized it and
    /// whether it holds the chosen keys. Never writes.
    Check {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        keys: KeyArgs,
        #[command(flatten)]
        pin: PinArgs,
        #[command(flatten)]
        policy: PolicyArgs,
    },

    /// Reset a card and give it what the card seed derives for it
    ///
    /// Erases the card's applets, then installs the card's own credentials (the PIV
    /// management key and puk, the OpenPGP admin pin), its identifiers and the PIV card
    /// authentication key, and sets the user pin. No key of the identity's: `upload` adds
    /// those. Asks before the reset and names the card.
    Init {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        card_data: CardDataArgs,
        #[command(flatten)]
        pin: PinArgs,
        #[command(flatten)]
        write: WriteArgs,
    },

    /// Put the key seed's keys and certificates onto a card the card seed initialized
    ///
    /// Compares the card with what the seeds derive and writes only what differs, so it
    /// repairs, re-certifies and changes policies as readily as it provisions. Lists what it
    /// would write before asking.
    Upload {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        keys: KeyArgs,
        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        card_data: CardDataArgs,
        #[command(flatten)]
        write: WriteArgs,
    },

    /// Move a card to a new key generation (`--date`), or off a leaked key seed
    ///
    /// Reads the generation the card holds, keeps its PIV decryption key in a retired slot,
    /// then uploads the new generation. Publish the new certificates afterwards, and revoke
    /// the previous generation's.
    Rotate {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        policy: PolicyArgs,

        /// The key seed the card's keys come from now, when the rotation moves off it
        /// (asked for in a session when given without a value)
        #[arg(
            long,
            env = "MIND_THE_FROM_KEY_SEED",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "",
            value_name = "PHRASE"
        )]
        from_key_seed: Option<Zeroizing<String>>,

        /// Password of the key seed the card's keys come from now
        #[arg(long, env = "MIND_THE_FROM_KEY_PASSWORD")]
        from_key_password: Option<Zeroizing<String>>,

        #[command(flatten)]
        write: WriteArgs,
    },

    /// Change a card's user pin with the current one, or with `--reset` set a new one with
    /// the card seed
    Pin {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,

        /// The new user pin (a session asks for it twice)
        #[arg(short = 'i', long, env = "MIND_THE_PIN")]
        pin: Option<Zeroizing<String>>,

        /// The card's current user pin (a session asks for it)
        #[arg(long, value_name = "PIN", env = "MIND_THE_CURRENT_PIN")]
        current_pin: Option<Zeroizing<String>>,

        /// Set the new pin with the card seed's puk (PIV) or admin pin (OpenPGP) instead of
        /// the current one, which also unblocks a blocked pin
        #[arg(long)]
        reset: bool,

        #[command(flatten)]
        write: WriteArgs,
    },

    /// Reset a card's applets without giving it anything, to retire or hand it on
    Wipe {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        card: CardArgs,
        #[command(flatten)]
        derive: DeriveArgs,

        /// Wipe a card this card seed did not initialize
        #[arg(long)]
        force: bool,

        #[command(flatten)]
        write: WriteArgs,
    },

    /// Certify another identity's OpenPGP certificate with the key seed's identity
    Trust {
        /// The certificate to certify
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// How well the identity claim was verified
        #[arg(long, value_enum, default_value_t)]
        level: pgp::VerificationKind,

        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        output: OutputArgs,
    },

    /// Revoke a device's keys, a decryption key, or the whole identity
    ///
    /// OpenPGP revocation signatures, and for PIV a revocation list signed by the identity's
    /// authority. A revocation is a capability, so it is written like a secret.
    Revoke {
        #[command(flatten)]
        app: AppArgs,

        /// What the revocation covers: `subkeys` retires this device's keys of this
        /// generation, `certificate` the whole identity and every card with it
        // Required on purpose: the one choice here that cannot be taken back has no default
        #[arg(long, value_enum)]
        kind: RevocationKind,

        /// Revocation reason: 0 unspecified, 1 superseded, 2 compromised, 3 retired
        ///
        /// A lost or stolen card is 2 if the pin may be known, else 3.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
        code: u8,

        /// Human-readable revocation reason
        #[arg(long, default_value = "Unspecified")]
        reason: String,

        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        keys: KeyArgs,
        #[command(flatten)]
        output: OutputArgs,
        #[command(flatten)]
        write: DryRunArgs,
    },

    /// Write public material out of the gap: certificates, SSH keys, a WKD layout
    Publish {
        #[command(flatten)]
        app: AppArgs,

        /// Which part to publish
        #[arg(long, value_enum, default_value_t)]
        part: output::Part,

        /// The format to write it in
        #[arg(long, value_enum, default_value_t)]
        format: output::Format,

        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        keys: KeyArgs,
        #[command(flatten)]
        output: OutputArgs,
    },

    /// Write secret keys out of the gap, encrypted under `--pin`, for software use or escrow
    ///
    /// OpenPGP keys as a secret key certificate, PIV keys as encrypted PKCS#8 next to their
    /// certificates.
    Ungap {
        #[command(flatten)]
        app: AppArgs,
        #[command(flatten)]
        derive: DeriveArgs,
        #[command(flatten)]
        path: PathArgs,
        #[command(flatten)]
        identity: IdentityArgs,
        #[command(flatten)]
        keys: KeyArgs,
        #[command(flatten)]
        pin: PinArgs,
        #[command(flatten)]
        output: OutputArgs,
    },

    /// Run a ceremony: a recipe from a ceremony file, after the recipes it depends on
    Run {
        /// The recipe to run (the file's first where omitted)
        recipe: Option<String>,

        /// The ceremony file (the user's, or the image's, where omitted)
        #[arg(long, value_name = "FILE", env = "MIND_THE_CEREMONY")]
        ceremony: Option<PathBuf>,

        /// Keep a transcript of the ceremony, never a secret, in this directory
        #[arg(long, value_name = "DIR", env = "MIND_THE_RECORD")]
        record: Option<PathBuf>,

        /// Only show the steps, and what the writing ones would write
        #[arg(long)]
        dry_run: bool,

        /// Check the whole ceremony file and list the recipe's steps, running none: no card
        /// is touched and no seed asked for
        #[arg(long, conflicts_with_all = ["dry_run", "record"])]
        check: bool,
    },

    /// Set session defaults, `name=value`, by the options' long names; alone, show them
    Set {
        /// Also write the defaults to the user's config file, where they outlast the session;
        /// the one way to set them on the command line
        #[arg(long, requires = "settings")]
        save: bool,

        /// The defaults to set
        #[arg(value_name = "NAME=VALUE")]
        settings: Vec<String>,
    },

    /// Forget defaults in force, each back to the one beneath it: the environment's, a
    /// config file's or the built-in one
    Unset {
        /// Also take the defaults out of the user's config file; the one way to forget them
        /// on the command line
        #[arg(long)]
        save: bool,

        /// The defaults to forget
        #[arg(value_name = "NAME", required = true)]
        names: Vec<String>,
    },

    /// Leave the session
    Quit,
}

/// How a command takes one of the seeds
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeedUse {
    /// Not at all
    Unused,
    /// When it is at hand without asking: a listing says more with it, and works without
    IfKnown,
    /// Always: asked for once in a session, an error without in a one-shot invocation
    Required,
}

impl Verb {
    /// How the verb takes the card seed and the key seed
    pub(super) fn seed_use(&self) -> (SeedUse, SeedUse) {
        use SeedUse::*;
        match self {
            Verb::Generate | Verb::Run { .. } | Verb::Set { .. } | Verb::Unset { .. } => {
                (Unused, Unused)
            }
            Verb::Quit => (Unused, Unused),
            Verb::List { .. } => (IfKnown, IfKnown),
            Verb::Check { .. } | Verb::Upload { .. } | Verb::Rotate { .. } => (Required, Required),
            Verb::Init { .. } => (Required, Unused),
            // The legacy scheme derives the admin pin from the one seed
            Verb::Pin { reset: true, .. } => (Required, Unused),
            Verb::Pin { .. } => (Unused, Unused),
            Verb::Wipe { force: true, .. } => (Unused, Unused),
            Verb::Wipe { .. } => (Required, Unused),
            Verb::Trust { .. }
            | Verb::Revoke { .. }
            | Verb::Publish { .. }
            | Verb::Ungap { .. } => (Unused, Required),
        }
    }

    /// The verb as its first word names it
    pub(super) fn name(&self) -> &'static str {
        match self {
            Verb::Generate => "generate",
            Verb::List { .. } => "list",
            Verb::Check { .. } => "check",
            Verb::Init { .. } => "init",
            Verb::Upload { .. } => "upload",
            Verb::Rotate { .. } => "rotate",
            Verb::Pin { .. } => "pin",
            Verb::Wipe { .. } => "wipe",
            Verb::Trust { .. } => "trust",
            Verb::Revoke { .. } => "revoke",
            Verb::Publish { .. } => "publish",
            Verb::Ungap { .. } => "ungap",
            Verb::Run { .. } => "run",
            Verb::Set { .. } => "set",
            Verb::Unset { .. } => "unset",
            Verb::Quit => "quit",
        }
    }
}

/// Return the clap command, for testing and documentation
///
/// `quit` leaves a session and has nothing to do on the command line, so its help and the
/// man pages leave it out.
pub fn command() -> Command {
    let command = Cli::command();
    let names = config::settable_names(&command);
    command
        .long_version(version())
        .mut_subcommand("quit", |quit| quit.hide(true))
        .mut_subcommand("set", |set| set.after_long_help(names.clone()))
        .mut_subcommand("unset", |unset| unset.after_long_help(names))
}

/// The release, the derivation scheme its keys come from, and the source revision where the
/// build was told it, as `--version` says it and a ceremony transcript records it
///
/// The scheme decides which keys a seed derives, so a record has to name it as much as the
/// release. The revision is given by the build of the released image alone: every other build
/// leaves it out, so that a change to no source rebuilds nothing.
fn version() -> String {
    let scheme = crate::seed::SCHEME_VERSION;
    match option_env!("MIND_THE_GAP_REVISION") {
        Some(revision) => {
            format!("{} (scheme {scheme}, revision {revision})", env!("CARGO_PKG_VERSION"))
        }
        None => format!("{} (scheme {scheme})", env!("CARGO_PKG_VERSION")),
    }
}

/// The process options, fixed when the program starts, which no session line changes
const PROCESS_OPTIONS: [&str; 3] = ["log_level", "plumbing", "config"];

/// The secrets no session line carries: the seed phrase and the passwords, fixed for the
/// session or asked for
const LINE_SECRETS: [&str; 4] = ["seed", "password", "card_password", "key_password"];

/// The command a session line or a ceremony step is parsed with
///
/// A line has no program name, so neither has the usage its help shows, and the help leaves
/// out the options a line cannot change. They are hidden rather than removed: a line that
/// names one still parses, and is refused with the reason. The seed flags stay, said the way a
/// line takes them: bare, they ask for that seed.
fn session_command() -> Command {
    let asks = |seed: &str| {
        format!(
            "Ask for the {seed} for this line alone, on a hidden prompt; a phrase on the line is refused"
        )
    };
    let mut command = command()
        .no_binary_name(true)
        .override_usage("<COMMAND> [OPTIONS]")
        .mut_subcommand("quit", |quit| quit.hide(false))
        .mut_arg("card_seed", |arg| arg.help(asks("card seed")))
        .mut_arg("key_seed", |arg| arg.help(asks("key seed")))
        .mut_subcommand("rotate", |rotate| {
            rotate
                .mut_arg("from_key_seed", |arg| {
                    arg.help(
                        "Ask for the key seed the card's keys come from now, on a hidden \
                         prompt; a phrase on the line is refused",
                    )
                })
                .mut_arg("from_key_password", |arg| arg.hide(true))
        });
    for id in PROCESS_OPTIONS.into_iter().chain(LINE_SECRETS) {
        command = command.mut_arg(id, |arg| arg.hide(true));
    }
    command
}

/// The command-line spelling of a value, for messages that echo an option back
fn spelled<T: clap::ValueEnum>(value: &T) -> String {
    value
        .to_possible_value()
        .map_or_else(String::new, |value| value.get_name().to_string())
}

/// Parse the command line and run: one verb, a ceremony, or the interactive session
pub fn run() -> Result<()> {
    let defaults = config::Defaults::load(config_path_from_args().as_deref())?;
    let matches = defaults.apply(command()).get_matches();
    // Each applet's half parsed again with its own table, where the config has one; the
    // flags and variables are the same in every parse, so only the tables' values differ
    let views = if defaults.has_tables() {
        let parse = |app| -> Result<Option<Verb>> {
            let matches = defaults.for_app(app).apply(command()).get_matches();
            Ok(Cli::from_arg_matches(&matches)?.verb)
        };
        match (parse(App::Piv)?, parse(App::Pgp)?) {
            (Some(piv), Some(pgp)) => Some((piv, pgp)),
            _ => None,
        }
    } else {
        None
    };
    let Cli { seeds, log_level: _, plumbing, config: _, verb } = Cli::from_arg_matches(&matches)?;

    if !matches!(verb, Some(Verb::Set { save: true, .. })) {
        defaults.require_named_file()?;
    }
    let mut session = Session::new(seeds, defaults, plumbing)?;
    let file = session.defaults.user_file().map_or_else(
        || "$XDG_CONFIG_HOME/mind-the-gap/config.toml".into(),
        |path| path.display().to_string(),
    );
    // What `set` and `unset` change in a session is gone when it ends, and a one-shot run ends
    // with its verb, so on the command line they change the config file or nothing; `set`
    // alone changes nothing, and shows the defaults wherever it runs
    match verb {
        Some(Verb::Set { save: false, settings }) if !settings.is_empty() => bail!(
            "`set` on the command line would change nothing that outlasts it: `set --save` \
             writes defaults to the config file, {file}, and `set` alone shows them"
        ),
        Some(Verb::Unset { save: false, .. }) => bail!(
            "`unset` on the command line would forget nothing that outlasts it: `unset --save` \
             takes defaults out of the config file, {file}"
        ),
        Some(Verb::Quit) => bail!("`quit` leaves a session, and the command line has none"),
        Some(verb) => session.run_verb(verb, views),
        // The image runs its ceremony where it has one, then hands over to the session with
        // the seeds it asked for; elsewhere a bare invocation is the session
        None if !plumbing && ceremony::image_default().is_some() => session::image(session),
        None => session::repl(session),
    }
}

/// The `--config` path, picked out of argv by hand: the defaults it holds must be known
/// before clap parses, since they become clap's own defaults
fn config_path_from_args() -> Option<PathBuf> {
    early_flag("--config")
        .or_else(|| std::env::var_os("MIND_THE_CONFIG"))
        .map(PathBuf::from)
}

/// The value of a process option that has to be known before clap parses, picked out of argv
/// by hand: the last `--flag VALUE` or `--flag=VALUE`
///
/// clap still declares the option, for help and validation, and refuses it given twice.
fn early_flag(flag: &str) -> Option<OsString> {
    let mut found = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            found = args.next();
        } else if let Some(value) = arg
            .to_str()
            .and_then(|arg| arg.strip_prefix(flag))
            .and_then(|rest| rest.strip_prefix('='))
        {
            found = Some(value.into());
        }
    }
    found
}

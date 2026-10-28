//! What the options alone decide, judged before any seed is stretched.
//!
//! A derivation costs a second or more per seed, and a one-shot run that lacked a name and
//! the emails used to learn of each after one. So everything the options decide on their own
//! is judged here, all of it at once: what the verb's applets need of the identity, a validity
//! and the generation's day, a slot, the pins a pin change takes. Where the applets depend on
//! the card attached (`upload` and `rotate` without `--app`), an applet's own needs wait for
//! the card, and the builders refuse what is missing there.

use super::{Opts, default_generation, refuse_impossible_generation, slot_app};
use crate::cli::Verb;
use crate::cli::options::{App, AppArgs, IdentityArgs, KeyArgs};
use crate::cli::output::{Format, Part};
use crate::pgp;
use crate::piv;
use crate::seed::Algorithm;

use anyhow::{Result, bail};

/// Why `init` refuses the legacy scheme
const LEGACY_INIT: &str = "`init` installs what the current scheme derives; a \
     legacy card moves to it with `init` and `upload` without --legacy (see the compatibility \
     chapter), and keeps working as it is until then";

/// Why a rotation without a new generation or another key seed goes nowhere
const ROTATION_GOES_NOWHERE: &str = "A rotation needs a new generation, --date, or a key seed \
     to move off, --from-key-seed";

/// Refuse a command whose options cannot work, naming everything that is wrong with them;
/// `views` are the command parsed again for each applet, PIV's first, where the defaults have
/// a table for one
pub(in crate::cli) fn preflight(verb: &Verb, views: Option<&(Verb, Verb)>) -> Result<()> {
    let mut verb = verb.clone();
    default_generation(&mut verb);
    let own = Opts::of(&verb);
    let opts = |app: App| match views {
        Some((piv, pgp)) => {
            let mut view = match app {
                App::Piv => piv.clone(),
                App::Pgp => pgp.clone(),
            };
            default_generation(&mut view);
            Opts::of(&view)
        }
        None => own.clone(),
    };
    let mut problems = Problems::default();
    match &verb {
        Verb::Check { app, keys, pin, .. } => {
            let (apps, named) = problems.applets(app, keys);
            for app in apps {
                let opts = opts(app);
                problems.generation(&opts);
                problems.slot(app, &opts.keys);
                problems.algorithm(app, &opts, named);
                if app == App::Piv {
                    problems.identity(&opts.identity, false);
                    // Names or a list URL PIV cannot take fail the command where it was
                    // named; otherwise `check` leaves PIV out with a warning, as it does a pin
                    problems.piv_identity(&opts.identity, named);
                }
                // A pin the applet cannot take is a warning where the applet was not named
                if let (true, Some(pin)) = (named, &pin.pin) {
                    problems.note(refuse_unfit_pin(app, pin.as_str()));
                }
            }
        }
        Verb::Upload { app, .. } => {
            problems.generation(&own);
            for app in card_independent(&mut problems, app, Some(&own.keys)) {
                let opts = opts(app);
                problems.generation(&opts);
                problems.slot(app, &opts.keys);
                problems.algorithm(app, &opts, true);
                if app == App::Piv {
                    problems.identity(&opts.identity, false);
                    problems.piv_identity(&opts.identity, true);
                }
            }
        }
        Verb::Rotate { app, from_key_seed, .. } => {
            problems.generation(&own);
            if own.path.date.is_none() && from_key_seed.is_none() {
                problems.other(ROTATION_GOES_NOWHERE.into());
            }
            for app in card_independent(&mut problems, app, None) {
                let opts = opts(app);
                problems.generation(&opts);
                problems.algorithm(app, &opts, true);
                if app == App::Piv {
                    problems.identity(&opts.identity, false);
                    problems.piv_identity(&opts.identity, true);
                }
            }
        }
        Verb::Revoke { app, keys, .. } | Verb::Ungap { app, keys, .. } => {
            let ungap = matches!(verb, Verb::Ungap { .. });
            let (apps, _) = problems.applets(app, keys);
            for app in apps {
                let opts = opts(app);
                problems.generation(&opts);
                problems.slot(app, &opts.keys);
                problems.algorithm(app, &opts, true);
                match app {
                    App::Piv => {
                        problems.identity(&opts.identity, false);
                        problems.piv_identity(&opts.identity, true);
                    }
                    // Secret keys carry the user ids, which take the emails
                    App::Pgp if ungap => problems.identity(&opts.identity, true),
                    App::Pgp => {}
                }
            }
        }
        Verb::Publish { app, part, format, keys, .. } => {
            let (apps, named) = problems.applets(app, keys);
            for app in apps {
                // The applets a part or a format leaves out, as `publish` does
                match app {
                    App::Piv if *format == Format::Wkd => continue,
                    App::Pgp if *part == Part::Crl && !named => continue,
                    _ => {}
                }
                let opts = opts(app);
                problems.generation(&opts);
                problems.slot(app, &opts.keys);
                problems.algorithm(app, &opts, true);
                match app {
                    App::Piv => {
                        problems.identity(&opts.identity, false);
                        problems.piv_identity(&opts.identity, true);
                    }
                    // User ids go into everything but the subkeys alone and an SSH key
                    App::Pgp
                        if !matches!(part, Part::Keys | Part::Crl) && *format != Format::Ssh =>
                    {
                        problems.identity(&opts.identity, true)
                    }
                    App::Pgp => {}
                }
            }
        }
        Verb::Trust { .. } => problems.algorithm(App::Pgp, &opts(App::Pgp), true),
        Verb::Init { app, pin, .. } => {
            if app.app != Some(App::Piv) && opts(App::Pgp).derive.legacy {
                problems.other(LEGACY_INIT.into());
            }
            if let Some(named) = app.app {
                problems.algorithm(named, &opts(named), true);
                if let Some(pin) = &pin.pin {
                    problems.note(refuse_unfit_pin(named, pin.as_str()));
                }
            }
        }
        Verb::Pin { app, pin, current_pin, reset, write, .. } => {
            // A dry run writes no pin, so it needs none, as a session does not ask for one
            // under it
            if pin.is_none() && !write.dry_run {
                problems.other(
                    "No new pin given; pass it with --pin (or MIND_THE_PIN), or change it in an \
                     interactive session, which asks for it"
                        .into(),
                );
            }
            if let (Some(pin), Some(app)) = (pin, app.app) {
                problems.note(refuse_unfit_pin(app, pin.as_str()));
            }
            if current_pin.is_none() && !reset && !write.dry_run {
                problems.other(
                    "No current pin given; pass it with --current-pin (or MIND_THE_CURRENT_PIN), \
                     set a new one with the card seed with --reset, or change it in an \
                     interactive session, which asks for it"
                        .into(),
                );
            }
        }
        Verb::List { .. }
        | Verb::Wipe { .. }
        | Verb::Generate
        | Verb::Run { .. }
        | Verb::Set { .. }
        | Verb::Unset { .. }
        | Verb::Quit => {}
    }
    problems.into_result()
}

/// The applets a card verb acts on whatever card is attached: the one `--app` names, or PIV
/// where a `--slot` places a key, and none where the card decides
fn card_independent(problems: &mut Problems, app: &AppArgs, keys: Option<&KeyArgs>) -> Vec<App> {
    let app = match keys {
        Some(keys) => problems.note_with(slot_app(app, keys), app.clone()),
        None => app.clone(),
    };
    app.app.into_iter().collect()
}

/// Refuse a user pin no card of the applet takes
pub(super) fn refuse_unfit_pin(app: App, pin: &str) -> Result<()> {
    match app {
        App::Piv => piv::refuse_unfit_pin(pin),
        App::Pgp => pgp::refuse_unfit_pin(pin),
    }
}

/// Refuse an identity no PIV certificate can be issued to: names past their bounds, or a
/// list URL no list can be named from, all of them told at once
pub(super) fn refuse_unfit_piv_identity(identity: &IdentityArgs) -> Result<()> {
    let names = piv::refuse_unfit_names(
        identity.name.as_deref(),
        identity.org.as_deref(),
        identity.unit.as_deref(),
        identity.country.as_deref(),
    );
    let url = identity
        .crl_url
        .as_deref()
        .map_or(Ok(()), piv::refuse_unfit_crl_url);
    let told: Vec<String> = [names, url]
        .into_iter()
        .filter_map(|result| result.err().map(|err| format!("{err:#}")))
        .collect();
    if !told.is_empty() {
        bail!("{}", told.join("\n"));
    }
    Ok(())
}

/// What is wrong with a command's options, gathered to be told at once
#[derive(Default)]
struct Problems {
    /// The identity's name is missing, where an applet needs it
    name: bool,
    /// The emails are missing, where an applet's user ids need them
    emails: bool,
    /// Everything else, each told once
    other: Vec<String>,
}

impl Problems {
    fn other(&mut self, problem: String) {
        if !self.other.contains(&problem) {
            self.other.push(problem);
        }
    }

    fn note(&mut self, result: Result<()>) {
        if let Err(err) = result {
            self.other(format!("{err:#}"));
        }
    }

    /// The value of `result`, or `fallback` with its error noted
    fn note_with<T>(&mut self, result: Result<T>, fallback: T) -> T {
        result.unwrap_or_else(|err| {
            self.other(format!("{err:#}"));
            fallback
        })
    }

    /// The applets a verb that needs no card acts on, and whether they were named
    fn applets(&mut self, app: &AppArgs, keys: &KeyArgs) -> (Vec<App>, bool) {
        self.note_with(slot_app(app, keys), app.clone()).apps()
    }

    /// The identity an applet's certificates are issued to, with `emails` for user ids
    fn identity(&mut self, identity: &IdentityArgs, emails: bool) {
        self.name |= identity.name.is_none();
        self.emails |= emails && identity.emails.is_empty();
    }

    /// What the identity's PIV certificates cannot carry, names past their bounds or a list
    /// URL no list can be named from, where `fatal` says it fails the command
    fn piv_identity(&mut self, identity: &IdentityArgs, fatal: bool) {
        if fatal {
            self.note(refuse_unfit_piv_identity(identity));
        }
    }

    fn generation(&mut self, opts: &Opts) {
        self.note(refuse_impossible_generation(&opts.identity, &opts.path));
    }

    fn slot(&mut self, app: App, keys: &KeyArgs) {
        if let (App::Piv, Some(slot)) = (app, keys.slot) {
            self.note(piv::refuse_unfit_slot(slot, &keys.key));
        }
    }

    /// An algorithm the applet cannot derive under, where its failing fails the command
    fn algorithm(&mut self, app: App, opts: &Opts, fatal: bool) {
        if fatal && app == App::Pgp && opts.derive.algorithm == Some(Algorithm::P384) {
            self.other(pgp::P384_REFUSED.into());
        }
    }

    fn into_result(self) -> Result<()> {
        let mut told = Vec::new();
        match (self.name, self.emails) {
            (true, true) => told.push(
                "Missing --name (or MIND_THE_NAME) and --emails (or MIND_THE_EMAILS); in a \
                 session, `set` them"
                    .to_string(),
            ),
            (true, false) => told.push(
                "Missing --name (or MIND_THE_NAME); in a session, `set name=...`".to_string(),
            ),
            (false, true) => told.push(
                "Missing --emails (or MIND_THE_EMAILS); in a session, `set emails=...`".to_string(),
            ),
            (false, false) => {}
        }
        told.extend(self.other);
        if !told.is_empty() {
            bail!("{}", told.join("\n"));
        }
        Ok(())
    }
}

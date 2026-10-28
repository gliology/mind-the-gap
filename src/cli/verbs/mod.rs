//! The verbs: each one's work, from resolved seeds and parsed options to cards and files.
//!
//! Here what every verb shares: the context it runs in, the options of each applet and the
//! builders made of them. What the options alone decide is judged in `preflight`, before any
//! seed is stretched; the verbs that talk to a card are in `cards`, the ones that only write
//! files in `files`.

mod cards;
mod files;
mod preflight;

pub(super) use preflight::preflight;

use super::Verb;
use super::options::{
    App, AppArgs, CardDataArgs, DeriveArgs, IdentityArgs, KeyArgs, PathArgs, PolicyArgs, Validity,
};
use super::seeds::{Roots, resolve_one};
use crate::pgp;
use crate::piv;
use crate::prompt;
use crate::seed::{Algorithm, Seeds};

use std::time::Duration;

use anyhow::{Result, anyhow, bail};

/// What a verb runs with besides its options
struct Context {
    /// The seeds' roots, as the verb takes them
    roots: Roots,
    /// Whether a person is there to answer questions
    interactive: bool,
    /// Each applet's options, which differ where the config has a table for one
    opts: PerApp,
}

impl Context {
    /// The options one applet's half of the command takes
    fn opts(&self, app: App) -> &Opts {
        match app {
            App::Piv => &self.opts.piv,
            App::Pgp => &self.opts.pgp,
        }
    }

    /// The same context for the seeds of another key seed, as a rotation's previous
    /// generation derives
    fn with_key(&self, key: Option<crate::seed::SecretSeed>) -> Context {
        Context {
            roots: Roots {
                card: self.roots.card.clone(),
                key: key.or_else(|| self.roots.key.clone()),
                key_entropy: None,
            },
            interactive: self.interactive,
            opts: self.opts.clone(),
        }
    }
}

/// The options of one applet's half of a command, as its own parse gave them
#[derive(Clone, Default)]
struct Opts {
    derive: DeriveArgs,
    path: PathArgs,
    identity: IdentityArgs,
    keys: KeyArgs,
    policy: PolicyArgs,
    card_data: CardDataArgs,
}

impl Opts {
    /// The options a verb carries, each group its default where the verb has none
    fn of(verb: &Verb) -> Opts {
        let mut opts = Opts::default();
        match verb {
            Verb::List { derive, path, keys, .. } => {
                opts.derive = derive.clone();
                opts.path = path.clone();
                opts.keys = keys.clone();
            }
            Verb::Check { derive, path, identity, keys, policy, .. } => {
                opts.derive = derive.clone();
                opts.path = path.clone();
                opts.identity = identity.clone();
                opts.keys = keys.clone();
                opts.policy = policy.clone();
            }
            Verb::Init { derive, policy, card_data, .. } => {
                opts.derive = derive.clone();
                opts.policy = policy.clone();
                opts.card_data = card_data.clone();
            }
            Verb::Upload { derive, path, identity, keys, policy, card_data, .. } => {
                opts.derive = derive.clone();
                opts.path = path.clone();
                opts.identity = identity.clone();
                opts.keys = keys.clone();
                opts.policy = policy.clone();
                opts.card_data = card_data.clone();
            }
            Verb::Rotate { derive, path, identity, policy, .. } => {
                opts.derive = derive.clone();
                opts.path = path.clone();
                opts.identity = identity.clone();
                opts.policy = policy.clone();
            }
            Verb::Pin { derive, .. } | Verb::Wipe { derive, .. } => opts.derive = derive.clone(),
            Verb::Trust { derive, identity, .. } => {
                opts.derive = derive.clone();
                opts.identity = identity.clone();
            }
            Verb::Revoke { derive, path, identity, keys, .. }
            | Verb::Publish { derive, path, identity, keys, .. }
            | Verb::Ungap { derive, path, identity, keys, .. } => {
                opts.derive = derive.clone();
                opts.path = path.clone();
                opts.identity = identity.clone();
                opts.keys = keys.clone();
            }
            Verb::Generate
            | Verb::Run { .. }
            | Verb::Set { .. }
            | Verb::Unset { .. }
            | Verb::Quit => {}
        }
        opts
    }
}

/// Each applet's options
#[derive(Clone)]
struct PerApp {
    piv: Opts,
    pgp: Opts,
}

/// Run one verb on the seeds' `roots`; `views` are the command parsed again for each applet,
/// where the config has a table for one, PIV's first
pub(super) fn dispatch(
    mut verb: Verb,
    views: Option<(Verb, Verb)>,
    roots: Roots,
    interactive: bool,
) -> Result<()> {
    default_generation(&mut verb);
    // The command's own options, which decide for it as a whole where the applets' differ
    let own = Opts::of(&verb);
    let opts = match views {
        Some((mut piv, mut pgp)) => {
            default_generation(&mut piv);
            default_generation(&mut pgp);
            PerApp { piv: Opts::of(&piv), pgp: Opts::of(&pgp) }
        }
        None => PerApp { piv: own.clone(), pgp: own.clone() },
    };
    let context = &Context { roots, interactive, opts };
    match verb {
        Verb::List { app, .. } => cards::list(context, &app),
        Verb::Check { app, card, keys, pin, .. } => cards::check(context, &app, &card, &keys, &pin),
        Verb::Init { app, card, pin, write, .. } => cards::init(context, &app, &card, &pin, &write),
        Verb::Upload { app, card, write, .. } => cards::upload(context, &app, &card, &own, &write),
        Verb::Rotate { app, card, from_key_seed, from_key_password, write, .. } => {
            let from =
                resolve_one(from_key_seed, from_key_password, "previous key seed", interactive)?;
            cards::rotate(context, &app, &card, from, &write)
        }
        Verb::Pin { app, card, pin, current_pin, reset, write, .. } => {
            cards::change_pin(context, &app, &card, pin, current_pin, reset, &write)
        }
        Verb::Wipe { app, card, force, write, .. } => {
            cards::wipe(context, &app, &card, force, &write)
        }
        Verb::Trust { input, level, output, .. } => files::trust(context, &input, level, &output),
        Verb::Revoke { app, kind, code, reason, keys, output, write, .. } => {
            let revocation = files::Revocation { kind, code, reason: &reason };
            files::revoke(context, &app, &revocation, &keys, &output, &write)
        }
        Verb::Publish { app, part, format, keys, output, .. } => {
            files::publish(context, &app, part, format, &keys, &output)
        }
        Verb::Ungap { app, keys, pin, output, .. } => {
            files::ungap(context, &app, &keys, &pin, &output)
        }
        Verb::Generate | Verb::Run { .. } | Verb::Set { .. } | Verb::Unset { .. } | Verb::Quit => {
            bail!("`{}` belongs to a session", verb.name())
        }
    }
}

/// The seeds of a context, as the builders take them
fn seeds(context: &Context) -> Seeds<'_> {
    Seeds {
        card: context.roots.card.as_deref().map(|seed| &**seed),
        key: context.roots.key.as_deref().map(|seed| &**seed),
    }
}

/// Warn when `algorithm` asks for more strength than the phrase can give it
///
/// A key is never stronger than the secret it comes from: RSA-4096 from a 12 word phrase
/// costs the larger key's price for the phrase's 128 bits. Only a warning, since the keys
/// are still sound and a password may well make up the difference.
fn warn_if_phrase_is_weaker(entropy: Option<u32>, algorithm: Algorithm) {
    let Some(entropy) = entropy else {
        return;
    };
    let strength = algorithm.strength_bits();
    if entropy < strength {
        log::warn!(
            "{} keys aim at about {strength} bits of strength, but the phrase carries {entropy} \
             bits of entropy (a password adds what it adds, which cannot be measured here)",
            algorithm.name()
        );
    }
}

/// Without a `--date`, the keys are of the generation the identity was created in
///
/// A key cannot be older than the identity that certifies it: OpenPGP drops a subkey older
/// than its primary, and a PIV slot certificate would start before its root authority. So an
/// identity date is also the first generation's, as reproducible as any date given.
fn default_generation(verb: &mut Verb) {
    let (Verb::Check { path, identity, .. }
    | Verb::Upload { path, identity, .. }
    | Verb::Rotate { path, identity, .. }
    | Verb::Revoke { path, identity, .. }
    | Verb::Publish { path, identity, .. }
    | Verb::Ungap { path, identity, .. }) = verb
    else {
        return;
    };
    if path.date.is_none() {
        path.date = identity.identity_date;
    }
}

/// Refuse a generation dated before the identity that certifies it, and a validity counted
/// from no date at all or ending past the last day an end can be told on
fn refuse_impossible_generation(identity: &IdentityArgs, path: &PathArgs) -> Result<()> {
    // An undated generation is created at the epoch, so its certificates and subkey
    // bindings would have expired by 1971
    match (identity.validity, path.date) {
        (Some(validity), None) => return Err(undated_validity(validity)),
        (Some(validity), Some(date)) => {
            validity.end(date)?;
        }
        (None, _) => {}
    }
    if let (Some(identity_date), Some(date)) = (identity.identity_date, path.date)
        && date < identity_date
    {
        bail!(
            "The keys of {date} would be older than the identity, created on {identity_date}: \
             no key can be older than the identity that certifies it, so pass a --date on or \
             after it, or none for the identity's own"
        );
    }
    Ok(())
}

/// A validity given for keys created on no day
fn undated_validity(validity: Validity) -> anyhow::Error {
    anyhow!(
        "A validity of {validity} counts from the day the keys were created, and these have \
         none: pass --date, or --identity-date for the identity's own generation"
    )
}

/// The validity as the builders take it, counted on the calendar from the generation's day
fn validity_duration(identity: &IdentityArgs, path: &PathArgs) -> Result<Option<Duration>> {
    match (identity.validity, path.date) {
        (None, _) => Ok(None),
        (Some(validity), Some(date)) => validity.duration_from(date).map(Some),
        (Some(validity), None) => Err(undated_validity(validity)),
    }
}

/// The PIV builder for the seeds and options a verb has
fn piv_builder(
    context: &Context,
    derive: &DeriveArgs,
    path: &PathArgs,
    identity: &IdentityArgs,
    keys: Option<&KeyArgs>,
    policy: Option<&PolicyArgs>,
) -> Result<piv::SeededSmartcard> {
    // The card's own key and credentials need no name; the identity's certificates do
    let name = match &identity.name {
        Some(name) => name.clone(),
        None if context.roots.key.is_some() => {
            bail!("Missing --name (or MIND_THE_NAME); in a session, `set name=...`")
        }
        None => String::new(),
    };
    let mut builder = piv::SeededSmartcard::new(seeds(context), path.path(), name);
    if let Some(algorithm) = derive.algorithm {
        warn_if_phrase_is_weaker(context.roots.key_entropy, algorithm);
        builder = builder.with_algorithm(algorithm);
    }
    for address in &identity.emails {
        builder = builder.add_email(address)?;
    }
    if let Some(org) = &identity.org {
        builder = builder.with_org(org.clone());
    }
    if let Some(unit) = &identity.unit {
        builder = builder.with_org_unit(unit.clone());
    }
    if let Some(country) = &identity.country {
        builder = builder.with_country(country.clone());
    }
    builder = builder.with_intermediate(identity.intermediate);
    if let Some(date) = identity.identity_date {
        builder = builder.with_identity_time(crate::seed::midnight(date));
    }
    if let Some(validity) = validity_duration(identity, path)? {
        builder = builder.with_validity_duration(validity);
    }
    if let Some(url) = &identity.crl_url {
        builder = builder.with_crl_url(url)?;
    }
    if let Some(keys) = keys {
        if !keys.key.is_empty() {
            builder = builder.with_keys(&keys.key)?;
        }
        if let Some(slot) = keys.slot {
            builder = builder.with_slot(slot)?;
        }
    }
    if let Some(policy) = policy {
        if let Some(chosen) = policy.policy {
            builder = builder.with_policy(chosen);
        }
        if let Some(algorithm) = policy.management_algorithm {
            builder = builder.with_management_key(algorithm);
        }
        builder = builder.with_msroots(!policy.no_msroots);
    }
    Ok(builder)
}

/// The OpenPGP builder for the seeds and options a verb has
///
/// `uids` for the verbs that mint user ids, which need the name and the emails.
fn pgp_builder(
    context: &Context,
    derive: &DeriveArgs,
    path: &PathArgs,
    identity: &IdentityArgs,
    keys: Option<&KeyArgs>,
) -> Result<pgp::SeededSmartcard> {
    if derive.algorithm == Some(Algorithm::P384) {
        bail!(pgp::P384_REFUSED);
    }
    let name = identity.name.clone().unwrap_or_default();
    let mut builder = if derive.legacy {
        log::warn!("Using the legacy derivation scheme");
        let roots = &context.roots;
        let seed = match (roots.card.as_deref(), roots.key.as_deref()) {
            (Some(card), Some(key)) if card != key => bail!(
                "The legacy scheme derives the admin pin and the keys from one seed; give the \
                 seed alone, without a card seed or key seed apart"
            ),
            (Some(seed), _) | (None, Some(seed)) => seed,
            (None, None) => bail!("The legacy scheme needs the seed"),
        };
        // The legacy scheme read a subkey id 0x01 as the primary's label, and an empty one as
        // no subkey id at all
        if path.subkey.as_deref() == Some("\u{1}") {
            bail!("Subkey id 0x01 collides with the primary key under --legacy; pick another");
        }
        if path.subkey.as_deref() == Some("") {
            bail!("An empty subkey id is the same as none under --legacy; leave -k out instead");
        }
        let mut builder = pgp::SeededSmartcard::legacy(seed, path.subkey.clone(), name);
        if let Some(date) = path.date {
            builder = builder.with_legacy_subkey_time(crate::seed::midnight(date));
        }
        builder
    } else {
        pgp::SeededSmartcard::new(seeds(context), path.path(), name)
    };
    if let Some(algorithm) = derive.algorithm {
        warn_if_phrase_is_weaker(context.roots.key_entropy, algorithm);
        builder = builder.with_algorithm(algorithm)?;
    }
    for address in &identity.emails {
        builder = builder.add_email(address)?;
    }
    if let Some(date) = identity.identity_date {
        builder = builder.with_identity_time(crate::seed::midnight(date));
    }
    if let Some(validity) = validity_duration(identity, path)? {
        builder = builder.with_subkey_validity(validity);
    }
    if let Some(keys) = keys
        && !keys.key.is_empty()
    {
        builder = builder.with_keys(&keys.key)?;
    }
    Ok(builder)
}

/// The applets a verb acts on, where `--slot` narrows them to PIV
///
/// A slot is PIV's alone, and the key it places is often another identity's, which must not
/// also replace the card's own OpenPGP key of the same role.
fn slot_app(app: &AppArgs, keys: &KeyArgs) -> Result<AppArgs> {
    Ok(match (keys.slot, app.app) {
        (Some(_), Some(App::Pgp)) => {
            bail!("--slot places a PIV key; OpenPGP has no slot to choose")
        }
        (Some(_), None) => AppArgs { app: Some(App::Piv) },
        _ => app.clone(),
    })
}

/// Ask a yes/no question before a write, without side effects on the data channels
///
/// The warning and the question go to stderr: stdout may be carrying certificates.
/// Answers come from the controlling terminal, never stdin, so a script's next line can never
/// be consumed as a yes. With no terminal there is nobody to ask and --yes is the way to say
/// it in advance.
pub(super) fn ask(warning: &str) -> Result<()> {
    eprintln!("{warning}");
    // Automation says yes in advance or not at all: a terminal it happens to run on is
    // nobody's to answer
    if super::plumbing::active() {
        bail!("Plumbing asks nothing: pass --yes to write");
    }
    match prompt::confirm("Continue?") {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Aborted, nothing was changed"),
        Err(_) => bail!("Refusing to continue without confirmation, use --yes"),
    }
}

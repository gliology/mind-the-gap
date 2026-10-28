//! The verbs that talk to a card: list, check, init, upload, rotate, pin and wipe.

use super::preflight::{refuse_unfit_pin, refuse_unfit_piv_identity};
use super::{Context, Opts, ask, pgp_builder, piv_builder, refuse_impossible_generation, slot_app};
use crate::backend::{Applet, Backend, UpdatePlan};
use crate::cli::options::{
    App, AppArgs, CardArgs, IdentityArgs, KeyArgs, PathArgs, PinArgs, PolicyArgs, WriteArgs,
};
use crate::cli::plumbing::{self, Json};
use crate::cli::seeds::{Roots, seed_id};
use crate::common;
use crate::pgp;
use crate::piv;
use crate::policy::Policy;
use crate::target::{self, Attached, CardTarget};

use anyhow::{Result, bail};

use der::Encode;

use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

/// The card a verb addresses and the applets it acts on there
///
/// Without `--app` a verb acts on every applet the card carries and skips the others; an
/// applet named with `--app` that the card lacks is an error.
fn locate(app: &AppArgs, card: &CardArgs) -> Result<(Attached, Vec<App>)> {
    let found = target::locate(card.card.as_ref())?;
    let (apps, named) = app.apps();
    let mut present = Vec::new();
    for app in apps {
        let has = match app {
            App::Piv => found.piv.is_some(),
            App::Pgp => found.pgp.is_some(),
        };
        if has {
            present.push(app);
        } else if named {
            bail!("The card {} has no {} application", found.describe(), app.name());
        } else {
            log::info!("The card has no {} application, leaving it out", app.name());
        }
    }
    if present.is_empty() {
        bail!("The card {} has no PIV or OpenPGP application", found.describe());
    }
    Ok((found, present))
}

/// The card target both backends open: the reader, which addresses either applet and asks
/// no other card who it is
fn reader(found: &Attached) -> Option<CardTarget> {
    Some(CardTarget::Reader(found.reader.clone()))
}

/// Warn about what a policy gives up, before the card is touched
///
/// Warnings rather than refusals, like the factory pin: every mode is a legitimate choice for
/// some card, a build server's for one, and the user should hear the cost once.
fn warn_policy(policy: Policy, apps: &[App]) {
    if policy == Policy::Never {
        log::warn!(
            "Policy `never`: no pin and no touch, so whoever holds the card can use every key \
             on it that needs no pin entry per session"
        );
    }
    if apps.contains(&App::Pgp) && policy.drops_pin() {
        log::warn!(
            "An OpenPGP card always asks for the pin once per session; `{}` cannot drop it",
            crate::cli::spelled(&policy)
        );
    }
    if apps.contains(&App::Piv) && policy.weakens_signature_pin() {
        log::warn!(
            "Policy `{}`: the signature slot 9C no longer asks for the pin before every \
             signature, which NIST SP 800-73-4 asks for so that a signature stays \
             non-repudiable",
            crate::cli::spelled(&policy)
        );
    }
}

pub(super) fn list(context: &Context, app: &AppArgs) -> Result<()> {
    let known = context.roots.card.is_some() || context.roots.key.is_some();
    let identity = IdentityArgs { name: Some(String::new()), ..Default::default() };
    let (apps, _) = app.apps();
    // Asked once, and first: a machine without pcscd hears it once, and each applet then
    // reads only the cards that carry it
    let readers = target::attached()?;
    let mut listings: Vec<crate::ownership::Listing> = Vec::new();
    for app in apps {
        let opts = context.opts(app);
        let (derive, path, keys) = (&opts.derive, &opts.path, &opts.keys);
        // Each applet on its own: options one of them cannot derive under (p384 for
        // OpenPGP) must not hide the other's cards
        let found = match app {
            App::Piv => known
                .then(|| piv_builder(context, derive, path, &identity, Some(keys), None))
                .transpose()
                .and_then(|owner| piv::list(owner.as_ref(), &readers)),
            App::Pgp => known
                .then(|| pgp_builder(context, derive, path, &identity, Some(keys)))
                .transpose()
                .and_then(|owner| pgp::list(owner.as_ref(), &readers)),
        };
        match found {
            Ok(found) => listings.extend(found),
            Err(err) => log::error!("Cannot list the {} cards: {err:#}", app.name()),
        }
    }

    if readers.is_empty() {
        println!("No card attached");
    }
    let mut cards = Vec::new();
    for reader in readers {
        // Card text is untrusted: what a card calls itself is escaped before it is shown
        println!("{}", common::printable(&reader.reader));
        let applets: Vec<_> = listings
            .iter()
            .filter(|listing| listing.reader == reader.reader)
            .collect();
        if applets.is_empty() {
            println!("  no PIV or OpenPGP application");
        }
        for listing in &applets {
            println!("  {} card {}", listing.applet, common::printable(&listing.card));
            if let Some(owner) = &listing.owner {
                println!("    {}", common::printable(owner));
            }
            if let Some(holder) = &listing.holder {
                println!("    Cardholder: {}", common::printable(holder));
            }
            for key in &listing.keys {
                println!(
                    "    {} key: {}{}{}",
                    key.slot,
                    key.fingerprint,
                    key.subject
                        .as_ref()
                        .map(|subject| format!(" ({})", common::printable(subject)))
                        .unwrap_or_default(),
                    if key.ours { ", this key seed's" } else { "" }
                );
            }
        }
        cards.push(Json::Object(vec![
            ("reader", Json::Str(reader.reader.clone())),
            ("applets", Json::Array(applets.iter().map(|listing| listed(listing)).collect())),
        ]));
    }
    plumbing::attach("cards", Json::Array(cards));
    Ok(())
}

/// One applet of a listing, for a report
fn listed(listing: &crate::ownership::Listing) -> Json {
    let keys = listing
        .keys
        .iter()
        .map(|key| {
            Json::Object(vec![
                ("slot", Json::Str(key.slot.clone())),
                ("fingerprint", Json::Str(key.fingerprint.clone())),
                ("subject", Json::maybe(key.subject.as_deref())),
                ("ours", Json::Bool(key.ours)),
            ])
        })
        .collect();
    Json::Object(vec![
        ("applet", Json::Str(listing.applet.to_string())),
        ("card", Json::Str(listing.card.clone())),
        ("owner", Json::maybe(listing.owner.as_deref())),
        ("holder", Json::maybe(listing.holder.as_deref())),
        ("keys", Json::Array(keys)),
    ])
}

pub(super) fn check(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    keys: &KeyArgs,
    pin: &PinArgs,
) -> Result<()> {
    // The record first: what a phrase written down with its seed ids and fingerprints is
    // compared with before anything is trusted to it
    show_seed_ids(&context.roots);
    let app = &slot_app(app, keys)?;
    let (apps, named) = app.apps();
    let mut applets = Vec::new();
    for &app in &apps {
        if let Some(applet) = recorded(context, app, named, pin)? {
            applets.push((app, applet));
        }
    }

    // A card only where one is named or is the one attached: without, the record is the
    // whole answer, and with several there is no telling which was meant
    if card.card.is_none() {
        match target::attached()?.len() {
            0 => return Ok(()),
            1 => {}
            many => {
                println!("{many} cards are attached; name one with --card to compare it");
                return Ok(());
            }
        }
    }
    compare(&applets, app, card)
}

/// Show the seed ids, which a record kept with the phrase is compared with
fn show_seed_ids(roots: &Roots) {
    let show = |what, field, root| {
        let id = seed_id(root);
        println!("{what}: {id}");
        plumbing::attach(field, Json::Str(id));
    };
    match (roots.card.as_deref(), roots.key.as_deref()) {
        (Some(card), Some(key)) if card == key => show("Seed id", "seed_id", card),
        (card, key) => {
            if let Some(card) = card {
                show("Card seed id", "card_seed_id", card);
            }
            if let Some(key) = key {
                show("Key seed id", "key_seed_id", key);
            }
        }
    }
}

/// The builder `check` compares one applet with, once the identity it derives is shown;
/// none for an identity the options cannot make, where the applet was not named: names or a
/// list URL PIV's certificates cannot carry, or an OpenPGP identity without its emails
fn recorded(
    context: &Context,
    app: App,
    named: bool,
    pin: &PinArgs,
) -> Result<Option<Box<dyn Applet>>> {
    let opts = context.opts(app);
    let (derive, path, identity, keys, policy) =
        (&opts.derive, &opts.path, &opts.identity, &opts.keys, &opts.policy);
    Ok(Some(match app {
        App::Piv => {
            match refuse_unfit_piv_identity(identity) {
                Err(err) if !named => {
                    log::warn!("No PIV identity: {err:#}");
                    return Ok(None);
                }
                result => result?,
            }
            let mut builder =
                piv_builder(context, derive, path, identity, Some(keys), Some(policy))?;
            if let Some(pin) = pin_for(app, named, pin)? {
                builder = builder.with_pin(pin)?;
            }
            let root = builder.root_certificate()?;
            let digest = format!("{:x}", Sha256::digest(root.to_der()?));
            println!("PIV root authority: {digest} ({})", root.tbs_certificate().subject());
            plumbing::attach("piv_root", Json::Str(digest));
            Box::new(builder)
        }
        App::Pgp => {
            let mut builder = match pgp_builder(context, derive, path, identity, Some(keys)) {
                Ok(builder) => builder,
                Err(err) if !named => {
                    log::warn!("No OpenPGP identity: {err:#}");
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            if let Some(pin) = pin_for(app, named, pin)? {
                builder = builder.with_pin(pin)?;
            }
            let primary = builder.certify(pgp::CertificateKind::Primary)?;
            println!("OpenPGP identity: {}", primary.fingerprint());
            plumbing::attach("pgp_identity", Json::Str(primary.fingerprint().to_hex()));
            Box::new(builder)
        }
    }))
}

/// The one `--pin` as one applet's `check` takes it
///
/// A pin that applet cannot take is refused where the applet was named. Otherwise the applet
/// is compared without it, with a warning, since a pin made for the other applet must neither
/// hide the record nor hold back that applet's comparison.
fn pin_for(app: App, named: bool, pin: &PinArgs) -> Result<Option<Zeroizing<String>>> {
    let Some(pin) = &pin.pin else {
        return Ok(None);
    };
    match refuse_unfit_pin(app, pin) {
        Ok(()) => Ok(Some(pin.clone())),
        Err(err) if !named => {
            log::warn!("{err:#}, so {} is compared without it", app.name());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Compare the card with each applet's builder, and say for each whether it holds what the
/// seeds derive
fn compare(applets: &[(App, Box<dyn Applet>)], app: &AppArgs, card: &CardArgs) -> Result<()> {
    let (found, present) = locate(app, card)?;
    println!("Card {}:", found.describe());
    let mut failures = Vec::new();
    let mut verdicts = Vec::new();
    for app in present {
        let result = applets
            .iter()
            .find(|(applet, _)| *applet == app)
            .map(|(_, builder)| builder.check(reader(&found)));
        let mut verdict = vec![("applet", Json::Str(app.name().to_string()))];
        if let Some(Err(err)) = &result {
            failures.push(format!("{}: {err:#}", app.name()));
            verdict.push(("ok", Json::Bool(false)));
            verdict.push(("error", Json::Str(format!("{err:#}"))));
        } else if result.is_some() {
            println!("{}: the card holds what the seeds derive", app.name());
            verdict.push(("ok", Json::Bool(true)));
        }
        verdicts.push(Json::Object(verdict));
    }
    plumbing::attach("reader", Json::Str(found.reader.clone()));
    plumbing::attach("applets", Json::Array(verdicts));
    if !failures.is_empty() {
        bail!("{}", failures.join("\n"));
    }
    Ok(())
}

pub(super) fn init(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    pin: &PinArgs,
    write: &WriteArgs,
) -> Result<()> {
    // Said and judged before a card is looked for, so that it is on record whatever card is
    // attached
    if pin.pin.is_none() {
        log::warn!(
            "No pin supplied: the card keeps the factory user pin ({}), usable by anyone who \
             finds it; pass --pin to set one",
            common::FACTORY_USER_PIN
        );
    }
    let (found, apps) = locate(app, card)?;

    let mut applets = Vec::new();
    let mut names = Vec::new();
    for &app in &apps {
        warn_policy(context.opts(app).policy.policy.unwrap_or_default(), &[app]);
        let applet = initializing(context, app, pin)?;
        let name = applet.preflight(reader(&found))?;
        names.push(format!("the {} application of {name}", applet.name()));
        applets.push(applet);
    }

    let what = format!(
        "Initializing resets\n  {}\nEvery key and certificate on it is erased.",
        names.join("\n  ")
    );
    if write.dry_run {
        println!("{what}");
        return Ok(());
    }
    if !write.yes {
        ask(&what)?;
    }
    for applet in applets {
        applet.init(reader(&found))?;
        log::info!("Initialized the {} application", applet.name());
    }
    println!("Initialized {}: `upload` puts the key seed's keys on it", found.describe());
    Ok(())
}

/// The builder `init` gives one applet of a card with, the user pin `pin` sets
fn initializing(context: &Context, app: App, pin: &PinArgs) -> Result<Box<dyn Applet>> {
    let (identity, path) = (IdentityArgs::default(), PathArgs::default());
    let opts = context.opts(app);
    let (derive, policy) = (&opts.derive, &opts.policy);
    Ok(match app {
        App::Piv => {
            let mut builder = piv_builder(context, derive, &path, &identity, None, Some(policy))?;
            if let Some(pin) = &pin.pin {
                builder = builder.with_pin(pin.clone())?;
            }
            Box::new(builder)
        }
        App::Pgp => {
            let mut builder = pgp_builder(context, derive, &path, &identity, None)?
                .with_card_data(opts.card_data.data())
                .with_kdf(policy.kdf.unwrap_or_default());
            if let Some(pin) = &pin.pin {
                builder = builder.with_pin(pin.clone())?;
            }
            Box::new(builder)
        }
    })
}

/// One applet's plan, whichever backend made it
trait Pending {
    /// Whether the card holds what the seeds derive already
    fn is_empty(&self) -> bool;

    /// Show the plan, naming the applet and the card
    fn show(&self);

    /// Write the plan to the card in `target`; whether the card holds what the seeds derive
    /// afterwards, and what it lacks
    fn apply(&self, target: Option<CardTarget>) -> Result<(bool, String)>;
}

/// A plan as a backend made it, with the builder that writes it and the previous generation a
/// rotation moves off
struct Planned<B: Backend> {
    builder: B,
    previous: Option<B>,
    plan: UpdatePlan<B::Change>,
}

impl<B: Backend> Pending for Planned<B> {
    fn is_empty(&self) -> bool {
        self.plan.is_empty()
    }

    fn show(&self) {
        println!("{} application of {}:\n{}", self.builder.name(), self.plan.card, self.plan);
    }

    fn apply(&self, target: Option<CardTarget>) -> Result<(bool, String)> {
        let left = match &self.previous {
            None => self.builder.upload(target, &self.plan)?,
            Some(previous) => self.builder.rotate_from(previous, target, &self.plan)?,
        };
        Ok((left.is_empty(), left.to_string()))
    }
}

/// Plan an upload of `builder`, or its rotation from `previous`, against the card found
fn planned<B: Backend + 'static>(
    builder: B,
    previous: Option<B>,
    found: &Attached,
) -> Result<Box<dyn Pending>> {
    let plan = match &previous {
        None => builder.plan_upload(reader(found))?,
        Some(previous) => builder.plan_rotation_from(previous, reader(found))?,
    };
    Ok(Box::new(Planned { builder, previous, plan }))
}

/// Show the plans, ask once, write each and report what any card still lacks
fn write_plans(
    plans: Vec<Box<dyn Pending>>,
    write: &WriteArgs,
    verb: &str,
    found: &Attached,
) -> Result<()> {
    for plan in &plans {
        plan.show();
    }
    if write.dry_run || plans.iter().all(|plan| plan.is_empty()) {
        return Ok(());
    }
    if !write.yes {
        ask(&format!("{verb} writes the changes above. Nothing is erased that is not listed."))?;
    }
    let mut remaining = Vec::new();
    for plan in plans.iter().filter(|plan| !plan.is_empty()) {
        let (complete, left) = plan.apply(reader(found))?;
        if !complete {
            remaining.push(left);
        }
    }
    if !remaining.is_empty() {
        bail!(
            "The card still differs from what the seeds derive after the {verb}:\n{}",
            remaining.join("\n")
        );
    }
    println!("Done: the card holds what the seeds derive");
    Ok(())
}

pub(super) fn upload(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    own: &Opts,
    write: &WriteArgs,
) -> Result<()> {
    let app = &slot_app(app, &own.keys)?;
    let (found, apps) = locate(app, card)?;
    if let Some(policy) = own.policy.policy {
        warn_policy(policy, &apps);
    }
    if own.identity.emails.is_empty() {
        log::warn!(
            "No --emails given: certificates are issued without any, and a card provisioned \
             with emails gets every certificate rewritten"
        );
    }
    let mut plans = Vec::new();
    for app in apps {
        let opts = context.opts(app);
        let (derive, path, identity) = (&opts.derive, &opts.path, &opts.identity);
        refuse_impossible_generation(identity, path)?;
        plans.push(match app {
            App::Piv => {
                let builder = piv_builder(
                    context,
                    derive,
                    path,
                    identity,
                    Some(&opts.keys),
                    Some(&opts.policy),
                )?;
                planned(builder, None, &found)?
            }
            App::Pgp => {
                let builder = pgp_builder(context, derive, path, identity, Some(&opts.keys))?
                    .with_card_data(opts.card_data.data());
                planned(with_touch(builder, &opts.policy), None, &found)?
            }
        });
    }
    write_plans(plans, write, "Uploading", &found)
}

pub(super) fn rotate(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    from: Option<crate::seed::SecretSeed>,
    write: &WriteArgs,
) -> Result<()> {
    let (found, apps) = locate(app, card)?;
    // The previous generation: the same options under the card's own date, from the previous
    // key seed where the rotation moves off one
    let old = context.with_key(from.clone());
    let mut plans = Vec::new();
    for app in apps {
        plans.push(rotation(context, &old, app, &found, from.is_some())?);
    }
    // The previous generation is the one planned against: a card whose generation changed
    // since is planned differently where it is written, and refused there
    let result = write_plans(plans, write, "Rotating", &found);
    if result.is_ok() && !write.dry_run {
        println!(
            "Publish the new certificates with `publish`, and revoke the previous generation's \
             with `revoke --kind subkeys --date <previous>`"
        );
    }
    result
}

/// One applet's rotation from the generation the card holds, which `old` derives; to another
/// generation of the same key seed unless the rotation is `moving_off` one
fn rotation(
    context: &Context,
    old: &Context,
    app: App,
    found: &Attached,
    moving_off: bool,
) -> Result<Box<dyn Pending>> {
    let opts = context.opts(app);
    let (derive, path, identity, policy) = (&opts.derive, &opts.path, &opts.identity, &opts.policy);
    refuse_impossible_generation(identity, path)?;
    let generation = match app {
        App::Piv => piv::generation_on_card(reader(found))?,
        App::Pgp => pgp::generation_on_card(reader(found))?,
    };
    let shown = generation.map_or("no date".into(), |date| date.to_string());
    if !moving_off && generation == path.date {
        bail!(
            "The {} application already holds the generation of {shown}; pass a new --date",
            app.name()
        );
    }
    log::info!("The {} application holds the generation of {shown}", app.name());
    let previous_path = PathArgs { subkey: path.subkey.clone(), date: generation };
    // An undated generation went onto the card without a validity, which counts from a day
    let previous_identity = IdentityArgs {
        validity: generation.and(identity.validity),
        ..identity.clone()
    };
    match app {
        App::Piv => {
            let builder = piv_builder(context, derive, path, identity, None, Some(policy))?;
            let previous =
                piv_builder(old, derive, &previous_path, &previous_identity, None, Some(policy))?;
            planned(builder, Some(previous), found)
        }
        App::Pgp => {
            let builder = pgp_builder(context, derive, path, identity, None)?;
            let previous = pgp_builder(old, derive, &previous_path, &previous_identity, None)?;
            planned(with_touch(builder, policy), Some(previous), found)
        }
    }
}

pub(super) fn change_pin(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    pin: Option<Zeroizing<String>>,
    current: Option<Zeroizing<String>>,
    reset: bool,
    write: &WriteArgs,
) -> Result<()> {
    // The pins a pin change needs, and one the named applet cannot take, were refused before
    // the seeds; a pin is judged here against the applets the card carries
    let (found, apps) = locate(app, card)?;
    if let Some(pin) = &pin {
        for app in &apps {
            refuse_unfit_pin(*app, pin)?;
        }
    }
    if write.dry_run {
        println!(
            "Would {} the user pin of the {} application(s) of {}",
            if reset { "reset" } else { "change" },
            apps.iter()
                .map(|app| app.name())
                .collect::<Vec<_>>()
                .join(" and "),
            found.describe()
        );
        return Ok(());
    }
    let pin = pin.expect("required unless a dry run");
    let current = if reset { None } else { current };
    for app in apps {
        match (app, &current) {
            (App::Piv, Some(current)) => piv::change_pin(reader(&found), current, &pin)?,
            (App::Pgp, Some(current)) => pgp::change_pin(reader(&found), current, &pin)?,
            (app, None) => card_applet(context, app)?.reset_pin(reader(&found), &pin)?,
        }
    }
    Ok(())
}

pub(super) fn wipe(
    context: &Context,
    app: &AppArgs,
    card: &CardArgs,
    force: bool,
    write: &WriteArgs,
) -> Result<()> {
    let (found, apps) = locate(app, card)?;
    let mut names = Vec::new();
    let mut applets = Vec::new();
    for app in apps {
        let applet = card_applet(context, app)?;
        let name = applet.plan_wipe(reader(&found), force)?;
        names.push(format!("the {} application of {name}", applet.name()));
        applets.push(applet);
    }
    let what = format!(
        "Wiping resets\n  {}\nEvery key and certificate on it is erased, and nothing is put back.",
        names.join("\n  ")
    );
    if write.dry_run {
        println!("{what}");
        return Ok(());
    }
    if !write.yes {
        ask(&what)?;
    }
    for applet in applets {
        applet.wipe(reader(&found), force)?;
    }
    println!("Wiped {}", found.describe());
    Ok(())
}

/// An OpenPGP builder with the touch an upload gives the keys
fn with_touch(builder: pgp::SeededSmartcard, policy: &PolicyArgs) -> pgp::SeededSmartcard {
    let builder = builder.with_fixed_touch(policy.fixed_touch);
    match policy.policy {
        Some(policy) => builder.with_policy(policy),
        None => builder,
    }
}

/// The builder of what administers one applet of a card, without an identity
fn card_applet(context: &Context, app: App) -> Result<Box<dyn Applet>> {
    let (identity, path) = (IdentityArgs::default(), PathArgs::default());
    let derive = &context.opts(app).derive;
    Ok(match app {
        App::Piv => Box::new(piv_builder(context, derive, &path, &identity, None, None)?),
        App::Pgp => Box::new(pgp_builder(context, derive, &path, &identity, None)?),
    })
}

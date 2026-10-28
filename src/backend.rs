//! What the two backends share: what their builders do with a card, the plan of an upload,
//! and the subtrees of the seeds a builder derives from.
//!
//! Both builders do the same things to a card, each to its own applet: [`Applet`] is what a
//! command holds of either, and [`Backend`] what is typed by a backend's own writes.
//!
//! Each backend derives under an application subtree of its own (`app:piv`, `app:pgp`) of the
//! card seed and of the key seed. A subtree is derived when the builder is made, and the ones
//! below the key seed's only once a key needs them, so that a command derives no more than it
//! uses: one argon2 pass is a noticeable fraction of a second.

use crate::role::KeyRole;
use crate::seed::{KeyPath, SecretSeed, Seed256, Seed256Derive, Seeds};
use crate::target::CardTarget;

use std::fmt;
use std::sync::OnceLock;

use anyhow::{Result, anyhow};

/// What a builder of either backend does with a card, each to its own applet
///
/// Object safe, so that a command holds the builders of a card's two applets side by side.
pub trait Applet {
    /// The applet, as messages name it: `PIV` or `OpenPGP`
    fn name(&self) -> &'static str;

    /// Open the card `init` would reset, refuse it if it cannot take what `init` installs, and
    /// name it, for the confirmation
    fn preflight(&self, target: Option<CardTarget>) -> Result<String>;

    /// Reset the card and give it what the card seed derives for it, no key of the identity's
    fn init(&self, target: Option<CardTarget>) -> Result<()>;

    /// Check that the card holds what the seeds derive, reporting every difference at once
    fn check(&self, target: Option<CardTarget>) -> Result<()>;

    /// Open the card `wipe` would reset, refuse it unless this card seed initialized it or
    /// `force` says it may be anyone's, and name it
    fn plan_wipe(&self, target: Option<CardTarget>, force: bool) -> Result<String>;

    /// Reset the card, as `plan_wipe` named it, and give it nothing
    fn wipe(&self, target: Option<CardTarget>, force: bool) -> Result<()>;

    /// Set a new user pin on a card this card seed initialized, with the credential it derives
    /// for the card, which needs no current pin
    fn reset_pin(&self, target: Option<CardTarget>, new: &str) -> Result<()>;
}

/// What a builder of either backend writes to a card, typed by the backend's own writes
///
/// Every write is planned first, from what the card shows without a credential, and made only
/// as the confirmed plan lists it: a card that changed in between is refused.
pub trait Backend: Applet + Sized {
    /// One write an upload makes
    type Change: fmt::Display + fmt::Debug + Clone + PartialEq;

    /// What an upload to the card would write
    fn plan_upload(&self, target: Option<CardTarget>) -> Result<UpdatePlan<Self::Change>>;

    /// Write what `confirmed` lists, and return what the card still lacks afterwards
    fn upload(
        &self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan<Self::Change>,
    ) -> Result<UpdatePlan<Self::Change>>;

    /// What rotating the card from `previous`'s generation to this one would write
    fn plan_rotation_from(
        &self,
        previous: &Self,
        target: Option<CardTarget>,
    ) -> Result<UpdatePlan<Self::Change>>;

    /// Rotate the card from `previous`'s generation to this one, as `confirmed` lists
    fn rotate_from(
        &self,
        previous: &Self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan<Self::Change>,
    ) -> Result<UpdatePlan<Self::Change>>;
}

/// What an upload to one card would write
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan<C> {
    /// The card, as the confirmation names it
    pub card: String,
    /// The writes, in the order they are made
    pub changes: Vec<C>,
    /// What the upload leaves alone, and why
    pub notes: Vec<String>,
}

impl<C> UpdatePlan<C> {
    /// Whether the card already holds everything the key seed derives
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl<C: fmt::Display> fmt::Display for UpdatePlan<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.changes.is_empty() {
            f.write_str("  nothing to change")?;
        }
        for (index, change) in self.changes.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "  {change}")?;
        }
        for note in &self.notes {
            write!(f, "\n  note: {note}")?;
        }
        Ok(())
    }
}

/// The value in `cell`, derived into it first if it holds none yet
///
/// What a builder derives is kept this way, so that it is derived once however often the
/// command uses it.
pub(crate) fn cached<T>(cell: &OnceLock<T>, derive: impl FnOnce() -> Result<T>) -> Result<&T> {
    if let Some(value) = cell.get() {
        return Ok(value);
    }
    let value = derive()?;
    Ok(cell.get_or_init(|| value))
}

/// The subtrees one application derives from: the card seed's and the key seed's, each where
/// the command has that seed
pub(crate) struct Subtrees {
    /// The card seed's subtree, which every card credential and identifier derives from
    card: Option<SecretSeed>,
    /// The key seed's subtree, and the key path below it
    key: Option<KeySide>,
}

impl Subtrees {
    /// The application `name`'s subtrees of `seeds`, the keys along `path`
    ///
    /// One seed in both roles is one subtree, derived once.
    pub(crate) fn new(seeds: Seeds<'_>, name: &str, path: &KeyPath) -> Subtrees {
        let card = seeds.card.map(|seed| seed.app(name));
        let key = seeds.key.map(|seed| {
            let app = match (&card, seeds.card) {
                (Some(card), Some(card_seed)) if card_seed == seed => card.clone(),
                _ => seed.app(name),
            };
            KeySide::new(app, path.clone())
        });
        Subtrees { card, key }
    }

    /// Subtrees fixed in advance, as the legacy scheme has them
    pub(crate) fn fixed(card: SecretSeed, key: KeySide) -> Subtrees {
        Subtrees { card: Some(card), key: Some(key) }
    }

    /// Whether the command has the card seed
    pub(crate) fn has_card(&self) -> bool {
        self.card.is_some()
    }

    /// Whether the command has the key seed
    pub(crate) fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// The card seed's subtree, for what administers a card
    pub(crate) fn card(&self) -> Result<&Seed256> {
        self.card
            .as_deref()
            .map(|seed| &**seed)
            .ok_or_else(|| anyhow!("This needs the card seed, which administers the card"))
    }

    /// The key seed's subtrees, for the identity and its keys
    pub(crate) fn key(&self) -> Result<&KeySide> {
        self.key
            .as_ref()
            .ok_or_else(|| anyhow!("This needs the key seed, which derives the identity's keys"))
    }
}

/// What the key seed derives under one application
///
/// The identity sits in the application subtree itself; its keys sit below it, a device's own
/// under `[sub:<id>] / [date:<iso>]` and the ones every card of the identity shares under
/// `[date:<iso>]`.
pub(crate) struct KeySide {
    /// The application subtree, where the identity sits
    app: SecretSeed,
    /// Where the keys sit below it
    path: KeyPath,
    /// The device's own keys' subtree
    device: OnceLock<SecretSeed>,
    /// The subtree of the keys every card of the identity shares
    shared: OnceLock<SecretSeed>,
}

impl KeySide {
    /// The key side of an application subtree, its keys along `path`
    fn new(app: SecretSeed, path: KeyPath) -> KeySide {
        KeySide { app, path, device: OnceLock::new(), shared: OnceLock::new() }
    }

    /// A key side whose subtrees are fixed in advance, as the legacy scheme has them
    pub(crate) fn fixed(app: SecretSeed, device: SecretSeed, shared: SecretSeed) -> KeySide {
        KeySide {
            app,
            path: KeyPath::default(),
            device: OnceLock::from(device),
            shared: OnceLock::from(shared),
        }
    }

    /// The application subtree, where the identity sits
    pub(crate) fn app(&self) -> &Seed256 {
        &self.app
    }

    /// The subtree of the device's own keys
    pub(crate) fn device(&self) -> &Seed256 {
        self.device.get_or_init(|| self.path.device(&self.app))
    }

    /// The subtree a usable key derives from: the device's own, or for the decryption key the
    /// one every card of the identity shares
    pub(crate) fn seed_for(&self, role: KeyRole) -> &Seed256 {
        if role.is_device_bound() {
            self.device()
        } else {
            self.shared.get_or_init(|| self.path.shared(&self.app))
        }
    }
}

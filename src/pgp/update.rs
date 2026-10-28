//! Uploading keys to an OpenPGP card the card seed initialized, without a factory reset.
//!
//! The card is compared with what the key seed derives from what it shows without a pin: the
//! fingerprints, the key attributes, the touch flags, how long a signing pin entry lasts and
//! the cardholder data. Only then is the admin pin the card seed derives for the card spent,
//! and the card is compared again first, so a card swapped after the question is not written
//! blind.

use super::card::{Subkey, card_facts, describe, open_card, role_keys};
use super::ownership::Fingerprints;
use super::{KeyRole, Scheme, SeededSmartcard};
use crate::ownership::Ownership;
use crate::policy::Touch;
use crate::seed;
use crate::target::CardTarget;

use anyhow::{Result, anyhow, bail};

use chrono::NaiveDate;

use openpgp_card::Card;
use openpgp_card::ocard::data::{Lang, TouchPolicy};
use openpgp_card::state::{Admin, Transaction};

use secrecy::SecretString;

use std::fmt;
use std::time::SystemTime;

/// One write an upload makes
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Import the role's derived key: the card holds another, or its touch policy is fixed
    /// and only a new import lets it change
    Key {
        /// The role written to
        role: KeyRole,
    },
    /// Set the role's touch policy to the chosen one
    Touch {
        /// The role written to
        role: KeyRole,
    },
    /// Set how long one signing pin entry lasts
    SigningPin {
        /// Whether every signature asks for the pin
        forced: bool,
    },
    /// Write the cardholder name
    CardholderName,
    /// Write the cardholder language preferences
    Lang,
    /// Write the URL of the public certificate
    Url,
    /// Write the login data
    Login,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Change::Key { role } => write!(f, "{role} key: import the derived key"),
            Change::Touch { role } => write!(f, "{role} key: set the chosen touch policy"),
            Change::SigningPin { forced: true } => {
                f.write_str("signing pin: ask for it before every signature")
            }
            Change::SigningPin { forced: false } => {
                f.write_str("signing pin: ask for it once per session")
            }
            Change::CardholderName => f.write_str("cardholder name: write the given one"),
            Change::Lang => f.write_str("language preferences: write the given ones"),
            Change::Url => f.write_str("certificate url: write the given one"),
            Change::Login => f.write_str("login data: write the given one"),
        }
    }
}

/// What an upload to one OpenPGP card would write
pub type UpdatePlan = crate::backend::UpdatePlan<Change>;

/// What one key slot shows without a pin
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RoleState {
    pub(super) fingerprint: Option<[u8; 20]>,
    /// Whether the slot's attributes are this card's algorithm, `None` when unreadable
    pub(super) fits: Option<bool>,
    /// The touch policy of its user interaction flag, `None` on cards without one
    pub(super) touch: Option<TouchPolicy>,
}

/// What a card shows of everything an upload may write, read without a pin
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CardState {
    /// The card, as the confirmation names it
    pub(super) card: String,
    /// Signing, decryption and authentication, in [`KeyRole::PGP`] order
    pub(super) keys: [RoleState; 3],
    pub(super) signing_pin_forced: Option<bool>,
    /// Whether the card takes the cached touch, a Yubico extension of the flag that a
    /// YubiKey 5 (OpenPGP card 3.4) has and a YubiKey 4 or a spec-conforming card has not
    pub(super) cached_touch: bool,
    pub(super) name: Option<String>,
    pub(super) lang: Option<Vec<[u8; 2]>>,
    pub(super) url: Option<String>,
    pub(super) login: Option<String>,
}

/// The key generation an OpenPGP card holds: `None` for an undated one
///
/// Read off the decryption key's creation time, which an upload sets to the generation's
/// midnight; any other time is a key this tool did not upload.
pub fn generation_on_card(target: Option<CardTarget>) -> Result<Option<NaiveDate>> {
    let mut card = open_card(target)?;
    let mut transaction = card.transaction()?;
    let time = transaction
        .key_generation_time(KeyRole::Decryption.key_type())?
        .ok_or_else(|| anyhow!("The card holds no decryption key to rotate from"))?;
    seed::generation_of(SystemTime::from(&time)).ok_or_else(|| {
        anyhow!(
            "The card's decryption key was created at no generation's midnight; it was not \
             uploaded by this tool"
        )
    })
}

/// The touch policies an upload aims for, of those that satisfy the chosen one: the cached
/// ones where the card takes them, else the plain ones that stand in for them
fn touch_goals(wanted: &[TouchPolicy], cached: bool) -> Vec<TouchPolicy> {
    let is_cached =
        |touch: &TouchPolicy| matches!(touch, TouchPolicy::Cached | TouchPolicy::CachedFixed);
    match wanted.first() {
        Some(first) if cached && is_cached(first) => vec![*first],
        _ => wanted
            .iter()
            .copied()
            .filter(|touch| !is_cached(touch))
            .collect(),
    }
}

impl SeededSmartcard {
    /// Read what the card shows; no pin is asked for and no try spent
    pub(super) fn read_state(&self, card: &mut Card<Transaction<'_>>) -> Result<CardState> {
        let keys = KeyRole::PGP.map(|role| {
            let kt = role.key_type();
            RoleState {
                fingerprint: card
                    .fingerprint(kt)
                    .ok()
                    .flatten()
                    .and_then(|fp| fp.as_bytes().try_into().ok()),
                fits: card
                    .algorithm_attributes(kt)
                    .ok()
                    .map(|attributes| self.fits(role, &attributes)),
                touch: card
                    .user_interaction_flag(kt)
                    .ok()
                    .flatten()
                    .map(|uif| uif.touch_policy()),
            }
        });
        let lang = card.cardholder_related_data().ok().map(|data| {
            data.lang()
                .unwrap_or_default()
                .iter()
                .filter_map(|lang| match lang {
                    Lang::Value(code) => Some(*code),
                    Lang::Invalid(_) => None,
                })
                .collect()
        });
        Ok(CardState {
            card: describe(card)?,
            keys,
            signing_pin_forced: card.pw_status_bytes().ok().map(|s| s.pw1_cds_valid_once()),
            cached_touch: card
                .application_identifier()
                .is_ok_and(|aid| aid.manufacturer() == 0x0006 && aid.version() >= 0x0304),
            name: card.cardholder_name().ok(),
            lang,
            url: card.url().ok(),
            login: card
                .login_data()
                .ok()
                .map(|data| String::from_utf8_lossy(&data).into_owned()),
        })
    }

    /// The touch policies that satisfy the chosen one, as an upload would leave them: a card
    /// that refuses cached or fixed gets the plain variant, and that counts as done
    ///
    /// `None` without `--policy` or `--fixed-touch` on a key the card already holds: an
    /// upload then keeps its touch as it is, so changing a name never quietly adds or drops a
    /// touch requirement.
    fn wanted_touch(&self, importing: bool) -> Option<&'static [TouchPolicy]> {
        if !(self.policy_given || self.fixed_touch || importing) {
            return None;
        }
        Some(match (self.policy.pgp_touch(), self.fixed_touch) {
            (Touch::Never, _) => &[TouchPolicy::Off],
            (Touch::Always, false) => &[TouchPolicy::On],
            (Touch::Always, true) => &[TouchPolicy::Fixed, TouchPolicy::On],
            (Touch::Cached, false) => &[TouchPolicy::Cached, TouchPolicy::On],
            (Touch::Cached, true) => &[
                TouchPolicy::CachedFixed,
                TouchPolicy::Fixed,
                TouchPolicy::On,
            ],
        })
    }

    /// The writes that make the card hold what the key seed derives, from what it shows
    ///
    /// Refuses another algorithm: other keys under other labels, which a card takes from a
    /// reset, attributes and all.
    pub(super) fn plan(&self, expected: &Fingerprints, state: &CardState) -> Result<UpdatePlan> {
        let mut changes = Vec::new();
        let mut touch_changes = Vec::new();
        let mut unreported = false;

        for (role, want) in expected {
            let slot = KeyRole::PGP
                .iter()
                .position(|r| r == role)
                .expect("every role has a slot");
            let key = &state.keys[slot];
            let mut import = key.fingerprint.as_ref() != Some(want);
            // An empty slot takes whatever its import brings, attributes and all, as one
            // fresh from `init` does; only a key of another algorithm in place needs a reset
            if import && key.fingerprint.is_some() && key.fits == Some(false) {
                bail!(
                    "The card's {role} key slot holds another algorithm than the {} the key \
                     seed derives; changing the algorithm takes `init`, which resets the card, \
                     then `upload`",
                    self.algorithm
                );
            }
            if let Some(wanted) = self.wanted_touch(import) {
                let goals = touch_goals(wanted, state.cached_touch);
                match key.touch {
                    // A card that shows no flag has none to compare; it is said once, below
                    None => unreported |= wanted != [TouchPolicy::Off],
                    Some(touch) if !goals.contains(&touch) => {
                        // A fixed flag only changes with the key it guards
                        if matches!(touch, TouchPolicy::Fixed | TouchPolicy::CachedFixed) {
                            import = true;
                        }
                        touch_changes.push(Change::Touch { role: *role });
                    }
                    Some(_) => {}
                }
            }
            if import {
                changes.push(Change::Key { role: *role });
            }
        }
        changes.extend(touch_changes);

        let importing = changes
            .iter()
            .any(|change| matches!(change, Change::Key { .. }));
        if self.policy_given || importing {
            let forced = self.policy.pgp_signing_pin_forced();
            if state.signing_pin_forced != Some(forced) {
                changes.push(Change::SigningPin { forced });
            }
        }
        // The cardholder is the identity whose keys fill the card, so only an upload of all
        // of them names it; another key seed's single key leaves the name as it is
        if self.keys.len() == KeyRole::PGP.len()
            && let Some(name) = self.cardholder_name()
            && state.name.as_deref() != Some(name)
        {
            changes.push(Change::CardholderName);
        }
        let data = &self.card_data;
        if !data.lang.is_empty() && state.lang.as_ref() != Some(&data.lang) {
            changes.push(Change::Lang);
        }
        if data.url.is_some() && state.url != data.url {
            changes.push(Change::Url);
        }
        if data.login.is_some() && state.login != data.login {
            changes.push(Change::Login);
        }

        let mut notes = Vec::new();
        if unreported {
            notes.push(
                "the card shows no touch policies, so they are neither compared nor written".into(),
            );
        }
        Ok(UpdatePlan { card: state.card.clone(), changes, notes })
    }

    /// Warn about each pin and touch requirement the card holds other than the policy's, as
    /// `check` does on PIV: advisory, since a card provisioned under another `--policy` still
    /// holds the right keys
    pub(super) fn warn_policy_differences(&self, card: &mut Card<Transaction<'_>>) {
        // Advisory: a card that cannot be read for it is held to nothing
        let Ok(state) = self.read_state(card) else {
            return;
        };
        let wanted = self.wanted_touch(true).unwrap_or(&[]);
        let goals = touch_goals(wanted, state.cached_touch);
        for (role, key) in KeyRole::PGP.iter().zip(&state.keys) {
            if self.keys.contains(role)
                && let Some(touch) = key.touch
                && !goals.contains(&touch)
            {
                log::warn!("Touch policy of the {role} key: card={touch:?}, expected={goals:?}");
            }
        }
        let forced = self.policy.pgp_signing_pin_forced();
        if let Some(on_card) = state.signing_pin_forced
            && on_card != forced
        {
            log::warn!("Pin for every signature: card={on_card}, expected={forced}");
        }
    }

    /// What is left of a plan once written: a touch the card refused for the next best one
    /// it has, which the plan aimed past, is what the card can do
    fn settled(&self, mut plan: UpdatePlan, state: &CardState) -> UpdatePlan {
        let wanted = self.wanted_touch(true).unwrap_or(&[]);
        let before = plan.changes.len();
        plan.changes.retain(|change| match change {
            Change::Touch { role } => !KeyRole::PGP
                .iter()
                .zip(&state.keys)
                .any(|(r, key)| r == role && key.touch.is_some_and(|t| wanted.contains(&t))),
            _ => true,
        });
        if plan.changes.len() != before {
            plan.notes.push(
                "the card refused the touch policy asked for and took the closest one it has"
                    .into(),
            );
        }
        plan
    }

    /// Refuse a card this card seed did not initialize, before any pin is spent
    ///
    /// A card without room for the card identifier cannot show whose it is; the card seed's
    /// admin pin is then taken at its word, which a wrong card seed pays for with one try,
    /// behind the guard.
    pub(super) fn refuse_unowned(
        &self,
        card: &mut Card<Transaction<'_>>,
        keys: Option<&Fingerprints>,
        what: &str,
    ) -> Result<()> {
        // The legacy scheme wrote no card identifier, so its cards are told by their keys,
        // which `pin --reset` and `wipe` would otherwise not look at
        let derived;
        let keys = match keys {
            None if self.scheme == Scheme::Legacy => {
                derived = self.fingerprints(&self.signed_cert()?)?;
                Some(&derived)
            }
            keys => keys,
        };
        let facts = card_facts(card)?;
        let ownership = self.ownership(&facts, keys)?;
        let private_use = card
            .extended_capabilities()
            .is_ok_and(|capabilities| capabilities.private_use_dos());
        match ownership {
            Ownership::Owned => Ok(()),
            _ if !private_use => {
                log::warn!(
                    "The card has no room for a card identifier, so it cannot show whose it is; \
                     trusting the card seed, which costs an admin pin try if it is the wrong one"
                );
                Ok(())
            }
            other => {
                let hint = match other {
                    Ownership::Blank => "`init` gives it what the card seed derives",
                    _ => "give the card seed it was initialized with, or reset it with `init`",
                };
                bail!("The card is {other}, so it cannot be {what}; {hint}")
            }
        }
    }

    /// Open the card, refuse it unless the card seed initialized it, and plan
    fn open_owned<'app>(
        &self,
        card: &'app mut Card<openpgp_card::state::Open>,
        expected: &Fingerprints,
        previous: Option<&Fingerprints>,
    ) -> Result<(Card<Transaction<'app>>, UpdatePlan)> {
        let mut transaction = card.transaction()?;
        self.refuse_unowned(&mut transaction, Some(expected), "uploaded to")?;
        self.refuse_unfit_keys(&mut transaction)?;
        let state = self.read_state(&mut transaction)?;
        if let Some(previous) = previous {
            refuse_unrelated(&state, previous, expected)?;
        }
        let mut plan = self.plan(expected, &state)?;
        if previous.is_some() && self.keys.contains(&KeyRole::Decryption) {
            plan.notes.push(
                "an OpenPGP card has one decryption slot, so the previous decryption key leaves \
                 the card; `ungap` with the previous --date exports it for decrypting in software"
                    .into(),
            );
        }
        Ok((transaction, plan))
    }

    /// What an upload to the card would write, read without a pin
    pub(super) fn plan_upload(&self, target: Option<CardTarget>) -> Result<UpdatePlan> {
        let expected = self.fingerprints(&self.signed_cert()?)?;
        let mut card = open_card(target)?;
        Ok(self.open_owned(&mut card, &expected, None)?.1)
    }

    /// Write what `confirmed` lists under the derived admin pin, and return what the card
    /// still lacks afterwards
    ///
    /// The plan is made again on the card opened here, and nothing is written unless it is
    /// the confirmed one.
    pub(super) fn upload(
        &self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
    ) -> Result<UpdatePlan> {
        self.write_plan(target, confirmed, None)
    }

    /// What rotating the card from `previous`'s generation to this one would write
    ///
    /// An OpenPGP card has no slot to keep a previous key in, so a rotation is an upload of
    /// the new generation to a card that holds the previous one.
    pub(super) fn plan_rotation_from(
        &self,
        previous: &SeededSmartcard,
        target: Option<CardTarget>,
    ) -> Result<UpdatePlan> {
        let expected = self.fingerprints(&self.signed_cert()?)?;
        let old = previous.fingerprints(&previous.signed_cert()?)?;
        let mut card = open_card(target)?;
        Ok(self.open_owned(&mut card, &expected, Some(&old))?.1)
    }

    /// Rotate the card from `previous`'s generation to this one, as `confirmed` lists
    pub(super) fn rotate_from(
        &self,
        previous: &SeededSmartcard,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
    ) -> Result<UpdatePlan> {
        let old = previous.fingerprints(&previous.signed_cert()?)?;
        self.write_plan(target, confirmed, Some(&old))
    }

    /// Authenticate, write a confirmed plan and report what the card still lacks
    fn write_plan(
        &self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
        previous: Option<&Fingerprints>,
    ) -> Result<UpdatePlan> {
        let cert = self.signed_cert()?;
        let expected = self.fingerprints(&cert)?;
        let mut card = open_card(target)?;
        let (mut transaction, plan) = self.open_owned(&mut card, &expected, previous)?;
        if plan != *confirmed {
            bail!("The card changed since the plan was shown; run the command again to see it");
        }
        if plan.is_empty() {
            return Ok(plan);
        }

        let keys = role_keys(&cert, &self.keys, self.subkey_creation_time())?;
        {
            let mut admin = self.authenticate(&mut transaction)?;
            for change in &plan.changes {
                self.apply(&mut admin, &keys, change)?;
            }
        }

        // The application related data is cached by the transaction, and is stale now
        transaction.invalidate_cache()?;
        let after = self.read_state(&mut transaction)?;
        Ok(self.settled(self.plan(&expected, &after)?, &after))
    }

    /// Make one write of a plan on a card opened under the admin pin
    fn apply(
        &self,
        admin: &mut Card<Admin<'_, '_>>,
        keys: &[(KeyRole, Subkey)],
        change: &Change,
    ) -> Result<()> {
        log::info!("Writing {change}");
        match change {
            Change::Key { role } => {
                let (_, subkey) = keys
                    .iter()
                    .find(|(r, _)| r == role)
                    .ok_or_else(|| anyhow!("{role} key not found in cert"))?;
                self.import_role(admin, *role, subkey)?;
            }
            Change::Touch { role } => self.set_policy_touch(admin, role.key_type(), true),
            Change::SigningPin { forced } => {
                // Explicit rather than the card's default, which differs between cards (a
                // YubiKey asks once per session, opcard before every signature); advisory,
                // like the touch
                if let Err(err) = admin.set_user_pin_signing_validity(*forced) {
                    log::warn!("Card refused to set how long a signing pin entry lasts ({err})");
                }
            }
            Change::CardholderName => {
                if let Some(name) = self.cardholder_name() {
                    admin.set_cardholder_name(name)?;
                }
            }
            Change::Lang => {
                let langs: Vec<Lang> = self
                    .card_data
                    .lang
                    .iter()
                    .map(|code| Lang::Value(*code))
                    .collect();
                admin.set_lang(&langs)?;
            }
            Change::Url => {
                if let Some(url) = &self.card_data.url {
                    admin.set_url(url)?;
                }
            }
            Change::Login => {
                if let Some(login) = &self.card_data.login {
                    admin.set_login_data(login.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Set a new user pin on a card this card seed initialized, under its derived admin pin
    ///
    /// The admin pin resets the user pin outright, so the current one is not needed and a
    /// forgotten one is recovered without a reset.
    pub(super) fn reset_pin(&self, target: Option<CardTarget>, pin: &str) -> Result<()> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        self.refuse_unowned(&mut transaction, None, "unblocked")?;

        // The card says how long a pin it takes; the spec asks for six characters at least
        let longest = usize::from(transaction.pw_status_bytes()?.pw1_max_len());
        let length = pin.len();
        if !(6..=longest).contains(&length) {
            bail!(
                "The card takes user pins of 6 to {longest} characters, this one has {length}; \
                 nothing was changed"
            );
        }

        let mut admin = self.authenticate(&mut transaction)?;
        admin.reset_user_pin(SecretString::from(pin.to_owned()))?;
        log::info!("User pin reset on {}", describe(admin.as_transaction())?);
        Ok(())
    }
}

/// Refuse a rotation of a card that holds neither the previous generation nor this one
fn refuse_unrelated(
    state: &CardState,
    previous: &Fingerprints,
    expected: &Fingerprints,
) -> Result<()> {
    let holds = |keys: &Fingerprints| {
        keys.iter().any(|(role, fingerprint)| {
            let slot = KeyRole::PGP.iter().position(|r| r == role);
            slot.and_then(|slot| state.keys[slot].fingerprint).as_ref() == Some(fingerprint)
        })
    };
    if !holds(previous) && !holds(expected) {
        bail!(
            "The card holds neither the previous generation's keys nor this one's; check the \
             previous --date and --from-key-seed, or `upload` the new generation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::seed::{KeyPath, Seed256, Seeds};

    const SEED: Seed256 = [0xa7u8; 32];

    fn path(date: Option<&str>) -> KeyPath {
        KeyPath {
            subkey: Some("laptop".into()),
            date: date.map(|date| date.parse().unwrap()),
        }
    }

    fn card() -> SeededSmartcard {
        SeededSmartcard::new(Seeds::one(&SEED), path(None), "Test".into())
    }

    fn fingerprints(card: &SeededSmartcard) -> Fingerprints {
        card.fingerprints(&card.signed_cert().unwrap()).unwrap()
    }

    /// A card holding exactly what `card` derives, under the relaxed policy an upload gives it
    fn provisioned(card: &SeededSmartcard) -> CardState {
        let mut keys: [RoleState; 3] = Default::default();
        for (role, fingerprint) in fingerprints(card) {
            let slot = KeyRole::PGP.iter().position(|r| *r == role).unwrap();
            keys[slot] = RoleState {
                fingerprint: Some(fingerprint),
                fits: Some(true),
                touch: Some(TouchPolicy::Cached),
            };
        }
        CardState {
            card: String::new(),
            keys,
            signing_pin_forced: Some(false),
            cached_touch: true,
            name: Some("Test".into()),
            lang: Some(vec![*b"en"]),
            url: Some(String::new()),
            login: Some(String::new()),
        }
    }

    #[test]
    fn a_card_holding_the_derivation_needs_nothing() {
        let card = card();
        let plan = card
            .plan(&fingerprints(&card), &provisioned(&card))
            .unwrap();
        assert!(plan.is_empty(), "{plan}");
    }

    /// The decryption key belongs to the identity, so another device's card already holds it
    #[test]
    fn another_device_shares_the_decryption_key() {
        let state = provisioned(&card());
        let phone = SeededSmartcard::new(
            Seeds::one(&SEED),
            KeyPath { subkey: Some("phone".into()), date: None },
            "Test".into(),
        );
        let plan = phone.plan(&fingerprints(&phone), &state).unwrap();
        assert_eq!(
            plan.changes,
            vec![
                Change::Key { role: KeyRole::Signature },
                Change::Key { role: KeyRole::Authentication }
            ]
        );
    }

    #[test]
    fn a_chosen_key_is_all_an_upload_touches() {
        let state = provisioned(&card());
        let team = SeededSmartcard::new(Seeds::one(&[0x11; 32]), KeyPath::default(), "Test".into())
            .with_keys(&[KeyRole::Decryption])
            .unwrap();
        let plan = team.plan(&fingerprints(&team), &state).unwrap();
        assert_eq!(plan.changes, vec![Change::Key { role: KeyRole::Decryption }]);
    }

    #[test]
    fn touch_and_signing_pin_change_only_when_asked() {
        let card = card();
        let mut state = provisioned(&card);
        for key in &mut state.keys {
            key.touch = Some(TouchPolicy::Off);
        }
        state.signing_pin_forced = Some(true);
        assert!(card.plan(&fingerprints(&card), &state).unwrap().is_empty());

        let strict = self::card().with_policy(Policy::Strict);
        let plan = strict.plan(&fingerprints(&strict), &state).unwrap();
        assert_eq!(
            plan.changes,
            KeyRole::PGP
                .into_iter()
                .map(|role| Change::Touch { role })
                .collect::<Vec<_>>()
        );

        let relaxed = self::card().with_policy(Policy::Relaxed);
        let plan = relaxed.plan(&fingerprints(&relaxed), &state).unwrap();
        assert!(plan.changes.contains(&Change::SigningPin { forced: false }));
    }

    /// A key going onto the card gets the policy whether or not one was chosen, as the
    /// provisioning upload of a freshly initialized card does
    #[test]
    fn a_new_key_gets_the_policy() {
        let card = card();
        let mut state = CardState::default();
        for key in &mut state.keys {
            key.touch = Some(TouchPolicy::Off);
        }
        let plan = card.plan(&fingerprints(&card), &state).unwrap();
        assert!(
            plan.changes
                .contains(&Change::Touch { role: KeyRole::Signature }),
            "{plan}"
        );
        assert!(plan.changes.contains(&Change::SigningPin { forced: false }), "{plan}");
    }

    /// A plain touch stands in for the cached one on a card without it, and only there: a
    /// YubiKey 5 left at touch-always is brought to the cached touch `relaxed` asks for
    #[test]
    fn a_plain_on_satisfies_cached_only_where_the_card_lacks_it() {
        let card = card().with_policy(Policy::Relaxed);
        let mut state = provisioned(&card);
        for key in &mut state.keys {
            key.touch = Some(TouchPolicy::On);
        }
        let plan = card.plan(&fingerprints(&card), &state).unwrap();
        assert!(
            plan.changes
                .contains(&Change::Touch { role: KeyRole::Signature }),
            "{plan}"
        );

        state.cached_touch = false;
        assert!(card.plan(&fingerprints(&card), &state).unwrap().is_empty());

        // A card that claims the cached touch and still refuses it is settled with the next
        state.cached_touch = true;
        let settled = card.settled(card.plan(&fingerprints(&card), &state).unwrap(), &state);
        assert!(settled.is_empty(), "{settled}");
        assert_eq!(settled.notes.len(), 1, "{settled}");
    }

    #[test]
    fn a_card_without_touch_flags_is_not_held_to_one() {
        let never = card().with_policy(Policy::NeverTouch);
        let mut state = provisioned(&never);
        for key in &mut state.keys {
            key.touch = None;
        }
        assert!(
            never
                .plan(&fingerprints(&never), &state)
                .unwrap()
                .is_empty()
        );

        // Asked for a touch, it shows none to compare, so nothing is planned for it on any
        // run, and the plan says why
        let strict = card().with_policy(Policy::Strict);
        let plan = strict.plan(&fingerprints(&strict), &state).unwrap();
        assert_eq!(plan.changes, vec![Change::SigningPin { forced: true }]);
        assert_eq!(plan.notes.len(), 1, "{plan}");
    }

    #[test]
    fn a_fixed_touch_is_changed_with_its_key() {
        let card = card().with_policy(Policy::NeverTouch);
        let mut state = provisioned(&card);
        state.keys[0].touch = Some(TouchPolicy::Fixed);
        for key in &mut state.keys[1..] {
            key.touch = Some(TouchPolicy::Off);
        }
        let plan = card.plan(&fingerprints(&card), &state).unwrap();
        assert_eq!(
            plan.changes,
            vec![
                Change::Key { role: KeyRole::Signature },
                Change::Touch { role: KeyRole::Signature }
            ]
        );
    }

    #[test]
    fn given_card_data_is_written_and_the_rest_left_alone() {
        let card = card();
        let mut state = provisioned(&card);
        state.name = None;
        let plan = card.plan(&fingerprints(&card), &state).unwrap();
        assert_eq!(plan.changes, vec![Change::CardholderName]);

        let data = super::super::CardData {
            lang: vec![*b"de", *b"en"],
            url: Some("https://example.org/key.asc".into()),
            login: None,
        };
        let card = self::card().with_card_data(data);
        let plan = card
            .plan(&fingerprints(&card), &provisioned(&card))
            .unwrap();
        assert_eq!(plan.changes, vec![Change::Lang, Change::Url]);
    }

    #[test]
    fn another_algorithm_is_refused() {
        let card = card();
        let mut state = provisioned(&card);
        for key in &mut state.keys {
            key.fits = Some(false);
        }
        let p256 = self::card()
            .with_algorithm(crate::seed::Algorithm::P256)
            .unwrap();
        let err = p256.plan(&fingerprints(&p256), &state).unwrap_err();
        assert!(err.to_string().contains("init"), "{err}");
    }

    #[test]
    fn a_rotation_moves_every_key_and_needs_the_previous_generation() {
        let old = card();
        let state = provisioned(&old);
        let new = SeededSmartcard::new(Seeds::one(&SEED), path(Some("2027-01-01")), "Test".into());
        let plan = new.plan(&fingerprints(&new), &state).unwrap();
        assert_eq!(
            plan.changes,
            KeyRole::PGP
                .into_iter()
                .map(|role| Change::Key { role })
                .collect::<Vec<_>>()
        );
        assert!(refuse_unrelated(&state, &fingerprints(&old), &fingerprints(&new)).is_ok());

        let stranger = SeededSmartcard::new(Seeds::one(&[1; 32]), path(None), "Test".into());
        assert!(refuse_unrelated(&state, &fingerprints(&stranger), &fingerprints(&new)).is_err());
    }
}

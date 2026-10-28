//! Uploading keys to a PIV card the card seed initialized, and rotating them, without a reset.
//!
//! An upload compares what the card shows with what the key seed derives and writes only the
//! difference, under the management key the card seed derives for the card. Everything it
//! compares is public (slot metadata, certificates, msroots), so the plan is made, shown and
//! confirmed before any credential is used. The card is planned against again once
//! authenticated, so a card that changed in between is not written blind.

use super::card::{describe, finish, open_token, write_certificate};
use super::slots::{FIRST_RETIRED_SLOT, LAST_RETIRED_SLOT};
use super::{CertChain, SeededSmartcard};
use crate::role::KeyRole;
use crate::seed::{self, CardSerial};
use crate::target::CardTarget;

use anyhow::{Result, anyhow, bail};

use chrono::NaiveDate;

use yubikey::piv::{self, ManagementSlotId, RetiredSlotId, SlotId};
use yubikey::{
    Certificate as CardCertificate, Error as CardError, MgmAlgorithmId, MsRoots, PinPolicy,
    TouchPolicy, YubiKey,
};

use x509_cert::Certificate as X509Certificate;

use cms::content_info::ContentInfo;

use der::{Decode, Encode};

use std::fmt;

/// One write an upload makes
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Import a key's derived bytes
    Key {
        /// The key written
        role: KeyRole,
        /// The slot written to
        slot: SlotId,
        /// Why the key has to go in
        reason: KeyReason,
    },
    /// Store a key's derived certificate
    Certificate {
        /// The key the certificate is for
        role: KeyRole,
        /// The slot written to
        slot: SlotId,
    },
    /// Keep the previous generation's decryption key, with its certificate, in a retired slot
    Archive {
        /// The retired slot written to
        slot: SlotId,
    },
    /// Store the certificate authorities in msroots
    Msroots,
    /// Delete msroots, as `--no-msroots` asks of a card that still has authorities stored
    RemoveMsroots,
    /// Require a touch for management access, or stop requiring one
    ManagementTouch {
        /// Whether management access demands a touch afterwards
        touch: bool,
    },
    /// Count the retired keys in the key history object, which is how middleware finds them
    KeyHistory {
        /// Retired slots from 82 on that hold a key and its certificate
        on_card: u8,
    },
}

/// Why an upload imports a key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyReason {
    /// The slot holds no key, or another one than the key seed derives
    Differs,
    /// The key is right but its pin and touch policy are not, and a card fixes those when the
    /// key is imported
    Policy,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Change::Key { role, slot, reason: KeyReason::Differs } => {
                write!(f, "{slot:?} slot: import the derived {role} key")
            }
            Change::Key { slot, reason: KeyReason::Policy, .. } => {
                write!(f, "{slot:?} slot: import the same key again, under the new policy")
            }
            Change::Certificate { role, slot } => {
                write!(f, "{slot:?} slot: store the derived {role} certificate")
            }
            Change::Archive { slot } => {
                write!(f, "{slot:?} slot: keep the previous decryption key and its certificate")
            }
            Change::Msroots => f.write_str("msroots: store the certificate authorities"),
            Change::RemoveMsroots => {
                f.write_str("msroots: delete the stored certificate authorities")
            }
            Change::ManagementTouch { touch: true } => {
                f.write_str("management key: require a touch")
            }
            Change::ManagementTouch { touch: false } => {
                f.write_str("management key: stop requiring a touch")
            }
            Change::KeyHistory { on_card } => {
                write!(f, "key history: {on_card} retired keys from slot 82 on")
            }
        }
    }
}

/// What an upload to one PIV card would write
pub type UpdatePlan = crate::backend::UpdatePlan<Change>;

impl UpdatePlan {
    /// Make the key history object count `slot`, a retired slot the plan fills or that is
    /// filled already
    ///
    /// Middleware reads retired keys only as far as the object counts them, from 82 on, so a
    /// key kept in 85 needs a count of four however many of the slots before it are empty;
    /// the count never shrinks, since a slot above this one may hold another key still.
    fn count_retired(&mut self, slot: SlotId, state: &CardState) {
        let SlotId::Retired(retired) = slot else {
            return;
        };
        let index = u8::from(retired) - FIRST_RETIRED_SLOT + 1;
        let current = state.key_history.unwrap_or(0);
        let on_card = current.max(index);
        if state.key_history != Some(on_card) {
            self.changes
                .retain(|change| !matches!(change, Change::KeyHistory { .. }));
            self.changes.push(Change::KeyHistory { on_card });
        }
    }
}

/// What one slot shows without a credential
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SlotState {
    /// The public key the card reports, DER encoded
    pub(super) public: Option<Vec<u8>>,
    /// The pin and touch policy the card reports
    pub(super) policy: Option<(PinPolicy, TouchPolicy)>,
    /// Whether the card answers GET METADATA at all
    pub(super) metadata: bool,
    /// The stored certificate, DER encoded
    pub(super) certificate: Option<Vec<u8>>,
}

impl SlotState {
    /// Read what the card shows of one slot; no object is written and no try is spent
    fn read(token: &mut YubiKey, slot: SlotId) -> Result<SlotState> {
        let mut state = SlotState { metadata: true, ..Default::default() };
        match piv::metadata(token, slot) {
            Ok(metadata) => {
                state.public = metadata.public.map(|key| key.to_der()).transpose()?;
                state.policy = metadata.policy;
            }
            Err(CardError::NotSupported) => state.metadata = false,
            // An empty slot answers with an error of its own; it holds nothing
            Err(_) => {}
        }
        state.certificate = CardCertificate::read(token, slot)
            .ok()
            .and_then(|cert| cert.cert.to_der().ok());
        Ok(state)
    }

    /// The key the slot holds: what the card reports, or, without GET METADATA, the one its
    /// certificate names, which an upload writes together with the key
    fn key(&self) -> Option<Vec<u8>> {
        if self.metadata {
            return self.public.clone();
        }
        self.certificate.as_deref().and_then(|der| {
            X509Certificate::from_der(der).ok().and_then(|cert| {
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .ok()
            })
        })
    }
}

/// What a card shows of everything an upload may write, read without a credential
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CardState {
    /// The card, as the confirmation names it
    pub(super) card: String,
    /// Every slot the upload writes, and with a rotation every retired slot
    pub(super) slots: Vec<(SlotId, SlotState)>,
    pub(super) msroots: Option<Vec<u8>>,
    pub(super) management_touch: Option<TouchPolicy>,
    /// How many retired keys the key history object counts, `None` without one
    pub(super) key_history: Option<u8>,
}

impl CardState {
    /// Read what the card shows for `slots`; no object is written and no try is spent
    pub(super) fn read(token: &mut YubiKey, slots: &[SlotId]) -> Result<CardState> {
        let slots = slots
            .iter()
            .map(|slot| Ok((*slot, SlotState::read(token, *slot)?)))
            .collect::<Result<_>>()?;
        let management_touch =
            piv::metadata(token, SlotId::Management(ManagementSlotId::Management))
                .ok()
                .and_then(|metadata| metadata.policy)
                .map(|(_, touch)| touch);
        Ok(CardState {
            card: describe(token),
            slots,
            msroots: MsRoots::read(token)
                .ok()
                .flatten()
                .map(|roots| AsRef::<[u8]>::as_ref(&roots).to_vec()),
            management_touch,
            key_history: token
                .fetch_object(KEY_HISTORY_OBJECT)
                .ok()
                .and_then(|object| key_history_count(&object)),
        })
    }

    fn slot(&self, slot: SlotId) -> Option<&SlotState> {
        self.slots
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, state)| state)
    }
}

/// Every retired slot, in order
/// Refuse a retired slot with an empty one below it
///
/// The key history object only counts retired keys, and SP 800-73-4 has them fill the slots
/// from 82 up, so middleware looks for the count's keys in 82 onwards: a key above an empty
/// slot would be counted with the gap and read where there is none. A slot that holds this
/// very key already is no new gap, whatever lies below it.
fn refuse_gap(slot: SlotId, chain: &CertChain, state: &CardState) -> Result<()> {
    let empty: Vec<SlotId> = retired_slots()
        .take_while(|retired| *retired != slot)
        .filter(|retired| state.slot(*retired).is_some_and(|s| s.key().is_none()))
        .collect();
    let Some(first) = empty.first() else {
        return Ok(());
    };
    let wanted = chain
        .leaves
        .iter()
        .find(|(leaf, _)| *leaf == slot)
        .map(|(_, cert)| cert.tbs_certificate().subject_public_key_info().to_der())
        .transpose()?;
    if wanted.is_some() && state.slot(slot).and_then(SlotState::key) == wanted {
        return Ok(());
    }
    let number = |slot: &SlotId| match slot {
        SlotId::Retired(retired) => format!("{:02x}", u8::from(*retired)),
        other => format!("{other:?}"),
    };
    bail!(
        "Slot {} would leave {} empty below it, where middleware looks for retired keys first; \
         use --slot {}, the first free one",
        number(&slot),
        empty.iter().map(number).collect::<Vec<_>>().join(", "),
        number(first)
    )
}

fn retired_slots() -> impl Iterator<Item = SlotId> {
    (FIRST_RETIRED_SLOT..=LAST_RETIRED_SLOT)
        .filter_map(|byte| RetiredSlotId::try_from(byte).ok().map(SlotId::Retired))
}

/// The key history object of SP 800-73-4 part 1, section 3.3.2
const KEY_HISTORY_OBJECT: u32 = 0x005f_c10c;

/// How many retired keys with certificates on the card a key history object counts
fn key_history_count(object: &[u8]) -> Option<u8> {
    crate::ownership::top_level_tlvs(object)?
        .into_iter()
        .find(|(tag, _)| *tag == 0xC1)
        .and_then(|(_, value)| value.first().copied())
}

/// A key history object counting `on_card` retired keys with their certificates on the card
/// and none off it: `keysWithOnCardCerts`, `keysWithOffCardCerts`, then the empty error
/// detection code
fn key_history(on_card: u8) -> [u8; 8] {
    [0xC1, 0x01, on_card, 0xC2, 0x01, 0x00, 0xFE, 0x00]
}

/// Delete every msroots object the card holds
///
/// msroots spans up to five data objects; clearing only the first would leave the rest
/// behind, unreachable but still stored. An empty PUT DATA deletes an object on a YubiKey and
/// on piv-authenticator alike, and objects the card never had are left alone.
fn remove_msroots(token: &mut YubiKey) -> Result<()> {
    log::info!("Deleting the certificate authorities in msroots");
    for object in 0x005f_ff11..=0x005f_ff15 {
        if token.fetch_object(object).is_ok() {
            token.save_object(object, &mut [])?;
        }
    }
    Ok(())
}

/// The key generation a card's 9D certificate was issued for: `None` for an undated one
///
/// The date is the certificate's notBefore, which a generation's certificates start at; any
/// other time is a certificate this tool did not issue.
pub fn generation_on_card(target: Option<CardTarget>) -> Result<Option<NaiveDate>> {
    let mut token = open_token(target)?;
    let cert = CardCertificate::read(&mut token, SlotId::KeyManagement).map_err(|_| {
        anyhow!("The card holds no key management certificate in 9D to rotate from")
    })?;
    let not_before = cert
        .cert
        .tbs_certificate()
        .validity()
        .not_before
        .to_system_time();
    seed::generation_of(not_before).ok_or_else(|| {
        anyhow!(
            "The 9D certificate starts at no generation's midnight; it was not issued by this tool"
        )
    })
}

impl SeededSmartcard {
    /// The policy a slot's key is (re)imported under: the chosen one, or what the card has
    ///
    /// Without `--policy` an upload keeps every slot's policy as it is, so changing a name or
    /// a validity never quietly adds or drops a touch requirement.
    fn wanted_policy(&self, slot: SlotId, state: Option<&SlotState>) -> (PinPolicy, TouchPolicy) {
        if self.policy_given {
            return self.policies_for(slot);
        }
        state
            .and_then(|state| state.policy)
            .unwrap_or_else(|| self.policies_for(slot))
    }

    /// The slots an upload reads: the chosen keys', and for a rotation every retired one
    fn slots_to_read(&self, rotating: bool) -> Vec<SlotId> {
        let mut slots: Vec<SlotId> = self.keys.iter().map(|&role| self.slot_of(role)).collect();
        if rotating {
            let retired: Vec<SlotId> = retired_slots()
                .filter(|slot| !slots.contains(slot))
                .collect();
            slots.extend(retired);
        }
        slots
    }

    /// The writes that make the card hold what the key seed derives, from what it shows
    ///
    /// Refuses what an upload cannot do in place: a key of another algorithm in a slot means
    /// another algorithm throughout, which `init` and `upload` do from a reset.
    pub(super) fn plan(&self, chain: &CertChain, state: &CardState) -> Result<UpdatePlan> {
        if let Some(slot @ SlotId::Retired(_)) = self.slot {
            refuse_gap(slot, chain, state)?;
        }
        let mut changes = Vec::new();
        let mut notes = Vec::new();
        let mut unreported = false;
        for (&role, (slot, cert)) in self.keys.iter().zip(&chain.leaves) {
            let slot = *slot;
            let Some(slot_state) = state.slot(slot) else {
                continue;
            };
            let spki = cert.tbs_certificate().subject_public_key_info();
            let want_key = spki.to_der()?;
            let want_cert = cert.to_der()?;
            let on_card = slot_state.key();

            if let Some(on_card) = &on_card
                && on_card != &want_key
                && let Ok(on_card) = spki::SubjectPublicKeyInfoOwned::from_der(on_card)
                && on_card.algorithm != spki.algorithm
                && !matches!(slot, SlotId::Retired(_))
            {
                bail!(
                    "The {slot:?} slot holds a key of another algorithm than the {} the key seed \
                     derives; changing the algorithm takes `init`, which resets the card, then \
                     `upload`",
                    self.algorithm
                );
            }

            let reason = if on_card.as_ref() != Some(&want_key) {
                Some(KeyReason::Differs)
            } else if !slot_state.metadata {
                // The policy cannot be read back, so a re-import for it would be planned on
                // every upload for good; the key keeps the policy it was imported with
                unreported = true;
                None
            } else if slot_state
                .policy
                .is_some_and(|p| p != self.wanted_policy(slot, Some(slot_state)))
            {
                Some(KeyReason::Policy)
            } else {
                None
            };
            if reason == Some(KeyReason::Differs)
                && matches!(slot, SlotId::Retired(_))
                && slot_state.public.is_some()
            {
                notes.push(format!("the {slot:?} slot holds another key, which this replaces"));
            }
            if let Some(reason) = reason {
                changes.push(Change::Key { role, slot, reason });
            }
            if slot_state.certificate.as_ref() != Some(&want_cert) {
                changes.push(Change::Certificate { role, slot });
            }
        }
        if unreported {
            notes.push(
                "the card cannot report slot policies; keys keep the ones they were imported \
                 with, and another policy takes `init`, then `upload`"
                    .to_string(),
            );
        }

        // msroots holds the authorities of the identity whose keys fill the live slots, so
        // only an upload of that whole identity touches it
        if self.whole_identity() {
            if self.msroots {
                let expected = ContentInfo::try_from(chain.cas())?.to_der()?;
                if state.msroots.as_ref() != Some(&expected) {
                    changes.push(Change::Msroots);
                }
            } else if state.msroots.is_some() {
                changes.push(Change::RemoveMsroots);
            }
        }

        // As with the slots: a touch the card cannot report would be written on every upload
        if self.policy_given
            && let Some(current) = state.management_touch
        {
            let want = self.policy.management_touch();
            if (current != TouchPolicy::Never) != want {
                changes.push(Change::ManagementTouch { touch: want });
            }
        }

        let mut plan = UpdatePlan { card: state.card.clone(), changes, notes };
        if let Some(SlotId::Retired(slot)) = self.slot {
            plan.count_retired(SlotId::Retired(slot), state);
        }
        Ok(plan)
    }

    /// Open the card, refuse it unless the card seed initialized it, and plan
    fn open_owned(
        &self,
        target: Option<CardTarget>,
        chain: &CertChain,
        previous: Option<&SeededSmartcard>,
    ) -> Result<(YubiKey, UpdatePlan, CardState)> {
        let mut token = open_token(target)?;
        self.refuse_unowned(&mut token, "uploaded to")?;
        let roles: Vec<_> = self.keys.iter().map(|&role| role.into()).collect();
        self.refuse_unfit(&token, &roles)?;
        let state = CardState::read(&mut token, &self.slots_to_read(previous.is_some()))?;
        let plan = match previous {
            None => self.plan(chain, &state)?,
            Some(previous) => self.plan_rotation(previous, chain, &state)?,
        };
        Ok((token, plan, state))
    }

    /// What an upload to the card would write, read without a credential
    pub(super) fn plan_upload(&self, target: Option<CardTarget>) -> Result<UpdatePlan> {
        let chain = self.generate_chain()?;
        let (_, plan, _) = self.open_owned(target, &chain, None)?;
        Ok(plan)
    }

    /// Write what `confirmed` lists, under the derived management key, and return what the
    /// card still lacks afterwards
    ///
    /// The plan is made again on the card opened here, and nothing is written unless it is
    /// the confirmed one: a card swapped or changed after the question would otherwise get
    /// writes nobody agreed to.
    pub(super) fn upload(
        &self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
    ) -> Result<UpdatePlan> {
        self.write_plan(target, confirmed, None)
    }

    /// What rotating the card from `previous`'s generation to this one would write: the
    /// previous decryption key kept in a retired slot, then this generation's keys
    pub(super) fn plan_rotation_from(
        &self,
        previous: &SeededSmartcard,
        target: Option<CardTarget>,
    ) -> Result<UpdatePlan> {
        let chain = self.generate_chain()?;
        let (_, plan, _) = self.open_owned(target, &chain, Some(previous))?;
        Ok(plan)
    }

    /// Rotate the card from `previous`'s generation to this one, as `confirmed` lists
    pub(super) fn rotate_from(
        &self,
        previous: &SeededSmartcard,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
    ) -> Result<UpdatePlan> {
        self.write_plan(target, confirmed, Some(previous))
    }

    /// The writes of a rotation: the previous decryption key into a retired slot first, so
    /// that an interrupted rotation never loses it, then everything an upload would write
    fn plan_rotation(
        &self,
        previous: &SeededSmartcard,
        chain: &CertChain,
        state: &CardState,
    ) -> Result<UpdatePlan> {
        if !self.whole_identity() {
            bail!("A rotation moves every key of the identity; it takes no --key or --slot");
        }
        let old = previous.role_key(KeyRole::Decryption)?.spki()?.to_der()?;
        let new = self.role_key(KeyRole::Decryption)?.spki()?.to_der()?;
        if old == new {
            bail!(
                "The previous generation has the same decryption key as this one: pass another \
                 --date, or --from-key-seed to move off another key seed"
            );
        }

        let live = state.slot(SlotId::KeyManagement).and_then(SlotState::key);
        let kept = retired_slots()
            .find(|slot| state.slot(*slot).and_then(SlotState::key).as_ref() == Some(&old));
        let mut plan = self.plan(chain, state)?;
        match (kept, live.as_ref()) {
            // Kept already, by an earlier run that got that far
            (Some(kept), _) => plan.count_retired(kept, state),
            (None, Some(live)) if *live == old => {
                let free = retired_slots()
                    .find(|slot| state.slot(*slot).is_some_and(|s| s.key().is_none()))
                    .ok_or_else(|| {
                        anyhow!("Every retired slot is taken; there is no room to keep the previous decryption key")
                    })?;
                plan.changes.insert(0, Change::Archive { slot: free });
                plan.count_retired(free, state);
            }
            (None, _) => bail!(
                "The card's 9D slot holds neither the previous generation's decryption key nor a \
                 kept copy of it; check --date and --from-key-seed, or `upload` the new \
                 generation without keeping the old key"
            ),
        }
        Ok(plan)
    }

    /// Authenticate, write a confirmed plan and report what the card still lacks
    fn write_plan(
        &self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
        previous: Option<&SeededSmartcard>,
    ) -> Result<UpdatePlan> {
        let chain = self.generate_chain()?;
        let (mut token, plan, state) = self.open_owned(target, &chain, previous)?;
        if plan != *confirmed {
            bail!("The card changed since the plan was shown; run the command again to see it");
        }
        if plan.is_empty() {
            return Ok(plan);
        }

        let serial = CardSerial::piv(token.serial().into());
        let management = self.authenticate(&mut token, &serial)?;
        let mut card = Writing {
            token: &mut token,
            serial,
            management,
            chain: &chain,
            state: &state,
            previous,
        };
        let result = self.apply(&plan, &mut card);
        if result.is_err() {
            finish(&mut token);
        }
        let refused = result?;

        let after = CardState::read(&mut token, &self.slots_to_read(false))?;
        let mut remaining = self.plan(&chain, &after)?;
        // What the card refused is not missing afterwards: it was said, and is not tried again
        let before = remaining.changes.len();
        remaining.changes.retain(|change| {
            !refused
                .iter()
                .any(|refused| std::mem::discriminant(refused) == std::mem::discriminant(change))
        });
        if remaining.changes.len() != before {
            remaining
                .notes
                .push("the card refused an optional object, which the keys do without".into());
        }
        finish(&mut token);
        Ok(remaining)
    }

    /// Make the writes of a plan, in its order, on an authenticated card; returns the optional
    /// objects the card refused, which the keys and certificates do without
    fn apply(&self, plan: &UpdatePlan, card: &mut Writing<'_>) -> Result<Vec<Change>> {
        let mut refused = Vec::new();
        for change in &plan.changes {
            log::info!("Writing {change}");
            if !self.write(change, card)? {
                refused.push(change.clone());
            }
        }
        Ok(refused)
    }

    /// Make one write of a plan; false where the card refused an optional object
    fn write(&self, change: &Change, card: &mut Writing<'_>) -> Result<bool> {
        let Writing { token, chain, state, .. } = card;
        match change {
            Change::Key { role, slot, .. } => {
                let policy = self.wanted_policy(*slot, state.slot(*slot));
                self.import_slot(token, *role, *slot, leaf(chain, *slot)?, policy)?;
            }
            Change::Certificate { slot, .. } => {
                write_certificate(token, *slot, leaf(chain, *slot)?)?
            }
            Change::Archive { slot } => {
                let previous = card
                    .previous
                    .ok_or_else(|| anyhow!("No previous generation"))?;
                previous.archive(*slot, card)?;
            }
            Change::Msroots => {
                if let Err(err) = self.upload_msroots(chain, token) {
                    log::warn!(
                        "The card refused the msroots object, where Windows finds the \
                         certificate authorities ({err}); --no-msroots leaves it out"
                    );
                    return Ok(false);
                }
            }
            Change::RemoveMsroots => remove_msroots(token)?,
            Change::KeyHistory { on_card } => {
                if let Err(err) = token.save_object(KEY_HISTORY_OBJECT, &mut key_history(*on_card))
                {
                    log::warn!(
                        "The card refused the key history object ({err}); the retired keys are \
                         on it, but middleware that counts them by that object will not find \
                         them"
                    );
                    return Ok(false);
                }
            }
            // As in `init`: a card that refuses the flag (stock piv-authenticator rejects
            // P2=FE) keeps its working keys, and the comparison afterwards reports the touch as
            // still missing where the card can show it
            Change::ManagementTouch { touch } => {
                if let Err(err) = self
                    .management_key(card.management, &card.serial)?
                    .set_manual(card.token, *touch)
                {
                    log::warn!(
                        "The card refused the touch requirement for management access: {err}"
                    );
                }
            }
        }
        Ok(true)
    }

    /// Keep this generation's decryption key, with its certificate, in the retired `slot`
    fn archive(&self, slot: SlotId, card: &mut Writing<'_>) -> Result<()> {
        // The certificate the card held for the key is the one that was published, whatever
        // names or validity it was issued with; the derived one stands in only where the card
        // held none for this key
        let key = self.role_key(KeyRole::Decryption)?.spki()?;
        let live = card.state.slot(SlotId::KeyManagement);
        let held = live
            .and_then(|slot| slot.certificate.as_deref())
            .and_then(|der| X509Certificate::from_der(der).ok())
            .filter(|held| *held.tbs_certificate().subject_public_key_info() == key);
        let cert = match held {
            Some(cert) => cert,
            None => self.leaf(KeyRole::Decryption)?,
        };
        // The kept key keeps the policy it had in 9D
        let policy = self.wanted_policy(SlotId::KeyManagement, live);
        self.import_slot(card.token, KeyRole::Decryption, slot, &cert, policy)?;
        write_certificate(card.token, slot, &cert)
    }
}

/// A card being written to under its derived management key, and what the writes come from
struct Writing<'a> {
    token: &'a mut YubiKey,
    serial: CardSerial,
    /// The algorithm of the management key the card was authenticated with
    management: MgmAlgorithmId,
    /// The chain the plan was made from
    chain: &'a CertChain,
    /// What the card showed when the plan was made
    state: &'a CardState,
    /// The generation a rotation moves off
    previous: Option<&'a SeededSmartcard>,
}

/// The certificate the chain holds for `slot`
fn leaf(chain: &CertChain, slot: SlotId) -> Result<&X509Certificate> {
    chain
        .leaves
        .iter()
        .find(|(s, _)| *s == slot)
        .map(|(_, cert)| cert)
        .ok_or_else(|| anyhow!("No derived certificate for the {slot:?} slot"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::seed::{Algorithm, KeyPath, Seed256, Seeds};

    const SEED: Seed256 = [0x5au8; 32];

    fn path(date: Option<&str>) -> KeyPath {
        KeyPath {
            subkey: Some("laptop".into()),
            date: date.map(|date| date.parse().unwrap()),
        }
    }

    fn card() -> SeededSmartcard {
        SeededSmartcard::new(Seeds::one(&SEED), path(None), "Test".into())
    }

    /// The state of a card that holds exactly what `card` derives, under the default policy
    fn provisioned(card: &SeededSmartcard, chain: &CertChain) -> CardState {
        let mut slots: Vec<_> = chain
            .leaves
            .iter()
            .map(|(slot, cert)| {
                let state = SlotState {
                    public: Some(
                        cert.tbs_certificate()
                            .subject_public_key_info()
                            .to_der()
                            .unwrap(),
                    ),
                    policy: Some(card.policies_for(*slot)),
                    metadata: true,
                    certificate: Some(cert.to_der().unwrap()),
                };
                (*slot, state)
            })
            .collect();
        slots.extend(
            retired_slots().map(|slot| (slot, SlotState { metadata: true, ..Default::default() })),
        );
        CardState {
            card: String::new(),
            slots,
            msroots: Some(
                ContentInfo::try_from(chain.cas())
                    .unwrap()
                    .to_der()
                    .unwrap(),
            ),
            management_touch: Some(TouchPolicy::Always),
            key_history: None,
        }
    }

    #[test]
    fn a_card_holding_the_derivation_needs_nothing() {
        let card = card();
        let chain = card.generate_chain().unwrap();
        let plan = card.plan(&chain, &provisioned(&card, &chain)).unwrap();
        assert!(plan.is_empty(), "{plan}");
        assert!(plan.notes.is_empty());
    }

    #[test]
    fn a_new_validity_rewrites_the_certificates_only() {
        let card = card();
        let state = provisioned(&card, &card.generate_chain().unwrap());
        let longer = self::card().with_validity_duration(std::time::Duration::from_secs(86_400));
        let plan = longer
            .plan(&longer.generate_chain().unwrap(), &state)
            .unwrap();
        assert!(!plan.changes.is_empty());
        assert!(
            plan.changes
                .iter()
                .all(|change| matches!(change, Change::Certificate { .. })),
            "{plan}"
        );
    }

    /// The decryption key belongs to the identity, so another device's card already holds it
    #[test]
    fn another_device_shares_the_decryption_key() {
        let card = card();
        let state = provisioned(&card, &card.generate_chain().unwrap());
        let phone = SeededSmartcard::new(
            Seeds::one(&SEED),
            KeyPath { subkey: Some("phone".into()), date: None },
            "Test".into(),
        );
        let plan = phone
            .plan(&phone.generate_chain().unwrap(), &state)
            .unwrap();
        for slot in [SlotId::Authentication, SlotId::Signature] {
            assert!(
                plan.changes
                    .iter()
                    .any(|change| matches!(change, Change::Key { slot: s, .. } if *s == slot)),
                "{plan}"
            );
        }
        assert!(
            !plan
                .changes
                .iter()
                .any(|change| matches!(change, Change::Key { slot: SlotId::KeyManagement, .. })),
            "{plan}"
        );
    }

    #[test]
    fn a_chosen_key_is_all_an_upload_touches() {
        let card = card();
        let state = provisioned(&card, &card.generate_chain().unwrap());
        let team = SeededSmartcard::new(Seeds::one(&[0x11; 32]), KeyPath::default(), "Team".into())
            .with_keys(&[KeyRole::Decryption])
            .unwrap()
            .with_slot(0x82)
            .unwrap();
        let plan = team.plan(&team.generate_chain().unwrap(), &state).unwrap();
        let retired = SlotId::Retired(RetiredSlotId::try_from(0x82).unwrap());
        assert_eq!(
            plan.changes,
            vec![
                Change::Key {
                    role: KeyRole::Decryption,
                    slot: retired,
                    reason: KeyReason::Differs
                },
                Change::Certificate { role: KeyRole::Decryption, slot: retired },
                Change::KeyHistory { on_card: 1 },
            ]
        );
    }

    /// The key history object counts retired keys from 82 on, so a key kept further up
    /// counts every slot below it, and a count never shrinks for a slot below another key
    #[test]
    fn the_key_history_covers_every_retired_key() {
        let card = card();
        let mut state = provisioned(&card, &card.generate_chain().unwrap());
        let team = |slot| {
            SeededSmartcard::new(Seeds::one(&[0x11; 32]), KeyPath::default(), "Team".into())
                .with_keys(&[KeyRole::Decryption])
                .unwrap()
                .with_slot(slot)
                .unwrap()
        };
        // A slot above empty ones is refused, naming the first free one
        let refused = team(0x85)
            .plan(&team(0x85).generate_chain().unwrap(), &state)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("--slot 82"), "{refused}");

        // Above taken ones it is the next retired key, and the count covers it
        for below in [0x82, 0x83, 0x84] {
            let below = SlotId::Retired(RetiredSlotId::try_from(below).unwrap());
            state.slots.retain(|(slot, _)| *slot != below);
            let key = SlotState {
                public: Some(vec![below.into()]),
                metadata: true,
                ..Default::default()
            };
            state.slots.push((below, key));
        }
        let plan = team(0x85)
            .plan(&team(0x85).generate_chain().unwrap(), &state)
            .unwrap();
        assert!(plan.changes.contains(&Change::KeyHistory { on_card: 4 }), "{plan}");

        state.key_history = Some(6);
        let plan = team(0x82)
            .plan(&team(0x82).generate_chain().unwrap(), &state)
            .unwrap();
        assert!(
            !plan
                .changes
                .iter()
                .any(|change| matches!(change, Change::KeyHistory { .. })),
            "{plan}"
        );
        assert_eq!(key_history_count(&key_history(4)), Some(4));
    }

    #[test]
    fn a_slot_takes_the_decryption_key_alone() {
        assert!(card().with_slot(0x82).is_err());
        assert!(
            card()
                .with_keys(&[KeyRole::Decryption])
                .unwrap()
                .with_slot(0x9a)
                .is_err()
        );
        assert!(
            card()
                .with_keys(&[KeyRole::Decryption])
                .unwrap()
                .with_slot(0x9e)
                .is_err()
        );
        assert!(
            card()
                .with_keys(&[KeyRole::Decryption])
                .unwrap()
                .with_slot(0x95)
                .is_ok()
        );
    }

    #[test]
    fn policies_change_only_when_asked() {
        let card = card();
        let chain = card.generate_chain().unwrap();
        let mut state = provisioned(&card, &chain);
        // A card provisioned under once-pin, then uploaded to without --policy: kept as it is
        for (_, slot_state) in &mut state.slots {
            if slot_state.public.is_some() {
                slot_state.policy = Some((PinPolicy::Once, TouchPolicy::Never));
            }
        }
        state.management_touch = Some(TouchPolicy::Never);
        assert!(card.plan(&chain, &state).unwrap().is_empty());

        // With --policy relaxed, every slot goes in again, and management gets its touch
        let relaxed = self::card().with_policy(Policy::Relaxed);
        let plan = relaxed.plan(&chain, &state).unwrap();
        assert!(
            plan.changes
                .contains(&Change::ManagementTouch { touch: true })
        );
        assert!(plan.changes.contains(&Change::Key {
            role: KeyRole::Signature,
            slot: SlotId::Signature,
            reason: KeyReason::Policy
        }));
    }

    #[test]
    fn no_msroots_deletes_stored_authorities() {
        let with_roots = card();
        let state = provisioned(&with_roots, &with_roots.generate_chain().unwrap());
        assert!(state.msroots.is_some());
        let without = card().with_msroots(false);
        let plan = without
            .plan(&without.generate_chain().unwrap(), &state)
            .unwrap();
        assert_eq!(plan.changes, vec![Change::RemoveMsroots]);
    }

    #[test]
    fn missing_certificates_and_authorities_are_repaired() {
        let card = card();
        let chain = card.generate_chain().unwrap();
        let mut state = provisioned(&card, &chain);
        state.msroots = None;
        state.slots[0].1.certificate = None;
        let plan = card.plan(&chain, &state).unwrap();
        assert_eq!(
            plan.changes,
            vec![
                Change::Certificate { role: KeyRole::Authentication, slot: chain.leaves[0].0 },
                Change::Msroots
            ]
        );
    }

    #[test]
    fn a_card_without_metadata_keeps_its_policies_and_says_so() {
        let card = card();
        let chain = card.generate_chain().unwrap();
        let mut state = provisioned(&card, &chain);
        for (_, slot_state) in &mut state.slots {
            *slot_state = SlotState {
                metadata: false,
                certificate: slot_state.certificate.clone(),
                ..Default::default()
            };
        }
        state.management_touch = None;
        let plan = card.plan(&chain, &state).unwrap();
        assert!(plan.is_empty(), "{plan}");
        assert_eq!(plan.notes.len(), 1);

        // A policy the card cannot read back would be applied again on every upload, so it
        // is not applied to keys already there, and the note says how to change it
        let strict = self::card().with_policy(Policy::Strict);
        let plan = strict.plan(&chain, &state).unwrap();
        assert!(plan.is_empty(), "{plan}");
        assert!(plan.notes[0].contains("`init`"), "{plan}");
    }

    #[test]
    fn another_algorithm_is_refused() {
        let card = card();
        let state = provisioned(&card, &card.generate_chain().unwrap());
        let p384 = self::card().with_algorithm(Algorithm::P384);
        let err = p384
            .plan(&p384.generate_chain().unwrap(), &state)
            .unwrap_err();
        assert!(err.to_string().contains("init"), "{err}");
    }

    fn first_retired() -> SlotId {
        SlotId::Retired(RetiredSlotId::try_from(0x82).unwrap())
    }

    #[test]
    fn a_rotation_keeps_the_previous_decryption_key_first() {
        let old = card();
        let state = provisioned(&old, &old.generate_chain().unwrap());
        let new = SeededSmartcard::new(Seeds::one(&SEED), path(Some("2027-01-01")), "Test".into());
        let plan = new
            .plan_rotation(&old, &new.generate_chain().unwrap(), &state)
            .unwrap();
        assert_eq!(plan.changes[0], Change::Archive { slot: first_retired() }, "{plan}");
        for slot in [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
        ] {
            assert!(
                plan.changes.iter().any(|change| matches!(change, Change::Key { slot: s, reason: KeyReason::Differs, .. } if *s == slot)),
                "{slot:?}: {plan}"
            );
        }
    }

    #[test]
    fn a_rotation_run_again_keeps_nothing_twice() {
        let old = card();
        let new = SeededSmartcard::new(Seeds::one(&SEED), path(Some("2027-01-01")), "Test".into());
        let mut state = provisioned(&new, &new.generate_chain().unwrap());
        // The previous decryption key is kept in 82 already
        let kept = old.leaf(KeyRole::Decryption).unwrap();
        state.slots.retain(|(slot, _)| *slot != first_retired());
        state.slots.push((
            first_retired(),
            SlotState {
                public: Some(
                    kept.tbs_certificate()
                        .subject_public_key_info()
                        .to_der()
                        .unwrap(),
                ),
                policy: Some(old.policies_for(first_retired())),
                metadata: true,
                certificate: Some(kept.to_der().unwrap()),
            },
        ));
        state.key_history = Some(1);
        let plan = new
            .plan_rotation(&old, &new.generate_chain().unwrap(), &state)
            .unwrap();
        assert!(plan.is_empty(), "{plan}");
    }

    #[test]
    fn a_rotation_to_the_same_generation_is_refused() {
        let old = card();
        let state = provisioned(&old, &old.generate_chain().unwrap());
        assert!(
            card()
                .plan_rotation(&old, &card().generate_chain().unwrap(), &state)
                .is_err()
        );
    }
}

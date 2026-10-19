//! The key slots and their default policies.

use super::{
    SeededSmartcard, chain::ID_MS_SMARTCARD_LOGON, chain::ID_PIV_CARD_AUTH,
    keys::NAME_KEY_MANAGEMENT,
};
use crate::policy::{Pin, Touch};
use crate::seed::Algorithm;

use yubikey::piv::{AlgorithmId, SlotId};
use yubikey::{PinPolicy, TouchPolicy};

use x509_cert::der::oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_EMAIL_PROTECTION};
use x509_cert::ext::pkix::KeyUsages;

use der::flagset::FlagSet;

use spki::ObjectIdentifier;

/// First retired key management slot, per SP 800-73; twenty follow, up to 0x95
pub(super) const FIRST_RETIRED_SLOT: u8 = 0x82;

/// Last retired key management slot
pub(super) const LAST_RETIRED_SLOT: u8 = 0x95;

/// Role a certificate plays, mapped one-to-one onto a NIST PIV key slot
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotRole {
    /// Slot 9A: client authentication, SSH and smartcard logon
    Authentication,
    /// Slot 9C: non-repudiable document and email signing
    Signature,
    /// Slot 9D: ECDH key agreement for email encryption
    KeyManagement,
    /// Slot 9E: PIN-less card-to-reader authentication
    CardAuthentication,
}

impl SlotRole {
    /// Every role, in the order of their slots; `0x9b` is the management key and therefore
    /// deliberately absent
    pub const ALL: [SlotRole; 4] = [
        SlotRole::Authentication,
        SlotRole::Signature,
        SlotRole::KeyManagement,
        SlotRole::CardAuthentication,
    ];

    /// The slot holding this role's live key, numbered per NIST SP 800-73-4
    pub fn slot(self) -> SlotId {
        match self {
            SlotRole::Authentication => SlotId::Authentication,
            SlotRole::Signature => SlotId::Signature,
            SlotRole::KeyManagement => SlotId::KeyManagement,
            SlotRole::CardAuthentication => SlotId::CardAuthentication,
        }
    }

    /// The role a slot plays, by which its key is derived and its algorithm chosen
    ///
    /// A retired slot holds a superseded key management key, so it plays that role.
    pub(super) fn of(slot: SlotId) -> SlotRole {
        match slot {
            SlotId::Authentication => SlotRole::Authentication,
            SlotId::Signature => SlotRole::Signature,
            SlotId::KeyManagement | SlotId::Retired(_) => SlotRole::KeyManagement,
            SlotId::CardAuthentication => SlotRole::CardAuthentication,
            other => unreachable!("{other:?} holds no derived key"),
        }
    }

    /// Derivation name for the role's key, by the *role* rather than where it sits
    ///
    /// Positional names (`slot-9d`) would tie a key to one slot, but the retired slots hold
    /// superseded key management keys: the same key has to derive identically whether it lives
    /// in 9D or in 0x82, or an archived generation could never be re-derived.
    pub(super) fn name(self) -> &'static str {
        match self {
            SlotRole::Authentication => "authentication",
            SlotRole::Signature => "signature",
            SlotRole::KeyManagement => NAME_KEY_MANAGEMENT,
            SlotRole::CardAuthentication => "card-authentication",
        }
    }

    /// Key usage bits appropriate for this role, for an RSA key if `rsa`
    pub(super) fn key_usage(&self, rsa: bool) -> FlagSet<KeyUsages> {
        match self {
            SlotRole::Authentication => KeyUsages::DigitalSignature.into(),
            SlotRole::Signature => KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
            // An RSA key transports keys, which is `keyEncipherment`; an EC key agrees on
            // them, and `keyEncipherment` is invalid there (RFC 5480 section 3, RFC 8813),
            // NSS rejects such a certificate for S/MIME decryption. `encipherOnly` and
            // `decipherOnly` stay unset, as either breaks `openssl verify -purpose smimeencrypt`.
            SlotRole::KeyManagement if rsa => KeyUsages::KeyEncipherment.into(),
            SlotRole::KeyManagement => KeyUsages::KeyAgreement.into(),
            SlotRole::CardAuthentication => KeyUsages::DigitalSignature.into(),
        }
    }

    /// Extended key usages appropriate for this role
    pub(super) fn extended_key_usage(&self) -> Vec<ObjectIdentifier> {
        match self {
            SlotRole::Authentication => vec![ID_KP_CLIENT_AUTH, ID_MS_SMARTCARD_LOGON],
            SlotRole::Signature => vec![ID_KP_EMAIL_PROTECTION],
            SlotRole::KeyManagement => vec![ID_KP_EMAIL_PROTECTION, ID_KP_CLIENT_AUTH],
            SlotRole::CardAuthentication => vec![ID_PIV_CARD_AUTH],
        }
    }

    /// Whether certificates in this role carry the user's alternative names.
    ///
    /// Slot 9E authenticates the *card*, not the person, so it stays unbound (FIPS 201-3
    /// section 4.2.3).
    pub(super) fn is_user_bound(&self) -> bool {
        *self != SlotRole::CardAuthentication
    }

    /// Label segment of this role's key under `algorithm`: key management agrees, the rest sign
    pub(super) fn algorithm_segment(&self, algorithm: Algorithm) -> &'static str {
        match self {
            SlotRole::KeyManagement => algorithm.agreement_segment(),
            _ => algorithm.signing_segment(),
        }
    }

    /// The card algorithm this role's key takes when the chain is derived with `algorithm`
    pub(super) fn card_algorithm(&self, algorithm: Algorithm) -> AlgorithmId {
        match (algorithm, self) {
            (Algorithm::P256, _) => AlgorithmId::EccP256,
            (Algorithm::P384, _) => AlgorithmId::EccP384,
            (Algorithm::Curve25519, SlotRole::KeyManagement) => AlgorithmId::X25519,
            (Algorithm::Curve25519, _) => AlgorithmId::Ed25519,
            (Algorithm::Rsa2048, _) => AlgorithmId::Rsa2048,
            (Algorithm::Rsa3072, _) => AlgorithmId::Rsa3072,
            (Algorithm::Rsa4096, _) => AlgorithmId::Rsa4096,
        }
    }
}

impl SeededSmartcard {
    /// Effective pin and touch policy for a slot, from the card's [`Policy`](crate::policy::Policy)
    pub(super) fn policies_for(&self, slot: SlotId) -> (PinPolicy, TouchPolicy) {
        match slot {
            // The card authentication key MUST be usable without cardholder verification, and
            // a touch would defeat the contactless door access it exists for, so no policy
            // reaches it
            SlotId::CardAuthentication => (PinPolicy::Never, TouchPolicy::Never),
            // A retired slot holds a superseded key management key, so it keeps that slot's
            // policy
            slot => {
                let (pin, touch) = self.policy.piv_slot(slot == SlotId::Signature);
                (pin_policy(pin), touch_policy(touch))
            }
        }
    }
}

fn pin_policy(pin: Pin) -> PinPolicy {
    match pin {
        Pin::Never => PinPolicy::Never,
        Pin::Once => PinPolicy::Once,
        Pin::Always => PinPolicy::Always,
    }
}

fn touch_policy(touch: Touch) -> TouchPolicy {
    match touch {
        Touch::Never => TouchPolicy::Never,
        Touch::Cached => TouchPolicy::Cached,
        Touch::Always => TouchPolicy::Always,
    }
}

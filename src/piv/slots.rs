//! The key slots and their default policies.

use super::{
    SeededSmartcard, chain::ID_MS_SMARTCARD_LOGON, chain::ID_PIV_CARD_AUTH,
    keys::NAME_KEY_MANAGEMENT,
};
use crate::seed::Algorithm;

use yubikey::piv::{AlgorithmId, SlotId};
use yubikey::{PinPolicy, TouchPolicy};

use x509_cert::der::oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_EMAIL_PROTECTION};
use x509_cert::ext::pkix::KeyUsages;

use der::flagset::FlagSet;

use spki::ObjectIdentifier;

/// Configuration of key slots to be generated and uploaded.
///
/// Slot numbering follows NIST SP 800-73-4; note that `0x9b` is the management key slot and
/// therefore deliberately absent. PIN and touch policies are the per-slot defaults required
/// (9E) or recommended (the rest) by the same document -- see [`SeededSmartcard::policies_for`].
pub(super) const DEFAULT_KEY_SLOTS: [(SlotId, SlotRole, PinPolicy, TouchPolicy); 4] = [
    // One PIN verification unlocks a series of authentication operations (SSH, TLS, logon).
    (SlotId::Authentication, SlotRole::Authentication, PinPolicy::Once, TouchPolicy::Cached),
    // Non-repudiable signing: PIN and touch immediately before every single signature.
    (SlotId::Signature, SlotRole::Signature, PinPolicy::Always, TouchPolicy::Always),
    (SlotId::KeyManagement, SlotRole::KeyManagement, PinPolicy::Once, TouchPolicy::Cached),
    // The card authentication key MUST be usable without cardholder verification.
    (
        SlotId::CardAuthentication,
        SlotRole::CardAuthentication,
        PinPolicy::Never,
        TouchPolicy::Never,
    ),
];

/// First retired key management slot, per SP 800-73; twenty follow, up to 0x95
pub(super) const FIRST_RETIRED_SLOT: u8 = 0x82;

/// Role a slot plays, by which its key is derived and its algorithm chosen
///
/// A retired slot holds a superseded key management key, so it plays that role.
pub(super) fn slot_role(slot: SlotId) -> SlotRole {
    match slot {
        SlotId::Retired(_) => SlotRole::KeyManagement,
        other => {
            DEFAULT_KEY_SLOTS
                .iter()
                .find(|(candidate, ..)| *candidate == other)
                .expect("slot is one of DEFAULT_KEY_SLOTS")
                .1
        }
    }
}

/// Derivation name for a slot's key, by the *role* it plays rather than where it sits
///
/// Positional names (`slot-9d`) would tie a key to one slot, but the retired slots hold
/// superseded key management keys: the same key has to derive identically whether it lives in
/// 9D or in 0x82, or an archived generation could never be re-derived.
pub(super) fn slot_name(slot: SlotId) -> &'static str {
    match slot {
        SlotId::Authentication => "authentication",
        SlotId::Signature => "signature",
        SlotId::KeyManagement => NAME_KEY_MANAGEMENT,
        SlotId::CardAuthentication => "card-authentication",
        other => unreachable!("{other:?} is not one of DEFAULT_KEY_SLOTS"),
    }
}

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
    /// Effective pin and touch policy for a slot
    pub(super) fn policies_for(&self, slot: SlotId) -> (PinPolicy, TouchPolicy) {
        // A retired slot holds a superseded key management key, so it keeps that slot's policy
        let slot = match slot {
            SlotId::Retired(_) => SlotId::KeyManagement,
            other => other,
        };

        let (_, _, pin, touch) = DEFAULT_KEY_SLOTS
            .iter()
            .find(|(candidate, ..)| *candidate == slot)
            .expect("slot is one of DEFAULT_KEY_SLOTS");

        // Slot 9E must stay pin-less and touch-less to remain spec compliant, so overrides
        // deliberately do not apply to it.
        if slot == SlotId::CardAuthentication {
            if self.pin_policy.is_some() || self.touch_policy.is_some() {
                log::warn!("Ignoring policy override for the card authentication slot");
            }
            return (*pin, *touch);
        }

        (self.pin_policy.unwrap_or(*pin), self.touch_policy.unwrap_or(*touch))
    }
}

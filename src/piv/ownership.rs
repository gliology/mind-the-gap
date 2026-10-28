//! Whether a PIV card belongs to the card seed, from its public objects alone.
//!
//! The card identity shows in two places, both derived from the card seed and the card's own
//! serial: the CHUID's Card UUID and the 9E card authentication key. Either names the card;
//! the CHUID is checked first because it costs one cheap derivation, where the 9E key may be an
//! RSA key whose primes take seconds to find.

use super::algorithms::algorithm_of;
use super::{SeededSmartcard, SlotRole};
use crate::ownership::{Ownership, top_level_tlvs};
use crate::seed::{self, Algorithm, CardSerial};

use anyhow::Result;

use yubikey::piv::SlotId;
use yubikey::{Certificate as CardCertificate, YubiKey};

use x509_cert::Certificate as X509Certificate;
use x509_cert::der::{Decode, Encode};

/// Tag of the Card UUID within the CHUID
const TAG_GUID: u16 = 0x34;

/// The Card Holder Unique Identifier and the Card Capability Container (SP 800-73-4 part 1,
/// table 3)
pub(super) const CHUID_OBJECT: u32 = 0x005f_c102;
pub(super) const CCC_OBJECT: u32 = 0x005f_c107;

/// The slots whose certificate means a card was provisioned at all
const SLOTS: [SlotId; 4] = [
    SlotId::Authentication,
    SlotId::Signature,
    SlotId::KeyManagement,
    SlotId::CardAuthentication,
];

/// What a PIV card shows without a pin
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    /// The serial the card reports, which its credentials and identifiers are bound to
    pub(super) serial: CardSerial,
    /// The Card UUID of its CHUID
    pub(super) guid: Option<Vec<u8>>,
    /// The certificate in slot 9E, DER encoded
    pub(super) card_authentication: Option<Vec<u8>>,
    /// Whether it carries a CHUID or any slot certificate at all
    pub(super) provisioned: bool,
}

impl Facts {
    /// Read what a card shows without a pin; no object is written and no try is spent
    pub(super) fn read(token: &mut YubiKey) -> Facts {
        let serial = CardSerial::piv(token.serial().into());
        // Read as an object rather than through `ChuId`, which slices a short one and panics
        let guid = token
            .fetch_object(CHUID_OBJECT)
            .ok()
            .and_then(|chuid| guid_of(&chuid));
        let mut provisioned = guid.is_some();
        let mut card_authentication = None;
        for slot in SLOTS {
            let Ok(cert) = CardCertificate::read(token, slot) else {
                continue;
            };
            provisioned = true;
            if slot == SlotId::CardAuthentication {
                card_authentication = cert.cert.to_der().ok();
            }
        }
        Facts { serial, guid, card_authentication, provisioned }
    }
}

/// The Card UUID of a CHUID's content
pub(super) fn guid_of(chuid: &[u8]) -> Option<Vec<u8>> {
    top_level_tlvs(chuid)?
        .into_iter()
        .find(|(tag, _)| *tag == TAG_GUID)
        .map(|(_, value)| value.to_vec())
}

impl SeededSmartcard {
    /// Whether the card these facts were read from was initialized from this card seed
    pub(super) fn ownership(&self, facts: &Facts) -> Result<Ownership> {
        if facts.guid.as_deref() == Some(&self.chuid_guid(&facts.serial)?[..]) {
            return Ok(Ownership::Owned);
        }
        // A card whose CHUID was lost or replaced still names its card seed by the 9E key
        if let Some(der) = &facts.card_authentication
            && self.holds_card_authentication(der, &facts.serial)?
        {
            return Ok(Ownership::Owned);
        }
        Ok(if facts.provisioned {
            Ownership::Foreign
        } else {
            Ownership::Blank
        })
    }

    /// Whether a 9E certificate carries this card's derived card authentication key
    ///
    /// The key is derived for the algorithm the certificate shows, so a card initialized
    /// with another `--algorithm` than the one given now is still recognised.
    fn holds_card_authentication(&self, der: &[u8], serial: &CardSerial) -> Result<bool> {
        let Ok(cert) = X509Certificate::from_der(der) else {
            return Ok(false);
        };
        let on_card = cert.tbs_certificate().subject_public_key_info();
        let Some(algorithm) = algorithm_of(on_card) else {
            return Ok(false);
        };
        Ok(self
            .card_authentication_key(algorithm, serial)?
            .spki()?
            .to_der()?
            == on_card.to_der()?)
    }
}

/// The label a card's 9E key derives under, for one algorithm and one card:
/// `key:card-authentication:<algorithm>:<serial>`
pub(super) fn card_authentication_label(algorithm: Algorithm, serial: &CardSerial) -> Vec<u8> {
    let role = SlotRole::CardAuthentication;
    seed::segments_label(
        seed::PREFIX_KEY,
        &[
            role.name(),
            role.algorithm_segment(algorithm),
            serial.segment(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{KeyPath, Seeds};

    fn card(seed: u8) -> SeededSmartcard {
        SeededSmartcard::new(Seeds::one(&[seed; 32]), KeyPath::default(), "Owner".into())
    }

    fn serial() -> CardSerial {
        CardSerial::piv(12345678)
    }

    #[test]
    fn the_chuid_guid_names_the_card() {
        let card = card(7);
        let mut chuid = card.chuid(&serial()).unwrap();
        assert_eq!(guid_of(&chuid), Some(card.chuid_guid(&serial()).unwrap()));

        let facts = Facts {
            serial: serial(),
            guid: guid_of(&chuid),
            card_authentication: None,
            provisioned: true,
        };
        assert_eq!(card.ownership(&facts).unwrap(), Ownership::Owned);

        // Another card seed, or the same card seed on another card, is a stranger
        assert_eq!(self::card(8).ownership(&facts).unwrap(), Ownership::Foreign);
        let other = Facts { serial: CardSerial::piv(87654321), ..facts.clone() };
        assert_eq!(card.ownership(&other).unwrap(), Ownership::Foreign);

        // A CHUID from elsewhere, or none at all
        chuid[30] ^= 0xFF;
        let facts = Facts { guid: guid_of(&chuid), ..facts };
        assert_eq!(card.ownership(&facts).unwrap(), Ownership::Foreign);
        let blank = Facts {
            serial: serial(),
            guid: None,
            card_authentication: None,
            provisioned: false,
        };
        assert_eq!(card.ownership(&blank).unwrap(), Ownership::Blank);
    }

    #[test]
    fn the_card_authentication_key_names_the_card_without_a_chuid() {
        let card = card(7);
        let nine_e = card
            .card_authentication_certificate(Algorithm::P256, &serial())
            .unwrap();
        let facts = Facts {
            serial: serial(),
            guid: None,
            card_authentication: Some(nine_e.to_der().unwrap()),
            provisioned: true,
        };
        assert_eq!(card.ownership(&facts).unwrap(), Ownership::Owned);

        // Recognised whatever algorithm the command line asks for now
        let p384 = self::card(7).with_algorithm(Algorithm::P384);
        assert_eq!(p384.ownership(&facts).unwrap(), Ownership::Owned);
    }
}

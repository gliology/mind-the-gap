//! Whether an OpenPGP card belongs to the card seed, from what it shows without a pin.
//!
//! The card identity is the card seed and the card's own serial, which derive the admin pin.
//! `init` writes a card identifier, derived from them like the PIV CHUID's Card UUID, into the
//! private-use data object 0102, which anyone can read and only the admin pin can write. The
//! keys come from a key seed and say nothing about who administers the card, so a card without
//! the identifier is told apart only as far as its keys go. Cards provisioned under the legacy
//! scheme derive the admin pin from the same seed as their keys, so there the keys tell.

use super::card::{fingerprint_bytes, role_keys};
use super::{KeyRole, Scheme, SeededSmartcard};
use crate::ownership::Ownership;
use crate::seed::CardSerial;

use anyhow::Result;

use sequoia_openpgp::cert::Cert;

/// What an OpenPGP card shows without a pin
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    /// The card's manufacturer and serial, which its credentials and identifier are bound to
    pub(super) serial: CardSerial,
    /// The content of the private-use data object 0102
    pub(super) identifier: Option<Vec<u8>>,
    /// Signing, decryption and authentication fingerprint, `None` for an empty slot
    pub(super) keys: [Option<[u8; 20]>; 3],
}

/// The fingerprints the key seed's chosen keys have, by role
pub(super) type Fingerprints = Vec<(KeyRole, [u8; 20])>;

impl SeededSmartcard {
    /// The fingerprints of the chosen keys, from a certificate with the subkeys
    pub(super) fn fingerprints(&self, cert: &Cert) -> Result<Fingerprints> {
        role_keys(cert, &self.keys, self.subkey_creation_time())?
            .into_iter()
            .map(|(role, key)| Ok((role, fingerprint_bytes(&key)?)))
            .collect()
    }

    /// Whether the card these facts were read from was initialized from this card seed
    ///
    /// `keys` are the key seed's fingerprints, where there is one: they tell a card without
    /// an identifier that holds the key seed's keys from a stranger's.
    pub(super) fn ownership(
        &self,
        facts: &Facts,
        keys: Option<&Fingerprints>,
    ) -> Result<Ownership> {
        let holds_keys = keys.is_some_and(|keys| {
            keys.iter().any(|(role, expected)| {
                let slot = KeyRole::PGP.iter().position(|r| r == role);
                slot.and_then(|slot| facts.keys[slot]).as_ref() == Some(expected)
            })
        });
        let anything = facts.identifier.is_some() || facts.keys.iter().any(Option::is_some);

        if self.scheme == Scheme::Legacy {
            return Ok(if holds_keys {
                Ownership::Owned
            } else if anything {
                Ownership::Foreign
            } else {
                Ownership::Blank
            });
        }

        let expected = self.card_identifier(&facts.serial)?.map(String::into_bytes);
        Ok(match &facts.identifier {
            Some(identifier) if Some(identifier) == expected.as_ref() => Ownership::Owned,
            // Another identifier is another card seed's card, whatever keys it holds
            Some(_) => Ownership::Foreign,
            None if holds_keys => Ownership::KeysOnly,
            None if anything => Ownership::Foreign,
            None => Ownership::Blank,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{KeyPath, Seeds};

    fn card(seed: u8) -> SeededSmartcard {
        SeededSmartcard::new(Seeds::one(&[seed; 32]), KeyPath::default(), "Owner".into())
    }

    fn serial() -> CardSerial {
        CardSerial::pgp(0x0006, 0x1234_5678)
    }

    fn facts(identifier: Option<Vec<u8>>, keys: [Option<[u8; 20]>; 3]) -> Facts {
        Facts { serial: serial(), identifier, keys }
    }

    #[test]
    fn the_card_identifier_names_the_card() {
        let card = card(7);
        let identifier = card
            .card_identifier(&serial())
            .unwrap()
            .unwrap()
            .into_bytes();
        let on_card = facts(Some(identifier.clone()), [None; 3]);
        assert_eq!(card.ownership(&on_card, None).unwrap(), Ownership::Owned);

        // Another card seed, or the same card seed's identifier on another card
        assert_eq!(self::card(8).ownership(&on_card, None).unwrap(), Ownership::Foreign);
        let moved = Facts { serial: CardSerial::pgp(0x0006, 0x1234_5679), ..on_card };
        assert_eq!(card.ownership(&moved, None).unwrap(), Ownership::Foreign);
    }

    #[test]
    fn keys_without_an_identifier_name_no_administrator() {
        let keys = vec![(KeyRole::Signature, [1; 20])];
        let on_card = facts(None, [Some([1; 20]), None, None]);
        assert_eq!(card(7).ownership(&on_card, Some(&keys)).unwrap(), Ownership::KeysOnly);
        assert_eq!(card(7).ownership(&on_card, None).unwrap(), Ownership::Foreign);
        assert_eq!(card(7).ownership(&facts(None, [None; 3]), None).unwrap(), Ownership::Blank);
    }

    #[test]
    fn legacy_cards_are_told_by_their_keys() {
        let legacy = SeededSmartcard::legacy(&[7; 32], None, "Owner".into());
        let keys = vec![(KeyRole::Decryption, [2; 20])];
        let on_card = facts(None, [None, Some([2; 20]), None]);
        assert_eq!(legacy.ownership(&on_card, Some(&keys)).unwrap(), Ownership::Owned);
        let other = facts(None, [None, Some([3; 20]), None]);
        assert_eq!(legacy.ownership(&other, Some(&keys)).unwrap(), Ownership::Foreign);
    }
}

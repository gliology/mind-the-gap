//! Whether a card belongs to a card seed, told from what it shows without a pin.
//!
//! A card's identity is the card seed and the card's own serial: together they derive the
//! credentials that administer it (the PIV management key and puk, the OpenPGP admin pin) and
//! the card's own identifiers. Keys on the card are contents, which may come from any key seed,
//! so they say nothing about who administers the card. Each backend reads only public objects
//! to decide, spending no pin tries and asking for no touch, which is what makes it safe to ask
//! of every attached card.

use std::fmt;

/// What a card shows of its relation to a card seed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    /// Initialized from this card seed
    Owned,
    /// Holds keys of this seed, but no identifier of its own to tell who administers it: a
    /// card initialized under the legacy scheme, or one without room for an identifier
    KeysOnly,
    /// Initialized with something this card seed did not derive
    Foreign,
    /// Nothing on it to judge by
    Blank,
}

impl fmt::Display for Ownership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Ownership::Owned => "initialized by this card seed",
            Ownership::KeysOnly => "holds keys of this seed, administrator unknown",
            Ownership::Foreign => "not initialized by this card seed",
            Ownership::Blank => "blank",
        })
    }
}

/// What `list` shows of one applet on one attached card
pub struct Listing {
    /// The PC/SC reader the card sits in
    pub reader: String,
    /// The applet, as messages name it: `PIV` or `OpenPGP`
    pub applet: &'static str,
    /// What the card calls itself in the applet: a serial number or an identifier
    pub card: String,
    /// Whether the card seed initialized it, where a card seed was given
    pub owner: Option<String>,
    /// The cardholder name the card shows, where it keeps one
    pub holder: Option<String>,
    /// The keys it holds
    pub keys: Vec<ListedKey>,
}

/// One key a card holds, as `list` shows it
pub struct ListedKey {
    /// The slot or role it sits in
    pub slot: String,
    /// The fingerprint: the SHA-256 of the PIV certificate, the OpenPGP fingerprint
    pub fingerprint: String,
    /// The PIV certificate's subject, untrusted text from the card
    pub subject: Option<String>,
    /// Whether the key seed's chosen generation derives it
    pub ours: bool,
}

/// Split a run of BER-TLV objects into its top-level `(tag, value)` pairs
///
/// Flat on purpose: inside the CHUID the FASC-N carries the constructed bit in its tag
/// without holding objects, so descending into everything that looks constructed, as
/// [`crate::readers::find_tlv`] does, would misread it.
pub(crate) fn top_level_tlvs(mut data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut objects = Vec::new();
    while !data.is_empty() {
        let (tag, _, value, rest) = crate::readers::split_tlv(data)?;
        objects.push((tag, value));
        data = rest;
    }
    Some(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_objects_are_not_descended_into() {
        // 30 is constructed by its tag bit, but its content is no TLV run
        let data = [
            0x30, 0x02, 0xFF, 0xFF, 0x34, 0x02, 0xAA, 0xBB, 0x5F, 0x50, 0x81, 0x01, 0x42,
        ];
        assert_eq!(
            top_level_tlvs(&data),
            Some(vec![
                (0x30, &[0xFF, 0xFF][..]),
                (0x34, &[0xAA, 0xBB][..]),
                (0x5F50, &[0x42][..])
            ])
        );
        assert_eq!(top_level_tlvs(&data[..5]), None);
    }

    #[test]
    fn ownership_reads_as_a_sentence() {
        assert_eq!(Ownership::Owned.to_string(), "initialized by this card seed");
        assert_eq!(Ownership::Blank.to_string(), "blank");
    }
}

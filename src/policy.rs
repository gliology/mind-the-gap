//! One choice of pin and touch requirements for every key a card is given.
//!
//! Both applets know per-key policies, but in different terms: PIV a pin policy and a touch
//! policy per slot, OpenPGP a signing pin validity and a touch flag per key. A [`Policy`] is
//! the one decision a user makes, in words that mean the same on either card, and each
//! backend maps it onto what its card can express. The PIV mapping is in
//! [`Policy::piv_slot`] and [`Policy::management_touch`], the OpenPGP one in
//! [`Policy::pgp_signing_pin_forced`] and [`Policy::pgp_touch`].

/// How often a key asks for the pin
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pin {
    /// Never: whoever holds the card can use the key
    Never,
    /// Once per session
    Once,
    /// Before every single operation
    Always,
}

/// How often a key asks for a touch
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Touch {
    /// Never
    Never,
    /// Once, then not again for about fifteen seconds
    Cached,
    /// Before every single operation
    Always,
}

/// The pin and touch requirements `upload` gives every key, in one word
///
/// The first three follow NIST SP 800-73-4's pin rules per slot: the signature slot asks for
/// the pin before every signature, the others once per session. They differ in touch only.
/// The rest apply one pin and one touch requirement to every key alike. In every mode the
/// card authentication slot 9E stays without pin and touch, as the standard requires.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    /// The standard's pins, and a touch before every use of every key
    Strict,
    /// The standard's pins, a touch before every signature and a cached one otherwise
    #[default]
    Relaxed,
    /// The standard's pins and no touch, which is what other tools and the cards default to
    NeverTouch,
    /// Pin and touch before every use of every key
    Always,
    /// Pin once per session, touch before every use
    OnceAlways,
    /// Pin once per session, a cached touch
    OnceCached,
    /// No pin, touch before every use
    AlwaysTouch,
    /// No pin, a cached touch
    CachedTouch,
    /// Pin before every use, no touch
    AlwaysPin,
    /// Pin once per session, no touch
    OncePin,
    /// Neither pin nor touch: whoever holds the card can use every key
    Never,
}

impl Policy {
    /// Pin and touch for a slot playing the signature role (9C) or another one (9A, 9D and
    /// the retired slots); the caller keeps 9E out of this
    pub fn piv_slot(self, signature: bool) -> (Pin, Touch) {
        // The standard asks for the pin before every signature, once per session otherwise
        let standard = if signature { Pin::Always } else { Pin::Once };
        match self {
            Policy::Strict => (standard, Touch::Always),
            // A signature is the one act a touch should always witness; a login or a
            // decryption repeats often enough that a cached touch is the usable middle
            Policy::Relaxed if signature => (standard, Touch::Always),
            Policy::Relaxed => (standard, Touch::Cached),
            Policy::NeverTouch => (standard, Touch::Never),
            Policy::Always => (Pin::Always, Touch::Always),
            Policy::OnceAlways => (Pin::Once, Touch::Always),
            Policy::OnceCached => (Pin::Once, Touch::Cached),
            Policy::AlwaysTouch => (Pin::Never, Touch::Always),
            Policy::CachedTouch => (Pin::Never, Touch::Cached),
            Policy::AlwaysPin => (Pin::Always, Touch::Never),
            Policy::OncePin => (Pin::Once, Touch::Never),
            Policy::Never => (Pin::Never, Touch::Never),
        }
    }

    /// Whether management access to a provisioned PIV card demands a touch: whenever the
    /// mode asks for touch at all, since administering the card is at least as weighty as
    /// using one of its keys
    pub fn management_touch(self) -> bool {
        self.touch() != Touch::Never
    }

    /// Whether an OpenPGP signature asks for the pin every time, rather than once per
    /// session
    ///
    /// Only where a mode asks for the pin before every use of every key, or is strict. The
    /// standard modes otherwise keep a signature at one pin entry per session, which is
    /// what a YubiKey does out of the box. An OpenPGP card has no setting without a pin, so
    /// the pin-less modes mean once per session here.
    pub fn pgp_signing_pin_forced(self) -> bool {
        matches!(self, Policy::Strict | Policy::Always | Policy::AlwaysPin)
    }

    /// The touch requirement of every OpenPGP key, which has no per-role distinction: the
    /// mode's touch for the frequently used keys
    pub fn pgp_touch(self) -> Touch {
        self.touch()
    }

    /// Whether the mode leaves the PIV signature slot without a pin before every signature,
    /// which NIST SP 800-73-4 asks for non-repudiation
    pub fn weakens_signature_pin(self) -> bool {
        self.piv_slot(true).0 != Pin::Always
    }

    /// Whether the mode drops the pin altogether
    pub fn drops_pin(self) -> bool {
        self.piv_slot(false).0 == Pin::Never
    }

    /// The mode's touch requirement for the keys that are used most, 9A and 9D on PIV and
    /// every OpenPGP key
    fn touch(self) -> Touch {
        self.piv_slot(false).1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    /// Every mode, spelled out: (9C, 9A/9D, management touch, OpenPGP signing pin forced,
    /// OpenPGP touch). The table is the specification, so a change to the mapping has to
    /// change it too.
    #[test]
    fn every_mode_maps_as_specified() {
        use Pin as P;
        use Touch as T;
        let table = [
            (Policy::Strict, (P::Always, T::Always), (P::Once, T::Always), true, true, T::Always),
            (Policy::Relaxed, (P::Always, T::Always), (P::Once, T::Cached), true, false, T::Cached),
            (
                Policy::NeverTouch,
                (P::Always, T::Never),
                (P::Once, T::Never),
                false,
                false,
                T::Never,
            ),
            (Policy::Always, (P::Always, T::Always), (P::Always, T::Always), true, true, T::Always),
            (
                Policy::OnceAlways,
                (P::Once, T::Always),
                (P::Once, T::Always),
                true,
                false,
                T::Always,
            ),
            (
                Policy::OnceCached,
                (P::Once, T::Cached),
                (P::Once, T::Cached),
                true,
                false,
                T::Cached,
            ),
            (
                Policy::AlwaysTouch,
                (P::Never, T::Always),
                (P::Never, T::Always),
                true,
                false,
                T::Always,
            ),
            (
                Policy::CachedTouch,
                (P::Never, T::Cached),
                (P::Never, T::Cached),
                true,
                false,
                T::Cached,
            ),
            (
                Policy::AlwaysPin,
                (P::Always, T::Never),
                (P::Always, T::Never),
                false,
                true,
                T::Never,
            ),
            (Policy::OncePin, (P::Once, T::Never), (P::Once, T::Never), false, false, T::Never),
            (Policy::Never, (P::Never, T::Never), (P::Never, T::Never), false, false, T::Never),
        ];
        assert_eq!(table.len(), Policy::value_variants().len(), "a mode is missing from the table");
        for (policy, signature, other, management, forced, pgp_touch) in table {
            assert_eq!(policy.piv_slot(true), signature, "{policy:?} on 9C");
            assert_eq!(policy.piv_slot(false), other, "{policy:?} on 9A and 9D");
            assert_eq!(policy.management_touch(), management, "{policy:?} management touch");
            assert_eq!(policy.pgp_signing_pin_forced(), forced, "{policy:?} signing pin");
            assert_eq!(policy.pgp_touch(), pgp_touch, "{policy:?} OpenPGP touch");
        }
    }

    #[test]
    fn relaxed_is_the_default() {
        assert_eq!(Policy::default(), Policy::Relaxed);
    }

    /// The modes that keep the signature pin are exactly those the warning stays quiet for
    #[test]
    fn signature_pin_warning_covers_the_weakening_modes() {
        let keep = [
            Policy::Strict,
            Policy::Relaxed,
            Policy::NeverTouch,
            Policy::Always,
            Policy::AlwaysPin,
        ];
        for policy in Policy::value_variants() {
            assert_eq!(policy.weakens_signature_pin(), !keep.contains(policy), "{policy:?}");
        }
    }
}

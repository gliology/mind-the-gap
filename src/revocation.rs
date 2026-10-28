//! What a revocation covers and why, in words both applets share.
//!
//! OpenPGP revokes with signatures, PIV with a list its root authority signs, but the choice
//! is the same on either: which keys to retire, and the reason given for it. The reason codes
//! are OpenPGP's reasons for revocation; a revocation list names the same four reasons
//! by numbers of its own, RFC 5280's CRLReason, which the PIV backend maps them onto.

/// What a revocation covers
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationKind {
    /// Retire the whole identity, primary key and all
    Certificate,
    /// Retire only this device's subkeys of this generation, leaving the identity and every
    /// other card alone
    ///
    /// The point of provisioning each device under its own subkey id: one lost card can be
    /// taken out of service without reissuing the identity everywhere.
    Subkeys,
}

/// A reason both applets can state, by its code
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// No reason given: code 0
    Unspecified,
    /// The keys are replaced by newer ones: code 1
    Superseded,
    /// The keys may be known to someone else: code 2
    Compromised,
    /// The keys are no longer used: code 3
    Retired,
}

impl Reason {
    /// The reason a code names, `None` for a code outside the four both applets know
    pub(crate) fn of(code: u8) -> Option<Reason> {
        match code {
            0 => Some(Reason::Unspecified),
            1 => Some(Reason::Superseded),
            2 => Some(Reason::Compromised),
            3 => Some(Reason::Retired),
            _ => None,
        }
    }
}

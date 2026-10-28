//! The three usable keys every card carries, in words both applets share.

/// A usable key: what `--key` names, on either applet
///
/// PIV calls the decryption key its key management key and keeps it in slot 9D; OpenPGP calls
/// it the decryption key. One word for both, so that one option means the same on every card.
/// The card's own authentication key (PIV 9E) is not among them: it belongs to the card, not
/// to the identity, and comes from the card seed.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Authentication: SSH, client certificates, smart card logon (PIV 9A)
    Authentication,
    /// Signature: documents, mail, code (PIV 9C)
    Signature,
    /// Decryption: mail and files encrypted to the identity (PIV 9D, or a retired slot)
    Decryption,
}

impl KeyRole {
    /// Every role, in PIV slot order
    pub const ALL: [KeyRole; 3] = [
        KeyRole::Authentication,
        KeyRole::Signature,
        KeyRole::Decryption,
    ];

    /// Whether the key belongs to one device, and so derives under the subkey id
    ///
    /// A sender encrypts to one decryption key of an identity and cannot know which card the
    /// recipient holds, so the decryption key is the identity's, the same on every card;
    /// signatures and logins are checked against whichever key made them, so those stay with
    /// the device and can be revoked with it.
    pub fn is_device_bound(self) -> bool {
        self != KeyRole::Decryption
    }

    /// The name the command line knows the role by
    pub fn name(self) -> &'static str {
        match self {
            KeyRole::Authentication => "authentication",
            KeyRole::Signature => "signature",
            KeyRole::Decryption => "decryption",
        }
    }
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

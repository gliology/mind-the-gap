//! Which card a command addresses, as `--card` names it.

use std::fmt;
use std::str::FromStr;

/// The card a command addresses
///
/// Three spellings, told apart by their shape alone: a PIV serial is all digits, an OpenPGP
/// identifier is four and eight hex digits around a colon, and a PC/SC reader name always has
/// a space in it (pcsc-lite appends the slot numbers, `Yubico YubiKey FIDO+CCID 01 00`). A
/// reader addresses either applet and is the one target that is opened without asking any
/// other card who it is, which is what lets several runs share a machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardTarget {
    /// A PIV card by the serial number it reports
    Serial(u32),
    /// An OpenPGP card by its identifier, `MANUFACTURER:SERIAL` in upper-case hex
    Ident(String),
    /// Whatever card sits in the PC/SC reader of exactly this name
    Reader(String),
}

impl FromStr for CardTarget {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let hex = |part: &str, len: usize| {
            part.len() == len && part.chars().all(|ch| ch.is_ascii_hexdigit())
        };
        if !text.is_empty() && text.chars().all(|ch| ch.is_ascii_digit()) {
            return text
                .parse()
                .map(CardTarget::Serial)
                .map_err(|_| format!("'{text}' is too large for a card serial number"));
        }
        if let Some((manufacturer, serial)) = text.split_once(':')
            && hex(manufacturer, 4)
            && hex(serial, 8)
        {
            return Ok(CardTarget::Ident(text.to_ascii_uppercase()));
        }
        if text.contains(' ') {
            return Ok(CardTarget::Reader(text.to_string()));
        }
        Err(format!(
            "'{text}' names no card: give a PIV serial number (digits), an OpenPGP identifier \
             (MMMM:SSSSSSSS) or a reader name, as `list` shows them"
        ))
    }
}

impl fmt::Display for CardTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CardTarget::Serial(serial) => write!(f, "{serial}"),
            CardTarget::Ident(ident) => f.write_str(ident),
            CardTarget::Reader(reader) => write!(f, "the card in reader '{reader}'"),
        }
    }
}

/// One attached reader, and the applets its card answers to
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    /// The reader's name, which addresses the card in it
    pub reader: String,
    /// The serial its PIV application reports
    pub piv: Option<u32>,
    /// The identifier of its OpenPGP application
    pub pgp: Option<String>,
}

impl Attached {
    /// Whether this is the card `target` names
    pub fn is(&self, target: &CardTarget) -> bool {
        match target {
            CardTarget::Serial(serial) => self.piv == Some(*serial),
            CardTarget::Ident(ident) => self
                .pgp
                .as_ref()
                .is_some_and(|own| own.eq_ignore_ascii_case(ident)),
            CardTarget::Reader(reader) => self.reader == *reader,
        }
    }

    /// The card as messages name it
    pub fn describe(&self) -> String {
        let mut applets = Vec::new();
        if let Some(serial) = self.piv {
            applets.push(format!("PIV {serial}"));
        }
        if let Some(ident) = &self.pgp {
            applets.push(format!("OpenPGP {ident}"));
        }
        let reader = crate::common::printable(&self.reader);
        if applets.is_empty() {
            format!("'{reader}' (no PIV or OpenPGP application)")
        } else {
            format!("'{reader}' ({})", applets.join(", "))
        }
    }
}

/// Every reader with a card in it, and the applets each card answers to, asked without
/// disturbing any of them
pub fn attached() -> anyhow::Result<Vec<Attached>> {
    let (context, readers) = crate::readers::list()?;
    let mut found = Vec::new();
    for reader in readers {
        // Both applets in one question; an empty reader cannot be asked and is no card at all
        let Ok(applets) = crate::readers::ask(&context, &reader, |transaction| {
            Some((crate::piv::read_serial(transaction), crate::pgp::read_ident(transaction)))
        }) else {
            continue;
        };
        let (piv, pgp) = applets.unwrap_or_default();
        found.push(Attached { reader: reader.to_string_lossy().into_owned(), piv, pgp });
    }
    Ok(found)
}

/// The one card `target` names, or the only one attached where it names none
pub fn locate(target: Option<&CardTarget>) -> anyhow::Result<Attached> {
    let cards = attached()?;
    let listing = || {
        cards
            .iter()
            .map(|card| format!("  {}", card.describe()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    match target {
        Some(target) => cards
            .iter()
            .find(|card| card.is(target))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No card {target} attached; the attached ones:\n{}",
                    if cards.is_empty() {
                        "  none".into()
                    } else {
                        listing()
                    }
                )
            }),
        None => match cards.as_slice() {
            [] => anyhow::bail!("No card attached, please insert one"),
            [only] => Ok(only.clone()),
            _ => anyhow::bail!(
                "{} cards are attached, name one with --card, by its PIV serial, OpenPGP \
                 identifier or reader:\n{}",
                cards.len(),
                listing()
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_tell_the_targets_apart() {
        assert_eq!("12345678".parse(), Ok(CardTarget::Serial(12345678)));
        assert_eq!("0006:2038a7b4".parse(), Ok(CardTarget::Ident("0006:2038A7B4".into())));
        assert_eq!(
            "Yubico YubiKey FIDO+CCID 01 00".parse(),
            Ok(CardTarget::Reader("Yubico YubiKey FIDO+CCID 01 00".into()))
        );
        // A reader whose name happens to contain a colon is still a reader
        assert_eq!(
            "Virtual PCD 00 00: x".parse(),
            Ok(CardTarget::Reader("Virtual PCD 00 00: x".into()))
        );
    }

    #[test]
    fn malformed_targets_are_refused() {
        for text in ["", "0006:123", "abc", "99999999999", "0006:1234567G"] {
            assert!(text.parse::<CardTarget>().is_err(), "{text:?} parsed");
        }
    }
}

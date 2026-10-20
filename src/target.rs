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
             (MMMM:SSSSSSSS) or a reader name, as `piv status` and `pgp status` show them"
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

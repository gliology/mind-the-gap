//! Helpers shared by both backends: the mismatch report their `check` commands raise, the
//! factory pins, and the sanitizer for printing untrusted text on a terminal.

use anyhow::{Result, bail};

/// Raise every collected `check` mismatch as one error, or return clean.
///
/// Both backends collect rather than bail on the first disagreement: a card provisioned
/// from the wrong seed disagrees everywhere, and seeing all of it is what tells that apart
/// from a single stale slot.
pub(crate) fn report_mismatches(subject: &str, mismatches: &[String]) -> Result<()> {
    if mismatches.is_empty() {
        return Ok(());
    }

    let detail = mismatches
        .iter()
        .map(|entry| format!("  - {entry}"))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "Card does not match the derived {subject}, {} problem(s) found:\n{detail}",
        mismatches.len()
    );
}

/// The user pin every OpenPGP and PIV card ships with
pub(crate) const FACTORY_USER_PIN: &str = "123456";

/// The admin pin every OpenPGP card ships with
pub(crate) const FACTORY_ADMIN_PIN: &str = "12345678";

/// Make untrusted text safe to print on a terminal
///
/// User IDs from a third-party certificate and strings read off a card are the two
/// genuinely untrusted inputs this tool displays, and a terminal interprets what it is
/// shown: an embedded escape sequence can rewrite earlier lines, hide a fingerprint, or
/// forge a verification message on the operator's console. Everything below space, DEL,
/// the C1 range and the bidi controls are escaped; printable text of any language passes
/// through.
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| {
            // Bidi controls are not control characters to Unicode, but they reorder what
            // follows them on screen, so a card could make its name read as something else
            let bidi = matches!(ch, '\u{61c}' | '\u{200e}' | '\u{200f}')
                || ('\u{202a}'..='\u{202e}').contains(&ch)
                || ('\u{2066}'..='\u{2069}').contains(&ch);
            if ch.is_control() || ('\u{80}'..='\u{9f}').contains(&ch) || bidi {
                ch.escape_unicode().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a terminal would act on comes out as a visible escape: CSI introduced by ESC or
    /// as the single C1 byte, operating system commands, DEL, and the C0 controls down to
    /// line breaks and the bell.
    #[test]
    fn printable_escapes_terminal_controls() {
        for (input, expected) in [
            ("\u{1b}[2J\u{1b}[1;1H", "\\u{1b}[2J\\u{1b}[1;1H"),
            ("ok\u{9b}31mforged", "ok\\u{9b}31mforged"),
            ("\u{1b}]0;title\u{7}", "\\u{1b}]0;title\\u{7}"),
            ("rub\u{7f}out", "rub\\u{7f}out"),
            ("one\ntwo\rthree\tfour", "one\\u{a}two\\u{d}three\\u{9}four"),
            ("\u{0}\u{1f}\u{80}\u{9f}", "\\u{0}\\u{1f}\\u{80}\\u{9f}"),
        ] {
            assert_eq!(printable(input), expected, "{input:?}");
        }
    }

    /// Bidi controls reorder what follows them, so a name could display as someone else's;
    /// they come out escaped while the text around them stays.
    #[test]
    fn printable_escapes_bidi_controls() {
        for (input, expected) in [
            ("Jane\u{202e}eoD", "Jane\\u{202e}eoD"),
            ("a\u{2066}b\u{2069}c", "a\\u{2066}b\\u{2069}c"),
            ("\u{200e}\u{200f}\u{61c}", "\\u{200e}\\u{200f}\\u{61c}"),
        ] {
            assert_eq!(printable(input), expected, "{input:?}");
        }
    }

    /// Printable text of any language and script passes through untouched.
    #[test]
    fn printable_keeps_text_of_any_language() {
        for text in [
            "Zoë Ångström <zoe@example.com>",
            "Дмитрий Шостакович",
            "李小龍",
            "محمد بن موسى",
            "Ελένη 😀",
        ] {
            assert_eq!(printable(text), text);
        }
    }
}

//! Helpers shared by both backends: clap value parsers for dates and durations, the
//! mismatch report their `check` commands raise, the factory pin warning, and the
//! sanitizer for printing untrusted text on a terminal.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};

use anyhow::{Result, anyhow, bail};

/// Raise every collected `check` mismatch as one error, or return clean.
///
/// Both backends collect rather than bail on the first disagreement: a card provisioned
/// from the wrong seed disagrees everywhere, and seeing all of it is what tells that apart
/// from a single stale slot.
pub(crate) fn report_mismatches(subject: &str, mismatches: Vec<String>) -> Result<()> {
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

/// Helpers to parse date with clap.
///
/// The date is read as midnight UTC, never local time: derivation inputs must not depend
/// on the timezone of the machine they are typed on.
pub(crate) fn parse_date(input: &str) -> Result<DateTime<Utc>> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|e| anyhow!(e))
        .map(|date| Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).expect("Static valid values")))
}

/// Helpers to parse duration with clap
pub(crate) use humantime::parse_duration;

/// Warn when a provisioned card keeps the well-known factory user pin
///
/// A warning rather than a refusal: scripts stay in charge of their own flags, and the
/// interactive session asks for the pin before this is reached.
pub(crate) fn warn_factory_pin(missing: bool) {
    if missing {
        log::warn!(
            "No pin supplied: the card keeps the factory user pin (123456), usable by anyone who finds it; pass --pin to set one"
        );
    }
}

/// Make untrusted text safe to print on a terminal
///
/// User IDs from a third-party certificate and strings read off a card are the two
/// genuinely untrusted inputs this tool displays, and a terminal interprets what it is
/// shown: an embedded escape sequence can rewrite earlier lines, hide a fingerprint, or
/// forge a verification message on the operator's console. Everything below space, plus
/// DEL and the C1 range, is escaped; printable text of any language passes through.
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_control() || ('\u{80}'..='\u{9f}').contains(&ch) {
                ch.escape_unicode().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

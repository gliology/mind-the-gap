//! The key paths both backends' golden vectors are pinned on.

use mind_the_gap::seed::KeyPath;

/// The key paths every algorithm is pinned on: no device and no date, a device, and the same
/// device in a dated generation
pub const PATHS: [(Option<&str>, Option<&str>); 3] = [
    (None, None),
    (Some("laptop"), None),
    (Some("laptop"), Some("2026-05-01")),
];

/// The key path an entry of [`PATHS`] names
pub fn key_path((subkey, date): (Option<&str>, Option<&str>)) -> KeyPath {
    KeyPath {
        subkey: subkey.map(String::from),
        date: date.map(|date| date.parse().unwrap()),
    }
}

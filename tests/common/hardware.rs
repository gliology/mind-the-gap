//! What both hardware suites take alike: the run's touch setting, the day a rotation moves a
//! card to, and the seeds of the test identities.

use mind_the_gap::seed::Seed256;

/// Whether this run provisions without touch policies, for a host that runs it unattended
///
/// `MTG_HARDWARE_TEST_TOUCH=never` provisions with the `never-touch` policy, the standard's
/// pins without any touch, and the assertions follow. A script cannot touch a YubiKey, so this
/// is how a suite runs without a person; it proves everything except that touch is enforced,
/// which the default run does.
pub fn touch_free() -> bool {
    match std::env::var("MTG_HARDWARE_TEST_TOUCH") {
        Err(_) => false,
        Ok(touch) if touch == "never" => true,
        Ok(other) => panic!("MTG_HARDWARE_TEST_TOUCH is `never` or unset, not `{other}`"),
    }
}

/// The day the rotation tests move a card to
pub fn next_generation() -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 1, 1).expect("a valid date")
}

/// A seed for test identities, from a tag and the name of the card under test
///
/// It must not be a seed anyone would use for real, since the card is wiped and re-provisioned
/// at will. It differs per card because the PKCS#11 stack and gpg-agent find keys by their
/// public half: with one identity on several attached cards, as on a test host, a step could
/// run on another card and pass there, or wait there for a touch.
pub fn seed_tagged(tag: u8, card: &str) -> Seed256 {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update([tag])
        .chain_update(card)
        .finalize()
        .into()
}

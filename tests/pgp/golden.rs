//! The frozen vectors of both schemes, `mtg1` and the legacy one.

use crate::SEED_A;

use mind_the_gap::pgp::{CertificateKind, Scheme, SeededSmartcard};
use mind_the_gap::seed::Algorithm;

use sequoia_openpgp::policy::StandardPolicy;

use std::time::{Duration, SystemTime};

/// The legacy derivation scheme is frozen.
///
/// Cards provisioned before the labels changed keep working only as long as `Scheme::Legacy`
/// reproduces exactly what it always did, so these vectors are a compatibility promise rather
/// than a snapshot of current behaviour: if this test fails, someone's card stopped matching
/// its certificate. They were captured from the scheme as it stood immediately before the
/// change.
#[test]
fn legacy_scheme_is_frozen() {
    let vectors = [
        (
            None,
            "7DEAD9D71E682BC9A6CA38A9F113EB1B0D8A3802",
            "492AA8FDCFB7345419EB9C5790E3D97667573C32",
            "4BFF9906723AE48B7DB134BF5653A9ED3C338CF4",
            "54F4305925427A458A3DF747A8FFE03B29910AF2",
        ),
        (
            Some("laptop"),
            "7DEAD9D71E682BC9A6CA38A9F113EB1B0D8A3802",
            "CAD5CB615E60AAC40868C8A3688C3689037B775E",
            "7F81A80B5793EB4BD41E7EA442690ADFD9F72515",
            "9C62E3890410573A9674841A5E73CA8DFCF44538",
        ),
    ];

    for (id, primary, signing, decryption, authentication) in vectors {
        let cert = SeededSmartcard::with_scheme(
            &SEED_A,
            id.map(|value| value.to_string()),
            "Alice".into(),
            Scheme::Legacy,
        )
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::default())
        .unwrap();

        assert_eq!(cert.fingerprint().to_hex(), primary, "primary key moved for {id:?}");

        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();

        for key in valid.keys().subkeys() {
            let flags = key.key_flags().unwrap();
            let expected = if flags.for_signing() {
                signing
            } else if flags.for_authentication() {
                authentication
            } else {
                decryption
            };

            assert_eq!(key.key().fingerprint().to_hex(), expected, "subkey moved for {id:?}",);
        }
    }
}

/// One frozen key set: subkey id, then the primary, signing, decryption and authentication
/// fingerprints
type FrozenKeys = (Option<&'static str>, &'static str, &'static str, &'static str, &'static str);

/// Assert that `algorithm` still derives exactly `vectors` under the current scheme
fn assert_current_scheme_frozen(algorithm: Algorithm, vectors: [FrozenKeys; 2]) {
    for (id, primary, signing, decryption, authentication) in vectors {
        let cert = SeededSmartcard::with_scheme(
            &SEED_A,
            id.map(|value| value.to_string()),
            "Alice".into(),
            Scheme::Current,
        )
        .with_algorithm(algorithm)
        .unwrap()
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::default())
        .unwrap();

        assert_eq!(cert.fingerprint().to_hex(), primary, "primary key moved for {id:?}");

        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();

        for key in valid.keys().subkeys() {
            let flags = key.key_flags().unwrap();
            let expected = if flags.for_signing() {
                signing
            } else if flags.for_authentication() {
                authentication
            } else {
                decryption
            };

            assert_eq!(key.key().fingerprint().to_hex(), expected, "subkey moved for {id:?}",);
        }
    }
}

/// The current `mtg1` scheme is frozen.
///
/// The 1.x versioning promise is that any release re-derives the very same keys from a
/// seed -- that is what makes a lost card replaceable years later. These vectors are that
/// promise in executable form: a one-character change to a label constant, a prefix or the
/// argon2 parameters would pass every other test while orphaning every provisioned card,
/// and this test is what fails instead. Do not update these values within a major version;
/// a derivation change ships as `mtg2` behind a new major.
#[test]
fn current_scheme_is_frozen() {
    assert_current_scheme_frozen(
        Algorithm::Curve25519,
        [
            (
                None,
                "88430F06B9F752ED2C341C36DE2AF5541838E809",
                "AB00BE7F835649188EAB5EE4A17BD588482B384C",
                "C97628A82FD1E82E546A625AB99670FFA38B11E6",
                "32C45264B695C2207EEF47559E0C7978DE44E988",
            ),
            (
                Some("laptop"),
                "88430F06B9F752ED2C341C36DE2AF5541838E809",
                "309AB6A06915C4E882C6DC068E0E96A1737672E3",
                "43F267E09AA430865C2231C467BB656C575DEC64",
                "15FFADF10464C79DA450A4F0FC71E4523479F307",
            ),
        ],
    );
}

/// The P-256 half of the same promise: `--algorithm p256` is part of `mtg1` and frozen with it.
#[test]
fn current_scheme_is_frozen_on_p256() {
    assert_current_scheme_frozen(
        Algorithm::P256,
        [
            (
                None,
                "022412B9B9C415FE99ECB1151B5B0F1FBDF2B3B1",
                "FA1D7D6AC880837C13F60F0886E1F118C99FE935",
                "77F2BDD072EF09FF12FF5C48C765E70B2E10100D",
                "7832C9B23902DE38CBEC5F6049380BDF9701B68D",
            ),
            (
                Some("laptop"),
                "022412B9B9C415FE99ECB1151B5B0F1FBDF2B3B1",
                "527C736AE891638340027B85FA9B38F89A250FAE",
                "1525D466A14E657B947CB297A57A7121F7265DA0",
                "0188C936832FD954C674DC41AEB42B6118B3B23A",
            ),
        ],
    );
}

/// The RSA-2048 half of the same promise: `--algorithm rsa2048` is part of `mtg1` and
/// frozen with it.
#[test]
fn current_scheme_is_frozen_on_rsa2048() {
    assert_current_scheme_frozen(
        Algorithm::Rsa2048,
        [
            (
                None,
                "648EF922E310FCFF534CEC58989A1599B3760585",
                "FC99E7F898391AA5D95905870A2A3819CAF7E132",
                "E98D89838836620F055CE0A1921560ABCBF6CAD9",
                "86147765F2F160C3ECCFAD34336F294CE9C91055",
            ),
            (
                Some("laptop"),
                "648EF922E310FCFF534CEC58989A1599B3760585",
                "94ED21C46D0AC6B335F69E81F47A6DEA7EA16ED5",
                "66FC340DDDB592E5F089FACA2A6C54E328A9DE66",
                "124CEA22D4E87BB9AE2BECA23783ECC7FCDEE20B",
            ),
        ],
    );
}

/// The RSA-3072 half of the same promise: `--algorithm rsa3072` is part of `mtg1` and
/// frozen with it.
#[test]
fn current_scheme_is_frozen_on_rsa3072() {
    assert_current_scheme_frozen(
        Algorithm::Rsa3072,
        [
            (
                None,
                "E2A7215DB4AB3648D24B67C8A45193DD5E8D1B31",
                "AC5EF1F59ECD2439A6DBD7E1963ABF5CD9577920",
                "8D6A15131D1A5AABA15A6AA727D91E5CE03F3F34",
                "CBBA2D15EFC789503D044074FF63C2E688A9E78D",
            ),
            (
                Some("laptop"),
                "E2A7215DB4AB3648D24B67C8A45193DD5E8D1B31",
                "A1C3CBD6EAB625637CCB72F3E1431230751B53EE",
                "8380BF575FCB27B9DA01292631A5401DD64987D2",
                "A6F0D44317780A711277582B62B00DBF07743188",
            ),
        ],
    );
}

/// The RSA-4096 half of the same promise: `--algorithm rsa4096` is part of `mtg1` and
/// frozen with it.
#[test]
fn current_scheme_is_frozen_on_rsa4096() {
    assert_current_scheme_frozen(
        Algorithm::Rsa4096,
        [
            (
                None,
                "A1567C043EA08D341C85D0C112D94D500A200AF9",
                "F35D4CF40303FD51878EE034393A6E7602DF1534",
                "FCB6A67C62AFDA4FF5C8BDA7389EEFA7D245F675",
                "1BDC3A7A343A3DC7BC7DF006D4901D56E0B45B90",
            ),
            (
                Some("laptop"),
                "A1567C043EA08D341C85D0C112D94D500A200AF9",
                "9D9F0D874C5B31956E60A7ADE9B23A1746FD5D3D",
                "25D380358B0CF34347E63648345F2F8631BC87C8",
                "2AA627714863A36B94EEDA4C345DE60C77D15F3F",
            ),
        ],
    );
}

/// The current scheme is a different scheme, not a rename.
///
/// Relabelling changes the argon2 salt, so every key moves. Asserted so that nobody mistakes
/// `--legacy` for a no-op flag.
#[test]
fn current_scheme_differs_from_legacy() {
    let build = |scheme| {
        SeededSmartcard::with_scheme(&SEED_A, None, "Alice".into(), scheme)
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .certify(CertificateKind::default())
            .unwrap()
    };

    assert_ne!(build(Scheme::Current).fingerprint(), build(Scheme::Legacy).fingerprint(),);
}

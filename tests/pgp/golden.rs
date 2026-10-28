//! The frozen vectors of both schemes, `mtg1` and the legacy one.

use crate::frozen::{PATHS, key_path};
use crate::hex::hex;
use crate::{SEED_A, SEED_B};

use mind_the_gap::mnemonic::MnemonicSeed;
use mind_the_gap::pgp::{CertificateKind, SeededSmartcard, VerificationKind};
use mind_the_gap::revocation::RevocationKind;
use mind_the_gap::role::KeyRole;
use mind_the_gap::seed::{Algorithm, CardSerial, KeyPath, Seed256, Seeds};

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::HashAlgorithm;
use sequoia_openpgp::{Cert, Packet, PacketPile};

use std::time::{Duration, SystemTime};

/// One frozen key set: the primary, signing, decryption and authentication fingerprints
type FrozenKeys = (&'static str, &'static str, &'static str, &'static str);

/// Assert that `cert` carries exactly `keys`, saying which key moved
fn assert_keys(
    cert: &Cert,
    (primary, signing, decryption, authentication): &FrozenKeys,
    what: &str,
) {
    assert_eq!(cert.fingerprint().to_hex(), *primary, "primary key moved for {what}");

    // Judged far ahead, so that a dated generation's subkeys are valid however it is run
    let policy = StandardPolicy::new();
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    let valid = cert.with_policy(&policy, Some(at)).unwrap();
    for (role, expected) in [
        (KeyRole::Signature, signing),
        (KeyRole::Decryption, decryption),
        (KeyRole::Authentication, authentication),
    ] {
        let key = valid
            .keys()
            .subkeys()
            .find(|key| key.key_flags().is_some_and(|flags| role.matches(&flags)))
            .unwrap_or_else(|| panic!("no {role} subkey for {what}"));
        assert_eq!(key.key().fingerprint().to_hex(), **expected, "{role} subkey moved for {what}");
    }
}

/// The legacy derivation scheme is frozen.
///
/// Cards provisioned before the labels changed keep working only as long as the legacy
/// scheme reproduces exactly what it always did, so these vectors are a compatibility promise
/// rather than a snapshot of current behaviour: if this test fails, someone's card stopped
/// matching its certificate. They were captured from the scheme as it stood immediately
/// before the change.
#[test]
fn legacy_scheme_is_frozen() {
    let vectors = [
        (
            None,
            (
                "7DEAD9D71E682BC9A6CA38A9F113EB1B0D8A3802",
                "492AA8FDCFB7345419EB9C5790E3D97667573C32",
                "4BFF9906723AE48B7DB134BF5653A9ED3C338CF4",
                "54F4305925427A458A3DF747A8FFE03B29910AF2",
            ),
        ),
        (
            Some("laptop"),
            (
                "7DEAD9D71E682BC9A6CA38A9F113EB1B0D8A3802",
                "CAD5CB615E60AAC40868C8A3688C3689037B775E",
                "7F81A80B5793EB4BD41E7EA442690ADFD9F72515",
                "9C62E3890410573A9674841A5E73CA8DFCF44538",
            ),
        ),
    ];

    for (id, keys) in vectors {
        let cert = SeededSmartcard::legacy(&SEED_A, id.map(String::from), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap();
        assert_keys(&cert, &keys, &format!("legacy {id:?}"));
    }
}

/// The legacy dates are frozen too, under their new names.
///
/// The legacy scheme took the primary's creation time as `--date` and the subkeys' as
/// `--subdate`, defaulting to the primary's; both are part of every fingerprint. They are now
/// `--identity-date` and `--date`. These vectors come from the release before the rename, run
/// on the test phrase: a card provisioned with dates must still match after it.
#[test]
fn legacy_dates_are_frozen() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon art";
    let root: Seed256 = **MnemonicSeed::from_phrase(phrase).unwrap().seed();
    let midnight = |date: &str| mind_the_gap::seed::midnight(date.parse().unwrap());
    let card = |id: Option<&str>, subkeys: Option<&str>| {
        let mut card = SeededSmartcard::legacy(&root, id.map(String::from), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_identity_time(midnight("2020-01-01"));
        if let Some(date) = subkeys {
            card = card.with_legacy_subkey_time(midnight(date));
        }
        card.certify(CertificateKind::default()).unwrap()
    };

    let both_dates: [(Option<&str>, FrozenKeys); 2] = [
        (
            None,
            (
                "61631450A0CDA8CB487098FDFA3F6DCCC167B1D8",
                "BDA03EC8A79F90434AD40EFD863A1E7C7D6D67C0",
                "C0AC29DF56AA3353F9921D8C77B7642683405D48",
                "E1BCC6AA14CBEEDF4674C8FCB3AF298B6F4EC6DB",
            ),
        ),
        (
            Some("laptop"),
            (
                "61631450A0CDA8CB487098FDFA3F6DCCC167B1D8",
                "5B8EA8904AED1EE0A349A926C13EB1B45AE5FDFD",
                "D9AEEE10C9186FE49ED64FB0A8C8B6D8B0C3FE6E",
                "CEFF12F9F67700BB5873F8E3D35F3CC314743696",
            ),
        ),
    ];
    for (id, keys) in both_dates {
        assert_keys(&card(id, Some("2021-06-15")), &keys, &format!("legacy dated {id:?}"));
    }

    // Without a subkey date the subkeys took the primary's, as they always did
    let primary_date: FrozenKeys = (
        "61631450A0CDA8CB487098FDFA3F6DCCC167B1D8",
        "B84C93E15BD0B1C967A0B1F72133F8B729071BD8",
        "56CC1EFA90A5A76BC89B5F0B2FCC4BB1879E64CD",
        "908F2E0045AE5416D70641B604633726BC88BD97",
    );
    assert_keys(&card(Some("laptop"), None), &primary_date, "legacy with one date");
}

/// Assert that `algorithm` still derives exactly `vectors` under the current scheme
fn assert_current_scheme_frozen(algorithm: Algorithm, vectors: &[FrozenKeys; 3]) {
    assert_frozen(vectors, |path| {
        SeededSmartcard::new(Seeds::one(&SEED_A), path, "Alice".into())
            .with_algorithm(algorithm)
            .unwrap()
    });
}

/// Assert that the card `build` makes for each path of [`PATHS`] still certifies exactly
/// `vectors`
fn assert_frozen(vectors: &[FrozenKeys; 3], build: impl Fn(KeyPath) -> SeededSmartcard) {
    for ((subkey, date), keys) in PATHS.into_iter().zip(vectors) {
        let cert = build(key_path((subkey, date)))
            .add_email("alice@example.com")
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap();
        assert_keys(&cert, keys, &format!("{subkey:?} {date:?}"));
    }
}

/// The Curve25519 vectors, the algorithm a card gets when none is chosen
const CURVE25519: [FrozenKeys; 3] = [
    (
        "88430F06B9F752ED2C341C36DE2AF5541838E809",
        "7A03457C3611E19E4177606D7F2B54833635F22D",
        "4A7098759CEBFC8A73E2E0B595AA044B4F85BE06",
        "23D706B8F2944FCEE0F45FF84A90EBCCA37A28F4",
    ),
    (
        "88430F06B9F752ED2C341C36DE2AF5541838E809",
        "309AB6A06915C4E882C6DC068E0E96A1737672E3",
        "4A7098759CEBFC8A73E2E0B595AA044B4F85BE06",
        "15FFADF10464C79DA450A4F0FC71E4523479F307",
    ),
    (
        "88430F06B9F752ED2C341C36DE2AF5541838E809",
        "7ACEEFA84790062E49EE3B875C369F31FDEEC5FA",
        "AA711F10ECAB19B1DA528B29FE1117817F1A25B5",
        "117C5D22111BD772195F221E8587CE005494DAC4",
    ),
];

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
    assert_current_scheme_frozen(Algorithm::Curve25519, &CURVE25519);
}

/// What a card gets when nothing is chosen is frozen with the rest.
///
/// The default scheme, algorithm and creation time are inputs to every fingerprint, so a
/// drifting default would move every key provisioned without `--algorithm` or a date while
/// each vector above, which sets the algorithm, kept passing.
#[test]
fn defaults_are_frozen() {
    assert_frozen(&CURVE25519, |path| {
        SeededSmartcard::new(Seeds::one(&SEED_A), path, "Alice".into())
    });
}

#[test]
fn current_scheme_is_frozen_on_p256() {
    assert_current_scheme_frozen(
        Algorithm::P256,
        &[
            (
                "022412B9B9C415FE99ECB1151B5B0F1FBDF2B3B1",
                "F356C183D349F992F1EA340101608F16C7D504D4",
                "08D08E2EFF1D22485533925A21A37E9C9A01E5C4",
                "0591AD5AE2C2B7F368797684BC732A61FCF86C87",
            ),
            (
                "022412B9B9C415FE99ECB1151B5B0F1FBDF2B3B1",
                "527C736AE891638340027B85FA9B38F89A250FAE",
                "08D08E2EFF1D22485533925A21A37E9C9A01E5C4",
                "0188C936832FD954C674DC41AEB42B6118B3B23A",
            ),
            (
                "022412B9B9C415FE99ECB1151B5B0F1FBDF2B3B1",
                "244EA985A668E2C1FC302710F2D80E02679114BF",
                "FD477B411483FA8985A7D961211461AEF05B01B3",
                "53D493D6C5E4DD3BA6900E6F726A27A99938BFB7",
            ),
        ],
    );
}

/// SHA-256 of `bytes` in hex
fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// Everything one algorithm writes on the default path, by SHA-256: the certificate as
/// `publish --format binary` writes it, the certificate and subkeys revocations, and `trust`
/// on Bob's certificate
#[derive(Debug, PartialEq)]
struct Output {
    certificate: String,
    revoke_certificate: String,
    revoke_subkeys: String,
    trust: String,
}

/// What `algorithm` writes on the default path
fn output(algorithm: Algorithm) -> Output {
    let card = SeededSmartcard::new(Seeds::one(&SEED_A), KeyPath::default(), "Alice".into())
        .with_algorithm(algorithm)
        .unwrap()
        .add_email("alice@example.com")
        .unwrap();
    let bob = SeededSmartcard::new(Seeds::one(&SEED_B), KeyPath::default(), "Bob".into())
        .add_email("bob@example.com")
        .unwrap()
        .certify(CertificateKind::default())
        .unwrap();
    let certificate = card
        .certify(CertificateKind::default())
        .unwrap()
        .to_vec()
        .unwrap();
    let revoke = |kind| card.revoke(kind, 0, "retired").unwrap();
    let revoke_certificate = revoke(RevocationKind::Certificate);
    let revoke_subkeys = revoke(RevocationKind::Subkeys);
    let trust = card
        .trust(bob, VerificationKind::default())
        .unwrap()
        .to_vec()
        .unwrap();

    // Every signature in all of it is over SHA-512, the hash RFC 6979 runs on for P-256, and
    // carries no salt, as the derivation chapter specifies
    for bytes in [&certificate, &revoke_certificate, &revoke_subkeys, &trust] {
        for packet in PacketPile::from_bytes(bytes).unwrap().into_children() {
            if let Packet::Signature(signature) = packet {
                assert_eq!(signature.hash_algo(), HashAlgorithm::SHA512, "{algorithm:?}");
                let salt = signature.notation("salt@notations.sequoia-pgp.org").count();
                assert_eq!(salt, 0, "{algorithm:?} salted a signature");
            }
        }
    }

    Output {
        certificate: digest(&certificate),
        revoke_certificate: digest(&revoke_certificate),
        revoke_subkeys: digest(&revoke_subkeys),
        trust: digest(&trust),
    }
}

/// What the commands write is frozen byte for byte, signatures included.
///
/// The fingerprints above pin the keys; these pin every signature made with them. Ed25519 and
/// PKCS#1 v1.5 signatures are deterministic by construction, and P-256 ones take RFC 6979
/// nonces with the HMAC on SHA-512 (src/pgp/signer.rs): a random nonce, or the HMAC on another
/// hash, keeps every fingerprint and fails here. Each algorithm runs twice, so a signature
/// that varies between runs fails as such, whatever the pinned value.
#[test]
fn output_is_frozen() {
    let vectors = [
        (
            Algorithm::Curve25519,
            Output {
                certificate: "ead8f023243fa2812b8b0ca0856713abd92d3e4b84ce48c856386f075f77a893"
                    .into(),
                revoke_certificate:
                    "65a32f2e3bd02c991b86974d5494a3fcb9d5f7a11d5cc89e2556b160c89f050a".into(),
                revoke_subkeys: "f72c8042ff06ee92311a2f715522d42ad89deb29802b839bbfb96a2f4e7b828b"
                    .into(),
                trust: "772246e56c0242a9a5e5788d63b24e738206f36972b971f08404464ffaecff37".into(),
            },
        ),
        (
            Algorithm::P256,
            Output {
                certificate: "e63131eb1c015ecd398036edc89b1637977dfff35f76f0f76358ba844c8dfa09"
                    .into(),
                revoke_certificate:
                    "570b18f0da456d13ddd44387c283c88bf15c28b48422fb4f7c056b6febbff120".into(),
                revoke_subkeys: "48816f9dbba5cf248c8ef1fb89cd820752748780170dd95520db7b23efcab341"
                    .into(),
                trust: "e241b0ee470ef5dc46c0c5daa01db182eefd2d200bbec1ad722112027250c700".into(),
            },
        ),
        (
            Algorithm::Rsa2048,
            Output {
                certificate: "d052ca0f002c1c5380fa7bc796aaf6d9652bfbda3cab2c370c934d754c205748"
                    .into(),
                revoke_certificate:
                    "e05d835a57386ef63c896e41a3263e571b610463391c095257efad529ba5bf1e".into(),
                revoke_subkeys: "07ebb6381c717b8b85bc57e85d8e1d287a38fe3b8102db325c64dcecc20b7923"
                    .into(),
                trust: "9f5290c9df37573969e363549018a19ac0c16bfc1f52d7f7e67a920410b73df6".into(),
            },
        ),
    ];
    for (algorithm, expected) in vectors {
        let first = output(algorithm);
        assert_eq!(first, output(algorithm), "two runs differ on {algorithm:?}");
        assert_eq!(first, expected, "output moved on {algorithm:?}");
    }
}

/// What `publish --app pgp --algorithm p256` writes, by SHA-256 of the armored certificate,
/// for each path of [`PATHS`]
const P256_CERTIFICATES: [&str; 3] = [
    "8cd11f318ba1437879eeae2b44ff6679ef769b66c11599259d167ceae9ca1161",
    "617b78dbff4fab268dde9389629da486dfd679cb1bc0341399adc7df34f9d21b",
    "62f234ed139fb00fc8ebed6c10027ffc612f684faa4566c7c0d0e5a68346edb6",
];

/// The armored P-256 certificate is frozen on every path, its subkeys' dates included.
#[test]
fn certificate_is_frozen_on_p256() {
    for ((subkey, date), expected) in PATHS.into_iter().zip(P256_CERTIFICATES) {
        let card =
            SeededSmartcard::new(Seeds::one(&SEED_A), key_path((subkey, date)), "Alice".into())
                .with_algorithm(Algorithm::P256)
                .unwrap()
                .add_email("alice@example.com")
                .unwrap();
        let armored = card
            .certify(CertificateKind::default())
            .unwrap()
            .armored()
            .to_vec()
            .unwrap();
        assert_eq!(digest(&armored), expected, "certificate moved for {subkey:?} {date:?}");
    }
}

#[test]
fn current_scheme_is_frozen_on_rsa2048() {
    assert_current_scheme_frozen(
        Algorithm::Rsa2048,
        &[
            (
                "648EF922E310FCFF534CEC58989A1599B3760585",
                "49E8A85728A077E8308023FE41A67C58D9ADA37D",
                "3FCF18E291ECD17EDF78C640B0A38D7A6F7FC247",
                "F88E844A8D7CB913D2C453232748C3B16CDF13B5",
            ),
            (
                "648EF922E310FCFF534CEC58989A1599B3760585",
                "94ED21C46D0AC6B335F69E81F47A6DEA7EA16ED5",
                "3FCF18E291ECD17EDF78C640B0A38D7A6F7FC247",
                "124CEA22D4E87BB9AE2BECA23783ECC7FCDEE20B",
            ),
            (
                "648EF922E310FCFF534CEC58989A1599B3760585",
                "65D525C010CB5F3F2D74F4401DC5F1BC7B478A80",
                "630DE17B7B197511383E097B301587DC069E598E",
                "D856C603B46A5C77BA87331A6EA3E3A0A104B182",
            ),
        ],
    );
}

#[test]
fn current_scheme_is_frozen_on_rsa3072() {
    assert_current_scheme_frozen(
        Algorithm::Rsa3072,
        &[
            (
                "E2A7215DB4AB3648D24B67C8A45193DD5E8D1B31",
                "DD74A6A406EC50855EB1FD1C109E05A5AD9080BA",
                "FE0D3F6CD6F0B5B08910E1E40ECACEE02B8F7857",
                "E77CC769A79B1069DEF6400423DFFA4A2656F7D7",
            ),
            (
                "E2A7215DB4AB3648D24B67C8A45193DD5E8D1B31",
                "A1C3CBD6EAB625637CCB72F3E1431230751B53EE",
                "FE0D3F6CD6F0B5B08910E1E40ECACEE02B8F7857",
                "A6F0D44317780A711277582B62B00DBF07743188",
            ),
            (
                "E2A7215DB4AB3648D24B67C8A45193DD5E8D1B31",
                "FEAAB97288AFE8C98B5C2363B890959E8A719C13",
                "AD703FFF73A1330F0F60842F70DAD208405DFA50",
                "7BF32E518B4B04DC99FF83E3E64B1C289942ECB1",
            ),
        ],
    );
}

#[test]
fn current_scheme_is_frozen_on_rsa4096() {
    assert_current_scheme_frozen(
        Algorithm::Rsa4096,
        &[
            (
                "A1567C043EA08D341C85D0C112D94D500A200AF9",
                "B5EB34C5E36447CA9012B0E53FE861BB0A58BA02",
                "1A8DEE3A444E9A0A35289B179CEB348AAE3F199C",
                "040E9230E8201A563759667AB77B77829600DB38",
            ),
            (
                "A1567C043EA08D341C85D0C112D94D500A200AF9",
                "9D9F0D874C5B31956E60A7ADE9B23A1746FD5D3D",
                "1A8DEE3A444E9A0A35289B179CEB348AAE3F199C",
                "2AA627714863A36B94EEDA4C345DE60C77D15F3F",
            ),
            (
                "A1567C043EA08D341C85D0C112D94D500A200AF9",
                "BB3FB846EE207C1F87E6C5276F71D2A63CC8C97F",
                "E7898583080E9B5CF4CF763FE02FCF5DB1BF24AB",
                "64DE275CAD25BD10A9F6D196B558D2147A77DF68",
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
    let current = SeededSmartcard::new(Seeds::one(&SEED_A), KeyPath::default(), "Alice".into());
    let legacy = SeededSmartcard::legacy(&SEED_A, None, "Alice".into());
    let fingerprint = |card: SeededSmartcard| {
        card.add_email("alice@example.com")
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap()
            .fingerprint()
    };
    assert_ne!(fingerprint(current), fingerprint(legacy));
}

/// The card identifier `init` names the card's card seed with is frozen too.
///
/// `list` and `check` tell whose card it is by it, so one that moved would make every
/// initialized card a stranger. It is the card seed's and the card's alone: no key seed and
/// no key path changes it. The legacy scheme has none.
#[test]
fn card_identifier_is_frozen() {
    for (serial, expected) in [
        (0x1234_5678, "mtg1:EFC46D2A3E0D7156711785459240D5FD"),
        (0x1234_5679, "mtg1:0C7E366A20384CCA36E2E14B5D5D4EE7"),
    ] {
        let serial = CardSerial::pgp(0x0006, serial);
        let card = SeededSmartcard::new(
            Seeds { card: Some(&SEED_A), key: Some(&SEED_B) },
            KeyPath { subkey: Some("laptop".into()), date: None },
            "Alice".into(),
        );
        assert_eq!(
            card.card_identifier(&serial).unwrap().as_deref(),
            Some(expected),
            "moved for {serial}"
        );
    }

    let legacy = SeededSmartcard::legacy(&SEED_A, None, "Alice".into());
    assert_eq!(legacy.card_identifier(&CardSerial::pgp(6, 1)).unwrap(), None);
}

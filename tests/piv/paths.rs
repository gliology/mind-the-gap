//! The two seeds and the key path: what each derives, and what each leaves alone.

use crate::{SEED_A, SEED_B, alice, device, digest, on_path, verifies_under};

use mind_the_gap::piv::{CertChain, CertificateKind, SeededSmartcard};
use mind_the_gap::role::KeyRole;
use mind_the_gap::seed::{Algorithm, CardSerial, KeyPath, Seeds};

use x509_cert::Certificate;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};

use yubikey::piv::{RetiredSlotId, SlotId};

/// The digests of a chain's slot certificates, in chain order
fn leaves(chain: &CertChain) -> Vec<Vec<u8>> {
    chain.leaves.iter().map(|(_, cert)| digest(cert)).collect()
}

/// A card's 9E certificate, as `init` writes it
fn nine_e(card: &SeededSmartcard, serial: u32) -> Certificate {
    card.card_authentication_certificate(Algorithm::P256, &CardSerial::piv(serial))
        .unwrap()
}

fn split(card: &[u8; 32], key: &[u8; 32]) -> SeededSmartcard {
    SeededSmartcard::new(
        Seeds { card: Some(card), key: Some(key) },
        KeyPath::default(),
        "Alice".into(),
    )
    .add_email("alice@example.com")
    .unwrap()
}

// --- The two seeds -----------------------------------------------------------

/// The card seed derives no key of the identity's: a card administered by anyone holds the
/// same chain for the same key seed
#[test]
fn keys_come_from_the_key_seed_alone() {
    let administered = split(&SEED_A, &SEED_B)
        .certify(CertificateKind::Chain)
        .unwrap();
    let own = on_path(&SEED_B, KeyPath::default(), "Alice", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();
    assert_eq!(digest(&administered.root), digest(&own.root));
    assert_eq!(leaves(&administered), leaves(&own));
}

/// The key seed derives nothing that administers a card: the 9E key and certificate are the
/// card seed's, the same whichever identity's keys the card carries
#[test]
fn the_card_key_comes_from_the_card_seed_alone() {
    let team = split(&SEED_A, &SEED_B);
    assert_eq!(digest(&nine_e(&team, 12345678)), digest(&nine_e(&alice(), 12345678)));
    assert_ne!(
        digest(&nine_e(&split(&SEED_B, &SEED_B), 12345678)),
        digest(&nine_e(&alice(), 12345678))
    );
}

/// A command given only one seed derives what that seed derives, and says which seed the
/// rest needs
#[test]
fn each_seed_alone_derives_its_half() {
    let card_only = SeededSmartcard::new(
        Seeds { card: Some(&SEED_A), key: None },
        KeyPath::default(),
        String::new(),
    );
    assert!(
        card_only
            .card_authentication_certificate(Algorithm::P256, &CardSerial::piv(1))
            .is_ok()
    );
    let err = card_only.certify(CertificateKind::Chain).unwrap_err();
    assert!(err.to_string().contains("key seed"), "{err}");

    let key_only = SeededSmartcard::new(
        Seeds { card: None, key: Some(&SEED_A) },
        KeyPath::default(),
        "Alice".into(),
    );
    assert!(key_only.certify(CertificateKind::Chain).is_ok());
    let err = key_only
        .card_authentication_certificate(Algorithm::P256, &CardSerial::piv(1))
        .unwrap_err();
    assert!(err.to_string().contains("card seed"), "{err}");
}

// --- The card's own key ------------------------------------------------------

/// The 9E certificate is the card's: self-signed, bound to its serial, for card
/// authentication alone, and naming no person
#[test]
fn the_card_authentication_certificate_names_the_card() {
    let card = alice();
    let cert = nine_e(&card, 12345678);
    let tbs = cert.tbs_certificate();

    assert_eq!(tbs.issuer(), tbs.subject());
    assert!(verifies_under(&cert, &cert), "9E is not signed by its own key");
    let subject = tbs.subject().to_string();
    assert!(subject.starts_with("CN=PIV Card mtg1:"), "{subject}");
    assert!(!subject.contains("Alice"), "9E names a person: {subject}");
    assert!(tbs.get_extension::<SubjectAltName>().unwrap().is_none());
    let eku = tbs.get_extension::<ExtendedKeyUsage>().unwrap().unwrap().1;
    assert_eq!(
        eku.0.iter().map(|oid| oid.to_string()).collect::<Vec<_>>(),
        ["2.16.840.1.101.3.6.8"]
    );

    // Another card is another key and another identifier
    let other = nine_e(&card, 87654321);
    assert_ne!(tbs.subject_public_key_info(), other.tbs_certificate().subject_public_key_info());
    assert_ne!(subject, other.tbs_certificate().subject().to_string());
}

/// The card authentication key derives per algorithm, like every other key
#[test]
fn the_card_authentication_key_follows_the_algorithm() {
    let serial = CardSerial::piv(12345678);
    let p256 = alice()
        .card_authentication_certificate(Algorithm::P256, &serial)
        .unwrap();
    let ed25519 = alice()
        .card_authentication_certificate(Algorithm::Curve25519, &serial)
        .unwrap();
    assert_ne!(
        p256.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key,
        ed25519
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
    );
    assert_eq!(p256.tbs_certificate().subject(), ed25519.tbs_certificate().subject());
}

// --- The key path --------------------------------------------------------------

/// A date is a generation: every key of it moves, the decryption key too, while the
/// identity's root authority stays as it is
#[test]
fn a_date_moves_every_key_but_the_identity() {
    let date = Some("2026-05-01".parse().unwrap());
    let plain = device("laptop").certify(CertificateKind::Chain).unwrap();
    let dated = on_path(
        &SEED_A,
        KeyPath { subkey: Some("laptop".into()), date },
        "Alice",
        "alice@example.com",
    )
    .certify(CertificateKind::Chain)
    .unwrap();

    assert_eq!(digest(&plain.root), digest(&dated.root));
    for ((slot, a), (_, b)) in plain.leaves.iter().zip(&dated.leaves) {
        assert_ne!(
            a.tbs_certificate().subject_public_key_info(),
            b.tbs_certificate().subject_public_key_info(),
            "{slot:?} kept its key across generations"
        );
    }
}

/// Within a generation the decryption key is the identity's, on every device alike, and the
/// device's own keys are its own
#[test]
fn devices_of_one_generation_share_the_decryption_key() {
    let date = Some("2026-05-01".parse().unwrap());
    let chain = |id: &str| {
        on_path(&SEED_A, KeyPath { subkey: Some(id.into()), date }, "Alice", "alice@example.com")
            .certify(CertificateKind::Chain)
            .unwrap()
    };
    let (laptop, phone) = (chain("laptop"), chain("phone"));
    assert_ne!(digest(&laptop.leaves[0].1), digest(&phone.leaves[0].1));
    assert_ne!(digest(&laptop.leaves[1].1), digest(&phone.leaves[1].1));
    assert_eq!(laptop.leaves[2].0, SlotId::KeyManagement);
    assert_eq!(digest(&laptop.leaves[2].1), digest(&phone.leaves[2].1));
}

/// A subkey id is a step of its own, never a part of another label: the empty id is an id,
/// and differs from none
#[test]
fn the_empty_subkey_id_is_an_id() {
    let none = alice().certify(CertificateKind::Chain).unwrap();
    let empty = device("").certify(CertificateKind::Chain).unwrap();
    assert_ne!(digest(&none.leaves[0].1), digest(&empty.leaves[0].1));
}

// --- Choosing keys and slots -------------------------------------------------------

/// `--key` chooses the certificates a chain carries, and nothing else about them
#[test]
fn chosen_keys_are_the_chain_s_leaves() {
    let full = device("laptop").certify(CertificateKind::Chain).unwrap();
    let signature = device("laptop")
        .with_keys(&[KeyRole::Signature])
        .unwrap()
        .certify(CertificateKind::Chain)
        .unwrap();
    assert_eq!(signature.leaves.len(), 1);
    assert_eq!(signature.leaves[0].0, SlotId::Signature);
    assert_eq!(digest(&signature.leaves[0].1), digest(&full.leaves[1].1));

    // Order follows the slots, whatever order they were named in
    let two = device("laptop")
        .with_keys(&[KeyRole::Decryption, KeyRole::Authentication])
        .unwrap()
        .certify(CertificateKind::Chain)
        .unwrap();
    let slots: Vec<_> = two.leaves.iter().map(|(slot, _)| *slot).collect();
    assert_eq!(slots, [SlotId::Authentication, SlotId::KeyManagement]);

    assert!(device("laptop").with_keys(&[]).is_err());
}

/// `--slot` puts the decryption key, certificate and all, into a retired slot: the same
/// certificate 9D would hold, so a card keeps another identity's or generation's key as is
#[test]
fn a_slot_moves_the_decryption_key_unchanged() {
    let full = alice().certify(CertificateKind::Chain).unwrap();
    let kept = alice()
        .with_keys(&[KeyRole::Decryption])
        .unwrap()
        .with_slot(0x82)
        .unwrap()
        .certify(CertificateKind::Chain)
        .unwrap();
    assert_eq!(kept.leaves.len(), 1);
    assert_eq!(kept.leaves[0].0, SlotId::Retired(RetiredSlotId::R1));
    assert_eq!(digest(&kept.leaves[0].1), digest(&full.leaves[2].1));

    // Only the decryption key moves, and only to 9d or a retired slot
    assert!(alice().with_slot(0x82).is_err(), "a slot without choosing the decryption key");
    let decryption = || alice().with_keys(&[KeyRole::Decryption]).unwrap();
    for slot in [0x9a, 0x9c, 0x9e, 0x81, 0x96] {
        assert!(decryption().with_slot(slot).is_err(), "slot {slot:02x} was accepted");
    }
    assert!(decryption().with_slot(0x9d).is_ok());
    assert!(decryption().with_slot(0x95).is_ok());
}

//! The shape of the chain: tiers, signatures, extensions and serial numbers.

use crate::{SEED_A, SLOTS, alice, builder, digest, extended_key_usage, key_usage, verifies_under};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SlotRole};

use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, SubjectAltName, SubjectKeyIdentifier,
};

use std::time::{Duration, SystemTime};

use yubikey::piv::SlotId;

#[test]
fn chain_is_two_tier_by_default() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    assert!(chain.intermediate.is_none());
    assert_eq!(chain.leaves.len(), 4);
    assert_eq!(chain.iter().count(), 5);

    let (_, constraints) = chain
        .root
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap();
    assert_eq!(constraints.path_len_constraint, Some(0));
}

#[test]
fn chain_is_three_tier_with_intermediate() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let intermediate = chain.intermediate.as_ref().expect("intermediate requested");
    assert_eq!(chain.iter().count(), 6);

    let root_constraints = chain
        .root
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap()
        .1;
    let sub_constraints = intermediate
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap()
        .1;

    assert_eq!(root_constraints.path_len_constraint, Some(1));
    assert_eq!(sub_constraints.path_len_constraint, Some(0));

    // The intermediate is signed by the root, the leaves by the intermediate
    assert!(verifies_under(intermediate, &chain.root));
    for (slot, leaf) in &chain.leaves {
        assert!(
            verifies_under(leaf, intermediate),
            "{slot:?} slot is not signed by the intermediate"
        );
    }
}

#[test]
fn certify_intermediate_without_intermediate_fails() {
    assert!(alice().certify(CertificateKind::Intermediate).is_err());
    assert!(
        alice()
            .with_intermediate(true)
            .certify(CertificateKind::Intermediate)
            .is_ok()
    );
}

/// The validity window follows the flags: infinite by default, bounded by --validity.
#[test]
fn validity_window_follows_the_flags() {
    let creation = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);

    // Default: leaves never expire, matching the promise that a derived certificate can be
    // reproduced years later
    let infinite = alice().certify(CertificateKind::Chain).unwrap();
    for (slot, cert) in &infinite.leaves {
        let validity = cert.tbs_certificate().validity();
        assert_eq!(validity.not_before.to_system_time(), creation, "{slot:?} notBefore moved");
        assert_eq!(
            validity.not_after.to_system_time(),
            x509_cert::time::Time::INFINITY.to_system_time(),
            "{slot:?} should not expire by default"
        );
    }

    // Bounded: --validity sets notAfter relative to the creation time, on the leaves only --
    // the authorities never expire, so a leaf can never outlive its issuer
    let bounded = alice()
        .with_validity_duration(ten_years)
        .certify(CertificateKind::Chain)
        .unwrap();
    for (slot, cert) in &bounded.leaves {
        assert_eq!(
            cert.tbs_certificate().validity().not_after.to_system_time(),
            creation + ten_years,
            "{slot:?} notAfter does not honour --validity"
        );
    }
    assert_eq!(
        bounded
            .root
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time(),
        x509_cert::time::Time::INFINITY.to_system_time(),
        "the root must never expire"
    );
}

/// `cas()` feeds the msroots object: issuing authority first, trust anchor last.
#[test]
fn cas_orders_the_root_last() {
    let plain = alice().certify(CertificateKind::Chain).unwrap();
    let cas = plain.cas();
    assert_eq!(cas.len(), 1);
    assert_eq!(digest(&cas[0]), digest(&plain.root));

    let tiered = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();
    let cas = tiered.cas();
    assert_eq!(cas.len(), 2);
    assert_eq!(digest(&cas[0]), digest(tiered.intermediate.as_ref().unwrap()));
    assert_eq!(digest(&cas[1]), digest(&tiered.root));
}

/// The msroots encoding is a degenerate PKCS#7: SignedData carrying only certificates.
///
/// This is what the Windows minidriver expects to find in the object; until now it was
/// asserted only on real hardware, i.e. never in CI.
#[test]
fn msroots_encodes_a_degenerate_pkcs7() {
    use cms::content_info::ContentInfo;
    use x509_cert::der::{Decode, Encode};

    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let encoded = ContentInfo::try_from(chain.cas())
        .expect("authorities do not form a PKCS#7")
        .to_der()
        .expect("PKCS#7 does not encode");

    // Round-trips as a ContentInfo declaring SignedData
    let decoded = ContentInfo::from_der(&encoded).expect("emitted DER does not parse back");
    assert_eq!(decoded.content_type.to_string(), "1.2.840.113549.1.7.2", "not SignedData");

    // Degenerate: both authorities embedded verbatim, root included
    let intermediate = chain.intermediate.as_ref().unwrap().to_der().unwrap();
    let root = chain.root.to_der().unwrap();
    let haystack = encoded.as_slice();
    let contains = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(contains(&intermediate), "intermediate certificate missing from msroots");
    assert!(contains(&root), "root certificate missing from msroots");
}

// --- Chain integrity ---------------------------------------------------------

#[test]
fn root_is_self_signed() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let root = &chain.root;

    assert_eq!(root.tbs_certificate().issuer(), root.tbs_certificate().subject());
    assert!(verifies_under(root, root));

    // RFC 5280 4.2.1.1: on a self-signed certificate the AKI mirrors the SKI
    let ski = root
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let aki = root
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(aki.key_identifier, Some(ski.0));
}

#[test]
fn leaves_chain_to_issuer() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let issuer = chain.issuer();

    let issuer_ski = issuer
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;

    for (slot, leaf) in &chain.leaves {
        assert_eq!(
            leaf.tbs_certificate().issuer(),
            issuer.tbs_certificate().subject(),
            "{slot:?} slot has the wrong issuer name"
        );
        assert_ne!(
            leaf.tbs_certificate().issuer(),
            leaf.tbs_certificate().subject(),
            "{slot:?} slot looks self-signed, which breaks path building"
        );

        let aki = leaf
            .tbs_certificate()
            .get_extension::<AuthorityKeyIdentifier>()
            .unwrap()
            .expect("leaves always carry an authority key identifier")
            .1;
        assert_eq!(
            aki.key_identifier,
            Some(issuer_ski.0.clone()),
            "{slot:?} slot does not point at the issuer's subject key identifier"
        );

        assert!(
            verifies_under(leaf, issuer),
            "{slot:?} slot signature does not verify under the issuer"
        );
    }
}

#[test]
fn dns_are_distinct_across_tiers() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let root = chain.root.tbs_certificate().subject();
    let intermediate = chain
        .intermediate
        .as_ref()
        .unwrap()
        .tbs_certificate()
        .subject();
    let user = chain.leaves[0].1.tbs_certificate().subject();

    assert_ne!(root, intermediate);
    assert_ne!(root, user);
    assert_ne!(intermediate, user);
}

#[test]
fn card_authentication_subject_is_not_person_bound() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    let user = chain.leaves[0].1.tbs_certificate().subject().to_string();
    let card = chain.leaves[3].1.tbs_certificate().subject().to_string();

    assert_eq!(chain.leaves[3].0, SlotId::CardAuthentication);
    assert_ne!(user, card);
    assert!(card.contains("PIV Card"), "unexpected card subject: {card}");
}

// --- Extensions --------------------------------------------------------------

#[test]
fn slot_key_usages_are_exact() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    for ((slot, cert), (_, role)) in chain.leaves.iter().zip(SLOTS.iter()) {
        let usage = key_usage(cert);
        let eku = extended_key_usage(cert);

        match role {
            SlotRole::Authentication => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert!(!usage.key_agreement(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"], "{slot:?}");
            }
            SlotRole::Signature => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert!(usage.non_repudiation(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.4"], "{slot:?}");
            }
            SlotRole::KeyManagement => {
                // ECDH keys take keyAgreement; keyEncipherment is RSA key transport and
                // makes NSS reject the certificate for S/MIME decryption.
                assert!(usage.key_agreement(), "{slot:?}");
                assert!(!usage.key_encipherment(), "{slot:?}");
                assert!(!usage.encipher_only() && !usage.decipher_only(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.2"], "{slot:?}");
            }
            SlotRole::CardAuthentication => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert_eq!(eku, vec!["2.16.840.1.101.3.6.8"], "{slot:?}");
            }
        }
    }
}

#[test]
fn ca_certs_are_ca_leaves_are_not() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    for ca in [&chain.root, chain.intermediate.as_ref().unwrap()] {
        let (critical, constraints) = ca
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .unwrap()
            .expect("authorities carry basic constraints");
        assert!(critical, "basic constraints must be critical on a CA");
        assert!(constraints.ca);

        let usage = key_usage(ca);
        assert!(usage.key_cert_sign());
        assert!(usage.crl_sign());

        // An absent EKU keeps the authority unconstrained across clientAuth,
        // emailProtection and id-PIV-cardAuth
        assert!(
            ca.tbs_certificate()
                .get_extension::<ExtendedKeyUsage>()
                .unwrap()
                .is_none()
        );
    }

    for (slot, leaf) in &chain.leaves {
        assert!(
            leaf.tbs_certificate()
                .get_extension::<BasicConstraints>()
                .unwrap()
                .is_none(),
            "{slot:?} slot should not carry basic constraints"
        );
    }
}

#[test]
fn emails_land_in_subject_alt_name() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    for (slot, leaf) in &chain.leaves {
        let san = leaf
            .tbs_certificate()
            .get_extension::<SubjectAltName>()
            .unwrap();

        if *slot == SlotId::CardAuthentication {
            assert!(san.is_none(), "the card slot must not be person bound");
        } else {
            let san = san.expect("user slots carry the email addresses").1;
            assert!(format!("{:?}", san.0).contains("alice@example.com"), "{slot:?}");
        }
    }
}

#[test]
fn no_empty_san() {
    // GeneralNames is a SEQUENCE SIZE (1..MAX), so with no emails the extension has to be
    // omitted rather than encoded empty.
    let chain = SeededSmartcard::new(&SEED_A, None, "Alice".into())
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::Chain)
        .unwrap();

    for (slot, leaf) in &chain.leaves {
        assert!(
            leaf.tbs_certificate()
                .get_extension::<SubjectAltName>()
                .unwrap()
                .is_none(),
            "{slot:?} slot emitted an empty subject alternative name"
        );
    }
}

#[test]
fn dn_attributes_are_applied_to_every_tier() {
    let chain = alice()
        .with_intermediate(true)
        .with_org("Example Corp".into())
        .with_org_unit("Engineering".into())
        .with_country("DE".into())
        .certify(CertificateKind::Chain)
        .unwrap();

    for cert in chain.iter() {
        let subject = cert.tbs_certificate().subject().to_string();
        assert!(subject.contains("O=Example Corp"), "{subject}");
        assert!(subject.contains("OU=Engineering"), "{subject}");
        assert!(subject.contains("C=DE"), "{subject}");
    }
}

#[test]
fn dn_special_characters_are_escaped() {
    let chain = builder(&SEED_A, "Doe, Jane A+B", "jane@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    // Round-trips as a single common name rather than splitting into extra RDNs
    let subject = chain.leaves[0].1.tbs_certificate().subject();
    assert_eq!(subject.iter_rdn().count(), 1);
    assert!(subject.to_string().contains("Doe\\, Jane A\\+B"));
}

// --- Serial numbers ----------------------------------------------------------

#[test]
fn serials_are_distinct_and_positive() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let mut seen = Vec::new();
    for cert in chain.iter() {
        let serial = cert.tbs_certificate().serial_number().as_bytes().to_vec();

        assert!(!serial.is_empty() && serial.len() <= 20, "{serial:?}");
        assert!(serial[0] < 0x80, "serial must be positive: {serial:?}");
        assert!(!seen.contains(&serial), "duplicate serial: {serial:?}");

        seen.push(serial);
    }
    assert_eq!(seen.len(), 6);
}

// --- External validation -----------------------------------------------------

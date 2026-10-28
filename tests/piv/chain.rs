//! The shape of the chain: tiers, signatures, extensions and serial numbers.

use crate::{
    SEED_A, SLOTS, alice, builder, device, digest, extended_key_usage, key_usage, list_url,
    on_path, verifies_under,
};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SlotRole};
use mind_the_gap::seed::{Algorithm, KeyPath, Seeds};

use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, SubjectAltName, SubjectKeyIdentifier,
};

use std::time::{Duration, SystemTime};

#[test]
fn chain_is_two_tier_by_default() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    assert!(chain.intermediate.is_none());
    assert_eq!(chain.leaves.len(), 3);
    assert_eq!(chain.iter().count(), 4);

    let (_, constraints) = chain
        .root
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap();
    // One below the root, used or not: the root is the same certificate with or without
    // an issuing authority on some device
    assert_eq!(constraints.path_len_constraint, Some(1));
    assert_eq!(
        chain.root,
        alice()
            .with_intermediate(true)
            .certify(CertificateKind::Chain)
            .unwrap()
            .root,
        "--intermediate changed the root"
    );
}

#[test]
fn chain_is_three_tier_with_intermediate() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let intermediate = chain.intermediate.as_ref().expect("intermediate requested");
    assert_eq!(chain.iter().count(), 5);

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

/// A generation's date is when its certificates start, and the identity's date when the root
/// does: the two are set apart, since the root outlives every generation
#[test]
fn dates_are_where_the_certificates_start() {
    let path = KeyPath { subkey: None, date: Some("2026-05-01".parse().unwrap()) };
    let generation = SystemTime::UNIX_EPOCH + Duration::from_secs(1_777_593_600);
    let identity = SystemTime::UNIX_EPOCH + Duration::from_secs(1_735_689_600);
    let chain = on_path(&SEED_A, path, "Alice", "alice@example.com")
        .with_identity_time(identity)
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let not_before = |cert: &x509_cert::Certificate| {
        cert.tbs_certificate()
            .validity()
            .not_before
            .to_system_time()
    };
    assert_eq!(not_before(&chain.root), identity);
    assert_eq!(not_before(chain.intermediate.as_ref().unwrap()), generation);
    for (slot, cert) in &chain.leaves {
        assert_eq!(not_before(cert), generation, "{slot:?}");
    }
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

/// The issuing authority of `card` with a revocation list URL: its subject, the URL its slot
/// certificates name, and the suffix its own list is published under
fn issuing(card: SeededSmartcard) -> (String, String, String) {
    let card = card
        .with_crl_url("http://example.org/alice.crl")
        .unwrap()
        .with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    let subject = chain
        .intermediate
        .as_ref()
        .unwrap()
        .tbs_certificate()
        .subject()
        .to_string();
    let urls: Vec<String> = chain
        .leaves
        .iter()
        .map(|(_, leaf)| list_url(leaf))
        .collect();
    assert!(urls.iter().all(|url| *url == urls[0]), "the slots name different lists: {urls:?}");
    let (suffix, _) = card.issuing_revocation_list().unwrap().unwrap();
    (subject, urls[0].clone(), suffix)
}

/// Every issuing authority of one identity has a name and a list of its own: across devices,
/// across generations of one device, and across algorithms of one device, which each derive
/// the authority's key apart
#[test]
fn issuing_authorities_are_named_apart() {
    let dated = |id: &str, date: &str| {
        on_path(
            &SEED_A,
            KeyPath { subkey: Some(id.into()), date: Some(date.parse().unwrap()) },
            "Alice",
            "alice@example.com",
        )
    };
    let authorities = [
        ("laptop", issuing(device("laptop"))),
        ("desktop", issuing(device("desktop"))),
        ("laptop 2026-05-01", issuing(dated("laptop", "2026-05-01"))),
        ("laptop 2027-05-01", issuing(dated("laptop", "2027-05-01"))),
        ("laptop curve25519", issuing(device("laptop").with_algorithm(Algorithm::Curve25519))),
        ("no device", issuing(alice())),
    ];
    for (index, (what, (subject, url, suffix))) in authorities.iter().enumerate() {
        for (other, (other_subject, other_url, other_suffix)) in &authorities[index + 1..] {
            assert_ne!(subject, other_subject, "{what} and {other} share an authority's name");
            assert_ne!(url, other_url, "{what} and {other} share a list URL");
            assert_ne!(suffix, other_suffix, "{what} and {other} share a list suffix");
        }
    }
}

/// The tag in the issuing authority's name is the first four bytes of its subject key
/// identifier, uppercase in the name and lowercase in its list's suffix and URL, which is the
/// URL its slot certificates name
#[test]
fn the_issuing_tag_is_its_key_identifier() {
    for algorithm in [
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::Curve25519,
        Algorithm::Rsa2048,
    ] {
        let card = device("laptop")
            .with_algorithm(algorithm)
            .with_crl_url("http://example.org/alice.crl")
            .unwrap()
            .with_intermediate(true);
        let chain = card.certify(CertificateKind::Chain).unwrap();
        let authority = chain.intermediate.as_ref().unwrap();
        let (_, identifier) = authority
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .unwrap()
            .unwrap();
        let tag: String = identifier.0.as_bytes()[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(
            authority.tbs_certificate().subject().to_string(),
            format!("CN=Alice PIV Issuing CA {}", tag.to_uppercase()),
            "{algorithm:?}"
        );
        let (suffix, _) = card.issuing_revocation_list().unwrap().unwrap();
        assert_eq!(suffix, format!("-{algorithm}-issuing-{tag}"), "{algorithm:?}");
        for (slot, leaf) in &chain.leaves {
            assert_eq!(
                list_url(leaf),
                format!("http://example.org/alice{suffix}.crl"),
                "{algorithm:?} {slot:?}"
            );
        }
    }
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
                unreachable!("9E is the card seed's, outside the chain")
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
            .unwrap()
            .expect("every slot of the chain is the person's and carries the addresses")
            .1;
        assert!(format!("{:?}", san.0).contains("alice@example.com"), "{slot:?}");
    }
}

#[test]
fn no_empty_san() {
    // GeneralNames is a SEQUENCE SIZE (1..MAX), so with no emails the extension has to be
    // omitted rather than encoded empty.
    let chain = SeededSmartcard::new(Seeds::one(&SEED_A), KeyPath::default(), "Alice".into())
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

/// A name of 40 characters fits every common name, the issuing authority's longest at the 64
/// RFC 5280 allows, on the algorithm with the longest root name; one more is refused, with an
/// issuing authority or without, counted in characters rather than bytes
#[test]
fn names_are_held_to_their_bound() {
    let named = |name: &str, intermediate: bool| {
        SeededSmartcard::new(
            Seeds::one(&SEED_A),
            KeyPath { subkey: Some("laptop".into()), date: None },
            name.into(),
        )
        .with_algorithm(Algorithm::Curve25519)
        .with_intermediate(intermediate)
    };
    let common_name = |cert: &x509_cert::Certificate| {
        let subject = cert.tbs_certificate().subject().to_string();
        subject.strip_prefix("CN=").unwrap().chars().count()
    };

    for name in ["A".repeat(40), "\u{e9}".repeat(40)] {
        let chain = named(&name, true).certify(CertificateKind::Chain).unwrap();
        assert_eq!(common_name(chain.intermediate.as_ref().unwrap()), 64);
        assert_eq!(common_name(&chain.root), 63);
        assert!(named(&name, false).certify(CertificateKind::Chain).is_ok());
    }
    for name in ["A".repeat(41), "\u{e9}".repeat(41)] {
        for intermediate in [false, true] {
            for kind in [CertificateKind::Root, CertificateKind::Chain] {
                let err = named(&name, intermediate).certify(kind).unwrap_err();
                assert!(
                    err.to_string().contains("--name is 41 characters")
                        && err.to_string().contains("at most 40"),
                    "{err}"
                );
            }
        }
    }
    let err = named("", false).certify(CertificateKind::Root).unwrap_err();
    assert!(err.to_string().contains("--name is empty"), "{err}");
}

/// A name of characters RFC 4514 escapes is held to the bound as given: 40 of them, a leading
/// `#` and a trailing space among them, make every common name, each one attribute carrying
/// the name unescaped, and one more is refused
#[test]
fn escaped_names_are_counted_as_given() {
    use x509_cert::der::asn1::Utf8StringRef;

    let pattern = "#, +\"\\<>;=\u{e9} ";
    let name = format!("{}\u{e9}+, ", pattern.repeat(3));
    assert_eq!(name.chars().count(), 40);
    let named = |name: &str| {
        SeededSmartcard::new(
            Seeds::one(&SEED_A),
            KeyPath { subkey: Some("laptop".into()), date: None },
            name.into(),
        )
        .with_algorithm(Algorithm::Curve25519)
        .with_intermediate(true)
    };
    // The one common name a subject holds, as its attribute carries it
    let common_name = |cert: &x509_cert::Certificate| {
        let subject = cert.tbs_certificate().subject();
        let rdns: Vec<_> = subject.iter_rdn().collect();
        assert_eq!(rdns.len(), 1, "{subject}");
        let attributes: Vec<_> = rdns[0].iter().collect();
        assert_eq!(attributes.len(), 1, "{subject}");
        attributes[0]
            .value
            .decode_as::<Utf8StringRef<'_>>()
            .unwrap()
            .as_str()
            .to_string()
    };

    let chain = named(&name).certify(CertificateKind::Chain).unwrap();
    let root = common_name(&chain.root);
    assert_eq!(root, format!("{name} PIV Root CA curve25519"));
    let issuing = common_name(chain.intermediate.as_ref().unwrap());
    assert!(issuing.starts_with(&format!("{name} PIV Issuing CA ")), "{issuing}");
    assert_eq!(issuing.chars().count(), 64);
    for (slot, leaf) in &chain.leaves {
        assert_eq!(common_name(leaf), name, "{slot:?}");
    }
    // Escaped, the subject is longer than the bound, which counts the name as given
    let escaped = chain.root.tbs_certificate().subject().to_string();
    assert!(escaped.chars().count() > 64 + "CN=".len(), "{escaped}");

    let err = named(&format!("{name},"))
        .certify(CertificateKind::Root)
        .unwrap_err();
    assert!(err.to_string().contains("--name is 41 characters"), "{err}");
}

/// The organization and its unit take 64 characters each, the country two uppercase
/// letters, and every refusal is told at once, in whatever order the setters ran
#[test]
fn subject_attributes_are_held_to_their_bounds() {
    let attributed = |org: &str, unit: &str, country: &str| {
        alice()
            .with_country(country.into())
            .with_org_unit(unit.into())
            .with_org(org.into())
            .certify(CertificateKind::Chain)
    };
    let long = "O".repeat(64);
    let wide = "\u{f6}".repeat(64);
    assert!(attributed(&long, &wide, "DE").is_ok());
    assert!(attributed(&wide, &long, "SE").is_ok());

    let err = attributed(&"O".repeat(65), &"\u{f6}".repeat(65), "de")
        .unwrap_err()
        .to_string();
    for told in [
        "--org is 65 characters",
        "--unit is 65 characters",
        "--country 'de' is no country code",
    ] {
        assert!(err.contains(told), "{told} untold:\n{err}");
    }
    for country in ["D", "DEU", "\u{c4}\u{d6}", "D1", ""] {
        let err = attributed("Org", "Unit", country).unwrap_err();
        assert!(err.to_string().contains("--country"), "{country}: {err}");
    }
    for (org, unit, told) in [
        ("", "Unit", "--org is empty"),
        ("Org", "", "--unit is empty"),
    ] {
        let err = attributed(org, unit, "DE").unwrap_err();
        assert!(err.to_string().contains(told), "{err}");
    }

    // What the command line judges before any seed is stretched is the same rule
    use mind_the_gap::piv::refuse_unfit_names;
    assert!(refuse_unfit_names(None, None, None, None).is_ok());
    assert!(
        refuse_unfit_names(Some(&"A".repeat(40)), Some(&long), Some(&wide), Some("DE")).is_ok()
    );
    assert!(refuse_unfit_names(Some(&"A".repeat(41)), None, None, None).is_err());
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
    assert_eq!(seen.len(), 5);
}

/// A serial names one certificate, not one key: a certificate issued again with another
/// validity or name carries a serial of its own, so a revocation list or a relying party's
/// cache can never take one for the other; issued again unchanged, it is the same
fn serial(chain: &mind_the_gap::piv::CertChain, index: usize) -> Vec<u8> {
    chain.leaves[index]
        .1
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec()
}

#[test]
fn serials_name_the_certificate_not_the_key() {
    let plain = alice().certify(CertificateKind::Chain).unwrap();
    let again = alice().certify(CertificateKind::Chain).unwrap();
    let longer = alice()
        .with_validity_duration(Duration::from_secs(86_400))
        .certify(CertificateKind::Chain)
        .unwrap();
    let renamed = builder(&SEED_A, "Alice A.", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();
    // What only the extensions carry moves the serial too
    let readdressed = builder(&SEED_A, "Alice", "alice@example.org")
        .certify(CertificateKind::Chain)
        .unwrap();
    let listed = alice()
        .with_crl_url("http://example.org/alice.crl")
        .unwrap()
        .certify(CertificateKind::Chain)
        .unwrap();

    for index in 0..3 {
        assert_eq!(serial(&plain, index), serial(&again, index));
        // The same key in both, only the certificate around it differs
        assert_eq!(
            plain.leaves[index]
                .1
                .tbs_certificate()
                .subject_public_key_info(),
            longer.leaves[index]
                .1
                .tbs_certificate()
                .subject_public_key_info()
        );
        assert_ne!(serial(&plain, index), serial(&longer, index), "validity reused a serial");
        assert_ne!(serial(&plain, index), serial(&renamed, index), "name reused a serial");
        assert_ne!(serial(&plain, index), serial(&readdressed, index), "emails reused a serial");
        assert_ne!(serial(&plain, index), serial(&listed, index), "a list URL reused a serial");
    }

    // Two devices' certificates of the one shared decryption key are one certificate, as the
    // subject carries no device: every card holds the same 9D certificate
    let laptop = device("laptop").certify(CertificateKind::Chain).unwrap();
    assert_eq!(serial(&plain, 2), serial(&laptop, 2));
}

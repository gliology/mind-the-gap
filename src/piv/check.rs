//! Comparing a card with the derived chain, by metadata or by a signature challenge.

use super::{ManagementKeyArg, SeededSmartcard, card::open_token, slots::slot_role};

use anyhow::{Result, anyhow};

use yubikey::piv::{self, AlgorithmId, ManagementSlotId, SlotId};
use yubikey::{
    Certificate as CardCertificate, Error as CardError, MgmAlgorithmId, MsRoots, PinPolicy,
    TouchPolicy, YubiKey,
};

use cms::content_info::ContentInfo;

use p256::ecdsa::DerSignature;
use p256::ecdsa::signature::hazmat::PrehashVerifier;

use rsa::pkcs1v15::Signature as RsaSignature;
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::traits::PublicKeyParts;

use der::Encode;

use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;

/// A SHA-256 `digest` in the block a raw RSA private key operation signs: EMSA-PKCS1-v1_5
/// (RFC 8017 section 9.2), padded to the modulus size in bytes
fn pkcs1_sha256_block(digest: &[u8], size: usize) -> Vec<u8> {
    const DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut block = vec![0xff; size];
    block[0] = 0x00;
    block[1] = 0x01;
    let tail = DIGEST_INFO.len() + digest.len();
    block[size - tail - 1] = 0x00;
    block[size - tail..size - digest.len()].copy_from_slice(&DIGEST_INFO);
    block[size - digest.len()..].copy_from_slice(digest);
    block
}

impl SeededSmartcard {
    /// Check that an available PIV card matches the derived chain
    ///
    /// Every slot is inspected before anything is reported. A card provisioned from the wrong
    /// seed, or with the wrong `--date`, `--subkey` or DN flags, disagrees in *all* of them,
    /// and failing on the first would hide how far the divergence actually goes.
    ///
    /// Slot keys are compared through `GET METADATA`. A card without it (YubiKey before
    /// 5.3) proves each key by signing a random challenge instead, which needs `--pin` for
    /// every slot whose pin policy is not `never`; its slot policies cannot be read at all.
    pub fn check(&self, target: Option<String>) -> Result<()> {
        let chain = self.generate_chain()?;
        let mut token = open_token(target)?;

        // Card has to be under our management key, in whatever algorithm it holds one: the
        // derivation for each is fixed, so the card's answer decides which to compare with
        let algorithm = MgmAlgorithmId::current(&mut token)?;
        let requested = self.management_algorithm(&token);
        if self.management_algorithm != ManagementKeyArg::Auto && algorithm != requested {
            log::warn!(
                "The card holds a {algorithm:?} management key, not the requested {requested:?}"
            );
        }

        // The management key's touch policy, where the card can report it. Advisory like the
        // slot policies below.
        let expected_touch = if self.management_touch {
            TouchPolicy::Always
        } else {
            TouchPolicy::Never
        };
        if let Ok(metadata) =
            piv::metadata(&mut token, SlotId::Management(ManagementSlotId::Management))
            && let Some((_, touch)) = metadata.policy
            && touch != expected_touch
        {
            log::warn!(
                "Policy mismatch in management key: card touch={touch:?}, expected={expected_touch:?}"
            );
        }

        // The prompt goes to stderr: stdout may be carrying PEM or a report, and a buried
        // prompt is a missed touch and a failed run
        log::info!("Verifying smart card {algorithm:?} management key");
        if self.management_touch {
            eprintln!("[Please touch device to authenticate management access!]");
        }
        token.authenticate(&self.management_key(algorithm)?)?;
        if self.management_touch {
            eprintln!();
        }

        // The supplied user pin, if any, has to open the card. A wrong pin consumes one of
        // the card's retries, but that is inherent to verifying it at all.
        if let Some(pin) = &self.pin {
            log::info!("Verifying smart card user pin");
            token.verify_pin(pin.as_bytes())?;
        }

        // Collected rather than raised, so one bad slot does not mask the others. Note that
        // `?` is still used for failures of *our* side -- a chain that will not encode is a
        // bug here, not a disagreement with the card.
        let mut mismatches: Vec<String> = Vec::new();

        // A card without GET METADATA warns about what it cannot show once, not per slot
        let mut policies_warned = false;
        let mut pin_warned = false;

        for (slot, expected) in &chain.leaves {
            match piv::metadata(&mut token, *slot) {
                Err(CardError::NotSupported) => {
                    if !policies_warned {
                        log::warn!(
                            "Card has no GET METADATA: slot pin and touch policies are not \
                             verifiable on this card, slot keys are proven by signing"
                        );
                        policies_warned = true;
                    }

                    let spki = expected.tbs_certificate().subject_public_key_info();
                    if let Some(problem) =
                        self.challenge_slot(&mut token, *slot, spki, &mut pin_warned)?
                    {
                        mismatches.push(problem);
                    }
                }
                Err(err) => mismatches.push(format!("{slot:?} slot: metadata unreadable: {err}")),
                Ok(metadata) => {
                    // Key material has to match what we would derive
                    let want = expected
                        .tbs_certificate()
                        .subject_public_key_info()
                        .to_der()?;

                    match metadata.public.as_ref().map(|key| key.to_der()) {
                        None => mismatches.push(format!("{slot:?} slot: no key on card")),
                        Some(Err(err)) => mismatches
                            .push(format!("{slot:?} slot: on-card public key is malformed: {err}")),
                        Some(Ok(got)) if got != want => mismatches
                            .push(format!("{slot:?} slot: public key is not the derived one")),
                        Some(Ok(_)) => {}
                    }

                    // Policies are advisory: warn rather than fail, they can be tightened by
                    // hand, and `upload` itself lets them be overridden
                    if let Some(policy) = metadata.policy {
                        let expected_policy = self.policies_for(*slot);
                        if policy != expected_policy {
                            log::warn!(
                                "Policy mismatch in {:?} slot: card={:?}, expected={:?}",
                                slot,
                                policy,
                                expected_policy
                            );
                        }
                    }
                }
            }

            // Certificate has to be byte identical
            let want = Sha256::digest(expected.to_der()?);
            match CardCertificate::read(&mut token, *slot) {
                Err(err) => {
                    mismatches.push(format!("{slot:?} slot: certificate unreadable: {err}"))
                }
                Ok(card) => match card.cert.to_der() {
                    Err(err) => mismatches
                        .push(format!("{slot:?} slot: on-card certificate is malformed: {err}")),
                    Ok(der) => {
                        let got = Sha256::digest(der);
                        if got != want {
                            mismatches.push(format!(
                                "{slot:?} slot: certificate mismatch: card={got:x}, derived={want:x}"
                            ));
                        } else {
                            log::info!("{:?} slot matches: {:x}", slot, got);
                        }
                    }
                },
            }
        }

        // Advisory for the same reason `upload` only warns when it cannot write it: msroots is
        // Windows-specific, and a card that never received it is not thereby wrong
        if self.msroots {
            let expected = ContentInfo::try_from(chain.cas())?.to_der()?;
            match MsRoots::read(&mut token) {
                Ok(Some(roots)) if AsRef::<[u8]>::as_ref(&roots) == expected.as_slice() => {
                    log::info!("Certificate authorities in msroots match")
                }
                Ok(Some(_)) => log::warn!("Certificate authorities in msroots do not match"),
                Ok(None) => log::warn!("No certificate authorities stored in msroots"),
                Err(err) => log::warn!("Could not read msroots: {err}"),
            }
        }

        // Tidy up, but never at the cost of the report: a failure to drop the management key
        // session must not swallow the mismatches we came here to show
        if let Err(err) = token.deauthenticate() {
            log::warn!("Could not deauthenticate management key: {err}");
        }

        crate::common::report_mismatches("chain", mismatches)
    }

    /// Prove that `slot` holds the key behind `spki` on a card that cannot report it
    ///
    /// The card signs a fresh random digest, as wide as the curve's field or SHA-256 wrapped
    /// in a PKCS#1 v1.5 block for RSA, and the signature has to verify under the derived
    /// public key. Only the holder of the derived private
    /// key can produce one, so this proves the key as firmly as reading it back would. It
    /// returns the mismatch to report, or `None` when the key verified or could not be
    /// challenged, which is warned about rather than failed: that is a limit of the card,
    /// not a disagreement with the seed.
    fn challenge_slot(
        &self,
        token: &mut YubiKey,
        slot: SlotId,
        spki: &SubjectPublicKeyInfoOwned,
        pin_warned: &mut bool,
    ) -> Result<Option<String>> {
        let algorithm = slot_role(slot).card_algorithm(self.algorithm);
        let width = match algorithm {
            // RSA signs a SHA-256 digest, padded below
            AlgorithmId::EccP256
            | AlgorithmId::Rsa2048
            | AlgorithmId::Rsa3072
            | AlgorithmId::Rsa4096 => 32,
            AlgorithmId::EccP384 => 48,
            // Cards without GET METADATA predate Ed25519 and X25519 by several firmware
            // generations, so this is a card answering inconsistently
            other => {
                log::warn!(
                    "{slot:?} slot: cannot verify a {other:?} key on a card without GET \
                     METADATA, skipping it"
                );
                return Ok(None);
            }
        };

        // Signing is subject to the slot's pin policy. Verified again right before the
        // signature, which is what a pin-always slot demands; a pin-once slot does not mind.
        let (pin_policy, touch_policy) = self.policies_for(slot);
        if pin_policy != PinPolicy::Never {
            match &self.pin {
                Some(pin) => token.verify_pin(pin.as_bytes())?,
                None => {
                    if !*pin_warned {
                        log::warn!(
                            "Slot keys cannot be verified on this card without --pin: it has \
                             no GET METADATA, and signing the challenge needs the pin"
                        );
                        *pin_warned = true;
                    }
                    return Ok(None);
                }
            }
        }

        let mut digest = vec![0u8; width];
        getrandom::fill(&mut digest)
            .map_err(|err| anyhow!("No OS entropy for the signature challenge: {err}"))?;

        if touch_policy != TouchPolicy::Never {
            eprintln!("[Please touch device to prove the {slot:?} key!]");
        }
        // The card applies the raw RSA private key operation, so the padding is ours
        let input = match algorithm {
            AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
                let key = rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?)
                    .map_err(|err| anyhow!("Derived RSA key is malformed: {err}"))?;
                pkcs1_sha256_block(&digest, key.size())
            }
            _ => digest.clone(),
        };
        let signature = match piv::sign_data(token, &input, algorithm, slot) {
            Ok(signature) => signature,
            Err(err) => {
                return Ok(Some(format!("{slot:?} slot: signature challenge failed: {err}")));
            }
        };

        let point = spki.subject_public_key.raw_bytes();
        let verified = match algorithm {
            AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
                use rsa::signature::hazmat::PrehashVerifier as _;
                let key = rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?)
                    .map_err(|err| anyhow!("Derived RSA key is malformed: {err}"))?;
                let key = rsa::pkcs1v15::VerifyingKey::<RsaSha256>::new(key);
                RsaSignature::try_from(&signature[..])
                    .is_ok_and(|signature| key.verify_prehash(&digest, &signature).is_ok())
            }
            AlgorithmId::EccP256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|err| anyhow!("Derived P-256 key is malformed: {err}"))?;
                DerSignature::from_bytes(&signature)
                    .is_ok_and(|signature| key.verify_prehash(&digest, &signature).is_ok())
            }
            _ => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|err| anyhow!("Derived P-384 key is malformed: {err}"))?;
                p384::ecdsa::DerSignature::from_bytes(&signature)
                    .is_ok_and(|signature| key.verify_prehash(&digest, &signature).is_ok())
            }
        };

        if !verified {
            return Ok(Some(format!(
                "{slot:?} slot: public key is not the derived one (signature challenge)"
            )));
        }

        log::info!("{slot:?} slot key proven by a signature challenge");
        Ok(None)
    }
}

use crate::Seed256;

use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use zeroize::Zeroize;

use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    Result,
};
use openpgp::cert::{
    Cert,
    CertRevocationBuilder,
};
use openpgp::crypto::Password;
use openpgp::packet::{
    self,
    key,
    Key,
};
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::types::{
    Features,
    HashAlgorithm,
    KeyFlags,
    SignatureType,
    SymmetricAlgorithm,
    ReasonForRevocation,
};

type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

/// Helper to create primary key-based signature builder including metadata.
fn new_primary_sbuilder(stype: SignatureType, ctime: SystemTime) -> Result<SignatureBuilder>
{
    SignatureBuilder::new(stype)
        .set_features(Features::sequoia())?
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_key_validity_period(None)?
        .set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA256,
        ])?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_signature_creation_time(ctime)
}

/// Config to create an ed25519/cv25519 user cert
pub struct SeededEd25519Cert<S: Seed256> {
    /// Seed used for primary key
    seed: S,

    /// Seed used for subkeys
    subseed: S,

    /// Password to use to protect secret keys
    password: Option<Password>,

    /// Creation time of key certificate, defaults to one second after unix epoch
    creation_time: Option<SystemTime>,

    /// Creation time of subkeys, defaults to creation time of certificate
    subkey_creation_time: Option<SystemTime>,

    /// Validity duration of subkeys
    subkey_validity: Option<Duration>,

    /// List of user ids to include in cert
    userids: Vec<packet::UserID>,
}

impl<S: Seed256> SeededEd25519Cert<S> {

    pub fn new(seed: S, subseed: S) -> Self {
        SeededEd25519Cert {
            seed,
            subseed,
            password: None,
            creation_time: None,
            subkey_creation_time: None,
            subkey_validity: None,
            userids: vec![]
        }
    }

    /// Set password to protect secret keys
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set certificate creation time
    pub fn with_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.creation_time = Some(timestamp);
        self
    }

    /// Set subkey creation time
    pub fn with_subkey_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.subkey_creation_time = Some(timestamp);
        self
    }

    /// Set subkey validity period
    pub fn with_subkey_validity(mut self, validity: Duration) -> Self {
        self.subkey_validity = Some(validity);
        self
    }

    /// Add userid to certificate
    pub fn add_userid(mut self, id: &str) -> Self {
        self.userids.push(id.into());
        self
    }

    /// Generate certificate and revocation signature
    pub fn generate(self) -> Result<(Cert, Packet)> {
        // Determine creation time
        let creation_time = self.creation_time.unwrap_or(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1)
        );

        // Generate and self-sign primary key.
        let primary : SecretPrimaryKey = Key4::import_secret_ed25519(
            &self.seed.seed(None), creation_time
        )?.into();

        let sig = new_primary_sbuilder(SignatureType::DirectKey, creation_time)?;

        let mut signer = primary.clone().into_keypair()
            .expect("key generated above has a secret");
        let sig = sig.sign_direct_key(&mut signer, primary.parts_as_public())?;

        let mut cert = Cert::try_from(vec![
            Packet::SecretKey({
                let mut primary = primary.clone();
                if let Some(ref password) = self.password {
                    primary.secret_mut().encrypt_in_place(password)?;
                }
                primary
            }),
            sig.into(),
        ])?;

        // Sign and add user ids
        for (i, uid) in self.userids.into_iter().enumerate() {
            let mut sig = new_primary_sbuilder(SignatureType::PositiveCertification, creation_time)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert.insert_packets(
                vec![Packet::from(uid), signature.into()])?;
        }

        // Create and sign subkeys
        let subkey_creation_time = self.subkey_creation_time.unwrap_or(creation_time);

        let subkeys : [(KeyFlags, &str); 3]  = [
            (KeyFlags::empty().set_signing(), "signature"),
            (KeyFlags::empty().set_transport_encryption().set_storage_encryption(), "encryption"),
            (KeyFlags::empty().set_authentication(), "authentication"),
        ];

        for (flags, path) in subkeys.iter() {

            // Derive subkey specific seed and turn into key
            let mut seed = self.subseed.seed(Some(path));

            let mut subkey : SecretSubKey = if flags.for_transport_encryption() || flags.for_storage_encryption() {

                // Curve25519 Paper, Sec. 3:
                // A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first
                // byte, clear bit 7 of the last byte, and set bit 6 of the last byte.
                seed[0] &= 0b1111_1000;
                seed[31] &= !0b1000_0000;
                seed[31] |= 0b0100_0000;

                Key4::import_secret_cv25519(&seed, None, None, subkey_creation_time)?.into()
            } else {
                Key4::import_secret_ed25519(&seed, subkey_creation_time)?.into()
            };

            seed.zeroize();

            // Sign subkey with primary
            let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(subkey_creation_time)?
                .set_key_flags(flags.clone())?
                .set_key_validity_period(self.subkey_validity)?;

            if flags.for_certification() || flags.for_signing() {
                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair()?;
                let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(subkey_creation_time)?
                    .set_hash_algo(HashAlgorithm::SHA512) 
                    .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.bind(&mut signer, &cert, builder)?;

            // Apply password protection
            if let Some(ref password) = self.password {
                subkey.secret_mut().encrypt_in_place(password)?;
            }

            // Add everything to certificate
            cert = cert.insert_packets(vec![Packet::SecretSubkey(subkey),
                                            signature.into()])?;
        }

        // Generate and sign revoaction certificate
        let revocation : Packet = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Unspecified")?
            .build(&mut signer, &cert, None)?.into();

        Ok((cert, revocation))
    }
}

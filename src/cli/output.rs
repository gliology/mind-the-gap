//! What leaves the gap: certificates, keys and revocations, to a file, a directory, stdout or
//! QR codes on the terminal, in the formats the outside world reads.

use crate::qr;
use crate::seed::Algorithm;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::{Result, anyhow, bail};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;

use der::Encode;

use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;

use spki::SubjectPublicKeyInfoOwned;

use zeroize::Zeroizing;

/// Which part of the identity's public material to publish
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Part {
    /// Everything: the identity and the chosen keys, with the PIV authorities
    #[default]
    All,
    /// The identity alone: the OpenPGP primary key with its user ids, the PIV root authority
    Identity,
    /// The chosen keys alone: the OpenPGP subkeys, the PIV slot certificates
    Keys,
    /// The PIV revocation lists as they stand, signed afresh: the root's, the one at `--to`
    /// with a new date or an empty one to publish before anything is revoked, and with
    /// `--intermediate` the issuing authority's
    Crl,
}

/// The format to publish in
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// PEM certificates and revocation lists for PIV, an ASCII-armored certificate for
    /// OpenPGP
    #[default]
    Text,
    /// DER certificates and revocation lists for PIV, one file each, a binary certificate
    /// for OpenPGP
    Binary,
    /// The authentication key as an OpenSSH public key line
    Ssh,
    /// A Web Key Directory for the OpenPGP certificate, one per email domain, as
    /// `gpg-wks-client --install-key` lays it out: `<domain>/hu/<hash>` and `<domain>/policy`
    Wkd,
}

/// One piece of material on its way out
pub(super) struct Artifact {
    /// The file name it takes in a directory, which may name subdirectories
    pub name: String,
    /// What a QR page or a log line calls it
    pub title: String,
    /// The bytes
    pub data: Zeroizing<Vec<u8>>,
    /// Whether it is a secret or a capability: written readable by the owner alone, and
    /// never to a terminal's main screen
    pub sensitive: bool,
    /// How it is split into QR codes, each a title and its bytes; one code of it all where
    /// empty
    pub pages: Vec<(String, Vec<u8>)>,
}

impl Artifact {
    pub(super) fn public(name: impl Into<String>, title: impl Into<String>, data: Vec<u8>) -> Self {
        Artifact {
            name: name.into(),
            title: title.into(),
            data: Zeroizing::new(data),
            sensitive: false,
            pages: Vec::new(),
        }
    }

    pub(super) fn sensitive(
        name: impl Into<String>,
        title: impl Into<String>,
        data: Zeroizing<Vec<u8>>,
    ) -> Self {
        Artifact {
            name: name.into(),
            title: title.into(),
            data,
            sensitive: true,
            pages: Vec::new(),
        }
    }
}

/// Write the artifacts where `--to` says: QR codes without it, stdout for `-`, a directory
/// that exists or ends in a slash, else one file
pub(super) fn emit(artifacts: &[Artifact], to: Option<&Path>) -> Result<()> {
    if artifacts.is_empty() {
        bail!("Nothing to write");
    }
    let sensitive = artifacts.iter().any(|artifact| artifact.sensitive);
    // The QR viewer waits for a key, which plumbing never presses
    if to.is_none() && super::plumbing::active() {
        bail!("Plumbing shows no QR codes; pass a file with --to");
    }
    let Some(to) = to else {
        let pages: Vec<_> = artifacts
            .iter()
            .flat_map(|artifact| {
                if artifact.pages.is_empty() {
                    vec![qr::QrPage { title: Some(artifact.title.clone()), data: &artifact.data }]
                } else {
                    artifact
                        .pages
                        .iter()
                        .map(|(title, data)| qr::QrPage { title: Some(title.clone()), data })
                        .collect()
                }
            })
            .collect();
        return qr::show_qr_pages(&pages, sensitive);
    };

    if to == Path::new("-") {
        // Plumbing keeps stdout for its reports, which material must not be mixed into
        if super::plumbing::active() {
            bail!("Plumbing keeps stdout for its reports; pass a file with --to");
        }
        // A layout of files, such as a Web Key Directory, has no single stream to be
        if artifacts.iter().any(|artifact| artifact.name.contains('/')) {
            bail!("A layout of several files needs a directory: pass --to <dir>/");
        }
        // A secret on stdout lands in a terminal's scrollback or a pipe's logs; it goes to a
        // file of the owner's, or to the alternate screen as QR codes
        if sensitive {
            bail!(
                "Secret material is not written to stdout; pass a file with --to, or omit it for QR codes"
            );
        }
        let mut stdout = io::stdout().lock();
        for artifact in artifacts {
            stdout.write_all(&artifact.data)?;
        }
        return Ok(());
    }

    let directory = is_directory(to);
    let nested = artifacts.iter().any(|artifact| artifact.name.contains('/'));
    if !directory && (artifacts.len() > 1 || nested) {
        bail!(
            "{} pieces to write, which need a directory: pass --to {}/",
            artifacts.len(),
            to.display()
        );
    }
    for artifact in artifacts {
        let path: PathBuf = if directory {
            to.join(&artifact.name)
        } else {
            to.to_path_buf()
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        log::info!("Writing {} to {}", artifact.title, path.display());
        if artifact.sensitive {
            write_sensitive(&path, &artifact.data)?;
        } else {
            fs::write(&path, &*artifact.data)?;
        }
    }
    Ok(())
}

/// Whether `--to` names a directory: one that exists, or a path that ends in a slash
pub(super) fn is_directory(to: &Path) -> bool {
    to.is_dir() || to.as_os_str().to_string_lossy().ends_with('/')
}

/// Write key material or another secret-bearing file, readable by its owner alone.
///
/// `fs::write` would create the file world-readable under the usual umask and follow a
/// symlink already sitting at the path. Creating with `O_EXCL` and mode 0600 does neither;
/// an existing regular file is removed first so exports stay overwritable. The permissions
/// are set at creation, so there is no window in which another user can open the file.
pub(super) fn write_sensitive(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;

    Ok(())
}

/// An SSH public key, the parts of its wire encoding
pub(super) enum SshKey {
    Ed25519([u8; 32]),
    /// A NIST curve by its SSH name (`nistp256`, `nistp384`) and its uncompressed point
    Ecdsa(&'static str, Vec<u8>),
    /// The public exponent and the modulus, big-endian
    Rsa {
        e: Vec<u8>,
        n: Vec<u8>,
    },
}

impl SshKey {
    /// The key as an OpenSSH `authorized_keys` line with `comment`
    pub(super) fn line(&self, comment: &str) -> String {
        let mut blob = Vec::new();
        let kind = match self {
            SshKey::Ed25519(key) => {
                put_string(&mut blob, b"ssh-ed25519");
                put_string(&mut blob, key);
                "ssh-ed25519".to_string()
            }
            SshKey::Ecdsa(curve, point) => {
                let kind = format!("ecdsa-sha2-{curve}");
                put_string(&mut blob, kind.as_bytes());
                put_string(&mut blob, curve.as_bytes());
                put_string(&mut blob, point);
                kind
            }
            SshKey::Rsa { e, n } => {
                put_string(&mut blob, b"ssh-rsa");
                put_mpint(&mut blob, e);
                put_mpint(&mut blob, n);
                "ssh-rsa".to_string()
            }
        };
        format!("{kind} {} {comment}\n", BASE64_STANDARD.encode(blob))
    }
}

impl SshKey {
    /// The SSH key of a PIV certificate's subject public key
    pub(super) fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<SshKey> {
        let raw = spki.subject_public_key.raw_bytes();
        match crate::piv::algorithm_of(spki) {
            Some(Algorithm::Curve25519) => {
                let key = raw
                    .try_into()
                    .map_err(|_| anyhow!("Ed25519 key of odd length"))?;
                return Ok(SshKey::Ed25519(key));
            }
            Some(Algorithm::P256) => return Ok(SshKey::Ecdsa("nistp256", raw.to_vec())),
            Some(Algorithm::P384) => return Ok(SshKey::Ecdsa("nistp384", raw.to_vec())),
            _ => {}
        }
        let key = rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?)
            .map_err(|err| anyhow!("Not a key SSH takes: {err}"))?;
        Ok(SshKey::Rsa {
            e: key.e().to_be_bytes().to_vec(),
            n: key.n().to_be_bytes().to_vec(),
        })
    }
}

/// An RFC 4251 string: its length, then its bytes
fn put_string(blob: &mut Vec<u8>, bytes: &[u8]) {
    blob.extend_from_slice(&u32::try_from(bytes.len()).expect("short").to_be_bytes());
    blob.extend_from_slice(bytes);
}

/// An RFC 4251 mpint: a positive number without leading zero bytes, with one added where
/// the top bit would read as a sign
fn put_mpint(blob: &mut Vec<u8>, bytes: &[u8]) {
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    let mut value = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend(trimmed);
    put_string(blob, &value);
}

/// The Web Key Directory name of a mailbox's local part: SHA-1 of its lower case, in z-base-32
pub(super) fn wkd_hash(local: &str) -> String {
    use sha1::Digest;
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let digest = sha1::Sha1::digest(local.to_lowercase().as_bytes());
    let mut out = String::with_capacity(32);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in digest.iter() {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// The local part and domain of an address
pub(super) fn split_address(address: &str) -> Result<(&str, &str)> {
    address
        .rsplit_once('@')
        .filter(|(local, domain)| !local.is_empty() && !domain.is_empty())
        .ok_or_else(|| anyhow!("'{address}' is no mailbox a Web Key Directory can hold"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of the WKD draft, section 3.1: Joe.Doe@Example.ORG
    #[test]
    fn wkd_hash_matches_the_draft() {
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }

    #[test]
    fn mpints_carry_their_sign_byte() {
        let mut blob = Vec::new();
        put_mpint(&mut blob, &[0x00, 0x80, 0x01]);
        assert_eq!(blob, [0, 0, 0, 3, 0x00, 0x80, 0x01]);
        let mut blob = Vec::new();
        put_mpint(&mut blob, &[0x01, 0x00, 0x01]);
        assert_eq!(blob, [0, 0, 0, 3, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn ed25519_lines_have_the_openssh_shape() {
        let line = SshKey::Ed25519([7; 32]).line("alice@laptop");
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"), "{line}");
        assert!(line.ends_with(" alice@laptop\n"));
    }
}

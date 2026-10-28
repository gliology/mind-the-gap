//! The verbs that only write files: trust, revoke, publish and ungap.

use super::{Context, pgp_builder, piv_builder, slot_app};
use crate::cli::options::{
    App, AppArgs, DryRunArgs, IdentityArgs, KeyArgs, OutputArgs, PathArgs, PinArgs,
};
use crate::cli::output::{self, Artifact, Format, Part, SshKey};
use crate::pgp;
use crate::piv;
use crate::revocation::RevocationKind;
use crate::role::KeyRole;

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};

use der::{Encode, EncodePem};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::Curve;

use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

pub(super) fn trust(
    context: &Context,
    input: &Path,
    level: pgp::VerificationKind,
    output: &OutputArgs,
) -> Result<()> {
    // Read before anything is derived, and here rather than by sequoia, whose error carries
    // the I/O error twice
    let bytes =
        std::fs::read(input).map_err(|err| anyhow!("Cannot read {}: {err}", input.display()))?;
    let other = Cert::from_bytes(&bytes)
        .map_err(|err| anyhow!("{} holds no OpenPGP certificate: {err}", input.display()))?;
    let opts = context.opts(App::Pgp);
    // A certification is the primary key's over the other's user ids, and carries none of
    // the subkeys a validity bounds, so a validity among the defaults has no day to count from
    // here and nothing to say
    let identity = IdentityArgs { validity: None, ..opts.identity.clone() };
    let builder = pgp_builder(context, &opts.derive, &PathArgs::default(), &identity, None)?
        .with_keys(&[KeyRole::Signature])?;
    log::info!("Certifying the certificate in {}", input.display());
    log::info!("Certifying certificate with id: {}", other);
    let cert = builder.trust(other, level)?;
    let armored = cert.armored().to_vec()?;
    output::emit(
        &[Artifact::public(
            "pgp-trust.asc",
            "certified certificate",
            armored,
        )],
        output.to.as_deref(),
    )
}

/// What a revocation covers and why, as `revoke` is asked for it
pub(super) struct Revocation<'a> {
    pub kind: RevocationKind,
    /// The reason code, as OpenPGP numbers it
    pub code: u8,
    /// The reason in words, which an OpenPGP revocation carries
    pub reason: &'a str,
}

pub(super) fn revoke(
    context: &Context,
    app: &AppArgs,
    revocation: &Revocation<'_>,
    keys: &KeyArgs,
    output: &OutputArgs,
    write: &DryRunArgs,
) -> Result<()> {
    let Revocation { kind, code, reason } = *revocation;
    let (apps, _) = slot_app(app, keys)?.apps();
    let mut artifacts = Vec::new();
    for app in apps {
        let opts = context.opts(app);
        let (derive, path, identity, keys) = (&opts.derive, &opts.path, &opts.identity, &opts.keys);
        match app {
            App::Pgp => {
                let builder = pgp_builder(context, derive, path, identity, Some(keys))?;
                let raw = builder.revoke(kind, code, reason)?;
                // Armored the gnupg way: a revocation travels as a public key block
                let mut armored = Vec::new();
                {
                    use std::io::Write;
                    let mut writer = sequoia_openpgp::armor::Writer::new(
                        &mut armored,
                        sequoia_openpgp::armor::Kind::PublicKey,
                    )?;
                    writer.write_all(&raw)?;
                    writer.finalize()?;
                }
                artifacts.push(Artifact::sensitive(
                    "pgp-revocation.asc",
                    "OpenPGP revocation",
                    Zeroizing::new(armored),
                ));
            }
            App::Piv => {
                let builder = piv_builder(context, derive, path, identity, Some(keys), None)?;
                let suffix = builder.revocation_list_suffix();
                let to = output.to.as_deref();
                let previous = previous_revocation_list(to, &suffix)?;
                let crl = builder.revocation_list(kind, code, previous.list.as_deref())?;
                // Public, unlike an OpenPGP revocation made ahead of time: a list is signed
                // when the keys are revoked, to be published right away. PEM, which is what
                // the next run reads back as the state
                let list = Artifact::public(
                    list_file(&suffix, Format::Text),
                    "PIV revocation list",
                    crl.into_bytes(),
                );
                refuse_replacing_lists(std::slice::from_ref(&list), to, &previous.read)?;
                artifacts.push(list);
            }
        }
    }
    if write.dry_run {
        for artifact in &artifacts {
            println!("Would write the {} ({} bytes)", artifact.title, artifact.data.len());
        }
        return Ok(());
    }
    output::emit(&artifacts, output.to.as_deref())
}

pub(super) fn publish(
    context: &Context,
    app: &AppArgs,
    part: Part,
    format: Format,
    keys: &KeyArgs,
    output: &OutputArgs,
) -> Result<()> {
    let (apps, named) = slot_app(app, keys)?.apps();
    let mut artifacts = Vec::new();
    for app in apps {
        let opts = context.opts(app);
        let (derive, path, identity, keys) = (&opts.derive, &opts.path, &opts.identity, &opts.keys);
        match app {
            App::Piv => {
                if format == Format::Wkd {
                    if named {
                        bail!("A Web Key Directory holds OpenPGP certificates only");
                    }
                    continue;
                }
                let builder = piv_builder(context, derive, path, identity, Some(keys), None)?;
                artifacts.extend(publish_piv(
                    &builder,
                    part,
                    format,
                    identity,
                    output.to.as_deref(),
                )?);
            }
            App::Pgp => {
                if part == Part::Crl && !named {
                    continue;
                }
                let builder = pgp_builder(context, derive, path, identity, Some(keys))?;
                artifacts.extend(publish_pgp(&builder, part, format, identity)?);
            }
        }
    }
    output::emit(&artifacts, output.to.as_deref())
}

/// The file a PIV revocation list with `suffix` is written to in a directory, in the form
/// `format` chooses: `piv-revocation-p256.crl.pem` as text, `piv-revocation-p256.crl` as
/// binary, ready to serve at the URL that ends in the same suffix
///
/// Fixed whatever `--crl-url` says, so that the previous list is found without it.
fn list_file(suffix: &str, format: Format) -> String {
    match format {
        Format::Binary => format!("piv-revocation{suffix}.crl"),
        _ => format!("piv-revocation{suffix}.crl.pem"),
    }
}

/// A revocation list, PEM as it is signed, in the form `format` chooses: the PEM, or the DER
/// it encodes, which RFC 5280 4.2.1.13 has an HTTP distribution point serve
fn list_form(pem: String, format: Format) -> Result<Vec<u8>> {
    Ok(match format {
        Format::Binary => {
            der::pem::decode_vec(pem.as_bytes())
                .map_err(|err| anyhow!("A revocation list does not decode: {err}"))?
                .1
        }
        _ => pem.into_bytes(),
    })
}

/// The revocation list published so far, and the list files it was judged from
#[derive(Default)]
struct Previous {
    /// The list, in PEM or DER
    list: Option<Vec<u8>>,
    /// Every list file read to find it, which a new list may therefore replace
    read: Vec<PathBuf>,
}

/// The revocation list published so far, read from where the new one goes: the file `--to`
/// names, in PEM or DER, or in the directory it names the root's list with `suffix`, as PEM,
/// as DER, or the newer of the two where both are
///
/// The published list is the only record of what was revoked before, so writing over it
/// keeps every entry it holds; two copies that disagree on it are refused rather than one
/// of them chosen.
fn previous_revocation_list(to: Option<&Path>, suffix: &str) -> Result<Previous> {
    let Some(to) = to.filter(|to| *to != Path::new("-")) else {
        return Ok(Previous::default());
    };
    let files = match output::is_directory(to) {
        true => [Format::Text, Format::Binary]
            .map(|format| to.join(list_file(suffix, format)))
            .to_vec(),
        false => vec![to.to_path_buf()],
    };
    let mut found = Vec::new();
    for file in files {
        match std::fs::read(&file) {
            Ok(bytes) => found.push((file, bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => bail!("Cannot read {}: {err}", file.display()),
        }
    }
    let read: Vec<PathBuf> = found.iter().map(|(file, _)| file.clone()).collect();
    let (file, bytes) = match found.len() {
        0 => return Ok(Previous::default()),
        1 => found.remove(0),
        _ => newer_list(found)?,
    };
    log::info!("Keeping the revocations of {}", file.display());
    Ok(Previous { list: Some(bytes), read })
}

/// The newer of two copies of the root's list, the PEM and the DER: the one with the greater
/// number, which has to revoke everything the older revokes; two lists of one number have
/// to be the same list
fn newer_list(mut copies: Vec<(PathBuf, Vec<u8>)>) -> Result<(PathBuf, Vec<u8>)> {
    let read = |(file, bytes): &(PathBuf, Vec<u8>)| {
        piv::read_revocation_list(bytes).map_err(|err| anyhow!("{}: {err:#}", file.display()))
    };
    let lists = copies.iter().map(read).collect::<Result<Vec<_>>>()?;
    let [first, second] = lists.as_slice() else {
        bail!("Not two copies of one list");
    };
    let name = |index: usize| copies[index].0.display().to_string();
    if first.number == second.number && first.der != second.der {
        bail!(
            "{} and {} are two different revocation lists of one number; keep the one that              was published and move the other away",
            name(0),
            name(1)
        );
    }
    let (newer, older) = match second.number > first.number {
        true => (1, 0),
        false => (0, 1),
    };
    let lost = lists[older]
        .revoked
        .iter()
        .any(|serial| !lists[newer].revoked.contains(serial));
    if lost {
        bail!(
            "{} revokes certificates that {}, the newer list, does not; keep the one that              holds every revocation and move the other away",
            name(older),
            name(newer)
        );
    }
    Ok(copies.swap_remove(newer))
}

/// Refuse to replace a list file with `lists` unless it was read for the previous list, or
/// holds the very bytes that would replace it: no list file is ever replaced by a list that
/// does not carry its revocations
fn refuse_replacing_lists(lists: &[Artifact], to: Option<&Path>, read: &[PathBuf]) -> Result<()> {
    let Some(to) = to.filter(|to| *to != Path::new("-")) else {
        return Ok(());
    };
    for list in lists {
        let file = match output::is_directory(to) {
            true => to.join(&list.name),
            false => to.to_path_buf(),
        };
        if read.contains(&file) {
            continue;
        }
        match std::fs::read(&file) {
            Ok(bytes) if bytes == *list.data => {}
            Ok(_) => bail!(
                "{} holds another revocation list than the one read for this run; move it                  away, or name it with --to to keep its revocations",
                file.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => bail!("Cannot read {}: {err}", file.display()),
        }
    }
    Ok(())
}

/// The PIV chain's public material in one format
fn publish_piv(
    builder: &piv::SeededSmartcard,
    part: Part,
    format: Format,
    identity: &IdentityArgs,
    to: Option<&Path>,
) -> Result<Vec<Artifact>> {
    let kind = match part {
        Part::All => piv::CertificateKind::Chain,
        Part::Identity => piv::CertificateKind::Root,
        Part::Keys => piv::CertificateKind::Leaves,
        Part::Crl => {
            if !matches!(format, Format::Text | Format::Binary) {
                bail!(
                    "A revocation list is published as PEM, --format text, or as DER, --format \
                     binary"
                );
            }
            // QR codes are read as text, so they carry the PEM whatever the format
            let format = match to {
                Some(_) => format,
                None => Format::Text,
            };
            let suffix = builder.revocation_list_suffix();
            let previous = previous_revocation_list(to, &suffix)?;
            let crl = builder.current_revocation_list(previous.list.as_deref())?;
            let mut lists = vec![Artifact::public(
                list_file(&suffix, format),
                "PIV revocation list",
                list_form(crl, format)?,
            )];
            // An issuing authority's own list, which its certificates name; empty for good,
            // so publishing it once is enough
            if let Some((suffix, issuing)) = builder.issuing_revocation_list()? {
                lists.push(Artifact::public(
                    list_file(&suffix, format),
                    "PIV issuing authority's revocation list",
                    list_form(issuing, format)?,
                ));
            }
            refuse_replacing_lists(&lists, to, &previous.read)?;
            return Ok(lists);
        }
    };
    // SSH takes the authentication key whatever the part, as on OpenPGP, so its leaf is
    // made even where the part names the authorities alone
    let chain = builder.certify(match format {
        Format::Ssh => piv::CertificateKind::Leaves,
        _ => kind,
    })?;
    for cert in chain.select(kind)? {
        log::info!("{}: SHA-256 {:x}", chain.name_of(cert), Sha256::digest(cert.to_der()?));
    }
    Ok(match format {
        Format::Text => {
            let name = match part {
                Part::All => "piv-chain.pem",
                Part::Identity => "piv-root.pem",
                Part::Keys | Part::Crl => "piv-certificates.pem",
            };
            // One QR code per certificate, which is what a code holds, and one file for all
            let mut pem = Vec::new();
            let mut pages = Vec::new();
            for cert in chain.select(kind)? {
                let text = cert.to_pem(der::pem::LineEnding::default())?.into_bytes();
                pem.extend_from_slice(&text);
                pages.push((chain.name_of(cert), text));
            }
            let mut artifact = Artifact::public(name, "PIV certificates", pem);
            artifact.pages = pages;
            vec![artifact]
        }
        Format::Binary => chain
            .select(kind)?
            .into_iter()
            .map(|cert| {
                let title = chain.name_of(cert);
                Ok(Artifact::public(
                    format!("piv-{}.der", title.replace(' ', "-")),
                    title,
                    cert.to_der()?,
                ))
            })
            .collect::<Result<_>>()?,
        Format::Ssh => {
            let slot = yubikey::piv::SlotId::Authentication;
            let cert = chain
                .leaves
                .iter()
                .find(|(s, _)| *s == slot)
                .map(|(_, cert)| cert)
                .ok_or_else(|| anyhow!("SSH takes the authentication key; choose it with --key"))?;
            let key = SshKey::from_spki(cert.tbs_certificate().subject_public_key_info())?;
            let comment = identity
                .emails
                .first()
                .cloned()
                .unwrap_or_else(|| "piv".into());
            vec![Artifact::public(
                "piv-authentication.pub",
                "PIV authentication key for SSH",
                key.line(&comment).into_bytes(),
            )]
        }
        Format::Wkd => bail!("A Web Key Directory holds OpenPGP certificates only"),
    })
}

/// The OpenPGP certificate's public material in one format
fn publish_pgp(
    builder: &pgp::SeededSmartcard,
    part: Part,
    format: Format,
    identity: &IdentityArgs,
) -> Result<Vec<Artifact>> {
    let kind = match part {
        Part::All => pgp::CertificateKind::Full,
        Part::Identity => pgp::CertificateKind::Uids,
        Part::Keys => pgp::CertificateKind::Subkeys,
        Part::Crl => bail!("A revocation list is PIV's; OpenPGP revokes with signatures"),
    };
    // SSH takes the authentication key whatever the part, as on PIV, and finds it valid only
    // through the whole certificate: a subkey binding is checked against its primary
    let cert = builder.certify(match format {
        Format::Ssh => pgp::CertificateKind::Full,
        _ => kind,
    })?;
    log::info!("OpenPGP certificate {}", cert.fingerprint());
    Ok(match format {
        Format::Text => vec![Artifact::public(
            "pgp.asc",
            "OpenPGP certificate",
            cert.armored().to_vec()?,
        )],
        Format::Binary => vec![Artifact::public(
            "pgp.gpg",
            "OpenPGP certificate",
            cert.to_vec()?,
        )],
        Format::Ssh => {
            let policy = sequoia_openpgp::policy::StandardPolicy::new();
            let valid = cert.with_policy(&policy, Some(builder.subkey_creation_time()))?;
            let key = valid
                .keys()
                .subkeys()
                .find(|key| {
                    key.key_flags()
                        .is_some_and(|flags| flags.for_authentication())
                })
                .ok_or_else(|| anyhow!("SSH takes the authentication key; choose it with --key"))?;
            let ssh = match key.key().mpis() {
                mpi::PublicKey::EdDSA { curve: Curve::Ed25519, q } => {
                    let point = q.value();
                    SshKey::Ed25519(
                        point
                            .get(1..)
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or_else(|| anyhow!("Ed25519 key of odd length"))?,
                    )
                }
                mpi::PublicKey::ECDSA { curve: Curve::NistP256, q } => {
                    SshKey::Ecdsa("nistp256", q.value().to_vec())
                }
                mpi::PublicKey::RSA { e, n } => {
                    SshKey::Rsa { e: e.value().to_vec(), n: n.value().to_vec() }
                }
                other => bail!("No SSH form for {:?}", other.algo()),
            };
            let comment = identity
                .emails
                .first()
                .cloned()
                .unwrap_or_else(|| "openpgp".into());
            vec![Artifact::public(
                "pgp-authentication.pub",
                "OpenPGP authentication key for SSH",
                ssh.line(&comment).into_bytes(),
            )]
        }
        Format::Wkd => {
            let binary = cert.to_vec()?;
            let mut artifacts = Vec::new();
            let mut domains = Vec::new();
            for address in &identity.emails {
                let (local, domain) = output::split_address(address)?;
                let domain = domain.to_lowercase();
                artifacts.push(Artifact::public(
                    format!("{domain}/hu/{}", output::wkd_hash(local)),
                    format!("Web Key Directory entry of {address}"),
                    binary.clone(),
                ));
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }
            for domain in domains {
                artifacts.push(Artifact::public(
                    format!("{domain}/policy"),
                    format!("Web Key Directory policy of {domain}"),
                    Vec::new(),
                ));
            }
            artifacts
        }
    })
}

pub(super) fn ungap(
    context: &Context,
    app: &AppArgs,
    keys: &KeyArgs,
    pin: &PinArgs,
    output: &OutputArgs,
) -> Result<()> {
    if pin.pin.is_none() {
        log::warn!(
            "Writing secret keys UNENCRYPTED, pass --pin to protect them; a file is readable only \
             by you"
        );
    }
    let (apps, _) = slot_app(app, keys)?.apps();
    let mut artifacts = Vec::new();
    for app in apps {
        let opts = context.opts(app);
        let (derive, path, identity, keys) = (&opts.derive, &opts.path, &opts.identity, &opts.keys);
        match app {
            App::Pgp => {
                let builder = pgp_builder(context, derive, path, identity, Some(keys))?;
                let cert = builder.export(pin.pin.as_deref().map(|p| p.as_str()))?;
                log::info!("OpenPGP secret keys of {}", cert.fingerprint());
                let tsk = Zeroizing::new(cert.as_tsk().armored().to_vec()?);
                artifacts.push(Artifact::sensitive("pgp-secret.asc", "OpenPGP secret keys", tsk));
            }
            App::Piv => {
                let builder = piv_builder(context, derive, path, identity, Some(keys), None)?;
                for (role, key, cert) in
                    builder.secret_keys(pin.pin.as_deref().map(|p| p.as_str()))?
                {
                    artifacts.push(Artifact::sensitive(
                        format!("piv-{role}.key.pem"),
                        format!("PIV {role} key"),
                        Zeroizing::new(key.as_bytes().to_vec()),
                    ));
                    artifacts.push(Artifact::public(
                        format!("piv-{role}.pem"),
                        format!("PIV {role} certificate"),
                        cert.into_bytes(),
                    ));
                }
            }
        }
    }
    output::emit(&artifacts, output.to.as_deref())
}

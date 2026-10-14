//! The frozen `mtg1` vectors: every algorithm, both subkey ids, pinned by digest.

use crate::{SEED_A, digest};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard};
use mind_the_gap::seed::Algorithm;

use x509_cert::der::Encode;

use std::time::{Duration, SystemTime};

use yubikey::piv::SlotId;

/// The current `mtg1` scheme is frozen.
///
/// The 1.x versioning promise is that any release re-derives the very same keys -- and,
/// because `check` compares certificates byte for byte, the very same certificates -- from
/// a seed. These vectors are that promise in executable form: a change to a label constant,
/// a prefix, the argon2 parameters, the certificate profile or its encoding would pass
/// every other test while making `check` fail against every provisioned card, and this
/// test is what fails instead. The SPKI digests pin the derived *keys*, the certificate
/// digests pin the *encoding* around them, so a failure says which of the two moved. Do
/// not update these values within a major version; a derivation change ships as `mtg2`
/// behind a new major.
#[test]
fn current_scheme_is_frozen() {
    assert_current_scheme_frozen(
        Algorithm::P256,
        [
            (
                None,
                [
                    (
                        "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
                        "861b8296ec2ebe1cb370b18db1e0ade1bc55b4eeb7f117aee85e7260be782c08",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "c55a30e8647a8912b07ba6f76d6abb6fcb4efad9dfaa0f7d691320d64c11d6ea",
                        "15c3cd1d34a5be9499f195b6f0a6daa0455b28f15f419335e0bc67a0a8a07c0f",
                        "CN=Alice",
                    ),
                    (
                        "ec7e41c73cd76ec8b7283332a0202a775dbf616096d05d18732ff0a211dfc0b1",
                        "f97b5ee9339aa13a79ff5fe962261c0e6fcff9760d5c96a0043410eb554c8de6",
                        "CN=Alice",
                    ),
                    (
                        "db4389e005f73edf3cfa500c81c9e28683c4beae122192c2ee21ebaedf2fdd00",
                        "6e764fe53fc1c906afc7cf2c215d9c07355fd7d84bdf6600ce91d993f54e38e4",
                        "CN=Alice",
                    ),
                    (
                        "93d0d7b044eb08ad6f62a20668e1f17b0838dc918c472a9cd7020d223f3970c3",
                        "5c2d5504506e5eafec3a6e1d86d6623ccbaca96f6e1d51ab3b89d3204d0c986b",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
                        "861b8296ec2ebe1cb370b18db1e0ade1bc55b4eeb7f117aee85e7260be782c08",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "5f22bc03848271a3b6e524b9e327eaceef0ae31b379ffa4bb3511bb3f189eda7",
                        "d004f480344e9ea8d889cffd004158c1027ba2def6d116a3c08fa6a291d594d1",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "555ad0a77ef68e4eb556d49551d0a948685077c64956d61fc5bda926c7a751ab",
                        "2765c5a08e03db99b74fb7b82fbefbd564e54083bf669f36529e254c9b2cdf37",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "e274fd327152f629470240f968efc8a42fe133a1b6816a920a03aedf422e0cd3",
                        "fbd4b7ffc16fb0622bdad2d2478976148346d3655cdadcb26ee5c9514b3abe2a",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "d8498196b0d80ec125cc48549465624b0eb9d15f2f35c9d98cedbf434a124036",
                        "36f92866b4769436a85e775eeccf50c7f3b187756c92aac6dc75771e2614bd5e",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The Curve25519 half of the same promise: `--algorithm curve25519` is part of `mtg1` and
/// frozen with it, Ed25519 signatures included (they are deterministic, so the DER pins).
#[test]
fn current_scheme_is_frozen_on_curve25519() {
    assert_current_scheme_frozen(
        Algorithm::Curve25519,
        [
            (
                None,
                [
                    (
                        "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
                        "614b41693fc5d41a9241b3f900737cb38b46aa82d065301cc50e0fad2a1a2618",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "39d78d631f03041f9da16a4588cbfbea092404f25cdadae8895c807307e9cc5e",
                        "fcfe945cff1a90da139c9eec97320eb336630495526a11e94600180e33a0b784",
                        "CN=Alice",
                    ),
                    (
                        "d303bcbb992f935e68ba7ea07f8a846410fe13e58169550c3dae3f61c0209f95",
                        "40fa233d768183c48704c0efe1da9120f6f9a87cecd29edb7ad36b7cbde18c85",
                        "CN=Alice",
                    ),
                    (
                        "d32cf40d03e67f4de0ea55541e673b0c64bb3d1861ebc039735e7684ac5e4791",
                        "5d807a2cc1d5b96848925078c051d0c4a6c10345c1ccb6bf56d1942a3e4a7b85",
                        "CN=Alice",
                    ),
                    (
                        "374b218d39ed4756bd703891fc765fbb75b97e3f3e5a3b110423547a622d1c59",
                        "57f022cbbb2c3c69107fecfbd13b1028fe49fa9c42fcd8412c29c592e6f4c810",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
                        "614b41693fc5d41a9241b3f900737cb38b46aa82d065301cc50e0fad2a1a2618",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "b29e70e6954f77a46ddbfe461e3b873dd8fdd8df5d93b3b556ad3984dcf72fb4",
                        "e68f98eb34a215c78c965ea92aaee4a6952626aca990bf2fdf3e5fcc856308e1",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "8cfc7e206526f869ef0a551255bcc3267f3be9ff9a6e0900c0a0da6e132568be",
                        "2d70219c85a1a174556eee0cfd9c073cfec06987fb03a499a97fe355c6ac0ca6",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "db0dbbf7d26cdbddc439020ba9e717e24459204e53e7c1597935cb9a10b747a4",
                        "bdd7bdcb938dff7fb1abdbe6f37fb04996775bae0892684e2754082909846fab",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "630220975eccb9267282b921887a9166958e837506053a6a2c7398a59b0a4c5e",
                        "82b30e1aa6300c20d27576494ef2e4dd32c844f9851674077392fb835e504a4a",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The P-384 third of the same promise: `--algorithm p384` derives under its own labels and the
/// documented 48-byte construction, and is frozen with the rest of `mtg1`. ECDSA signatures
/// use RFC 6979 nonces, so the certificate DER pins as well.
#[test]
fn current_scheme_is_frozen_on_p384() {
    assert_current_scheme_frozen(
        Algorithm::P384,
        [
            (
                None,
                [
                    (
                        "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
                        "b5cc125940a7bd667bfc3fe9035a84ededce92f6918490416183aa869c78a04a",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "2b3fd7575f7799de806830f0452b473647b42eab745b117c451460e9e0f56302",
                        "8ebbafc08a686ba6822ef7892a76bb44915c82f2f233853e7e81da9db6de583b",
                        "CN=Alice",
                    ),
                    (
                        "bd7177425a6d6234a9b1872b3cafd4d70e399481bab163e50d2ddf967e6ae175",
                        "9f6b68ef3662a2be96ea69b6973f083ff0ddbe948a51e7e1351077850d814fcc",
                        "CN=Alice",
                    ),
                    (
                        "9430d9eda51e0e30bd85972ce5d6584ef35bb48751a3d631fd514e1b0067ee92",
                        "f9264506cdc9cf78b1dbd707e303e307035141eb49c910d5e7b5322b5c193f96",
                        "CN=Alice",
                    ),
                    (
                        "77f5cf472efe6df02b9ff7a0512488575bd384934d41b1702e8adbc71c733d40",
                        "3b57d967b44279224150515024408d298930d8934eda117b3779e794992fa8a7",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
                        "b5cc125940a7bd667bfc3fe9035a84ededce92f6918490416183aa869c78a04a",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "aaec61040c30ae1e3fdb62590d4ebde9b3f51856aa183db8e6198a9e079e2251",
                        "3d18d4459c45ec40abc62990509ac1cc2f07d67d08607cd40d9fa4207ae6f231",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "224679124975033922323ddb5121c35da9cf86fc0e068bfe7c7f95476769b712",
                        "014312b4000489bed5bbee0411134ea978489330d9d1d99b3c87c166fa56b030",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "ab47865be4c685cb325786744390d17a36c2cdc910c2cc5b3046b72ec29bba6c",
                        "e0487b0eeac20e62b53e367611c38a79b2f0e89bbd7c6479aa6b3eb4ab99313e",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "dd2ae81a0cb116f6b0ca40756d99d0b13ff8a90bae404d2b7d840f7fb19db7d6",
                        "73eb90f051f4d81e19873642a1f80ca7da18f5d868e681ef8c327a59ac4a9906",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The RSA-2048 half of the same promise: `--algorithm rsa2048` is part of `mtg1` and
/// frozen with it; PKCS#1 v1.5 signatures are deterministic, so the DER pins.
#[test]
fn current_scheme_is_frozen_on_rsa2048() {
    assert_current_scheme_frozen(
        Algorithm::Rsa2048,
        [
            (
                None,
                [
                    (
                        "f8f92dc72cc7216fe612da655ec461bda33e6f33bddfbbcc668b40c29c867653",
                        "e8437057bb53f127398f9a214d050d85cf3671fb7a4b3761e2168a770c13cf72",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "fa82004283512aa88deca524bfb31294fc740ec805f04548c0a6945bc60fa83c",
                        "e199da4d759d6bfb1f4fcad381fb6e31f30264ca977b82b2bdbebbd2920aee90",
                        "CN=Alice",
                    ),
                    (
                        "7b576a6b37ffd8a8db0035ce1d5032179f9d270118bfb5b49742cd74a5c77ed1",
                        "eada816127afb7d6e42197ac70dd36283ce10190555cd1087d359290849e2079",
                        "CN=Alice",
                    ),
                    (
                        "8038d7304881dea2f3d9056a3d8ef04b75b32c591199644d2e938ea9fa310512",
                        "864adc4bec8815d5e5559f7644884f591769aba7678bc76faa870b790e868a1a",
                        "CN=Alice",
                    ),
                    (
                        "8d62743df0f626d811d81577e34e2725a600c5bea97f6cb65445dca8a6ccdde2",
                        "3c5c2bce6925d789de855f276395a9748618ea4e732029aa0d586ae679d37ac5",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "f8f92dc72cc7216fe612da655ec461bda33e6f33bddfbbcc668b40c29c867653",
                        "e8437057bb53f127398f9a214d050d85cf3671fb7a4b3761e2168a770c13cf72",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "ac20c26aba31ca03944fde6dc35821efa76ea55214657f42a90f376281fbd11b",
                        "ffedba909488e7a785e4c48507ca5cfa75c82e3f15011f512f6f80f61203c297",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "169a6af8a2f731f13496aeac4a8b4fb28b8733fa027725ac6454d524d74bd4bd",
                        "40ebc3db2ad9fed817a834993eeb7357115f95c4cab2cd1aaa5a2538f9c9cc5a",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "c5a56600e39c0c982cf86350c566e18866bb20477353b48357d380ca67da125d",
                        "c55499eef3155d1641a4cbdc1acc161e61c9c0c3f1a42308bce3447ea9126557",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "830e144a0a672398841369d897b4fd52baeea8e0385343f98ec998b0bfbd562a",
                        "7e327ddd3cdd8dadbd0c8a38e41ec1d6214954d4ea4fe28c2d4e169e601b12c8",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The RSA-3072 half of the same promise: `--algorithm rsa3072` is part of `mtg1` and
/// frozen with it; PKCS#1 v1.5 signatures are deterministic, so the DER pins.
#[test]
fn current_scheme_is_frozen_on_rsa3072() {
    assert_current_scheme_frozen(
        Algorithm::Rsa3072,
        [
            (
                None,
                [
                    (
                        "786bfbf1cfa1f0914ac65c021c37bbf445b7cde9e4a5f7b8bdd2cb695103ce84",
                        "1cf3729b088afab970d2ad0438ec0ef49f443a299f33d6bb6bc9fcbd0c037d2c",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "c1f0c998660faacf1ed69a931109319d7f3ed8c722e5574d2f06594fc23d0b8b",
                        "40a9aed8ab1138da05b490bfb7e2257c9b4ed765f65b0fe6dbe658bcbc22ff2c",
                        "CN=Alice",
                    ),
                    (
                        "a082ca0830cad754c5568d4efc68fe56bc1226256e568f9135d9cca99ed69794",
                        "49eb127f76606c06fb58cd3ba046c6d9ba1681b083eca826e1f9a2755f379998",
                        "CN=Alice",
                    ),
                    (
                        "b7254f486cbc64a923bf35c807512d8a82397502f1bdf62d08dc3f608004b00a",
                        "51382f1f5432b3169968d330a51f960cebdcf407148ecb032f11b351c8e154eb",
                        "CN=Alice",
                    ),
                    (
                        "942df91e7773589a5984ccc4a9f4752757c7451ce0572da939cf3bb8e83aff28",
                        "7214127db7c2e4d844188b10c3d69f62959b35b1180b9fdfc9eab892ad2f390d",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "786bfbf1cfa1f0914ac65c021c37bbf445b7cde9e4a5f7b8bdd2cb695103ce84",
                        "1cf3729b088afab970d2ad0438ec0ef49f443a299f33d6bb6bc9fcbd0c037d2c",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "52afa0e5a9ea7e9b38350d14b66b8a70308fd391c4f79e8de7e0f46628dcf547",
                        "f7a73e449bf6668dbf8d7844b861bd7eea938f2f17f70ad548a6a96e81d49c02",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "a19ca5869280975fd143704e1e9df7fd088860e2f42d07d07d56af1754e4a313",
                        "1fdd1355c4ad2c7f42ca8cca9e1b889f5e77fad72c54a9c804f474621d629a97",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "63e9944c269d5e57dedecca133378f1bc0207451d77cd3fc4578c5091ae8120a",
                        "7f1361a3e4bfd83bf5c5ecfd3885281d2e4d48c84aef3b73156377171f9750a8",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "e1e51e6ab76fbc1d6f37fad3485e6875afd17f6c0a9792dcb045dc48a1a04349",
                        "d709ba609d85c1266c191c9cdd8093239a650bb0d4c33d81140b7e3bd7df9e4c",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The RSA-4096 half of the same promise: `--algorithm rsa4096` is part of `mtg1` and
/// frozen with it; PKCS#1 v1.5 signatures are deterministic, so the DER pins.
#[test]
fn current_scheme_is_frozen_on_rsa4096() {
    assert_current_scheme_frozen(
        Algorithm::Rsa4096,
        [
            (
                None,
                [
                    (
                        "5ca3d47b84ae42da24b5c625342bc5298de67d439f325bd7acb3e2d3002a0d15",
                        "bf5dac6b1bc47187d8a7b8566e5ada6803a099da67185ee589c938ce83f5f666",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "36058b180932f23f9c8b6d6e1e47d2185720ace9006cf8d6c1cb93206a606dfa",
                        "5cd5107ba2f7f893e484b6df64e1f76f63e64ddc2b9464f7578057a1d2f50f5d",
                        "CN=Alice",
                    ),
                    (
                        "f5618904fb6336661186dc52923c6dc2f668141864d5b0dbce0b3d9ebafa99f2",
                        "25a2d97fa6b6b00d906aa5465a53c69e8b928fb810086305cd49a9980b608b6f",
                        "CN=Alice",
                    ),
                    (
                        "2d2e63a582d426216ff4e75a6eb838143f103ca4e5bb470616b0a53d881d30b1",
                        "b12ded0af6128a2f29f7ef91b793ef11a4455685754f3ab551536946f9ff3b24",
                        "CN=Alice",
                    ),
                    (
                        "de3f72accdea9ecdc62a9158f9d27a3c1ec91e70ad8866ce1fde2f64cbf6ba23",
                        "4991b1bd20cad414304920cbd113e0487e611550a9957bb8d26b4e2ed914addb",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "5ca3d47b84ae42da24b5c625342bc5298de67d439f325bd7acb3e2d3002a0d15",
                        "bf5dac6b1bc47187d8a7b8566e5ada6803a099da67185ee589c938ce83f5f666",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "28e6664817841e7c7b126703ff1587f3a8c00479e7a326aa6143781468b8617e",
                        "460437b4a816d579d2e5c932233dd8fb4bb86c6a54afad7d2fb08a29e6910a2c",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "f526a2bf452f04e5e29df964590002846f34c9d722191b0f38a3c21c5da4e336",
                        "1e88d09481d725f0dc6795b97afe4e89208f09c587b874e4bf6f494381e3b9df",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "51faad5bf1bdd03d2a45d9e2069876e80be8c723f05f090781587ba6eaa2ce58",
                        "b4b85885449f9ac0ae52d162c7233174738cf462d8e6a170e552484f6cc0ae58",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "f0f97f6e17d65793a3e80eafe682fbc224a3b339ca382d37cd810a17e25cb4e1",
                        "6830b51d07b1b5a3a09c551370e0685ed4cc97645e6fdda3236812bd796217dc",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// One pinned certificate: its SPKI digest, its DER digest, and its subject
type Pinned = (&'static str, &'static str, &'static str);

/// Assert that `algorithm` still derives exactly `vectors`: for each subkey id, the pins for
/// the root and the four slots
fn assert_current_scheme_frozen(algorithm: Algorithm, vectors: [(Option<&str>, [Pinned; 5]); 2]) {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    for (id, expected) in vectors {
        let chain = SeededSmartcard::new(&SEED_A, id.map(|v| v.to_string()), "Alice".into())
            .with_algorithm(algorithm)
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .certify(CertificateKind::Chain)
            .unwrap();

        let mut certs = vec![(&chain.root, "root")];
        certs.extend(chain.leaves.iter().map(|(slot, cert)| {
            (
                cert,
                match slot {
                    SlotId::Authentication => "9A",
                    SlotId::Signature => "9C",
                    SlotId::KeyManagement => "9D",
                    SlotId::CardAuthentication => "9E",
                    other => panic!("unexpected slot {other:?}"),
                },
            )
        }));

        for ((cert, slot), (spki, der, subject)) in certs.into_iter().zip(expected) {
            let got_spki = hex(&digest_bytes(
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .unwrap(),
            ));
            assert_eq!(got_spki, spki, "{slot} KEY moved for {id:?} -- derivation broke");
            assert_eq!(
                hex(&digest(cert)),
                der,
                "{slot} certificate encoding moved for {id:?} -- check will fail on provisioned cards"
            );
            assert_eq!(
                cert.tbs_certificate().subject().to_string(),
                subject,
                "{slot} subject moved for {id:?}"
            );
        }
    }

    fn digest_bytes(der: Vec<u8>) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(der).to_vec()
    }
}

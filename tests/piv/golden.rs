//! The frozen `mtg1` vectors: every algorithm, three key paths, the card's own key, pinned by
//! digest.

use crate::frozen::{PATHS, key_path};
use crate::hex::hex;
use crate::{SEED_A, SEED_B, digest, list_url};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard};
use mind_the_gap::role::KeyRole;
use mind_the_gap::seed::{Algorithm, CardSerial, KeyPath, Seeds};

use x509_cert::Certificate;
use x509_cert::der::Encode;

/// One pinned certificate: its SPKI digest, its DER digest, and its subject
type Pinned = (&'static str, &'static str, &'static str);

/// One algorithm's chains, a root and three slot certificates per path in [`PATHS`]
type Vectors = [[Pinned; 4]; 3];

/// The P-256 vectors, the algorithm a card gets when none is chosen
const P256: Vectors = [
    [
        (
            "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
            "397a1d53f30029fcde4cf20d144066b7d8fd819b5932b32a70850abdc79835f1",
            "CN=Alice PIV Root CA p256",
        ),
        (
            "f219e92899232df5f5b24cb1eb7bba2b647db7a6fe96c78852aac327bfa8758b",
            "221c0639b6b74ff11a132a2eed2057cff4f993bdf8f3b890fdaa16b342208952",
            "CN=Alice",
        ),
        (
            "804fab25c059b02c1297d0e58933ec07b2cac35c8d9fd838c8bea396e5b64cf3",
            "58508c4d4a4fe20b251f2c5064b1aa389cbd933d7095ad6bbd5804f6e3fb3fc0",
            "CN=Alice",
        ),
        (
            "27f3fb55442906022080c97a469d8aee53d0ea378dc39fecd12af73fe4d5fdf0",
            "ebb9b86fba3c7efb92ba4cf1e929d4312dab52f238e260b7238db45d24b25015",
            "CN=Alice",
        ),
    ],
    [
        (
            "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
            "397a1d53f30029fcde4cf20d144066b7d8fd819b5932b32a70850abdc79835f1",
            "CN=Alice PIV Root CA p256",
        ),
        (
            "5f22bc03848271a3b6e524b9e327eaceef0ae31b379ffa4bb3511bb3f189eda7",
            "3bc06437c917f7c95c7b4601daff3c3d19c5ddb3914e6beb1bb8ebfc0568f5c8",
            "CN=Alice",
        ),
        (
            "555ad0a77ef68e4eb556d49551d0a948685077c64956d61fc5bda926c7a751ab",
            "b260dc6376c23f2f74091876fbb545db4747d4b9b781729ed0217f44af54d92b",
            "CN=Alice",
        ),
        (
            "27f3fb55442906022080c97a469d8aee53d0ea378dc39fecd12af73fe4d5fdf0",
            "ebb9b86fba3c7efb92ba4cf1e929d4312dab52f238e260b7238db45d24b25015",
            "CN=Alice",
        ),
    ],
    [
        (
            "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
            "397a1d53f30029fcde4cf20d144066b7d8fd819b5932b32a70850abdc79835f1",
            "CN=Alice PIV Root CA p256",
        ),
        (
            "6e82560ce4119280ff2de6e63dd06050e29ba33d6d3fdbe695bc715be6a0bd58",
            "d73efa31ef7931ed7d670f005807cb5c74cc717523aaa120d19e287dfc45d233",
            "CN=Alice",
        ),
        (
            "c8e706c8636a1f60ba3d228044ae055e8827eff787b1ed005f73c6e5f0e228ce",
            "94f5dcdc6a92d728efa0aecd3b87871f6367dd9fcca980fb01eb272a3395d36a",
            "CN=Alice",
        ),
        (
            "45b2815909260e2c175ee7c96353e1f1cbdb42a8a4e65bfe0dcaf35e2c057f28",
            "5e62b4fe6270ee3c64ce4eacf29dd6505a9320054c8a145082f9dae46f80063e",
            "CN=Alice",
        ),
    ],
];

/// The Curve25519 vectors: Ed25519 signatures are deterministic, so the DER pins
const CURVE25519: Vectors = [
    [
        (
            "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
            "ec0bbd6d762fc5d331f527ae60539c658227809ff82aa5f61efd9acb120d0580",
            "CN=Alice PIV Root CA curve25519",
        ),
        (
            "d74c39e183bc75865ee4e4dc55c44f63a453d2120a56e284a387ec467ab3c2bb",
            "c49cc7e1c491afae57945134235578f6ad01df9d2e6f8e497c28f8d9d0b9bf04",
            "CN=Alice",
        ),
        (
            "d88caf2184002b68071db52db63ad14f9c2b830cdf416bc25ab674b843224170",
            "e0533ccd1f3dbb174b40b65553b72809b79d1ca60570882ab82e691a85e70922",
            "CN=Alice",
        ),
        (
            "1e0920baa37055c703589903d8f384b3bd24f50323f3491541495a292e382222",
            "b3294eda27356b314b474b8d264968ba21c5b369317a8ceeb643160c399bef73",
            "CN=Alice",
        ),
    ],
    [
        (
            "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
            "ec0bbd6d762fc5d331f527ae60539c658227809ff82aa5f61efd9acb120d0580",
            "CN=Alice PIV Root CA curve25519",
        ),
        (
            "b29e70e6954f77a46ddbfe461e3b873dd8fdd8df5d93b3b556ad3984dcf72fb4",
            "6e0bac4aa1ad18dca67a97da3c86fcb29fcc4e2a15608dd4c89bbeb32424ccce",
            "CN=Alice",
        ),
        (
            "8cfc7e206526f869ef0a551255bcc3267f3be9ff9a6e0900c0a0da6e132568be",
            "9025536e9a01f966c17c19ec818578c70557f442e58d8e2ddfcf41c73d967845",
            "CN=Alice",
        ),
        (
            "1e0920baa37055c703589903d8f384b3bd24f50323f3491541495a292e382222",
            "b3294eda27356b314b474b8d264968ba21c5b369317a8ceeb643160c399bef73",
            "CN=Alice",
        ),
    ],
    [
        (
            "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
            "ec0bbd6d762fc5d331f527ae60539c658227809ff82aa5f61efd9acb120d0580",
            "CN=Alice PIV Root CA curve25519",
        ),
        (
            "7f687f06ac2d9632183d3497909d794f3c28999306fdbc89b8fdc7b6be8727b8",
            "d69c92c34a50347b7596e2b64c91727f5631aad8e13a416fb243a80fb5c7d15e",
            "CN=Alice",
        ),
        (
            "0d920dfd885f1b4a197d28b377759a7da0766d0a40db3f33dcf4d0967c871c66",
            "1008bd8b64b98aca15b3319580c54190ae49586837c6f8287296419b4c84a0df",
            "CN=Alice",
        ),
        (
            "93a11e7570d549e97e0b99106551b53217656eb11229795e8c485dc6d74d4c85",
            "2917fb8330bf9f9869cb984060f767f63778685143fdab11dcc661f7e9220cc3",
            "CN=Alice",
        ),
    ],
];

/// The P-384 vectors, under the documented 48-byte construction; ECDSA signatures use RFC 6979
/// nonces, so the DER pins
const P384: Vectors = [
    [
        (
            "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
            "916e42a0dc9a177f83d3698232987f800bfb244ba44bd6044f76f4f4af0c3f25",
            "CN=Alice PIV Root CA p384",
        ),
        (
            "fe78bdb592d99b5c8d1dc51b2f42d19f4047b546ec4b325bc8207903889c3411",
            "8d111cec3226685aa0bb883aae849732abcc68c7697a3d34da2105da448e2808",
            "CN=Alice",
        ),
        (
            "108c4ef0b7d1d74b81e3e6101ff2a006dda65747e69d602f66963674874c38cf",
            "6b9b285a1a64325c76337c02b57933a2daa1330c861b94187e1013ef4374cd1a",
            "CN=Alice",
        ),
        (
            "dc1dd215d4c57fe938ccaab3a2d5b3f127976d9d5dfffd77e692aac668244bc3",
            "998ac765b3bd3b00c8b528abd359ea5d4d5826cfa66fa4142dad202a986b2acf",
            "CN=Alice",
        ),
    ],
    [
        (
            "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
            "916e42a0dc9a177f83d3698232987f800bfb244ba44bd6044f76f4f4af0c3f25",
            "CN=Alice PIV Root CA p384",
        ),
        (
            "aaec61040c30ae1e3fdb62590d4ebde9b3f51856aa183db8e6198a9e079e2251",
            "6136460a3fe0f11bdc5e7827d087bbe4739a02c0464e6c55fff9ba926c55c8ce",
            "CN=Alice",
        ),
        (
            "224679124975033922323ddb5121c35da9cf86fc0e068bfe7c7f95476769b712",
            "43220c5192868fb01babfa2be00a9799e53e7483e79c9f4ddaec0e524ca56af6",
            "CN=Alice",
        ),
        (
            "dc1dd215d4c57fe938ccaab3a2d5b3f127976d9d5dfffd77e692aac668244bc3",
            "998ac765b3bd3b00c8b528abd359ea5d4d5826cfa66fa4142dad202a986b2acf",
            "CN=Alice",
        ),
    ],
    [
        (
            "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
            "916e42a0dc9a177f83d3698232987f800bfb244ba44bd6044f76f4f4af0c3f25",
            "CN=Alice PIV Root CA p384",
        ),
        (
            "9491c2fcb020fb29e00dd79785e2b1c37793ba26fc9571919c24b4a674a4ee4c",
            "7bd336f1b17a985e9f0228a3e4103942511ac7c02b4fa6335a02f4a7bf5e89c6",
            "CN=Alice",
        ),
        (
            "e7816e4d584928570f9ebafbb14a33f62b1ec42266a7535226ebe44b1fafa9de",
            "b5c1a2de404a124e491958cdae2873e983626c8778bb6ea3e108d6767effb5c5",
            "CN=Alice",
        ),
        (
            "595812b41feff9f8a1ea593e938f9fd9b517d937372824f6d541a8da4275e4c7",
            "8f58c255b9d1123ae9a4a25af806630b3ecbf19d53b6f8ce947ef2a080fa7b94",
            "CN=Alice",
        ),
    ],
];

/// The RSA-2048 vectors: PKCS#1 v1.5 signatures are deterministic, so the DER pins
const RSA2048: Vectors = [
    [
        (
            "f8f92dc72cc7216fe612da655ec461bda33e6f33bddfbbcc668b40c29c867653",
            "314f75e04a4606f82fdb55b226032446ac7373125020c848c92ee11ae81b1a93",
            "CN=Alice PIV Root CA rsa2048",
        ),
        (
            "267b03d30c578e34ebbdf3076d29984b7a3246f4fcd34b4ca6c5e0ac9a50ab8d",
            "7849d7a9368d5f03d350dc3e62f1625c46defa1a6e4e57630b2fcc5782b4336b",
            "CN=Alice",
        ),
        (
            "f93be5522c884e372ccfc10724e6d0fc06113493e26d4e7b0b8c4416d24f1dd0",
            "eff8eb1f3fca4af06bb6b43534931a92795c97cf8d04049d722561552dbfc2bd",
            "CN=Alice",
        ),
        (
            "435bdd3edd6472eac8f5f0387efe9b23e5636c34dd7cf6c2ffc8fcb9f2a1ea32",
            "167637439fa06cf8919e145b00bf22c8f0787b954b4812ad0bc0364c64442bdb",
            "CN=Alice",
        ),
    ],
    [
        (
            "f8f92dc72cc7216fe612da655ec461bda33e6f33bddfbbcc668b40c29c867653",
            "314f75e04a4606f82fdb55b226032446ac7373125020c848c92ee11ae81b1a93",
            "CN=Alice PIV Root CA rsa2048",
        ),
        (
            "ac20c26aba31ca03944fde6dc35821efa76ea55214657f42a90f376281fbd11b",
            "e5598b957bb025beccfafeefb5c28f899edb065143848fbb08cec2cba7abbaef",
            "CN=Alice",
        ),
        (
            "169a6af8a2f731f13496aeac4a8b4fb28b8733fa027725ac6454d524d74bd4bd",
            "84f14449b1252538fc26f9d3e00abf8d07bed6a6c751aca0bd1b65edde7f0c11",
            "CN=Alice",
        ),
        (
            "435bdd3edd6472eac8f5f0387efe9b23e5636c34dd7cf6c2ffc8fcb9f2a1ea32",
            "167637439fa06cf8919e145b00bf22c8f0787b954b4812ad0bc0364c64442bdb",
            "CN=Alice",
        ),
    ],
    [
        (
            "f8f92dc72cc7216fe612da655ec461bda33e6f33bddfbbcc668b40c29c867653",
            "314f75e04a4606f82fdb55b226032446ac7373125020c848c92ee11ae81b1a93",
            "CN=Alice PIV Root CA rsa2048",
        ),
        (
            "a922fd616beba8694a5b7971df9dc4a32e7769b608d85ff98e4dc62d0adcd06e",
            "61c227561aeab43b82643a6d546982ac23f68e131cacdc7762b674396dccf5da",
            "CN=Alice",
        ),
        (
            "65f1e4e63e117cb41997fc502044630bbbe5265d821995ab0768809b139abdac",
            "0c12f59b9308a2f9eef301cda45c19e0d85b70183ec304d109000899efd36a79",
            "CN=Alice",
        ),
        (
            "0d5673dcead17098d4d686f078a535c019f116fb619845fc0cb7c99ed775c293",
            "03dc2503ef4a5a20c831aaa2e792f18c500f5be9e78b0c21f89f67c46b86e730",
            "CN=Alice",
        ),
    ],
];

/// The RSA-3072 vectors
const RSA3072: Vectors = [
    [
        (
            "786bfbf1cfa1f0914ac65c021c37bbf445b7cde9e4a5f7b8bdd2cb695103ce84",
            "feeb26070dd5090ec445d4b58ebf24fb7e4149fdc4137926d9a9b36c8c0faab4",
            "CN=Alice PIV Root CA rsa3072",
        ),
        (
            "292b3d04ae27d094889dce616d0e8d77ef5d907f16281d9f7897e94ab1fd3d59",
            "26980822b9b04eda29b90ea780753e8c536a62c33719ff5598d4dd580506ad35",
            "CN=Alice",
        ),
        (
            "2c34e33a17b3ea667466da96e5c83cfbb3553b69a438edceba7fe4ab21fda1aa",
            "a67fca775442ecdcf284568593845fdb7ef9f0dfd4f0ede1b48ac0fb97ec7458",
            "CN=Alice",
        ),
        (
            "ece889633668dc8aef68c0e21a4423ec375a759816fcf1ed754ccd80908712dc",
            "d4b187844f57bb33b73fbb5b3509d4174b4bbf01a325914dbe7070fd0b8bc29e",
            "CN=Alice",
        ),
    ],
    [
        (
            "786bfbf1cfa1f0914ac65c021c37bbf445b7cde9e4a5f7b8bdd2cb695103ce84",
            "feeb26070dd5090ec445d4b58ebf24fb7e4149fdc4137926d9a9b36c8c0faab4",
            "CN=Alice PIV Root CA rsa3072",
        ),
        (
            "52afa0e5a9ea7e9b38350d14b66b8a70308fd391c4f79e8de7e0f46628dcf547",
            "9fae23421be433eb4e58b49952322b308fef211a5ca3c878d1beb2b41700c2ff",
            "CN=Alice",
        ),
        (
            "a19ca5869280975fd143704e1e9df7fd088860e2f42d07d07d56af1754e4a313",
            "56c4b7d566765ab7c2362a562ea325c3e779db199b9c12059487d0660d9f0a27",
            "CN=Alice",
        ),
        (
            "ece889633668dc8aef68c0e21a4423ec375a759816fcf1ed754ccd80908712dc",
            "d4b187844f57bb33b73fbb5b3509d4174b4bbf01a325914dbe7070fd0b8bc29e",
            "CN=Alice",
        ),
    ],
    [
        (
            "786bfbf1cfa1f0914ac65c021c37bbf445b7cde9e4a5f7b8bdd2cb695103ce84",
            "feeb26070dd5090ec445d4b58ebf24fb7e4149fdc4137926d9a9b36c8c0faab4",
            "CN=Alice PIV Root CA rsa3072",
        ),
        (
            "bfa372e4cf2b9165cbbcb6943cced77781ce132ab8bd33b206e21fe9fca330db",
            "f863c39cccdc6ab56d420e7dfed4980bb797e8f4b053cc01068627b5c19e4e69",
            "CN=Alice",
        ),
        (
            "106bb89c03b4e687fbfe07df030d596d0f348bdb4b4a2c57172923496b12679b",
            "af4194b8cef5e0c0e16ff2cc382c0f5ed798447adacf7cf16127b2ab8f15d735",
            "CN=Alice",
        ),
        (
            "5a435bc3ae33bc6ea92bd10df22df93b98f91426adb82a6cabbd3b3678128222",
            "bccfa3daac89b25d5cbcb7baf460876258bfc4478754ab40329bd1e35b2ac90c",
            "CN=Alice",
        ),
    ],
];

/// The RSA-4096 vectors
const RSA4096: Vectors = [
    [
        (
            "5ca3d47b84ae42da24b5c625342bc5298de67d439f325bd7acb3e2d3002a0d15",
            "2f40b23f1088b0f0c93d54903f7df2e57c7daf64d16529feb87dc2132cfc20d1",
            "CN=Alice PIV Root CA rsa4096",
        ),
        (
            "94ab772d8f424f89bcef086fdb85bd54f3e9a5c6b0590eaaf0a3b88f32965412",
            "43321385b5e8035f883effa5659535e02d72b3c0cba50a0050e4ea1ef20421ac",
            "CN=Alice",
        ),
        (
            "df081c02e4b4b0b4e4be4226c238a5badab2ee280263483d0723bf8a538495ec",
            "f7d17be6bf6fdd931a690a67c9fbfa72ba8f1c44c861bbf154dd5d82d3ec4d2e",
            "CN=Alice",
        ),
        (
            "d4661eee029d85b2d21400cc2875514ab65ab73464355227260ff8068ea0821e",
            "616e8779d61cdaf0541ba7fcb22f3a65db559a05a86b5f5ee04934fe1c040612",
            "CN=Alice",
        ),
    ],
    [
        (
            "5ca3d47b84ae42da24b5c625342bc5298de67d439f325bd7acb3e2d3002a0d15",
            "2f40b23f1088b0f0c93d54903f7df2e57c7daf64d16529feb87dc2132cfc20d1",
            "CN=Alice PIV Root CA rsa4096",
        ),
        (
            "28e6664817841e7c7b126703ff1587f3a8c00479e7a326aa6143781468b8617e",
            "6ab6ec05a8fdd583115dbc083749b159bddfb631b76febae6237231ed469a8e8",
            "CN=Alice",
        ),
        (
            "f526a2bf452f04e5e29df964590002846f34c9d722191b0f38a3c21c5da4e336",
            "db79bfd696b7ed3c54bb23cde9c8184f743e391bb92d9f4b82f08e472e136e85",
            "CN=Alice",
        ),
        (
            "d4661eee029d85b2d21400cc2875514ab65ab73464355227260ff8068ea0821e",
            "616e8779d61cdaf0541ba7fcb22f3a65db559a05a86b5f5ee04934fe1c040612",
            "CN=Alice",
        ),
    ],
    [
        (
            "5ca3d47b84ae42da24b5c625342bc5298de67d439f325bd7acb3e2d3002a0d15",
            "2f40b23f1088b0f0c93d54903f7df2e57c7daf64d16529feb87dc2132cfc20d1",
            "CN=Alice PIV Root CA rsa4096",
        ),
        (
            "9953e449aca29753b2a4f64809dd2d27e4eb5ddf555449c898e492f6bf112e00",
            "5f784c40c539f293c3efc5433491d58bd1f591ae568ae180cd0c8de74f024513",
            "CN=Alice",
        ),
        (
            "ce5fd450879d9515d2051f1a6d668c40ef89bec95e91b65eaaf2a800ecb43036",
            "b86ef73a4a0290c85b3299fbecfec02dcbfbea26ba05dd83f52522fcb98b8c1c",
            "CN=Alice",
        ),
        (
            "8edeb9c2c172924092761a1dfb9b8cfb1ae18a90e996166ef41fe2951bbeb87d",
            "2a80328d86c4767c602c234466a175d7ded48ac8d06fcef49744a5d5070c88c0",
            "CN=Alice",
        ),
    ],
];

/// The card authentication certificate of card 12345678, per algorithm
const CARD_AUTHENTICATION: [(Algorithm, Pinned); 6] = [
    (
        Algorithm::P256,
        (
            "8916821c3f4fbabb5e2b462593f58981abdd51a579103ed5af13b8b45f4a3026",
            "58aa4ca70d4c49b7a00e11264e85ebb775c6337630409f3645f0847a4f6434e4",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
    (
        Algorithm::Curve25519,
        (
            "799d79e088f49ca53809a725c2587e72ece166f261cecf0c48a5cfdcf9c59f05",
            "9eb443b310cc651e8de861bd5c098002195e3031a3120d30a6fb51b581f14482",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
    (
        Algorithm::P384,
        (
            "fa4e7e9cc44e4594569b07d874804166170f933c0f9fa5a66d93b4545701f4d6",
            "9f44e767ee48b455b90327b87f7c4fb1bad52564dc3a7b1c38bf13a31c16b978",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
    (
        Algorithm::Rsa2048,
        (
            "144d098124b29cc53b6f5794a4a19859101a60a7e7ba2cea45090ecde6f64af5",
            "afff5e28ae5e8d2f5bcd6d4acd8cbd593f7268a78b2553a31edf37719120c46a",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
    (
        Algorithm::Rsa3072,
        (
            "89c3e9795cd0dbbc4b388e1b245d26aaee1c1a87ad00a0b1e4a0059b85f6e633",
            "d2a6748f0dbc70b1ee697c8f0dd3cc4c22e3d0e04eaaa82ac4ee06a58f293ede",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
    (
        Algorithm::Rsa4096,
        (
            "9493e6cac1cf3f50ef93d2bbdb235de15b06f1d6b77b1e8484b979298ff06c2b",
            "01cb722e57a18d745bd73c6f2bdecf9b02bcdc0688ab1116e32dca4599200be1",
            "CN=PIV Card mtg1:CC85C2FB",
        ),
    ),
];

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
    assert_current_scheme_frozen(Algorithm::P256, &P256);
}

/// What a card gets when nothing is chosen is frozen with the rest.
///
/// The default algorithm decides every key and the default creation time lands in every
/// certificate's validity, so a drifting default would fail `check` on every card
/// provisioned without `--algorithm` or `--date` while each vector above, which sets the
/// algorithm, kept passing.
#[test]
fn defaults_are_frozen() {
    assert_frozen(&P256, |path| SeededSmartcard::new(Seeds::one(&SEED_A), path, "Alice".into()));
}

#[test]
fn current_scheme_is_frozen_on_curve25519() {
    assert_current_scheme_frozen(Algorithm::Curve25519, &CURVE25519);
}

#[test]
fn current_scheme_is_frozen_on_p384() {
    assert_current_scheme_frozen(Algorithm::P384, &P384);
}

#[test]
fn current_scheme_is_frozen_on_rsa2048() {
    assert_current_scheme_frozen(Algorithm::Rsa2048, &RSA2048);
}

#[test]
fn current_scheme_is_frozen_on_rsa3072() {
    assert_current_scheme_frozen(Algorithm::Rsa3072, &RSA3072);
}

#[test]
fn current_scheme_is_frozen_on_rsa4096() {
    assert_current_scheme_frozen(Algorithm::Rsa4096, &RSA4096);
}

/// The card's own key is frozen too, per algorithm and bound to the card's serial.
///
/// `check` and `list` recognise a card by it when its CHUID is gone, and it is the one key a
/// door reader enrols; a 9E that moved would make every initialized card a stranger.
#[test]
fn card_authentication_is_frozen() {
    let card = SeededSmartcard::new(Seeds::one(&SEED_A), KeyPath::default(), String::new());
    for (algorithm, expected) in CARD_AUTHENTICATION {
        let cert = card
            .card_authentication_certificate(algorithm, &CardSerial::piv(12345678))
            .unwrap();
        assert_pinned(&cert, &expected, &format!("{algorithm:?} 9E"));
    }
}

/// Assert that `algorithm` still derives exactly `vectors`
fn assert_current_scheme_frozen(algorithm: Algorithm, vectors: &Vectors) {
    assert_frozen(vectors, |path| {
        SeededSmartcard::new(Seeds::one(&SEED_A), path, "Alice".into()).with_algorithm(algorithm)
    });
}

/// Assert that the chain `build` makes for each path of [`PATHS`] is still exactly `vectors`:
/// the root first, then the slots in chain order
fn assert_frozen(vectors: &Vectors, build: impl Fn(KeyPath) -> SeededSmartcard) {
    for ((subkey, date), expected) in PATHS.into_iter().zip(vectors) {
        let chain = build(key_path((subkey, date)))
            .add_email("alice@example.com")
            .unwrap()
            .certify(CertificateKind::Chain)
            .unwrap();
        let certs: Vec<_> = std::iter::once(&chain.root)
            .chain(chain.leaves.iter().map(|(_, cert)| cert))
            .collect();
        assert_eq!(
            certs.len(),
            expected.len(),
            "chain for {subkey:?} {date:?} has the wrong length"
        );
        for (index, (cert, pinned)) in certs.into_iter().zip(expected).enumerate() {
            assert_pinned(cert, pinned, &format!("certificate {index} for {subkey:?} {date:?}"));
        }
    }
}

/// Assert one certificate is still `pinned`, saying whether the key or its encoding moved
fn assert_pinned(cert: &Certificate, (spki, der, subject): &Pinned, what: &str) {
    let key = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    {
        use sha2::{Digest, Sha256};
        assert_eq!(hex(&Sha256::digest(key)), *spki, "{what}: KEY moved -- derivation broke");
    }
    assert_eq!(
        hex(&digest(cert)),
        *der,
        "{what}: certificate encoding moved -- check will fail on provisioned cards"
    );
    assert_eq!(cert.tbs_certificate().subject().to_string(), *subject, "{what}: subject moved");
}

/// The optional parts of a card are frozen too: the issuing authority `--intermediate`
/// inserts, and another identity's decryption key kept in a retired slot with `--slot`.
///
/// Both change what the vectors above cannot see: the intermediate every slot's issuer, the
/// retired slot where a key is certified for and under whose root. The root is the one the
/// vectors above pin, `--intermediate` or not.
#[test]
fn intermediate_and_retired_slots_are_frozen() {
    let chain = SeededSmartcard::new(
        Seeds::one(&SEED_A),
        KeyPath { subkey: Some("gen1".into()), date: None },
        "Alice".into(),
    )
    .add_email("alice@example.com")
    .unwrap()
    .with_intermediate(true)
    .certify(CertificateKind::Chain)
    .unwrap();
    let certs = std::iter::once(&chain.root)
        .chain(chain.intermediate.iter())
        .chain(chain.leaves.iter().map(|(_, cert)| cert));
    let expected: [Pinned; 5] = [
        (
            "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
            "397a1d53f30029fcde4cf20d144066b7d8fd819b5932b32a70850abdc79835f1",
            "CN=Alice PIV Root CA p256",
        ),
        (
            "05f3dc628b1954524442d52f21fe505606eba6cb7c366b889b9be3e76208926c",
            "02bd92cb95bd0e57516d1cae3f062f7ea27e04ed577614ac2eb18fb1b1e2527a",
            "CN=Alice PIV Issuing CA 6027DDE7",
        ),
        (
            "ec4c228b0c390cb5743e494dccfb5a62743dc8ef8ebfb56e1fafd1821272ff14",
            "642b85436787146cffb7cbec0773e31eb6868d1bf2408ee585c811c06907b520",
            "CN=Alice",
        ),
        (
            "42d11ccd87019c6d4862c267de60e237dd262545bff54be34f6d8282fbe54552",
            "6052165aef09a9278c1a8b21cf24540fa2ffbce27d7014b08719bdae1aae629c",
            "CN=Alice",
        ),
        (
            "27f3fb55442906022080c97a469d8aee53d0ea378dc39fecd12af73fe4d5fdf0",
            "ce221898bccae08c77878a761235ebd1b0ed7409ebd5576cb283fe28f3078e61",
            "CN=Alice",
        ),
    ];
    for (index, (cert, pinned)) in certs.zip(&expected).enumerate() {
        assert_pinned(cert, pinned, &format!("intermediate chain certificate {index}"));
    }

    // A team's decryption key on Alice's card: administered by her card seed, derived from
    // the team's key seed, certified by the team's root
    let chain = SeededSmartcard::new(
        Seeds { card: Some(&SEED_A), key: Some(&SEED_B) },
        KeyPath::default(),
        "Team".into(),
    )
    .add_email("team@example.com")
    .unwrap()
    .with_keys(&[KeyRole::Decryption])
    .unwrap()
    .with_slot(0x82)
    .unwrap()
    .certify(CertificateKind::Chain)
    .unwrap();
    let certs = std::iter::once(&chain.root).chain(chain.leaves.iter().map(|(_, cert)| cert));
    let expected: [Pinned; 2] = [
        (
            "67f5bb008aa64e330806b2c4bf74e9eb6af9f22ee3d5e81cab95e2d98ccf4823",
            "de89449006891e4ab874a4b452ec5c7988d5e0a692188d7c8416f643eee9db52",
            "CN=Team PIV Root CA p256",
        ),
        (
            "203ccd2ff8f7fee897bc77ab4e704268b650769915c9c484fc973f683becf259",
            "cbd2bf222af2ffd4dae20c6a52a6bf7124bb3201e167f7180da368555314c925",
            "CN=Team",
        ),
    ];
    for (index, (cert, pinned)) in certs.zip(&expected).enumerate() {
        assert_pinned(cert, pinned, &format!("retired slot chain certificate {index}"));
    }
}

/// Where an issuing authority's revocation list is, and the list itself, are frozen too.
///
/// The slot certificates of a device with `--intermediate` and `--crl-url` name the list's
/// URL, which carries the authority's tag, and that list is published once and kept: a URL
/// that moved would leave every such certificate pointing at nothing, and a list that moved
/// would be one more to publish. Pinned on a device in a dated generation, so that both steps
/// of the path reach the tag.
#[test]
fn issuing_list_is_frozen() {
    use sha2::{Digest, Sha256};

    let card = SeededSmartcard::new(Seeds::one(&SEED_A), key_path(PATHS[2]), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_crl_url("http://example.org/alice.crl")
        .unwrap()
        .with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    for (slot, leaf) in &chain.leaves {
        assert_eq!(
            list_url(leaf),
            "http://example.org/alice-p256-issuing-0e4d15ab.crl",
            "{slot:?}: list URL moved"
        );
    }
    let (suffix, list) = card.issuing_revocation_list().unwrap().unwrap();
    assert_eq!(suffix, "-p256-issuing-0e4d15ab", "list suffix moved");
    assert_eq!(
        hex(&Sha256::digest(list)),
        "8f285b9e5eda92ef321bcc6586a078cd283551bc654dd3d249e403301ddce981",
        "issuing list moved"
    );
}

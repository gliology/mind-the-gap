//! The seeds a session holds: where each comes from, and asking for it at most once.

use super::{SeedArgs, SeedUse};
use crate::mnemonic::MnemonicSeed;
use crate::prompt;
use crate::seed::{SecretSeed, Seed256, Seed256Derive};

use anyhow::{Result, bail};

use zeroize::Zeroizing;

/// Where one seed comes from
#[derive(Clone, Default)]
pub(super) enum Source {
    /// Not given: the card seed and the key seed then fall back to the seed
    #[default]
    Absent,
    /// A phrase from the command line or the environment, with its password
    Given(Zeroizing<String>, Option<Zeroizing<String>>),
    /// To be asked for on the terminal, where there is one
    Ask,
    /// Asked for or parsed already
    Resolved(MnemonicSeed),
}

impl Source {
    /// The source a phrase argument names: an empty one, `--card-seed` without a value,
    /// asks for it
    pub(super) fn from_args(
        phrase: Option<Zeroizing<String>>,
        password: Option<Zeroizing<String>>,
    ) -> Source {
        match phrase {
            None => Source::Absent,
            Some(phrase) if phrase.trim().is_empty() => Source::Ask,
            Some(phrase) => Source::Given(phrase, password),
        }
    }

    /// Whether the seed is at hand without asking
    fn known(&self) -> bool {
        matches!(self, Source::Given(..) | Source::Resolved(_))
    }

    /// The seed, parsed or asked for at most once
    ///
    /// A seed is never invented behind the user's back: minting a fresh one is what
    /// `generate` is for, and it does not let go until the phrase is written down. A phrase
    /// is never echoed back, since it would linger in scrollback next to everything derived
    /// from it.
    fn resolve(&mut self, which: &str, interactive: bool) -> Result<MnemonicSeed> {
        let seed = match std::mem::take(self) {
            Source::Resolved(seed) => seed,
            Source::Given(phrase, password) => {
                let seed: MnemonicSeed = phrase.trim().parse()?;
                match password {
                    Some(password) => seed.with_password(&password),
                    None => seed,
                }
            }
            Source::Ask | Source::Absent if interactive => {
                // A typo is reported before anything else is asked, and costs only the
                // phrase: the password belongs to the seed, so it follows in the same breath,
                // once the phrase is known to be valid
                let seed: MnemonicSeed = loop {
                    let text = prompt::read_secret(&format!("{} phrase: ", capitalized(which)))?;
                    match text.trim().parse() {
                        Ok(seed) => break seed,
                        Err(err) => log::error!("{err}; try again, or Ctrl-C to abort"),
                    }
                };
                match prompt::read_optional_secret("Password (empty for none): ")? {
                    Some(password) => seed.with_password(&password),
                    None => seed,
                }
            }
            source => {
                *self = source;
                bail!(
                    "No {which} phrase given. Pass it with {}; only an interactive session on a \
                     terminal asks for it, on a hidden prompt.",
                    flag_of(which)
                )
            }
        };
        *self = Source::Resolved(seed.clone());
        Ok(seed)
    }
}

fn capitalized(which: &str) -> String {
    let mut chars = which.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The ways to give a seed without a prompt, for the message that says one is missing
fn flag_of(which: &str) -> &'static str {
    match which {
        "card seed" => "--card-seed=PHRASE (or MIND_THE_CARD_SEED), or --seed for both",
        "key seed" => "--key-seed=PHRASE (or MIND_THE_KEY_SEED), or --seed for both",
        "previous key seed" => "--from-key-seed=PHRASE (or MIND_THE_FROM_KEY_SEED)",
        _ => "--seed (or MIND_THE_SEED); mint one with `generate`",
    }
}

/// The seeds of a session: the seed, and the card seed and key seed apart from it
#[derive(Clone, Default)]
pub(super) struct SeedBook {
    pub(super) seed: Source,
    pub(super) card: Source,
    pub(super) key: Source,
}

/// What a command derives from: each seed's root, where the command takes it
pub(super) struct Roots {
    /// The card seed's root
    pub(super) card: Option<SecretSeed>,
    /// The key seed's root
    pub(super) key: Option<SecretSeed>,
    /// The key seed's phrase entropy, for the warning about strong algorithms
    pub(super) key_entropy: Option<u32>,
}

impl SeedBook {
    /// The seeds as the command line and the environment give them
    pub(super) fn from_args(args: SeedArgs) -> SeedBook {
        SeedBook {
            seed: Source::from_args(args.seed, args.password),
            card: Source::from_args(args.card_seed, args.card_password),
            key: Source::from_args(args.key_seed, args.key_password),
        }
    }

    /// This book with a command's own `--card-seed` or `--key-seed` in place of the session's
    pub(super) fn overridden(&self, args: SeedArgs) -> SeedBook {
        let mut book = self.clone();
        if args.card_seed.is_some() {
            book.card = Source::from_args(args.card_seed, args.card_password);
        }
        if args.key_seed.is_some() {
            book.key = Source::from_args(args.key_seed, args.key_password);
        }
        book
    }

    /// Whether the session has the seed itself, given or resolved
    pub(super) fn has_seed(&self) -> bool {
        self.seed.known()
    }

    /// Adopt a freshly minted seed for the rest of the session
    pub(super) fn adopt(&mut self, seed: MnemonicSeed) {
        self.seed = Source::Resolved(seed);
    }

    /// The roots a command derives from, resolving each seed it takes at most once
    ///
    /// A seed the command takes only when known is never asked for: a listing must not stop
    /// on a prompt. One phrase in both roles is stretched once.
    pub(super) fn roots(
        &mut self,
        (card, key): (SeedUse, SeedUse),
        interactive: bool,
    ) -> Result<Roots> {
        let card_source = if matches!(self.card, Source::Absent) {
            None
        } else {
            Some(())
        };
        let key_source = if matches!(self.key, Source::Absent) {
            None
        } else {
            Some(())
        };

        let wants = |usage: SeedUse, known: bool| match usage {
            SeedUse::Required => true,
            SeedUse::IfKnown => known,
            SeedUse::Unused => false,
        };

        // The seed itself, where either role falls back to it
        let seed_known = self.seed.known();
        let needs_seed = (card_source.is_none() && wants(card, seed_known))
            || (key_source.is_none() && wants(key, seed_known));
        let seed = if needs_seed {
            Some(self.seed.resolve("seed", interactive)?)
        } else {
            None
        };
        let shared_root = seed.as_ref().map(MnemonicSeed::seed);

        let card_root = match card_source {
            None if wants(card, seed_known) => shared_root.clone(),
            Some(()) if wants(card, self.card.known()) => {
                Some(self.card.resolve("card seed", interactive)?.seed())
            }
            _ => None,
        };
        let (key_root, key_entropy) = match key_source {
            None if wants(key, seed_known) => {
                (shared_root, seed.as_ref().map(MnemonicSeed::entropy_bits))
            }
            Some(()) if wants(key, self.key.known()) => {
                let key = self.key.resolve("key seed", interactive)?;
                (Some(key.seed()), Some(key.entropy_bits()))
            }
            _ => (None, None),
        };
        Ok(Roots { card: card_root, key: key_root, key_entropy })
    }
}

/// Resolve a seed that one command takes on its own, like the key seed a rotation moves off
pub(super) fn resolve_one(
    phrase: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    which: &str,
    interactive: bool,
) -> Result<Option<SecretSeed>> {
    match Source::from_args(phrase, password) {
        Source::Absent => Ok(None),
        mut source => Ok(Some(source.resolve(which, interactive)?.seed())),
    }
}

/// The seed id of a root, as `check` shows it and a record keeps it
pub(super) fn seed_id(root: &Seed256) -> String {
    root.seed_id()
}

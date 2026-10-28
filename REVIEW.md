# Review of v1 (1.0.0-rc.1), 2026-10-22

A review of the whole codebase ahead of the release, by layer, and what came of each finding.
It complements [HUMAN.md](HUMAN.md), whose review guide it follows: the same layers, the
same order.

## How it was done

Five reviewers, one per layer, each with the specification chapters of the book for its
layer and [AGENTS.md](AGENTS.md):

| Layer | Scope |
|---|---|
| Derivation | `src/seed.rs`, `src/mnemonic.rs`, `src/rsa.rs`, the golden vectors, `docs/derivation.md` |
| PIV | `src/piv/`, `tests/piv/`, `tests/piv_hardware/` |
| OpenPGP | `src/pgp/`, `src/ownership.rs`, `src/readers.rs`, `tests/pgp*` |
| Command line | `src/cli/`, `src/prompt.rs`, `src/qr.rs`, `tests/cli.rs` |
| Image, packaging, docs | `flake.nix`, `nix/`, `Cargo.toml`, `deny.toml`, CI, `README.md`, `TODO.md`, `HUMAN.md`, `docs/` |

The review was read-only and touched no card: tests and the binary ran with PC/SC out of
reach (`PCSCLITE_CSOCK_NAME=/nonexistent/pcscd.comm`), and nothing was built into a VM. Each
finding was confirmed by tracing the code or by running the binary or the tests, or marked
plausible where only the code path was shown. Every finding was then checked again before it
was acted on, and each fix that changes behaviour comes with a test.

43 findings: 2 high, 16 medium, 24 low, 1 informational. All 43 are fixed.

## What moved

Some fixes change what the tool writes, all before 1.0, so no key moves but the cards and
certificates provisioned before them differ from what the same seeds give now (re-provisioning
was due anyway, see HUMAN.md):

- Every PIV certificate: the serial now hashes everything the certificate says (P3), and the
  root's path length is fixed (P1). The golden vectors in `tests/piv/golden.rs` and the root
  digest in `tests/cli.rs` are re-pinned; the key digests beside them did not change.
- The CHUID's Card UUID carries the RFC 4122 version 4 and variant bits (P11); its vector in
  `src/piv/keys.rs` is re-pinned.
- PIV revocation lists carry a CRL number and the authority key identifier (P4).
- Ed25519 keys out of `ungap` are PKCS#8 version 1 (P10).

## Derivation

The scheme came out clean: no label collision, no domain-separation gap, no two inputs
deriving one key. The RSA procedure as the book specifies it was recomputed independently and
reproduced the pinned 2048 and 3072 bit moduli.

| | Severity | Finding | Outcome |
|---|---|---|---|
| D1 | medium | The root derivation copied the seed's password into a salt buffer that was freed unwiped; NFKD normalization could leave partial copies while growing. | Fixed: the salt is `Zeroizing`, and the NFKD string is sized up front. |
| D2 | low | A `--date` before 1970 derived under its own label but read back as 1970-01-01, so `rotate` would aim at the wrong previous generation; years past OpenPGP's 32-bit time failed late. | Fixed: dates outside 1970-01-01 to 2106-02-07 are refused when parsed. Test `dates_outside_the_creation_times_are_refused`. |
| D3 | low | The SHAKE256 state that determines both RSA primes was not wiped: `sha3` was built without its `zeroize` feature. | Fixed: the feature is on. |
| D4 | low | The book omitted the P-256 scalar rejection (`key:p256-retry`), and attributed the RSA candidate bound to FIPS 186-5, which bounds half as many. | Fixed: a P-256 section in `docs/derivation.md`; the bound is described as twice FIPS's. |
| D5 | info | Under `--legacy`, an empty subkey id is no subkey id (frozen mtg0 behaviour), so `-k ""` silently addressed the card without one. | Fixed: refused, as subkey id 0x01 already was. Covered in `algorithm_selects_the_keys`. |

## Command line

| | Severity | Finding | Outcome |
|---|---|---|---|
| C1 | medium | In a session, a config file's `[piv]`/`[pgp]` value beat `set` and the environment, against the documented precedence; one-shot runs were right. | Fixed: defaults are kept per layer (image file, user file, environment, `set`), and a table wins only within its own layer or a stronger one. Unit test `a_stronger_layer_beats_a_weaker_table`. |
| C2 | medium | A ceremony step naming a secret was shown and written to the `--record` transcript before it was refused. | Fixed: every planned step is checked before anything is shown, recorded or run, and the refusal names the line, not its text. `ceremony_files_hold_no_secrets` now runs with `--record` and asserts nothing leaked. |
| C3 | medium | In plumbing mode, material without `--to` went to the QR viewer, which waits for a key. | Fixed: refused with "pass a file with --to". Test `plumbing_shows_no_qr_codes`. |
| C4 | low | A session line `--card-seed PHRASE` (a space instead of `=`) echoed the phrase's first word in clap's error. | Fixed: a word after a bare seed flag counts as naming a seed. Covered in `repl_rejects_secret_arguments`. |
| C5 | low | `pin --dry-run` demanded the pins, so a dry run of a ceremony stopped at a `pin` step. | Fixed: a dry run needs no pin. Test `a_pin_dry_run_needs_no_pins`. |
| C6 | low | The book said revocations never go to stdout; the PIV list, being public, does. | Fixed in `docs/commands.md`. |
| C7 | low | A trailing `# comment` in a ceremony became a dependency or an argument, though the book says `#` starts a comment. | Fixed: `#` starts a comment where a shell word would, outside quotes. Unit test `comments_end_a_line`. |
| C8 | low | `run --dry-run` appended `--dry-run` to a step that already had it, which clap refused. | Fixed: appended only when missing. |
| C9 | low | `unset` dropped a config file's value too, against its help text. | Fixed with C1: `unset` drops the value in force and goes back to the layer beneath. Unit test `unset_goes_back_a_layer`; help and book updated. |
| C10 | low | A bad value in a config file surfaced later as an error about a flag nobody typed, without naming the file. | Fixed: values are checked by each option's parser as the file is read. Covered in `config_files_refuse_what_is_no_default`. |

## PIV

| | Severity | Finding | Outcome |
|---|---|---|---|
| P1 | high | The root's path length was 0 without `--intermediate` and 1 with it, so the root an identity keeps for good existed as two certificates under one serial, and chains of a device with an issuing authority failed against the root published from one without. | Fixed: the root always asserts `pathLenConstraint: 1`. `chain_is_two_tier_by_default` asserts the root is the same either way. |
| P2 | medium | With `--intermediate`, the issuing authority signs no revocation list and its certificates name none, so verifiers that check revocation refuse the slot certificates below it. | Fixed: with `--crl-url`, each issuing authority signs its own list, empty for good (revocation happens at the root) and never due, so it is the same bytes however often it is signed and is published once next to the root's; its certificates name it. Tests `every_certificate_of_three_tiers_has_its_list` (OpenSSL, `-crl_check_all`) and `nss_checks_every_certificate_of_three_tiers` (NSS's vfychain, fresh lists required) accept the chain with both lists, refuse it without the authority's, and refuse it once the root revokes the authority. |
| P3 | medium | Serials hashed subject, key and validity only, so a certificate re-issued with other emails, another list URL or another issuer reused its predecessor's serial. | Fixed: the serial hashes the whole to-be-signed certificate, built once with a placeholder serial. `serials_name_the_certificate_not_the_key` covers emails and the URL. The book now says `revoke` has to be given the options the certificates were issued with. |
| P4 | medium | Revocation lists lacked the CRL number and authority key identifier RFC 5280 requires. | Fixed: both are written, the number being the second the list was signed in, and a clock that reads before the identity or the list being replaced is refused. Covered in `revocation_lists_accumulate_and_refuse_strangers`. |
| P5 | medium | A YubiKey was recognised by its reader's name, so one held to an NFC reader skipped the firmware checks and `init` could reset it before an import failed. | Fixed: a card that lists no algorithms and reports YubiKey firmware (4.x or 5.x) is judged by the firmware table. |
| P6 | medium | A short CHUID or CCC object made the pinned yubikey crate slice out of bounds and panic, for every verb that reads ownership. | Fixed: both are read as plain objects and compared by prefix. |
| P7 | low | `pin` only warned at one try left, though the book says it refuses to spend the last try. | Fixed on both applets: refused, pointing at `pin --reset`. |
| P8 | low | `pin` read an already verified pin (another program on a shared connection) as blocked. | Fixed: the tries come from GET METADATA where the card has it, and a bare zero from the empty VERIFY decides nothing. |
| P9 | low | The revocation section of `docs/multiple-cards.md` predated `--crl-url`. | Fixed. |
| P10 | low | Ed25519 keys were exported as PKCS#8 version 2 with the public key, which OpenSSL 1.1 and other older readers refuse. | Fixed: version 1, the seed alone, as for X25519. Unit test `ed25519_is_written_as_version_one`. |
| P11 | low | The CHUID GUID was 16 derived bytes, not a valid UUID as SP 800-73-4 asks. | Fixed: the version 4 and variant bits are set; 122 bits stay derived. |
| P12 | low | `rotate` archived a re-derived certificate for the old decryption key, which differs from the published one if names or validity changed between generations. | Fixed: the certificate the card held for that key is archived, the derived one only standing in where there is none. |
| P13 | low | The key history object counts retired keys up to the highest retired slot used, through empty ones below it, where middleware then finds nothing. | Fixed: `upload --slot` refuses a retired slot with an empty one below it and names the first free one, so retired keys always fill the slots from 82 up, as SP 800-73-4 has them. A slot already holding the key is accepted, so an earlier arrangement uploads again as it is. Unit test `the_key_history_covers_every_retired_key`. |

## OpenPGP

| | Severity | Finding | Outcome |
|---|---|---|---|
| G1 | high | `--validity` without a generation date bound subkeys created at the epoch, so `publish` wrote certificates that expired in 1971; the PIV leaves had the same flaw. | Fixed: a validity without `--date` or `--identity-date` is refused on every verb. Test `a_validity_needs_a_date`; `docs/best-practice.md` says why. |
| G2 | medium | Under `--legacy`, `pin --reset` and `wipe` refused every legacy card with private-use data objects, since ownership was judged without the keys. | Fixed: the legacy scheme's cards are told by the derived fingerprints. |
| G3 | medium | After `--policy strict`, `upload --policy relaxed` accepted touch-always as satisfying cached touch and changed nothing on a YubiKey 5. | Fixed: cached touch is aimed for where the card takes it (Yubico, OpenPGP 3.4), the plain variant elsewhere, and a card that still refuses is settled with the closest it took, with a note. Unit test `a_plain_on_satisfies_cached_only_where_the_card_lacks_it`. |
| G4 | medium | The book says `check` warns about policies other than `--policy`; the OpenPGP check only listed them. | Fixed: touch and signing pin differences are warned about, as on PIV. |
| G5 | low | `init --legacy` installed an admin pin no later legacy verb derives. | Fixed: refused, pointing at the migration path. Test `init_refuses_the_legacy_scheme`. |
| G6 | low | On a card that shows no touch flags (Gnuk), `upload --policy` planned the touch on every run. | Fixed: nothing is planned where nothing can be compared, with a note. Unit test `a_card_without_touch_flags_is_not_held_to_one`. |
| G7 | low | `primary_cert`'s comment contradicted which published certificates carry the direct key signature. | Fixed the comment. |

## Image, packaging and docs

| | Severity | Finding | Outcome |
|---|---|---|---|
| N1 | medium | The book said no downloader is on the image, but NixOS puts curl on every system; the test checked for wget. | Fixed: the book and comments say the firewall holds the gap; the vacuous assertion is gone, the end-to-end ping stays. |
| N2 | medium | The NixOS module accepted any config the tool would refuse, leaving every command on the image failing; the banner's recipe detection did not follow the tool's grammar. | Fixed: the module has the tool read the config at build time, and checks the ceremony with the new `run --check`, which plans every recipe and refuses secrets and nested runs without touching a card. Test `a_ceremony_is_checked_without_running`. |
| N3 | low | `forget` cleared kmscon's scrollback only through `tput reset`'s RIS, which the script treated as optional. | Fixed: RIS is sent explicitly, with the reason. |
| N4 | low | `env_logger`'s default features pulled in jiff for timestamps the logger turns off. | Fixed: default features off. |
| B1 | medium | Every chapter writes to `/media/usb/`, but nothing on the image mounts a stick and no chapter said how. | Fixed: "The transfer stick" in `docs/linux.md`, linked from the first card walkthrough. |
| B2 | medium | The PIV checklist's OpenSSL steps used the libp11 engine; the dev shell ships the pkcs11 provider. | Fixed: rewritten for the provider, as the suite drives it. |
| B3 | low | Stale statements in the PIV checklist: a `--no-touch-mgm` that does not exist, test counts of binaries long gone. | Fixed. |
| B4 | low | `docs/hardware-tests.md` listed four of six PIV checks, and claimed refusals for Gnuk that the check did not assert. | Fixed: all six listed; the Gnuk check asserts the RSA-3072 and RSA-4096 refusals too. |

## Found sound

Besides the findings, the reviewers reported as sound, among others: the label grammar and the
separation of card seed and key seed; argon2id parameters and salts; the golden vectors pinning
what they claim; X.509 profiles, deterministic signatures and the PBES2 export (decrypted by
OpenSSL); the upload plans being re-made on the opened card and empty after a write; the
admin pin's last try being guarded; the KDF data object setup; one-shot commands never
prompting; plumbing keeping stdout for reports; secrets never becoming defaults, never
entering session history and going to the alternate screen; output file permissions; untrusted
card text sanitized; the image's air gap (firewall, locked module loading, no swap, no
persistence, pstore off); CI actions pinned by commit; git dependencies pinned and allowlisted.

## Verification

`cargo fmt --check`, clippy with and without `destructive-hardware-tests`, the full test suite
and `nix flake check` pass on the result. No hardware suite was run for the fixes; the next
hardware runs (TODO.md) cover them on real cards.

## The book, reorganized

Before 1.0 the book was reorganized by reader rather than by command: getting started (the
first card, the live image, the machine after the gap, the flows), guides, reference, design,
testing and releases, each topic in one chapter that owns it and the others linking there. The
result was then read by three independent reviewers against the code, and their confirmed
findings were fixed: messages quoted as the source has them, facts the move had dropped put
back in their new owners, the upgrade from 0.x spelled out in full, and the re-provisioning of
cards from before 1.0.0-rc.1 back in the compatibility chapter.

Merging chapters that had grown apart brought out places where two of them said different
things. Each was settled by the code, and the book now says one thing:

| | Contradiction | Kept | Evidence |
|---|---|---|---|
| R1 | The introduction counted six steps to a first card, the walkthrough has seven | seven | `docs/quick-start.md`, sections 1 to 7 |
| R2 | The PIV suite was said to ask for three touches | a touch at `upload`, at `check`, at the signatures and the key agreement on the card, and at each end-use step | the module documentation and the `TOUCH` prompts in `tests/piv_hardware/main.rs` |
| R3 | The checklist's automation was "most of sections 1 to 4" in one place and sections 1 to 5 in another | sections 1 to 5, as the twelve numbered steps of `provision_and_verify_card` | steps `[1/12]` to `[12/12]` in `tests/piv_hardware/main.rs` |
| R4 | "Decryption on card succeeds" was a passed item next to the note that it fails upstream | the item is the 9D key agreement through PKCS#11; decryption through OpenSSL is blocked upstream | `key_agreement_through_pkcs11` in `tests/piv_hardware/end_use.rs`, openssl/openssl#24698 |
| R5 | NSS decryption on the card was "not matched to an upstream bug" | it fails through NSS too, from two upstream bugs, in OpenSC's ECDH derive and NSS's fallback | the reproduction recorded in `TODO.md` |
| R6 | The automation table's section 3 had only 9A signing | 9A and 9C sign and verify | `authentication_slot_signs` and `signature_slot_signs`, step 7 of `tests/piv_hardware/main.rs` |
| R7 | The builds before rc.1 were called release candidates | they were unreleased builds of the 1.0 branch; rc.1 is the first release candidate | `version = "1.0.0-rc.1"` in `Cargo.toml`, the first version the branch released |
| R8 | The issuing authority's own revocation list read as written by `revoke` | `publish --part crl` writes it, next to the root's | `Part::Crl` and `issuing_revocation_list` in `src/cli/verbs/files.rs` |
| R9 | The NSS fixture's ten-year validity was said to be long past | its certificates are dated at the epoch, so any finite validity has run out | the epoch fixture noted in `tests/piv_hardware/end_use.rs` |
| R10 | The seed table listed `wipe` among the verbs that take the card seed, `--force` or not | it takes no seed | `Verb::Wipe { force: true, .. } => (Unused, Unused)` in `seed_use`, `src/cli/mod.rs` |
| R11 | An unattended host's signing slot was 9D in one place and 9C in another | it signs with 9C, whose certificate is the one issued for signatures; 9D only agrees on keys | `docs/after-the-gap.md`, signing with 9C, and the 9C and 9D key usages in `docs/piv-certificates.md` |

## The code, restructured

Before 1.0 the code was restructured without moving a key: each key is derived once per
builder and only when a command uses it, the plan's keys are carried into the write instead
of derived again, what both backends do with a card sits behind the `Applet` and `Backend`
traits with one update plan, each backend owns its pin rules, the long verbs are cut into
named steps, and the command line and hardware tests are split by what they drive. No golden
vector changed. `ungap` with RSA-4096 went from 8.1 to 4.5 seconds and `check` from 1.35 to
0.55, and the test suites take about half as long.

Three independent reviewers then read the change against its base. Each confirmed that no
pinned value was edited, that every cache is keyed by what derives it and reset with the
algorithm, that card seed and key seed stay apart, that the write path still re-plans on the
opened card and refuses a changed one, and that no test was lost in the split: the 59 command
line tests and the 18 hardware tests keep their names and assertions. What they found:

| | Finding | Resolution |
|---|---|---|
| S1 | `check --pin` held one pin to both applets' rules before showing anything, so a pin only OpenPGP takes hid the record and stopped the OpenPGP comparison | each applet is held to its own rule; one not named with `--app` is compared without a pin it cannot take, with a warning (`check_holds_a_pin_to_the_applet_it_fits`) |
| S2 | `publish --app piv --part identity --format ssh` failed, since the authorities alone no longer derive the authentication key | SSH takes the authentication key whatever the part, as before and as on OpenPGP (`publish_writes_every_format`) |
| S3 | The 9E key was cloned to sign its own certificate, and slot keys could be cloned anywhere | the certificate borrows the key; slot keys are not `Clone` |
| S4 | OpenPGP's pin rule applied at `init` and `check` but not at `pin` | `pgp::refuse_unfit_pin`, as on PIV, checked before a card is opened |
| S5 | `cli::install_logger` panics on a second call | documented: a logger set before it would log card traffic unfiltered |
| S6 | The wrong export passphrase is now tried on one key, not on each | kept: each try costs openssl 600,000 PBKDF2 rounds, every key is encrypted by the same code, and the right passphrase is still checked on every key |
| S7 | OpenPGP `read_state` fails where the card's AID cannot be read, also right after a write | kept: a card whose AID cannot be read cannot show its fingerprints either, and a plan built from empty reads would claim the write undone |
| S8 | The OpenPGP user pin is held as `Zeroizing<String>` instead of sequoia's encrypted `Password` | kept: it only ever goes to the card, as the `SecretString` the card API takes, the way PIV holds its pin |
| S9 | The trait impls forward to inherent methods of the same names | kept: the hardware suites drive both backends through the public traits, and the inherent methods stay private to their backend |

One finding predated the change: OpenPGP P-256 signatures were not reproducible, since
sequoia signs ECDSA with a random nonce, though the keys and fingerprints were. P-256 signs
with RFC 6979 in `src/pgp/signer.rs` since, and `output_is_frozen` pins the output byte for
byte.

## The command line, reviewed

An ergonomics review drove the command line as a shell user would, and the changes it
proposed before 1.0 were made: `--validity` in calendar units alone (`d`, `w`, `mo`, `y`,
ending on the anniversary, a missing day clamped to the month's last) and without its `-v`;
the options a verb needs judged before any seed is stretched, all at once; `set` alone
showing the config files and the layer of each default, on the command line too;
`set --save` and `unset --save` writing the user's config file; help that shows a verb's own
options first, a session's help without the options a line cannot change, and the names
`set` takes; the recipes of a ceremony named; `--version` naming the scheme, and the
released image its revision; recipe completion in bash, zsh and fish, and tab completion in
the session; and an option reference rendered from the command line into the book, held
current by a test. No golden vector changed.

Three independent reviewers then read the change and drove the binary. What they found, and
what came of it:

| | Finding | Resolution |
|---|---|---|
| L1 | A validity ending after 2106-02-07 gave OpenPGP subkeys an expiry that wrapped into the past, with exit 0 | an end past 2106-02-07 is refused, before any seed is stretched |
| L2 | Tab after a non-breaking space panicked the session, and the panic echoed the line typed so far | completion cuts lines at character boundaries (`tab_completes_past_wide_whitespace`) |
| L3 | The config editor read `[ pgp ]` as the top level where the reader took it for the OpenPGP table | one tokenizer for both; a save that would change any pair but the ones asked for is refused |
| L4 | `set seed=...` was refused but stayed in the recallable history | a line setting a secret never enters the history |
| L5 | The `set` listing printed values as they were, so a value could draw a line of its own | the listing escapes what it shows; the file escapes every control character |
| L6 | `unset --save` wrote the file when nothing was removed; `--config NEW set --save` could not create it; a read-only file was replaced | written only when something changed; `--save` creates a missing `--config` file; a read-only one is refused |
| L7 | The session hid `--card-seed`, `--key-seed` and `--from-key-seed`, which a line takes bare and the book shows | shown, with session wording; only `--seed` and the passwords are hidden |
| L8 | A setting took `yes` and `no` beside `true` and `false` | `true` and `false` alone |
| L9 | Recipe completion ignored a `ceremony` default in the config file | read in the order `run` reads it |
| L10 | A suggested name lost its `piv.` or `pgp.` table | kept |
| L11 | The validity's new calendar, and `check` failing before its record without a name, were not in the release notes | both in the notes, with the repair for a config file in the old form |
| L12 | A symlinked config directory is written through | kept: dotfile managers link that directory on purpose, and a link to the file itself is still refused |
| L13 | A rotation off an undated generation re-issues that generation's certificate without an end | kept: it reproduces the certificate the card was given, which had none |


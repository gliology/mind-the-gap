# Working agreements

How work is done in this repository, for any agent or contributor. These are standing
decisions, not suggestions; when one must bend, say so explicitly rather than quietly.

## Commits and history

- Message style: `area: lowercase summary`, then a prose body that explains *why*, with
  bullets only for enumerating member changes. No double-dash em-dashes in new text.
- Commits are atomic and themed. Before review, history is compacted aggressively:
  fix-ups fold into the commit they correct, and whole branches are rewritten into a
  handful of narrative theme commits. Every rewrite starts from a backup branch and ends
  with a byte-identical tree check, and backups are deleted only after CI is green.
- Features that were tried and dropped are folded out of history entirely and never
  mentioned again, in commits or docs.

## Prose and documentation

- Comments explain why, never what the next line does. Code reads like the surrounding
  code.
- The README stays a landing page and duplicates nothing: user documentation lives in
  the mdBook under `docs/`, developer documentation in rustdoc on the items themselves,
  open items in `TODO.md`.

## Security UX

- A one-shot invocation never prompts and never hangs: a missing required secret is an
  error that names the ways out. The interactive session is the interface that asks,
  once per session, on the controlling terminal with no echo.
- Secrets are never logged, echoed back, or invented implicitly; no command mints key
  material except `generate`, which does not let go until the phrase is proven written
  down.
- Secrets are never banned from the command line or the environment: that interface is
  for experts and scripts, and the docs spell out what it exposes. The session line
  guard (which keeps secrets out of recallable history) is the one exception and stays.
- Anything secret shown on a terminal goes to the alternate screen and is gone from
  scrollback when dismissed; untrusted text is sanitized before it is printed.

## Compatibility

- Derivation is a consensus surface. The argon2 parameters, the label grammar, the
  scheme stamp and the sha2 generation are frozen constants of the current scheme
  (`mtg1`); changing any of them moves every key and ships only as a new scheme behind
  a new major version. The golden-vector tests are that promise in executable form.
- Protocol identifiers (AIDs, data objects, status words) are compatibility surfaces
  shared with other implementations and are never changed casually.

## Dependencies

- Every dependency carries a comment saying why it exists. Default features are
  disabled wherever the defaults pull unused trees.
- Forks and git dependencies are pinned by revision, never by tag, and allowlisted in
  `deny.toml`. `cargo deny`, `cargo machete` and `typos` run as flake checks and stay
  green.

## Verification bar

Before any push: `cargo fmt --check`, `cargo clippy --all-targets -- --deny warnings`,
the full test suite, and `nix flake check` (which also boots the live image and
provisions virtual OpenPGP and PIV cards). After any force-push: wait for CI before
deleting backups. The destructive hardware suites run only against a card named
explicitly by its serial, never auto-picked.

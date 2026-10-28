//! Derive OpenPGP and PIV smart card keys, certificates and pins from a BIP39 mnemonic.
//!
//! Everything a card carries descends from one phrase through argon2id: the base layer
//! ([`mnemonic`], [`seed`]) turns the phrase into a tree of labelled 256 bit seeds, the
//! backends ([`pgp`], [`piv`], alike where [`backend`] says) turn subtrees of it into key
//! material and certificates and move them onto hardware, and the frontend ([`cli`], with
//! its terminal prompts and QR viewer) is the interface the binary wires together.
//!
//! Unix only: secrets are read from and shown on the controlling terminal, `/dev/tty`.
//!
//! This rustdoc is the developer reference; the user guide and the design rationale live in
//! the book at <https://gliology.github.io/mind-the-gap/>.
#![warn(missing_docs)]

// Import base library
pub mod mnemonic;
pub mod revocation;
pub mod role;
pub mod rsa;
pub mod seed;
pub mod target;
// Import frontends
pub mod cli;
pub(crate) mod common;
pub mod ownership;
pub mod policy;
pub(crate) mod prompt;
pub(crate) mod qr;
pub(crate) mod readers;
// Import backends
pub mod backend;
pub mod pgp;
pub mod piv;

//! Derive OpenPGP and PIV smart card keys, certificates and pins from a BIP39 mnemonic.
//!
//! Everything a card carries descends from one 24 word phrase through argon2id: the base
//! layer ([`mnemonic`], [`seed`]) turns the phrase into a tree of labelled 256 bit seeds,
//! the backends ([`pgp`], [`piv`]) turn subtrees of it into key material and certificates
//! and move them onto hardware, and the frontends ([`cli`], [`prompt`], [`qr`]) are the
//! interface the binary wires together.
//!
//! This rustdoc is the developer reference; the user guide and the design rationale live in
//! the book at <https://gliology.github.io/mind-the-gap/>.
#![warn(missing_docs)]

// Import base library
pub mod mnemonic;
pub mod seed;
// Import frontends
pub mod cli;
pub(crate) mod common;
pub mod prompt;
pub mod qr;
// Import backends
pub mod pgp;
pub mod piv;

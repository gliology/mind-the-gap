pub mod mnemonic;
pub mod openpgp;

/// Constant to be used in all 256bit seed derivations
const SEED256_DERIVATION_ID : &[u8] = b"MINDTHEGAP256HDKD";

/// Base trait for 256-bit seed generation
pub trait Seed256 {
    fn seed(&self, path: Option<&str>) -> [u8; 32]; 
}

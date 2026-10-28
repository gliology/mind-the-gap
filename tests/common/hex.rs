//! Bytes in lowercase hex, as the pinned digests are written.

/// `bytes` in lowercase hex
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

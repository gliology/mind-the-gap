use mind_the_gap::seed::argon2id_256;

const DEFAULT_INPUT: &[u8] = b"Mind the gap, bro!";
const DEFAULT_HASH: [u8; 32] = [
    69, 6, 89, 187, 211, 68, 70, 103, 165, 93, 159, 125, 3, 143, 87, 131, 100, 182, 100, 74, 66,
    164, 77, 185, 134, 43, 254, 191, 239, 58, 128, 151,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2() {
        assert_eq!(*argon2id_256(DEFAULT_INPUT, None), DEFAULT_HASH);
    }

    /// Report the wall-clock cost of one derivation.
    ///
    /// The parameters (64 MiB, t=3) are a security property: every secret flows through
    /// this funnel, and each level of the derivation tree costs one pass, so knowing when
    /// the price moves matters in both directions. Ignored by default because wall-clock
    /// time is machine-dependent -- this prints, it does not assert:
    ///
    /// ```text
    /// cargo test --test argon -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "benchmark: prints the per-derivation cost, nothing to assert"]
    fn derivation_cost() {
        const ROUNDS: u32 = 10;

        let start = std::time::Instant::now();
        for index in 0..ROUNDS {
            argon2id_256(DEFAULT_INPUT, Some(&index.to_le_bytes()));
        }

        eprintln!(
            "argon2id_256: {:?} per derivation over {ROUNDS} rounds",
            start.elapsed() / ROUNDS
        );
    }
}

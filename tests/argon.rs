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
        assert_eq!(argon2id_256(DEFAULT_INPUT, None), DEFAULT_HASH);
    }

    // TODO: Bring back benchmarking
    /*
    #[bench]
    fn bench_argon2(b: &mut Bencher) {
        b.iter(|| argon2id_256(DEFAULT_INPUT, None));
    }
    */
}

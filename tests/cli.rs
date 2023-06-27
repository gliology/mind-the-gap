use mind_the_gap::cli::cmd;

#[cfg(test)]
mod cli {
    use super::*;

    #[test]
    fn cmd_debub_assert() {
        cmd().debug_assert()
    }
}

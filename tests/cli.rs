use mind_the_gap::cli::command;

#[cfg(test)]
mod cli {
    use super::*;

    #[test]
    fn cmd_debub_assert() {
        command().debug_assert()
    }
}

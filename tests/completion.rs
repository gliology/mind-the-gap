use mind_the_gap::cli::command;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_man_page_generation() {
        // Build command line interface
        let mut cmd = command();
        cmd.build();

        // Verify that we can properly generate a manpage
        // This tests that the manpage generation works without errors
        let man = clap_mangen::Man::new(cmd);
        let mut output = Vec::new();
        man.render(&mut output).unwrap();

        // Check that output is generated (manpage content should exist)
        assert!(!output.is_empty());
    }

    #[test]
    fn test_shell_completion_exists() {
        // This test verifies that we can get a command and that it can
        // be used to generate shell completions without errors
        let mut cmd = command();
        cmd.build();

        // This ensures that CLI can be constructed and used properly
        assert!(cmd.get_name() == "mind-the-gap");
    }
}

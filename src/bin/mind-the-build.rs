use std::path::PathBuf;

use clap::{Command, Parser, ValueEnum};

use clap_complete::Shell;
use clap_mangen::Man;

#[derive(Parser, Debug)]
#[command(author, version)]
struct OutputConfig {
    /// Prefix of output path of man page and completion
    prefix: std::path::PathBuf,
}

/// Helper command to easily write manpage of command to directory
fn generate_man_to(cmd: &Command, dir: PathBuf) -> std::io::Result<()> {
    let name = cmd.get_display_name().unwrap_or_else(|| cmd.get_name());
    let mut file = std::fs::File::create(dir.join(format!("{name}.1")))?;

    let man = Man::new(cmd.clone());
    man.render(&mut file)?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Parse command lone
    let OutputConfig { prefix } = OutputConfig::parse();

    // Build command line interface
    let mut cmd = mind_the_gap::cli::command();
    cmd.build();

    // Export manpage for ...
    let mandir = prefix.join("share/man/man1");

    println!("Exporting manpage to '{}'...", mandir.display());

    std::fs::create_dir_all(mandir.clone())?;

    // - Main executable ...
    generate_man_to(&cmd, mandir.clone())?;

    // - ... and each backend ...
    for subcmd in cmd.get_subcommands() {
        generate_man_to(subcmd, mandir.clone())?;

        // - ... and each of the backend's commands
        for subsubcmd in subcmd.get_subcommands() {
            generate_man_to(subsubcmd, mandir.clone())?;
        }
    }

    // Export shell completions
    let name = cmd.get_name().to_string();

    for &shell in Shell::value_variants() {
        let suffix = match shell {
            Shell::Bash => Some("share/bash-completion/completions"),
            Shell::Fish => Some("share/fish/vendor_completions.d"),
            Shell::Zsh => Some("share/zsh/vendor-completions"),
            _ => None,
        };

        if let Some(path) = suffix {
            let compdir = prefix.join(path);

            println!("Exporting completion to '{}'...", compdir.display());

            std::fs::create_dir_all(compdir.clone())?;
            clap_complete::generate_to(shell, &mut cmd, &name, compdir)?;
        }
    }

    Ok(())
}

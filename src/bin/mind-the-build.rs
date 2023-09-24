use clap::{Parser, ValueEnum};

use clap_mangen::Man;
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[command(author, version)]
struct OutputConfig {
    /// Prefix of output path of man page and completion
    prefix: std::path::PathBuf,
}

fn main() -> std::io::Result<()> {
    // Parse command lone
    let OutputConfig { prefix } = OutputConfig::parse();

    // Build command line interface
    let mut cmd = mind_the_gap::cli::command();
    let name = cmd.get_name().to_string();

    // Export manpage
    let man = Man::new(cmd.clone());
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    let mandir = prefix.join("share/man/man1");

    println!("Exporting manpage to '{}'...", mandir.display());

    std::fs::create_dir_all(mandir.clone())?;
    std::fs::write(mandir.join(format!("{name}.1")), buffer)?;

    // Export shell completions
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

use std::io::Write;
use std::path::Path;

use clap::{Command, Parser};

use clap_complete::Shell;
use clap_mangen::Man;

/// Where the documentation site lives, linked from every man page
const DOCS_URL: &str = "https://gliology.github.io/mind-the-gap/";

/// Shells to generate completions for, and where each expects them
///
/// Spelled out rather than filtered from `Shell::value_variants`, so a shell clap adds later
/// is a deliberate decision here rather than something silently dropped.
const COMPLETIONS: [(Shell, &str); 3] = [
    (Shell::Bash, "share/bash-completion/completions"),
    (Shell::Fish, "share/fish/vendor_completions.d"),
    (Shell::Zsh, "share/zsh/vendor-completions"),
];

#[derive(Parser, Debug)]
#[command(author, version)]
struct OutputConfig {
    /// Prefix of output path of man page and completion
    prefix: std::path::PathBuf,
}

/// Whether a subcommand is worth a man page of its own
///
/// `help` is clap's built-in, and rendering it produces pages with an empty NAME and a
/// malformed header -- `mind-the-gap-help-help(1)` being the reductio.
fn is_documented(cmd: &Command) -> bool {
    cmd.get_name() != "help"
}

/// Write the man page for one command, cross-referencing the pages around it
fn generate_man_to(cmd: &Command, dir: &Path, related: &[String]) -> std::io::Result<()> {
    let name = cmd.get_display_name().unwrap_or_else(|| cmd.get_name());
    let mut file = std::fs::File::create(dir.join(format!("{name}.1")))?;

    // Hide rather than remove: `help` stays a working command, it just does not appear in the
    // rendered SUBCOMMANDS list, which would otherwise cross-reference a page we do not write.
    // Leaf commands have no `help` of their own, and `mut_subcommand` panics on a missing one.
    let documented = if cmd.get_subcommands().any(|sub| sub.get_name() == "help") {
        cmd.clone().mut_subcommand("help", |help| help.hide(true))
    } else {
        cmd.clone()
    };

    Man::new(documented).render(&mut file)?;

    // clap_mangen renders no SEE ALSO, and roff is append-only, so add one here rather than
    // reimplementing the rest of the page
    if !related.is_empty() {
        let refs: Vec<String> = related
            .iter()
            .map(|entry| format!("\\fB{entry}\\fR(1)"))
            .collect();

        writeln!(file, ".SH SEE ALSO")?;
        writeln!(file, "{}", refs.join(", "))?;
    }

    writeln!(file, ".PP")?;
    writeln!(file, "Full documentation at \\fI{DOCS_URL}\\fR")?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Parse command line
    let OutputConfig { prefix } = OutputConfig::parse();

    // Build command line interface
    let mut cmd = mind_the_gap::cli::command();
    cmd.build();

    // Export manpage for ...
    let mandir = prefix.join("share/man/man1");

    println!("Exporting manpage to '{}'...", mandir.display());

    std::fs::create_dir_all(&mandir)?;

    let display = |cmd: &Command| {
        cmd.get_display_name()
            .unwrap_or_else(|| cmd.get_name())
            .to_string()
    };

    let root = display(&cmd);
    let backends: Vec<String> = cmd
        .get_subcommands()
        .filter(|c| is_documented(c))
        .map(display)
        .collect();

    // - Main executable, pointing at each backend ...
    generate_man_to(&cmd, &mandir, &backends)?;

    // - ... and each backend ...
    for subcmd in cmd.get_subcommands().filter(|c| is_documented(c)) {
        let commands: Vec<String> = subcmd
            .get_subcommands()
            .filter(|c| is_documented(c))
            .map(display)
            .collect();

        let mut related = vec![root.clone()];
        related.extend(commands.iter().cloned());
        generate_man_to(subcmd, &mandir, &related)?;

        // - ... and each of the backend's commands, which point back up
        let parent = display(subcmd);
        for subsubcmd in subcmd.get_subcommands().filter(|c| is_documented(c)) {
            generate_man_to(subsubcmd, &mandir, &[parent.clone(), root.clone()])?;
        }
    }

    // Export shell completions
    let name = cmd.get_name().to_string();

    for (shell, suffix) in COMPLETIONS {
        let compdir = prefix.join(suffix);

        println!("Exporting completion to '{}'...", compdir.display());

        std::fs::create_dir_all(&compdir)?;
        clap_complete::generate_to(shell, &mut cmd, &name, compdir)?;
    }

    Ok(())
}

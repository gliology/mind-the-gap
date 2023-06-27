// Import helper to add shared commands
mod common;

// Import subcommand implementation
mod generate;
mod status;

mod openpgp;
mod piv;

use crate::cli::common::MindTheCommand;

use clap::{command, ArgMatches, Command};

use anyhow::{anyhow, Result};

// Helper trait for simple error reporting
pub trait ResultErrToString<T> {
    fn map_err_to_string(self) -> Result<T, String>;
}

impl<T, E: ToString> ResultErrToString<T> for Result<T, E> {
    fn map_err_to_string(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

/// Main command line parser
pub fn cmd() -> Command {
    command!()
        .propagate_version(true)
        // Optional common parameters
        .add_common_args()
        // General commands
        .subcommand(generate::subcmd())
        .subcommand(status::subcmd())
        // Backend-specific commands
        .subcommand(openpgp::subcmd())
        .subcommand(piv::subcmd())
}

/// Command line subcommand router function
pub fn run(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        // General commands
        Some(("generate", args)) => generate::subrun(args),
        Some(("status", args)) => status::subrun(args),
        // Backend-specific commands
        Some(("openpgp", args)) => openpgp::subrun(args),
        Some(("piv", args)) => piv::subrun(args),
        // Unknown subcommamd
        Some((name, _)) => Err(anyhow!("Unknown subcommand: {}", name)),
        // Otherwise run status, if no subcommand was specified
        _ => status::subrun(matches),
    }?;

    Ok(())
}

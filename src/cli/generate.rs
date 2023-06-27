use clap::{ArgMatches, Command};

use anyhow::Result;

use crate::mnemonic::MnemonicSeed;

pub fn subcmd() -> Command {
    Command::new("generate").about("Provide random mnemonic seed")
}

pub fn subrun(_matches: &ArgMatches) -> Result<()> {
    let seed = MnemonicSeed::new();
    println!("export MIND_THE_SEED='{}'", seed.phrase());

    Ok(())
}

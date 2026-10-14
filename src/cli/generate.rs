//! `generate`: a fresh phrase on the alternate screen, and the quiz that proves it was
//! written down.

use crate::mnemonic::MnemonicSeed;
use crate::prompt;
use crate::qr;

use std::io::Write;

use anyhow::{Result, anyhow};

/// Ignore SIGINT and SIGQUIT for a guard's lifetime, restoring the old handlers after
///
/// Death by signal skips every `Drop`, so a Ctrl-C while a secret is on the alternate
/// screen would strand the terminal with the secret still showing. During a ceremony
/// the keys simply do nothing; leaving is what the prompts are for.
#[cfg(unix)]
pub(super) struct IgnoreInterrupts(libc::sighandler_t, libc::sighandler_t);

#[cfg(unix)]
impl IgnoreInterrupts {
    fn install() -> Self {
        unsafe {
            Self(
                libc::signal(libc::SIGINT, libc::SIG_IGN),
                libc::signal(libc::SIGQUIT, libc::SIG_IGN),
            )
        }
    }
}

#[cfg(unix)]
impl Drop for IgnoreInterrupts {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.0);
            libc::signal(libc::SIGQUIT, self.1);
        }
    }
}

/// Mint a new seed phrase and hold it on screen until the user proves it is written down
///
/// Returns the minted seed so an interactive session can adopt it; the one-shot path
/// drops it, since a fresh phrase is only useful once it exists on paper anyway.
pub(super) fn generate(in_session: bool) -> Result<MnemonicSeed> {
    let seed = MnemonicSeed::generate()?;
    let words = seed.words();

    // The whole ceremony happens on the alternate screen of the controlling terminal,
    // never stdout: under `generate > file` a stdout phrase would land on disk, and on
    // the main screen it would survive in scrollback. The RAII guard restores a clean
    // display on every exit path, errors included, and Ctrl-C is ignored throughout
    // because a signal death would skip that restoration.
    #[cfg(unix)]
    let _guard = IgnoreInterrupts::install();
    let mut screen = qr::Screen::enter_cooked()?;

    loop {
        // Show the phrase, numbered for transcription
        writeln!(screen.tty)?;
        writeln!(screen.tty, "This is your new seed phrase. Write it down now, on paper:")?;
        writeln!(screen.tty)?;
        for (index, word) in words.iter().enumerate() {
            write!(screen.tty, "  {:>2}. {:<12}", index + 1, word)?;
            if (index + 1) % 4 == 0 {
                writeln!(screen.tty)?;
            }
        }
        writeln!(screen.tty)?;

        prompt::read_ack("Press enter once it is written down... ")?;

        // Wipe before the quiz, so answers come from paper and not from the screen
        screen.wipe()?;

        // Prove the copy is complete and readable before letting go of the phrase
        if quiz(&mut screen.tty, &words)? {
            break;
        }

        writeln!(
            screen.tty,
            "That did not match your phrase, compare your copy against the original:"
        )?;
    }

    // Leave the alternate screen before the parting words: they hold no secret and
    // should stay readable, while everything above vanishes with the screen
    drop(screen);

    let mut tty = prompt::tty()?;
    writeln!(tty, "Seed phrase confirmed.")?;
    if in_session {
        writeln!(tty, "The session keeps it for the commands that follow, until you leave.")?;
    } else {
        writeln!(tty)?;
        writeln!(tty, "To provision cards with it, run mind-the-gap without arguments: the")?;
        writeln!(tty, "interactive session asks for the phrase once and keeps it in memory")?;
        writeln!(tty, "until you leave. Scripts take it with --seed.")?;
    }

    Ok(seed)
}

/// Ask for a few randomly chosen words of the phrase
pub(super) fn quiz(tty: &mut impl Write, words: &[String]) -> Result<bool> {
    writeln!(tty, "Confirm your copy by answering from it below.")?;
    writeln!(tty)?;

    // Sampled from the OS generator like the phrase itself; rejection keeps them distinct
    let mut indices: Vec<usize> = Vec::new();
    while indices.len() < 3 {
        let index = getrandom::u32()
            .map_err(|err| anyhow!("Operating system entropy source failed: {err}"))?
            as usize
            % words.len();
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices.sort_unstable();

    for index in indices {
        // An accidental empty Enter re-asks instead of aborting the whole ceremony
        let answer = loop {
            match prompt::read_optional_secret(&format!("Word {}: ", index + 1))? {
                Some(answer) => break answer,
                None => continue,
            }
        };
        if answer.trim() != words[index] {
            return Ok(false);
        }
    }

    Ok(true)
}

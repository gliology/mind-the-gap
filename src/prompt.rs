//! Prompt for secrets on the controlling terminal, with echo disabled.
//!
//! The point of prompting is to keep the seed phrase and password out of argv, the
//! environment and shell history, all of which outlive the process. `rpassword` handles the
//! terminal itself -- it talks to `/dev/tty` where there is one, so the prompt works inside
//! pipelines, and zeroizes its own buffers. The wrappers here add the policy: everything
//! returned zeroizing, nothing empty where a value is required, and an empty answer
//! meaning "none" where the secret is optional.

use std::fs::File;
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};

use zeroize::Zeroizing;

/// Read one line from the controlling terminal without echoing it
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    read_optional_secret(prompt)?.ok_or_else(|| anyhow!("Nothing was entered"))
}

/// Read one optional line from the controlling terminal without echoing it
///
/// An empty answer is a valid one and means "none". For secrets that are genuinely
/// optional, like the derivation password, where [`read_secret`]'s refusal of empty
/// input would turn skipping into an error.
pub fn read_optional_secret(prompt: &str) -> Result<Option<Zeroizing<String>>> {
    let line = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .context("No terminal to prompt on, pass the value another way")?,
    );

    if line.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(line))
    }
}

/// Ask a visible (non-secret) question on the controlling terminal
///
/// For the session's identity questions: the prompt and the echoed answer belong on
/// the terminal, and reading from `/dev/tty` keeps a piped session's script lines
/// from being consumed as answers.
pub fn read_public(prompt: &str) -> Result<String> {
    use std::io::{BufRead, BufReader, Write};
    let mut out = tty()?;
    write!(out, "{prompt}")?;
    out.flush()?;
    let tty_in = std::fs::File::open("/dev/tty")
        .context("No terminal to prompt on, pass the value another way")?;
    let mut line = String::new();
    if BufReader::new(tty_in).read_line(&mut line)? == 0 {
        bail!("Terminal closed before the prompt was answered");
    }
    Ok(line.trim().to_string())
}

/// The controlling terminal itself, for ceremony output.
///
/// Anything secret that is *shown* rather than read -- the freshly minted phrase, and the
/// escape codes that wipe it afterwards -- must go here and not to stdout: under
/// `generate > file` a stdout phrase lands on disk while the "wipe" scrubs only the file,
/// and the ceremony still looks like it succeeded.
pub fn tty() -> Result<File> {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("No controlling terminal to prompt on")
}

/// Wait for enter on the controlling terminal, with echo left as it is.
///
/// For acknowledgements rather than secrets -- anything typed before the newline is read and
/// discarded.
pub fn read_ack(prompt: &str) -> Result<()> {
    let mut tty = tty()?;

    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;

    let mut byte = [0u8; 1];
    loop {
        if tty.read(&mut byte)? == 0 {
            bail!("Terminal closed before the prompt was acknowledged");
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            return Ok(());
        }
    }
}

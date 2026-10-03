//! Render byte blobs as terminal QR codes, the transfer path off an air-gapped machine.
//!
//! The preferred display is [`show_qr`]: the code takes over the terminal's alternate
//! screen and vanishes without a trace when dismissed, so a QR of a secret key never
//! lingers in scrollback, the same guarantee the `generate` ceremony gives the seed
//! phrase. Callers declare whether the payload is sensitive: public certificates may
//! fall back to plain stdout for pipes and oversized codes, while secret material only
//! ever reaches the controlling terminal and is refused when there is none.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use anyhow::{Result, anyhow, bail};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use qrcode::QrCode;
use qrcode::render::unicode;
use zeroize::Zeroizing;

use crate::prompt;

/// Render the data as a unicode QR image, inverted so it scans on dark terminals
///
/// Wrapped in `Zeroizing` because the payload may be key material: the image is a
/// pixel-for-pixel encoding of it, so it wipes like the secret it carries.
fn render(data: &[u8]) -> Result<Zeroizing<String>> {
    let code = QrCode::new(data)
        .map_err(|e| anyhow!("Data too large for QR code ({} bytes): {e}", data.len()))?;
    Ok(Zeroizing::new(
        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light) // inverted for dark terminals
            .light_color(unicode::Dense1x2::Dark)
            .build(),
    ))
}

/// Display the data as a QR code that leaves no trace, dismissed with Esc
///
/// On a terminal the code takes over the alternate screen and is gone from scrollback
/// the moment it is dismissed. The kernel console has no alternate screen, so there the
/// screen is cleared before and after instead; equivalent in effect, since modern
/// kernels keep no console scrollback at all.
///
/// A sensitive payload never reaches stdout: redirected output is refused instead of
/// writing key material to a file that skips `write_sensitive`'s permissions, and the
/// oversized fallback goes to the controlling terminal with a scrollback warning.
/// Public payloads simply print in both cases.
pub fn show_qr(data: &[u8], sensitive: bool) -> Result<()> {
    // The largest QR code carries 2953 bytes; say so up front instead of letting the
    // encoder's raw error surface, and name the way out
    if data.len() > 2953 {
        bail!("{} bytes exceed what one QR code can carry (2953), use --output", data.len());
    }
    let image = render(data)?;

    if !io::stdout().is_terminal() {
        if sensitive {
            bail!(
                "Refusing to write a secret-material QR code to a pipe or file, \
                 use --output for a protected file or run on a terminal"
            );
        }
        println!("{}", *image);
        return Ok(());
    }

    let height = image.lines().count() as u16;
    let width = image
        .lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as u16;
    let (cols, rows) = terminal::size()?;
    // One extra row for the dismissal hint
    if width > cols || height + 1 > rows {
        if sensitive {
            // Inline on the controlling terminal, never stdout: a redirect must not
            // catch key material by surprise
            let mut tty = prompt::tty()?;
            tty.write_all(image.as_bytes())?;
            writeln!(tty)?;
        } else {
            println!("{}", *image);
        }
        log::warn!(
            "QR code larger than the screen; reduce the terminal font size \
             (often Ctrl+Minus, Ctrl+Alt+Minus on the console) to fit it on one screen"
        );
        if sensitive {
            log::warn!(
                "The code was rendered inline, clear the scrollback once transferred \
                 (e.g. `clear && printf '\\e[3J'`, or `forget` on the live image)"
            );
        }
        return Ok(());
    }

    let mut screen = Screen::enter()?;

    let top = (rows - height) / 2;
    let left = (cols - width) / 2;
    for (i, line) in image.lines().enumerate() {
        execute!(screen.tty, cursor::MoveTo(left, top + i as u16))?;
        screen.tty.write_all(line.as_bytes())?;
    }
    execute!(screen.tty, cursor::MoveTo(left, top + height))?;
    write!(screen.tty, "\x1b[2m[Esc to dismiss]\x1b[0m")?;
    screen.tty.flush()?;

    wait_for_escape(&mut screen.tty.0)?;
    Ok(())
}

/// A write-only view of the tty: `execute!` needs a type that is unambiguously
/// `io::Write`, which a bare `File` (also `io::Read`) is not
pub(crate) struct Tty(pub(crate) File);

impl Write for Tty {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// The taken-over terminal: the alternate screen, optionally raw mode, restored on drop
///
/// Restoration lives in `Drop` so an error or panic between entering and dismissing
/// cannot strand the terminal raw or on the wrong screen. A SIGKILL still can; the
/// interactive guards disable what they can (the QR viewer swallows Ctrl-C as a
/// dismissal, the generate ceremony ignores SIGINT), and anything stronger is outside
/// a process's power.
pub(crate) struct Screen {
    pub(crate) tty: Tty,
    /// The kernel console ignores the alternate-screen sequences; leaving then means
    /// wiping instead, so nothing of the display survives on screen
    alternate: bool,
    /// Raw mode is only for the QR viewer's keypress loop; line-reading ceremonies
    /// stay cooked so rpassword's canonical reads keep working
    raw: bool,
}

impl Screen {
    /// Take over the terminal for the QR viewer: alternate screen plus raw mode
    pub(crate) fn enter() -> Result<Self> {
        let mut screen = Self::enter_cooked()?;
        terminal::enable_raw_mode()?;
        screen.raw = true;
        Ok(screen)
    }

    /// Take over the terminal for a prompting ceremony: alternate screen, cooked input
    pub(crate) fn enter_cooked() -> Result<Self> {
        let mut tty = Tty(prompt::tty()?);
        let alternate = std::env::var("TERM")
            .map(|term| term != "linux")
            .unwrap_or(true);
        if alternate {
            execute!(tty, EnterAlternateScreen)?;
        }
        execute!(tty, Clear(ClearType::All), Clear(ClearType::Purge), cursor::Hide)?;
        Ok(Self { tty, alternate, raw: false })
    }

    /// Wipe the taken-over screen, for ceremonies that clear between acts
    pub(crate) fn wipe(&mut self) -> Result<()> {
        execute!(self.tty, Clear(ClearType::All), Clear(ClearType::Purge), cursor::MoveTo(0, 0))?;
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.raw {
            let _ = terminal::disable_raw_mode();
        }
        let _ = execute!(self.tty, Clear(ClearType::All), Clear(ClearType::Purge), cursor::Show);
        if self.alternate {
            let _ = execute!(self.tty, LeaveAlternateScreen);
        }
    }
}

/// Block until a lone Esc (or Enter, q, or Ctrl-C) is pressed
///
/// Arrow and function keys also start with the Esc byte; what distinguishes a bare Esc
/// is silence afterwards. A short poll after each Esc byte settles it, and the rest of
/// a sequence is drained so it cannot leak into the next prompt as stray input. Raw
/// mode delivers Ctrl-C as a plain byte, so it dismisses too instead of killing the
/// process with the secret still on screen.
fn wait_for_escape(tty: &mut File) -> Result<()> {
    let mut byte = [0u8; 1];
    loop {
        tty.read_exact(&mut byte)?;
        match byte[0] {
            b'q' | b'\r' | b'\n' | 0x03 => return Ok(()),
            0x1b => {
                if !readable_within(tty, 50)? {
                    return Ok(());
                }
                // An escape sequence: drain it (and anything queued behind it)
                while readable_within(tty, 5)? {
                    tty.read_exact(&mut byte)?;
                }
            }
            _ => {}
        }
    }
}

/// Whether the tty has input ready within the given number of milliseconds
fn readable_within(tty: &File, timeout_ms: u16) -> Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let fd = tty.as_fd();
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    let timeout = Timespec { tv_sec: 0, tv_nsec: i64::from(timeout_ms) * 1_000_000 };
    Ok(poll(&mut fds, Some(&timeout))? > 0)
}

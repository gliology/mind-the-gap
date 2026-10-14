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
use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};
use zeroize::Zeroizing;

use crate::prompt;

/// Render the data as a unicode QR image, inverted so it scans on dark terminals
///
/// Wrapped in `Zeroizing` because the payload may be key material: the image is a
/// pixel-for-pixel encoding of it, so it wipes like the secret it carries.
fn render(data: &[u8]) -> Result<Zeroizing<String>> {
    // The lowest error correction, so that the capacity checked in `show_qr` holds: a screen
    // is read in one go and damage is not a concern
    let code = QrCode::with_error_correction_level(data, EcLevel::L)
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
/// A single page of [`show_qr_pages`]; see there for where the code goes.
pub fn show_qr(data: &[u8], sensitive: bool) -> Result<()> {
    show_qr_pages(&[QrPage { title: None, data }], sensitive)
}

/// One code of a sequence: what it carries, and the bytes
pub struct QrPage<'a> {
    /// Shown above the code, so that whoever scans a sequence knows which one is which
    pub title: Option<String>,
    /// The payload, at most what one code carries
    pub data: &'a [u8],
}

/// Display one QR code after another, each leaving no trace, Enter for the next and Esc
/// to leave
///
/// On a terminal the codes take over the alternate screen and are gone from scrollback the
/// moment they are dismissed. The kernel console has no alternate screen, so there the
/// screen is cleared before and after instead; equivalent in effect, since modern kernels
/// keep no console scrollback at all.
///
/// A sensitive payload never reaches stdout or scrollback: redirected output is refused
/// instead of writing key material to a file that skips `write_sensitive`'s permissions,
/// and codes larger than the screen wait on the alternate screen until they fit. Public
/// payloads simply print in both cases, each under its title.
pub fn show_qr_pages(pages: &[QrPage<'_>], sensitive: bool) -> Result<()> {
    // The largest QR code carries 2953 bytes; say so up front instead of letting the
    // encoder's raw error surface, and name the way out
    if let Some(page) = pages.iter().find(|page| page.data.len() > 2953) {
        bail!("{} bytes exceed what one QR code can carry (2953), use --output", page.data.len());
    }
    let images = pages
        .iter()
        .map(|page| render(page.data))
        .collect::<Result<Vec<_>>>()?;
    let titles: Vec<Option<String>> = pages
        .iter()
        .enumerate()
        .map(|(index, page)| match (&page.title, pages.len()) {
            (Some(title), 1) => Some(title.clone()),
            (Some(title), count) => Some(format!("{} of {count}: {title}", index + 1)),
            (None, 1) => None,
            (None, count) => Some(format!("{} of {count}", index + 1)),
        })
        .collect();

    let print = || {
        for (title, image) in titles.iter().zip(&images) {
            if let Some(title) = title {
                println!("{title}");
            }
            println!("{}", **image);
        }
    };

    if !io::stdout().is_terminal() {
        if sensitive {
            bail!(
                "Refusing to write a secret-material QR code to a pipe or file, \
                 use --output for a protected file or run on a terminal"
            );
        }
        print();
        return Ok(());
    }

    // Every page gets the same box, the largest code plus a title row and a hint row
    let height = images
        .iter()
        .map(|image| image.lines().count())
        .max()
        .unwrap_or(0) as u16;
    let width = images
        .iter()
        .flat_map(|image| image.lines())
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as u16;
    let rows_needed = height + 2;
    let (cols, rows) = terminal::size()?;
    if !sensitive && (width > cols || rows_needed > rows) {
        print();
        log::warn!(
            "QR code larger than the screen; reduce the terminal font size \
             (often Ctrl+Minus, Ctrl+Alt+Minus on the console) to fit it on one screen"
        );
        return Ok(());
    }

    let mut screen = Screen::enter()?;
    // A secret never leaves the alternate screen: until the codes fit, the screen says how
    // to make room and waits for the terminal to grow
    let (cols, rows) = loop {
        let (cols, rows) = terminal::size()?;
        if width <= cols && rows_needed <= rows {
            break (cols, rows);
        }
        screen.wipe()?;
        write!(
            screen.tty,
            "The code needs {width}x{rows_needed} cells, the terminal has {cols}x{rows}.\r\n\
             Reduce the font size (often Ctrl+Minus, Ctrl+Alt+Minus on the console) \
             and it appears.\r\nEsc cancels."
        )?;
        screen.tty.flush()?;
        if pressed_within(&mut screen.tty.0, 250)? {
            bail!("QR code cancelled before it fit the screen; use --output for a protected file");
        }
    };

    let top = (rows - rows_needed) / 2;
    let left = (cols - width) / 2;
    for (index, (title, image)) in titles.iter().zip(&images).enumerate() {
        screen.wipe()?;
        if let Some(title) = title {
            execute!(screen.tty, cursor::MoveTo(left, top))?;
            write!(screen.tty, "\x1b[1m{title}\x1b[0m")?;
        }
        for (i, line) in image.lines().enumerate() {
            execute!(screen.tty, cursor::MoveTo(left, top + 1 + i as u16))?;
            screen.tty.write_all(line.as_bytes())?;
        }
        let last = index + 1 == images.len();
        let hint = if last {
            "[Esc to dismiss]"
        } else {
            "[Enter for the next, Esc to dismiss]"
        };
        execute!(screen.tty, cursor::MoveTo(left, top + 1 + height))?;
        write!(screen.tty, "\x1b[2m{hint}\x1b[0m")?;
        screen.tty.flush()?;

        if let Key::Dismiss = next_key(&mut screen.tty.0)? {
            break;
        }
    }
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

/// What a keypress asks of a sequence of codes
enum Key {
    /// Enter or space: the next code, or done after the last
    Next,
    /// Esc, q or Ctrl-C: leave
    Dismiss,
}

/// Block until a key that moves on: Enter or space, or a lone Esc, q or Ctrl-C
///
/// Arrow and function keys also start with the Esc byte; what distinguishes a bare Esc is
/// silence afterwards. A short poll after each Esc byte settles it, and the rest of a
/// sequence is drained so it cannot leak into the next prompt as stray input. Raw mode
/// delivers Ctrl-C as a plain byte, so it dismisses too instead of killing the process with
/// the secret still on screen.
fn next_key(tty: &mut File) -> Result<Key> {
    let mut byte = [0u8; 1];
    loop {
        tty.read_exact(&mut byte)?;
        match byte[0] {
            b'\r' | b'\n' | b' ' => return Ok(Key::Next),
            b'q' | 0x03 => return Ok(Key::Dismiss),
            0x1b => {
                if !readable_within(tty, 50)? {
                    return Ok(Key::Dismiss);
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

/// Whether a dismissing key arrives within the given number of milliseconds
///
/// Any other input is drained and ignored, so a stray keypress while zooming out does not
/// cancel the display.
fn pressed_within(tty: &mut File, timeout_ms: u16) -> Result<bool> {
    let mut byte = [0u8; 1];
    if !readable_within(tty, timeout_ms)? {
        return Ok(false);
    }
    tty.read_exact(&mut byte)?;
    let lone_escape = byte[0] == 0x1b && !readable_within(tty, 50)?;
    while readable_within(tty, 5)? {
        tty.read_exact(&mut byte)?;
    }
    Ok(lone_escape || matches!(byte[0], b'q' | 0x03))
}

/// Whether the tty has input ready within the given number of milliseconds
fn readable_within(tty: &File, timeout_ms: u16) -> Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let fd = tty.as_fd();
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    let timeout = Timespec { tv_sec: 0, tv_nsec: i64::from(timeout_ms) * 1_000_000 };
    Ok(poll(&mut fds, Some(&timeout))? > 0)
}

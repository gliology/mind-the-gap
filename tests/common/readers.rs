//! One lock over the host's card readers, shared by every hardware suite.
//!
//! The suites name their cards, so on a test host with several attached they can run at the
//! same time, with one exception: gpg's scdaemon opens every reader there is, exclusively,
//! and selects its own applet on each card while it looks for one. Every suite therefore
//! holds this lock shared while it talks to its card, and the step that starts scdaemon holds
//! it exclusively until scdaemon is stopped again. It is an advisory lock on a file in the
//! runtime directory, so it spans processes and is released by the kernel whatever way a
//! test ends.

use std::fs::File;
use std::path::PathBuf;

/// A hold on the readers, released when dropped
pub struct Readers {
    _file: File,
}

fn lock_file() -> File {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("mind-the-gap-hardware-tests.lock"))
        .expect("cannot open the hardware test lock file")
}

/// Talk to one named card while other suites talk to theirs
pub fn shared() -> Readers {
    let file = lock_file();
    file.lock_shared()
        .expect("cannot take the hardware test lock");
    Readers { _file: file }
}

/// Start something that takes every reader, such as scdaemon, once no suite is using one
#[allow(dead_code, reason = "only the OpenPGP suite starts scdaemon")]
pub fn exclusive() -> Readers {
    let file = lock_file();
    file.lock().expect("cannot take the hardware test lock");
    Readers { _file: file }
}

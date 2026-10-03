//! The `mind-the-gap` binary: logging setup around [`mind_the_gap::cli::run`].

use env_logger::Env;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Die quietly when stdout closes early: Rust ignores SIGPIPE by default, so a plain
    // `mind-the-gap pgp status | head` would end in a println! panic instead of the
    // silent exit every other unix tool gives. Nothing here relies on surviving EPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // A process that holds a seed phrase must not leave it in a core dump, and must not
    // be readable through ptrace or /proc/<pid>/mem by anything else running as the
    // same user; both matter doubly on the live image, which autologins one user with
    // passwordless sudo.
    #[cfg(unix)]
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit { rlim_cur: 0, rlim_max: 0 });
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // Nor may it leave the phrase in swap. The outcome is reported once the logger is up,
    // at debug level only: on the live image there is no swap and the limit is lifted, and
    // anywhere else a refusal is a fact about the host, not a failure of the run.
    #[cfg(target_os = "linux")]
    let memory_lock = lock_memory();

    // Parse logging config and init logger. The logger exists before clap runs, so
    // the --log-level flag is picked out of argv by hand here; clap still declares it
    // for help and validation, and the flag wins over the environment.
    let flag_filter = {
        let mut args = std::env::args().skip(1);
        let mut found = None;
        while let Some(arg) = args.next() {
            if arg == "--log-level" {
                found = args.next();
            } else if let Some(value) = arg.strip_prefix("--log-level=") {
                found = Some(value.to_string());
            }
        }
        found
    };
    let env = Env::default()
        .filter_or("MIND_THE_LOG_LEVEL", "mind_the_gap=info")
        .write_style_or("MIND_THE_LOG_STYLE", "auto");

    // The card stacks trace raw APDUs, which carry pins and imported key bytes, so
    // MIND_THE_LOG_LEVEL=trace while debugging a stubborn reader must not become a key
    // logger: their targets are clamped to info no matter what the filter says.
    let mut builder = match &flag_filter {
        Some(filter) => {
            let mut builder = env_logger::Builder::new();
            builder.parse_filters(filter);
            builder.parse_write_style(
                &std::env::var("MIND_THE_LOG_STYLE").unwrap_or_else(|_| "auto".into()),
            );
            builder
        }
        None => env_logger::Builder::from_env(env),
    };
    for target in [
        "openpgp_card",
        "card_backend",
        "card_backend_pcsc",
        "yubikey",
        "pcsc",
    ] {
        builder.filter_module(target, log::LevelFilter::Info);
    }
    builder.init();

    #[cfg(target_os = "linux")]
    if let Err(reason) = memory_lock {
        log::debug!("Memory not locked, secrets may be swapped out: {reason}");
    }

    // Parse command line and execute. Failures have to be reported through the exit status as
    // well, otherwise scripts and the nixos tests cannot tell a failed run from a successful
    // one. The alternate formatter prints the whole anyhow context chain, not just the
    // outermost message.
    match mind_the_gap::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Pin the whole process into RAM so no page that ever held the seed phrase can be
/// written to swap. Hibernation still writes RAM to disk regardless, locked or not; the
/// live image refuses both.
///
/// Best effort, with one deliberate refusal: `MCL_FUTURE` turns every later mapping past
/// `RLIMIT_MEMLOCK` into an allocation failure, and argon2 alone touches 64 MiB, so under
/// a small limit (8 MiB is the common desktop default) locking would trade a swapped page
/// for a crash mid-ceremony. The soft limit is raised to the hard limit first, and
/// anything below [`MEMLOCK_FLOOR`] skips the lock and says so.
#[cfg(target_os = "linux")]
fn lock_memory() -> Result<(), String> {
    /// Argon2's 64 MiB plus the mapped libraries and heap, with room to spare
    const MEMLOCK_FLOOR: libc::rlim_t = 256 * 1024 * 1024;

    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: plain libc calls on a valid, initialised rlimit struct that outlives them
    unsafe {
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        limit.rlim_cur = limit.rlim_max;
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    if limit.rlim_max != libc::RLIM_INFINITY && limit.rlim_max < MEMLOCK_FLOOR {
        return Err(format!(
            "the memlock limit is {} KiB, below the {} MiB the derivation needs",
            limit.rlim_max / 1024,
            MEMLOCK_FLOOR >> 20
        ));
    }

    // Lock on fault rather than up front: the libraries are mapped far beyond what is
    // ever touched, and only pages actually written can hold anything secret
    let flags = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
    // SAFETY: mlockall takes flags only and touches no memory of ours
    if unsafe { libc::mlockall(flags) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

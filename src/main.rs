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

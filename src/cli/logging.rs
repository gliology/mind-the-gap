//! The log: env_logger behind a filter that keeps card traffic out of it, and a copy of what
//! the user is told for a ceremony's transcript.

use super::ceremony::transcribe;

use env_logger::Env;

/// Set up the process's logger, from `--log-level` or `MIND_THE_LOG_LEVEL`
///
/// The logger exists before clap runs, so the flag is picked out of argv by hand here; clap
/// still declares it for help and validation, and the flag wins over the environment.
///
/// # Panics
///
/// Called a second time, or after another logger was set: a process has one logger, and
/// one set before this would log card traffic unfiltered.
pub fn install_logger() {
    let flag_filter =
        super::early_flag("--log-level").map(|filter| filter.to_string_lossy().into_owned());
    let env = Env::default()
        .filter_or("MIND_THE_LOG_LEVEL", "mind_the_gap=info")
        .write_style_or("MIND_THE_LOG_STYLE", "auto");

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
    // Timestamps help whoever chose a filter to debug; at the default level the log is the
    // tool talking to its user
    if flag_filter.is_none() && std::env::var_os("MIND_THE_LOG_LEVEL").is_none() {
        builder.format_timestamp(None).format_target(false);
    }
    let logger = CardSafeLogger(builder.build());
    log::set_max_level(logger.0.filter());
    log::set_boxed_logger(Box::new(logger)).expect("the logger is set once");
}

/// The card stacks trace raw APDUs, which carry pins and imported key bytes, so a filter
/// raised to trace while debugging a stubborn reader must not turn into a key logger
///
/// Their records above info are dropped here, after the filter: a directive can only ever
/// be overridden by a more specific one (`openpgp_card::ocard::apdu=debug` beats
/// `openpgp_card=info`), so no filter directive can make that promise.
struct CardSafeLogger(env_logger::Logger);

impl CardSafeLogger {
    const CARD_TARGETS: [&'static str; 5] = [
        "openpgp_card",
        "card_backend",
        "card_backend_pcsc",
        "yubikey",
        "pcsc",
    ];

    fn allows(metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
            || !Self::CARD_TARGETS.iter().any(|card| {
                metadata
                    .target()
                    .strip_prefix(card)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
            })
    }
}

impl log::Log for CardSafeLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        Self::allows(metadata) && self.0.enabled(metadata)
    }

    fn log(&self, record: &log::Record<'_>) {
        if Self::allows(record.metadata()) {
            // A ceremony being recorded keeps what the user is told, which is never a secret
            if self.0.enabled(record.metadata()) && record.level() <= log::Level::Info {
                transcribe(&format!("{}: {}", record.level(), record.args()));
            }
            self.0.log(record);
        }
    }

    fn flush(&self) {
        self.0.flush();
    }
}

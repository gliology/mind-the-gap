use env_logger::Env;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Parse logging config and init logger
    let env = Env::default()
        .filter_or("MIND_THE_LOG_LEVEL", "mind_the_gap=info")
        .write_style_or("MIND_THE_LOG_STYLE", "auto");

    env_logger::init_from_env(env);

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

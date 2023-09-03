use env_logger::Env;

fn main() {

    // Parse logging config and init logger
    let env = Env::default()
        .filter_or("MIND_THE_LOG_LEVEL", "mind_the_gap=info")
        .write_style_or("MIND_THE_LOG_STYLE", "auto");

    env_logger::init_from_env(env);

    // Parse command line and execute
    match mind_the_gap::cli::run() {
        Err(err) => log::error!("{}", err.to_string()),
        Ok(()) => (),
    }
}

use mind_the_gap::cli::{cmd, run, ResultErrToString};


/// Command line parse and execute
fn main() -> Result<(), String> {
    env_logger::init();

    run(&cmd().get_matches()).map_err_to_string()
}

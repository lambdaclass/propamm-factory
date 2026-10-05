//! The smallest quote updater: the library with its built-in pricing models (`fixed`,
//! `feed`, `volatile`) and nothing of its own. `make price-service` and the fork tests run
//! this one. A binary of yours starts here and adds `.pricer(..)`, `.market_guard(..)`,
//! `.quote_guard(..)` or `.observer(..)` before `run_from_env()`; see `custom_pricer.rs`.

fn main() -> std::process::ExitCode {
    quote_updater::Updater::builder().run_from_env()
}

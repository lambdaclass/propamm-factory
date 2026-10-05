//! The smallest quote updater: the three pricing kinds the library ships (`fixed`, `feed`,
//! `volatile`), registered like any kind of yours would be, and nothing else. `make
//! price-service` and the fork tests run this one. A binary of yours starts here and adds
//! `.pricer(..)`, `.market_guard(..)`, `.quote_guard(..)` or `.observer(..)` before
//! `run_from_env()`; see `custom_pricer.rs`.

use quote_updater::{Updater, pricers};

fn main() -> std::process::ExitCode {
    Updater::builder()
        .pricer("fixed", pricers::Fixed)
        .pricer("feed", pricers::Feed)
        .pricer("volatile", pricers::Volatile)
        .run_from_env()
}

//! Seals a config file for the first boot of a run inside an enclave (`--enclave`). Inside
//! an enclave the config is kept by the host only in sealed form, which the host can neither
//! read nor change; the enclave seals every save itself, but the very first config has to be
//! sealed by whoever holds the sealing key, before that key is encrypted for the key service.
//!
//! `CONFIG_SEAL_KEY=<64 hex digits> cargo run -p quote-updater --example seal_config -- config.toml > config.sealed`
//!
//! See docs/enclave.md.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: CONFIG_SEAL_KEY=<64 hex digits> seal_config <config.toml>");
        return ExitCode::from(2);
    };
    let Ok(key) = std::env::var("CONFIG_SEAL_KEY") else {
        eprintln!("CONFIG_SEAL_KEY is not set");
        return ExitCode::from(2);
    };
    let config = match std::fs::read(&path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("reading {path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    match quote_updater::seal_config(&key, &config) {
        Ok(sealed) => {
            println!("{sealed}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

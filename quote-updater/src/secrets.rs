//! Where secrets are read from: the updater keys, a pricer's `EnvSecret`, a venue's API
//! key. Normally the process environment. A run that was handed its secrets another way
//! (an enclave, where there is no environment to put them in and they arrive decrypted at
//! boot; see `enclave/`) installs them here once, and every read checks here first.
//!
//! One map, set once, read everywhere: a secret has one source per process, decided at
//! startup, and nothing later can change or add to it.

use std::{collections::BTreeMap, sync::OnceLock};

use eyre::{Result, ensure};

static INSTALLED: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Makes `secrets` the first place every lookup consults. Once per process; a second call
/// is a bug and is refused rather than silently ignored.
pub fn install(secrets: BTreeMap<String, String>) -> Result<()> {
    ensure!(
        INSTALLED.set(secrets).is_ok(),
        "secrets were installed twice; they are decided once at startup"
    );
    Ok(())
}

/// The secret under `name`: an installed one if any, else the environment variable of
/// that name. `None` when neither has it.
pub fn lookup(name: &str) -> Option<String> {
    lookup_in(INSTALLED.get(), name)
}

fn lookup_in(installed: Option<&BTreeMap<String, String>>, name: &str) -> Option<String> {
    if let Some(value) = installed.and_then(|installed| installed.get(name)) {
        return Some(value.clone());
    }
    std::env::var(name).ok()
}

/// Whether secrets were installed, as opposed to being read from the environment.
pub fn installed() -> bool {
    INSTALLED.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_installed_secret_beats_the_environment_and_the_rest_fall_through() {
        // PATH is set in any process a test runs in.
        let path = std::env::var("PATH").unwrap();
        let map: BTreeMap<String, String> = [("PATH".to_owned(), "from-map".to_owned())].into();
        assert_eq!(lookup_in(Some(&map), "PATH").as_deref(), Some("from-map"));
        assert_eq!(lookup_in(None, "PATH"), Some(path));
        assert_eq!(lookup_in(Some(&map), "QU_NOT_SET_ANYWHERE_7f3a"), None);
    }
}

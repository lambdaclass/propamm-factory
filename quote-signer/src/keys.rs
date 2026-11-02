//! How the keys reach the process. The one thing that differs between a plain host and a
//! confidential one is this step: on a plain host the operator hands the keys over (a
//! file); in an enclave they arrive as ciphertext and are released by a key service that
//! first checks what code is asking (`nitro`, behind its feature). Everything after this
//! step is the same program.

use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, ensure};

use crate::signing::SigningKey;

/// A way of obtaining the keys at startup.
pub trait KeyRelease {
    /// The keys, or why they could not be obtained. Called once, at startup.
    fn release(&self) -> impl std::future::Future<Output = Result<Vec<SigningKey>>> + Send;
}

/// Keys read from a file: one hex key per line, blank lines and `#` comments ignored.
#[derive(Clone, Debug)]
pub struct KeyFile {
    /// The file.
    pub path: PathBuf,
}

impl KeyRelease for KeyFile {
    async fn release(&self) -> Result<Vec<SigningKey>> {
        let text = tokio::fs::read_to_string(&self.path)
            .await
            .wrap_err_with(|| format!("reading keys from {}", self.path.display()))?;
        parse_key_file(&text, &self.path)
    }
}

/// The keys in a key file's text. Errors name the line, never its contents.
pub fn parse_key_file(text: &str, path: &Path) -> Result<Vec<SigningKey>> {
    let mut keys = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = SigningKey::parse(line)
            .wrap_err_with(|| format!("{}:{}", path.display(), index + 1))?;
        ensure!(
            !keys
                .iter()
                .any(|seen: &SigningKey| seen.address() == key.address()),
            "{}:{}: this key appears twice",
            path.display(),
            index + 1
        );
        keys.push(key);
    }
    ensure!(!keys.is_empty(), "{} holds no keys", path.display());
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const KEY_B: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    #[test]
    fn a_key_file_is_one_key_per_line_with_comments() {
        let text = format!("# updater keys\n{KEY_A}\n\n  {KEY_B}  \n");
        let keys = parse_key_file(&text, Path::new("keys.txt")).unwrap();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].address(), keys[1].address());
    }

    #[test]
    fn a_bad_line_is_named_without_being_quoted_and_a_repeat_is_refused() {
        let err = parse_key_file("zz\n", Path::new("keys.txt")).unwrap_err();
        let shown = format!("{err:#}");
        assert!(shown.contains("keys.txt:1"), "{shown}");
        assert!(!shown.contains("zz"), "{shown}");

        let err = parse_key_file(&format!("{KEY_A}\n{KEY_A}\n"), Path::new("k")).unwrap_err();
        assert!(format!("{err:#}").contains("twice"));

        assert!(parse_key_file("# nothing\n", Path::new("k")).is_err());
    }

    #[tokio::test]
    async fn a_key_file_on_disk_releases_its_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.txt");
        std::fs::write(&path, format!("{KEY_A}\n")).unwrap();
        let keys = KeyFile { path }.release().await.unwrap();
        assert_eq!(keys.len(), 1);
    }
}

//! Sealing the config for the host to keep. An enclave has no disk, so the host stores the
//! config between boots; it must not be able to read or change it. AES-256-GCM under a key
//! only the enclave holds: the host sees ciphertext, and any change to a byte of it fails
//! the authentication check when the enclave opens it.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use eyre::{Result, ensure, eyre};

/// The key's size.
pub const KEY_LEN: usize = 32;

const NONCE_LEN: usize = 12;

/// Bound to the ciphertext, so a blob sealed for another purpose with the same key could
/// not be handed in as a config.
const CONTEXT: &[u8] = b"quote-updater config seal v1";

/// A sealing key, from its hex (64 digits, `0x` optional). The error never quotes the
/// input.
pub fn parse_key(text: &str) -> Result<[u8; KEY_LEN]> {
    let hex = text.trim();
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|_| eyre!("the sealing key is not hex"))?;
    ensure!(
        bytes.len() == KEY_LEN,
        "the sealing key is {} bytes, not {KEY_LEN}",
        bytes.len()
    );
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// `plaintext` sealed under `key`: a fresh random nonce, then the ciphertext and its tag.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let cipher = Aes256Gcm::new(key.into());
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: CONTEXT,
            },
        )
        .map_err(|_| eyre!("sealing failed"))?;
    let mut blob = nonce.to_vec();
    blob.extend(sealed);
    Ok(blob)
}

/// The plaintext of a blob [`seal`] produced under `key`, or an error for a blob that was
/// changed, sealed under another key, or not sealed by this at all.
pub fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        blob.len() > NONCE_LEN,
        "the sealed config is too short to be one"
    );
    let (nonce, sealed) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: sealed,
                aad: CONTEXT,
            },
        )
        .map_err(|_| eyre!("the sealed config does not open: changed, or sealed under another key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_config_opens_under_its_key_and_under_nothing_else() {
        let key = parse_key("0x0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        let other =
            parse_key("0202020202020202020202020202020202020202020202020202020202020202").unwrap();
        let blob = seal(&key, b"[settings]\nrequote_ms = 25\n").unwrap();
        assert_eq!(open(&key, &blob).unwrap(), b"[settings]\nrequote_ms = 25\n");
        assert!(open(&other, &blob).is_err());

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&key, &tampered).is_err());
        let mut flipped = blob.clone();
        flipped[NONCE_LEN + 3] ^= 1;
        assert!(open(&key, &flipped).is_err());
        assert!(open(&key, &blob[..5]).is_err());

        // Two seals of the same text differ (a fresh nonce each), and both open.
        let again = seal(&key, b"[settings]\nrequote_ms = 25\n").unwrap();
        assert_ne!(again, blob);
        assert_eq!(open(&key, &again).unwrap(), open(&key, &blob).unwrap());
    }

    #[test]
    fn a_key_must_be_32_bytes_of_hex_and_the_error_does_not_echo_it() {
        let err = parse_key("abc").unwrap_err().to_string();
        assert!(!err.contains("abc"), "{err}");
        assert!(parse_key("0x00").is_err());
    }
}

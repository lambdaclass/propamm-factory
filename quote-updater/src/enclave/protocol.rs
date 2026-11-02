//! What crosses the one channel between an enclave and the host it runs on. Framed as a
//! 4-byte big-endian length followed by JSON, in both directions, over whatever stream the
//! two share (a vsock in an enclave, a Unix socket in a test).
//!
//! The host sends one [`ToEnclave::Boot`] when the enclave starts, and afterwards only a
//! reload or a shutdown request. The enclave answers the boot with [`FromEnclave::Ready`]
//! or [`FromEnclave::Failed`], then sends its log lines and, after every config save, the
//! sealed config for the host to keep.

use std::collections::BTreeMap;

use eyre::{Result, ensure, eyre};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame either side accepts: a sealed config with a few hundred pairs is well
/// under a megabyte; a frame near this bound is not something this protocol sends.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Temporary AWS credentials the host obtained for the enclave, which it uses once, to
/// have KMS decrypt the secrets at boot. Never printed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// The access key id.
    pub access_key_id: String,
    /// Its secret.
    pub secret_access_key: String,
    /// The session token, for temporary credentials (an instance role's).
    #[serde(default)]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(..)")
    }
}

/// What the host sends.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToEnclave {
    /// Everything the enclave needs to start, sent once.
    Boot {
        /// The credentials KMS is called with.
        credentials: Credentials,
        /// Every secret by name, each as KMS `Encrypt` returned it, base64. The names are
        /// the ones the config refers to (`key_env`, a pricer's `EnvSecret`, a venue's API
        /// key variable) plus the ones the enclave file names.
        secrets: BTreeMap<String, String>,
        /// The config, sealed under the config-sealing secret, base64: the last one the
        /// enclave sent back, or for the very first boot one made with `seal_config`.
        config: String,
        /// The PEM certificate chain the backoffice serves, when the enclave file has a
        /// `[backoffice]`. As is, not encrypted: a certificate is public, and it is only
        /// served with the private key KMS releases to the enclave, which it must match.
        /// Handed in rather than baked into the image so a renewal needs no new image.
        #[serde(default)]
        backoffice_certificate: Option<String>,
    },
    /// Re-read the config and converge on it, as SIGHUP does outside an enclave.
    Reload,
    /// Withdraw every quote and exit, as ctrl-c does outside an enclave.
    Shutdown,
}

/// What the enclave sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromEnclave {
    /// The boot succeeded; the run is starting.
    Ready {
        /// The names of the secrets that were decrypted, so the host's log says which
        /// without ever seeing a value.
        secrets: Vec<String>,
    },
    /// The boot failed; the process is exiting.
    Failed {
        /// Why.
        message: String,
    },
    /// One operator log line, as it would have gone to the terminal.
    Log {
        /// `stdout` or `stderr`.
        stream: String,
        /// The line.
        line: String,
    },
    /// The config as last saved, sealed, base64: what the host hands back at the next boot.
    Config {
        /// The sealed config.
        sealed: String,
    },
}

/// Writes one frame: the length, then the JSON.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(message)?;
    ensure!(
        body.len() <= MAX_FRAME,
        "frame of {} bytes exceeds the protocol's bound",
        body.len()
    );
    let len = u32::try_from(body.len()).map_err(|_| eyre!("frame too long"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame. `Ok(None)` at a clean end of stream (the peer closed between frames);
/// an error for anything else, including a close in the middle of a frame.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    ensure!(
        len <= MAX_FRAME,
        "frame of {len} bytes exceeds the protocol's bound"
    );
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_a_clean_close_reads_as_none() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let boot = ToEnclave::Boot {
            credentials: Credentials {
                access_key_id: "AKIA".into(),
                secret_access_key: "s".into(),
                session_token: None,
            },
            secrets: [("K".to_owned(), "AAAA".to_owned())].into(),
            config: "BBBB".into(),
            backoffice_certificate: None,
        };
        write_frame(&mut a, &boot).await.unwrap();
        write_frame(&mut a, &ToEnclave::Reload).await.unwrap();
        drop(a);
        let read: ToEnclave = read_frame(&mut b).await.unwrap().unwrap();
        assert!(matches!(read, ToEnclave::Boot { ref secrets, .. } if secrets.len() == 1));
        assert!(matches!(
            read_frame::<_, ToEnclave>(&mut b).await.unwrap(),
            Some(ToEnclave::Reload)
        ));
        assert!(read_frame::<_, ToEnclave>(&mut b).await.unwrap().is_none());
    }

    #[test]
    fn credentials_never_print_and_messages_are_tagged_by_kind() {
        let credentials = Credentials {
            access_key_id: "AKIA".into(),
            secret_access_key: "verysecret".into(),
            session_token: Some("tok".into()),
        };
        let shown = format!("{credentials:?}");
        assert!(
            !shown.contains("verysecret") && !shown.contains("AKIA"),
            "{shown}"
        );
        let json = serde_json::to_string(&FromEnclave::Ready { secrets: vec![] }).unwrap();
        assert_eq!(json, r#"{"kind":"ready","secrets":[]}"#);
    }
}

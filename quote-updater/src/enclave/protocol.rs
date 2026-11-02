//! What crosses the channel between an enclave and the host it runs on. Framed as a
//! 4-byte big-endian length followed by JSON, in both directions, over whatever connection
//! the platform's [`super::HostLink`] provides.
//!
//! The host sends one [`HostMessage::Boot`] when the run starts, and afterwards only a
//! reload or a shutdown request. The run answers the boot with [`RunMessage::Ready`] or
//! [`RunMessage::Failed`], then sends its log lines and, after every config save, the sealed
//! config for the host to keep.

use std::collections::BTreeMap;

use eyre::{Result, ensure, eyre};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame either side accepts: a sealed config with a few hundred pairs is well
/// under a megabyte; a frame near this bound is not something this protocol sends.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Whatever the platform's key service needs to be called with, by name: for AWS KMS, an
/// instance role's `access_key_id`, `secret_access_key` and `session_token`. Used once, at
/// boot. Never printed.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Credentials(pub BTreeMap<String, String>);

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({} fields)", self.0.len())
    }
}

/// What the host sends.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    /// Everything the run needs to start, sent once.
    Boot {
        /// What the key service is called with.
        credentials: Credentials,
        /// Every secret by name, each as the key service encrypted it, base64. The names
        /// are the ones the config refers to (`key_env`, a pricer's secret, a venue's API
        /// key variable) plus the ones the enclave file names.
        secrets: BTreeMap<String, String>,
        /// The config, sealed under the config-sealing secret, base64: the last one the run
        /// sent back, or for the very first boot one made with `seal_config`.
        config: String,
        /// The PEM certificate chain the backoffice serves, when the enclave file has a
        /// `[backoffice]`. As is, not encrypted: a certificate is public, and it is only
        /// served with the private key the key service releases, which it must match.
        /// Handed in rather than built into the image so a renewal needs no new image.
        #[serde(default)]
        backoffice_certificate: Option<String>,
    },
    /// Re-read the config and converge on it, as SIGHUP does elsewhere.
    Reload,
    /// Withdraw every quote and exit, as ctrl-c does elsewhere.
    Shutdown,
}

/// What the run sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunMessage {
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

    fn credentials() -> Credentials {
        Credentials(
            [
                ("access_key_id".to_owned(), "AKIA".to_owned()),
                ("secret_access_key".to_owned(), "verysecret".to_owned()),
            ]
            .into(),
        )
    }

    #[tokio::test]
    async fn frames_round_trip_and_a_clean_close_reads_as_none() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let boot = HostMessage::Boot {
            credentials: credentials(),
            secrets: [("K".to_owned(), "AAAA".to_owned())].into(),
            config: "BBBB".into(),
            backoffice_certificate: None,
        };
        write_frame(&mut a, &boot).await.unwrap();
        write_frame(&mut a, &HostMessage::Reload).await.unwrap();
        drop(a);
        let read: HostMessage = read_frame(&mut b).await.unwrap().unwrap();
        assert!(matches!(read, HostMessage::Boot { ref secrets, .. } if secrets.len() == 1));
        assert!(matches!(
            read_frame::<_, HostMessage>(&mut b).await.unwrap(),
            Some(HostMessage::Reload)
        ));
        assert!(
            read_frame::<_, HostMessage>(&mut b)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn credentials_are_a_plain_map_on_the_wire_and_never_print() {
        let json = serde_json::to_string(&credentials()).unwrap();
        assert_eq!(
            json,
            r#"{"access_key_id":"AKIA","secret_access_key":"verysecret"}"#
        );
        let shown = format!("{:?}", credentials());
        assert!(
            !shown.contains("verysecret") && !shown.contains("AKIA"),
            "{shown}"
        );
        let json = serde_json::to_string(&RunMessage::Ready { secrets: vec![] }).unwrap();
        assert_eq!(json, r#"{"kind":"ready","secrets":[]}"#);
    }
}

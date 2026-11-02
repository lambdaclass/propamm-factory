//! The client a quote updater embeds: one connection to the signer, kept open across
//! requests, redialled when it drops. Requests on one client are serialized; an updater
//! holds one client per pair, so pairs never queue behind each other.

use std::{pin::Pin, time::Duration};

use ethrex_common::Address;
use eyre::{Result, bail, eyre};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    sync::Mutex,
};

use crate::{
    protocol::{Request, Response, Signature, TxFields, read_frame, write_frame},
    signing::recover,
    spec::Endpoint,
};

/// A connected stream of either kind.
type Stream = Pin<Box<dyn Connected>>;

/// The two traits a stream needs, as one for the trait object.
trait Connected: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> Connected for T {}

/// A connection to one signer process.
pub struct Client {
    endpoint: Endpoint,
    timeout: Duration,
    stream: Mutex<Option<Stream>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client({}, timeout {:?})", self.endpoint, self.timeout)
    }
}

impl Client {
    /// A client for `endpoint`. No connection is made until the first request, so an
    /// updater can be configured and checked without the signer being up.
    pub fn new(endpoint: Endpoint, timeout: Duration) -> Self {
        Self {
            endpoint,
            timeout,
            stream: Mutex::new(None),
        }
    }

    /// Where this client connects.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The addresses the signer serves.
    pub async fn hello(&self) -> Result<Vec<Address>> {
        match self.exchange(&Request::Hello).await? {
            Response::Hello { addresses, .. } => Ok(addresses),
            other => bail!("unexpected answer to hello: {other:?}"),
        }
    }

    /// Signs `tx` with the signer's key for `address`. A refusal is an error naming the
    /// policy that failed; a signature that does not recover to `address` is an error
    /// too, so a signer that signed something else cannot have it published.
    pub async fn sign(&self, address: Address, tx: &TxFields) -> Result<Signature> {
        let request = Request::Sign {
            address,
            tx: tx.clone(),
        };
        match self.exchange(&request).await? {
            Response::Signed { signature } => {
                let signed_by = recover(tx, &signature)?;
                if signed_by != address {
                    bail!(
                        "the signer answered with a signature by {signed_by:#x}, not {address:#x}"
                    );
                }
                Ok(signature)
            }
            Response::Refused { reason } => bail!("the signer refused: {reason}"),
            Response::Failed { message } => bail!("the signer failed: {message}"),
            Response::Hello { .. } => bail!("unexpected hello in answer to a sign request"),
        }
    }

    /// One request, one response, under the timeout; the connection is dropped on any
    /// failure so the next request dials afresh.
    async fn exchange(&self, request: &Request) -> Result<Response> {
        let mut slot = self.stream.lock().await;
        let outcome = tokio::time::timeout(self.timeout, async {
            if slot.is_none() {
                *slot = Some(connect(&self.endpoint).await?);
            }
            let stream = slot.as_mut().expect("connected above");
            write_frame(stream, request).await?;
            read_frame::<_, Response>(stream)
                .await?
                .ok_or_else(|| eyre!("the signer closed the connection"))
        })
        .await;
        match outcome {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                *slot = None;
                Err(err.wrap_err(format!("signer at {}", self.endpoint)))
            }
            Err(_) => {
                *slot = None;
                Err(eyre!(
                    "signer at {} did not answer within {:?}",
                    self.endpoint,
                    self.timeout
                ))
            }
        }
    }
}

async fn connect(endpoint: &Endpoint) -> Result<Stream> {
    match endpoint {
        Endpoint::Unix(path) => Ok(Box::pin(UnixStream::connect(path).await?)),
        #[cfg(target_os = "linux")]
        Endpoint::Vsock { cid, port } => {
            let stream =
                tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(*cid, *port)).await?;
            Ok(Box::pin(stream))
        }
        #[cfg(not(target_os = "linux"))]
        Endpoint::Vsock { .. } => bail!("vsock endpoints exist on Linux only"),
    }
}

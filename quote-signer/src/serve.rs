//! The signer's request loop: read a frame, judge it, sign it, answer. One task per
//! connection, and a connection is one quote updater's pair, so a slow or broken peer
//! holds nothing else up.

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Instant};

use ethrex_common::Address;
use eyre::{Result, WrapErr, ensure};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixListener,
};

use crate::{
    policy::Policy,
    protocol::{Request, Response, VERSION, read_frame, write_frame},
    reference::Book,
    signing::SigningKey,
};

/// The keys, the policy and the reference book: everything a verdict needs.
#[derive(Debug)]
pub struct Signer {
    keys: HashMap<Address, SigningKey>,
    policy: Policy,
    book: Arc<Book>,
}

impl Signer {
    /// Pairs the released keys with the policy. Every key the policy names must have been
    /// released, or the policy describes a signer that does not exist; a released key the
    /// policy does not name is dropped, since nothing could ever be signed with it.
    pub fn new(keys: Vec<SigningKey>, policy: Policy, book: Arc<Book>) -> Result<Self> {
        let mut by_address: HashMap<Address, SigningKey> =
            keys.into_iter().map(|key| (key.address(), key)).collect();
        let mut kept = HashMap::new();
        for entry in &policy.keys {
            let key = by_address.remove(&entry.address).ok_or_else(|| {
                eyre::eyre!(
                    "the policy names {:#x} but no such key was released",
                    entry.address
                )
            })?;
            kept.insert(entry.address, key);
        }
        for address in by_address.keys() {
            tracing::warn!(
                "key {address:#x} was released but the policy does not name it; dropped"
            );
        }
        ensure!(!kept.is_empty(), "no key to sign with");
        Ok(Self {
            keys: kept,
            policy,
            book,
        })
    }

    /// The addresses this signer signs for.
    pub fn addresses(&self) -> Vec<Address> {
        let mut addresses: Vec<Address> = self.keys.keys().copied().collect();
        addresses.sort();
        addresses
    }

    /// The venue symbols the policy's price checks need.
    pub fn reference_symbols(&self) -> Vec<String> {
        let mut symbols: Vec<String> = self
            .policy
            .keys
            .iter()
            .filter_map(|key| key.reference.as_ref().map(|band| band.symbol.clone()))
            .collect();
        symbols.sort();
        symbols.dedup();
        symbols
    }

    /// Answers one request as of `now`.
    pub fn handle(&self, request: &Request, now: Instant) -> Response {
        match request {
            Request::Hello => Response::Hello {
                version: VERSION,
                addresses: self.addresses(),
            },
            Request::Sign { address, tx } => {
                let Some(key) = self.keys.get(address) else {
                    return Response::Failed {
                        message: format!("no key for {address:#x}"),
                    };
                };
                match self
                    .policy
                    .judge(*address, tx, |symbol| self.book.reading(symbol, now))
                {
                    Ok(()) => Response::Signed {
                        signature: key.sign(tx),
                    },
                    Err(reason) => {
                        tracing::warn!("refused to sign for {address:#x}: {reason}");
                        Response::Refused { reason }
                    }
                }
            }
        }
    }
}

/// Serves one connection until the peer closes it or sends something unreadable.
pub async fn serve_stream<S>(mut stream: S, signer: Arc<Signer>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(request) = read_frame::<_, Request>(&mut stream).await? {
        let response = signer.handle(&request, Instant::now());
        write_frame(&mut stream, &response).await?;
    }
    Ok(())
}

/// Where the signer listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listener {
    /// A Unix domain socket at this path; a stale socket file there is replaced.
    Unix(PathBuf),
    /// A vsock port, on every context id.
    Vsock(u32),
}

/// Accepts connections forever, one task each.
pub async fn serve(listener: Listener, signer: Arc<Signer>) -> Result<()> {
    match listener {
        Listener::Unix(path) => {
            if path.exists() {
                std::fs::remove_file(&path)
                    .wrap_err_with(|| format!("removing the stale socket {}", path.display()))?;
            }
            let listener = UnixListener::bind(&path)
                .wrap_err_with(|| format!("binding {}", path.display()))?;
            tracing::info!("listening on unix://{}", path.display());
            loop {
                let (stream, _) = listener.accept().await?;
                let signer = Arc::clone(&signer);
                tokio::spawn(async move {
                    if let Err(err) = serve_stream(stream, signer).await {
                        tracing::warn!("connection ended: {err:#}");
                    }
                });
            }
        }
        #[cfg(target_os = "linux")]
        Listener::Vsock(port) => {
            let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
                tokio_vsock::VMADDR_CID_ANY,
                port,
            ))
            .wrap_err_with(|| format!("binding vsock port {port}"))?;
            tracing::info!("listening on vsock port {port}");
            loop {
                let (stream, _) = listener.accept().await?;
                let signer = Arc::clone(&signer);
                tokio::spawn(async move {
                    if let Err(err) = serve_stream(stream, signer).await {
                        tracing::warn!("connection ended: {err:#}");
                    }
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        Listener::Vsock(_) => eyre::bail!("vsock exists on Linux only"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use ethrex_common::U256;
    use ethrex_l2_common::calldata::Value;
    use ethrex_l2_sdk::calldata::encode_calldata;

    use super::*;
    use crate::{
        client::Client,
        policy::{KeyPolicy, ReferenceBand, UPDATE_STATE_SIG},
        protocol::TxFields,
        signing::recover,
        spec::Endpoint,
    };

    const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn signer(book: Arc<Book>) -> Signer {
        let key = SigningKey::parse(KEY).unwrap();
        let policy = Policy {
            registry: Address::from_low_u64_be(0x1e9),
            chain_id: 1,
            max_gas_limit: 120_000,
            max_fee_per_gas: None,
            keys: vec![KeyPolicy {
                address: key.address(),
                target: Address::from_low_u64_be(0x7a1),
                lanes: vec![U256::from(42)],
                reference: Some(ReferenceBand {
                    symbol: "ETHUSDC".into(),
                    inverted: false,
                    price_decimals: 18,
                    max_distance: 0.02,
                    max_age: Duration::from_secs(30),
                }),
            }],
        };
        Signer::new(vec![key], policy, book).unwrap()
    }

    fn update(lane: u64) -> TxFields {
        let data = encode_calldata(
            UPDATE_STATE_SIG,
            &[
                Value::Address(Address::from_low_u64_be(0x7a1)),
                Value::Uint(U256::from(lane)),
                Value::Uint(U256::from(1_700_000_000u64)),
                Value::Array(vec![
                    Value::Uint(U256::from(1_000_000)),
                    Value::Uint(U256::from(2500) * U256::exp10(18)),
                ]),
            ],
        )
        .unwrap();
        TxFields {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 120_000,
            to: Address::from_low_u64_be(0x1e9),
            value: U256::zero(),
            data: Bytes::from(data),
        }
    }

    #[test]
    fn the_policy_must_name_a_released_key_and_unnamed_keys_are_dropped() {
        let key = SigningKey::parse(KEY).unwrap();
        let policy = Policy {
            registry: Address::zero(),
            chain_id: 1,
            max_gas_limit: 1,
            max_fee_per_gas: None,
            keys: vec![KeyPolicy {
                address: Address::zero(),
                target: Address::zero(),
                lanes: vec![],
                reference: None,
            }],
        };
        let err = Signer::new(vec![key.clone()], policy.clone(), Arc::default()).unwrap_err();
        assert!(err.to_string().contains("no such key"), "{err}");

        let mut named = policy;
        named.keys[0].address = key.address();
        let signer = Signer::new(vec![key.clone()], named, Arc::default()).unwrap();
        assert_eq!(signer.addresses(), vec![key.address()]);
    }

    #[tokio::test]
    async fn a_client_and_a_signer_over_a_unix_socket_sign_judge_and_recover() {
        let book = Arc::new(Book::default());
        book.record("ETHUSDC", 2500.0, Instant::now());
        let signer = Arc::new(signer(Arc::clone(&book)));
        let address = signer.addresses()[0];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signer.sock");
        let server = tokio::spawn(serve(Listener::Unix(path.clone()), Arc::clone(&signer)));
        // Bound inside `serve`; wait for the socket file rather than racing it.
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let client = Client::new(Endpoint::Unix(path.clone()), Duration::from_secs(2));
        assert_eq!(client.hello().await.unwrap(), vec![address]);

        let tx = update(42);
        let signature = client.sign(address, &tx).await.unwrap();
        assert_eq!(recover(&tx, &signature).unwrap(), address);

        let refused = client.sign(address, &update(7)).await.unwrap_err();
        assert!(refused.to_string().contains("lane"), "{refused}");

        let unknown = client.sign(Address::zero(), &tx).await.unwrap_err();
        assert!(unknown.to_string().contains("no key"), "{unknown}");

        // A second request after a refusal reuses the connection and still signs.
        client.sign(address, &tx).await.unwrap();

        server.abort();
    }

    #[tokio::test]
    async fn a_client_whose_signer_is_gone_reports_it_and_recovers_when_it_returns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signer.sock");
        let client = Client::new(Endpoint::Unix(path.clone()), Duration::from_millis(500));
        let err = client.hello().await.unwrap_err();
        assert!(format!("{err:#}").contains("signer at unix://"), "{err:#}");

        let signer = Arc::new(signer(Arc::default()));
        let server = tokio::spawn(serve(Listener::Unix(path.clone()), signer));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(client.hello().await.unwrap().len(), 1);
        server.abort();
    }
}

//! Who signs a pair's updates. The updater builds every update's transaction itself; the
//! signer only ever sees the unsigned fields and answers with the signature. Two
//! implementations: the key in this process ([`LocalSigner`]), and a separate signer
//! process reached over a socket ([`RemoteSigner`]) that holds the key and judges each
//! transaction before signing it. Which one a pair gets is decided by what its key
//! variable holds (see [`from_key_value`]), so nothing else in the config changes.

use std::{fmt, sync::Arc, time::Duration};

use ethrex_common::{Address, types::EIP1559Transaction};
use eyre::{Result, WrapErr, ensure};
use futures_util::future::BoxFuture;
pub use quote_signer::protocol::{Signature, TxFields};
use quote_signer::{client::Client, signing::SigningKey, spec::KeySpec};
use secp256k1::SecretKey;

/// How long a remote signer may take to answer. Signing is on the requote path, whose
/// budget is tens of milliseconds; a signer that takes a second is one that is gone.
pub const REMOTE_SIGN_TIMEOUT: Duration = Duration::from_secs(1);

/// Signs updates for one pair.
pub trait Signer: Send + Sync + fmt::Debug {
    /// The address the signatures recover to: the pair's updater.
    fn address(&self) -> Address;
    /// Where the key is, for `--check` and the logs: `local`, or the signer's endpoint.
    fn describe(&self) -> String;
    /// The signature over `fields`, or why there is none. A refusal from a remote signer
    /// is an error here: the update is not published this tick, and the reason is logged.
    fn sign<'a>(&'a self, fields: &'a TxFields) -> BoxFuture<'a, Result<Signature>>;
    /// Whether this signer can sign at all, without signing anything: for `--check`. A
    /// local key always can; a remote signer is asked whether it holds the key.
    fn probe(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// A signer shared by everything that quotes a pair.
pub type SharedSigner = Arc<dyn Signer>;

/// The key held in this process.
pub struct LocalSigner {
    key: SigningKey,
}

impl LocalSigner {
    /// A signer holding `secret`.
    pub fn new(secret: SecretKey) -> Self {
        Self {
            key: SigningKey::new(secret),
        }
    }
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key never prints; `SigningKey`'s Debug is the address alone.
        write!(f, "LocalSigner({:?})", self.key)
    }
}

impl Signer for LocalSigner {
    fn address(&self) -> Address {
        self.key.address()
    }

    fn describe(&self) -> String {
        "local".to_owned()
    }

    fn sign<'a>(&'a self, fields: &'a TxFields) -> BoxFuture<'a, Result<Signature>> {
        Box::pin(async move { Ok(self.key.sign(fields)) })
    }
}

/// A separate signer process holding the key for `address`.
#[derive(Debug)]
pub struct RemoteSigner {
    client: Client,
    address: Address,
}

impl Signer for RemoteSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn describe(&self) -> String {
        self.client.endpoint().to_string()
    }

    fn sign<'a>(&'a self, fields: &'a TxFields) -> BoxFuture<'a, Result<Signature>> {
        Box::pin(async move { self.client.sign(self.address, fields).await })
    }

    fn probe(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let addresses = self.client.hello().await?;
            ensure!(
                addresses.contains(&self.address),
                "the signer at {} holds no key for {:#x} (it signs for {})",
                self.client.endpoint(),
                self.address,
                addresses
                    .iter()
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(())
        })
    }
}

/// The signer a key variable's value names: the key itself, or a signer endpoint carrying
/// the key's address (`unix:///run/quote-signer.sock?address=0x…`,
/// `vsock://16:5000?address=0x…`). Errors never quote the value.
pub fn from_key_value(value: &str) -> Result<SharedSigner> {
    Ok(match KeySpec::parse(value)? {
        KeySpec::Local(key) => Arc::new(LocalSigner { key }),
        KeySpec::Remote { endpoint, address } => Arc::new(RemoteSigner {
            client: Client::new(endpoint, REMOTE_SIGN_TIMEOUT),
            address,
        }),
    })
}

/// A local signer for `secret`, shared. What tests build pairs with.
pub fn local(secret: SecretKey) -> SharedSigner {
    Arc::new(LocalSigner::new(secret))
}

/// `tx` with its signature filled in by `signer`. The fields are what the signer sees; the
/// signature is attached to the same transaction, so what is published is exactly what
/// was signed.
pub async fn sign_transaction(
    signer: &dyn Signer,
    mut tx: EIP1559Transaction,
) -> Result<EIP1559Transaction> {
    let fields = TxFields::from_transaction(&tx)?;
    let signature = signer
        .sign(&fields)
        .await
        .wrap_err_with(|| format!("signing as {:#x}", signer.address()))?;
    // The caches ethrex keeps on a transaction (its hash, its sender, its encoding) must
    // not have been filled while it was unsigned, or they would describe the wrong bytes.
    ensure!(
        tx.inner_hash.get().is_none() && tx.cached_canonical.get().is_none(),
        "the transaction was hashed before it was signed"
    );
    tx.signature_r = signature.r;
    tx.signature_s = signature.s;
    tx.signature_y_parity = signature.y_parity;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use ethrex_common::{U256, types::TxKind};
    use quote_signer::signing::recover;

    use super::*;

    fn unsigned() -> EIP1559Transaction {
        EIP1559Transaction {
            chain_id: 1,
            nonce: 5,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 120_000,
            to: TxKind::Call(Address::from_low_u64_be(0x1e9)),
            value: U256::zero(),
            data: vec![1, 2, 3].into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_local_signature_recovers_to_the_pairs_updater() {
        let signer = local(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let signed = sign_transaction(signer.as_ref(), unsigned()).await.unwrap();
        let fields = TxFields::from_transaction(&signed).unwrap();
        let signature = Signature {
            r: signed.signature_r,
            s: signed.signature_s,
            y_parity: signed.signature_y_parity,
        };
        assert_eq!(recover(&fields, &signature).unwrap(), signer.address());
        assert_eq!(signer.describe(), "local");
        assert!(!format!("{signer:?}").contains("0707"), "{signer:?}");
    }

    #[test]
    fn the_key_variable_decides_the_signer() {
        let local =
            from_key_value("0x0707070707070707070707070707070707070707070707070707070707070707")
                .unwrap();
        assert_eq!(local.describe(), "local");

        let remote = from_key_value(
            "unix:///run/quote-signer.sock?address=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        )
        .unwrap();
        assert_eq!(remote.describe(), "unix:///run/quote-signer.sock");
        assert_eq!(
            format!("{:#x}", remote.address()),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );

        let err = from_key_value("not-a-key").unwrap_err().to_string();
        assert!(!err.contains("not-a-key"), "{err}");
    }

    #[tokio::test]
    async fn a_probe_reaches_the_signer_and_checks_it_holds_the_key() {
        use quote_signer::{
            policy::{KeyPolicy, Policy},
            serve::{Listener, Signer as Process, serve},
            signing::SigningKey,
        };
        let key =
            SigningKey::parse("0x0707070707070707070707070707070707070707070707070707070707070707")
                .unwrap();
        let held = key.address();
        let process = Process::new(
            vec![key],
            Policy {
                registry: Address::zero(),
                chain_id: 1,
                max_gas_limit: 1,
                max_fee_per_gas: None,
                keys: vec![KeyPolicy {
                    address: held,
                    target: Address::zero(),
                    lanes: vec![U256::one()],
                    reference: None,
                }],
            },
            Arc::default(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signer.sock");
        let server = tokio::spawn(serve(Listener::Unix(path.clone()), Arc::new(process)));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let endpoint = format!("unix://{}", path.display());

        let right = from_key_value(&format!("{endpoint}?address={held:#x}")).unwrap();
        right.probe().await.unwrap();
        assert_eq!(
            local(SecretKey::from_slice(&[7u8; 32]).unwrap()).address(),
            held
        );

        let wrong = from_key_value(&format!("{endpoint}?address={:#x}", Address::zero())).unwrap();
        let err = wrong.probe().await.unwrap_err().to_string();
        assert!(err.contains("holds no key"), "{err}");
        server.abort();
    }

    #[tokio::test]
    async fn a_remote_signer_that_is_not_there_fails_the_sign_not_the_build() {
        let signer = from_key_value(
            "unix:///nonexistent/quote-signer.sock?address=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        )
        .unwrap();
        let err = sign_transaction(signer.as_ref(), unsigned())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("signer at unix://"), "{err:#}");
    }
}

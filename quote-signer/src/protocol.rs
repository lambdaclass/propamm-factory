//! The wire protocol between a quote updater and its signer: a request carrying the fields
//! of the unsigned transaction, a response carrying the signature or the refusal.
//!
//! Framed as a 4-byte big-endian length followed by JSON, over whatever byte stream the two
//! share (a Unix socket, a vsock). The fields travel as JSON rather than as the RLP payload
//! the signature is computed over, because the signer must read every one of them to judge
//! the transaction, and a self-describing encoding is what keeps that reading honest: the
//! signer rebuilds the payload from the fields it judged, so it can only ever sign what it
//! saw.

use bytes::Bytes;
use ethrex_common::{
    Address, U256,
    types::{EIP1559Transaction, TxKind},
};
use eyre::{Result, bail, ensure, eyre};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version a `Hello` answers with. Bumped on any change a peer could
/// misread.
pub const VERSION: u32 = 1;

/// The largest frame either side accepts. An update's calldata is a few hundred bytes;
/// anything near this bound is not a request this protocol knows.
pub const MAX_FRAME: usize = 64 * 1024;

/// The fields of an unsigned EIP-1559 transaction, exactly the ones the signature covers.
///
/// Only a plain call with an empty access list is representable: an update is one, and a
/// transaction that is not one has no business reaching a signer that exists to sign
/// updates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxFields {
    /// The chain the transaction is for.
    pub chain_id: u64,
    /// The sender's nonce.
    pub nonce: u64,
    /// The priority fee, in wei per gas.
    pub max_priority_fee_per_gas: u64,
    /// The fee cap, in wei per gas.
    pub max_fee_per_gas: u64,
    /// The gas limit.
    pub gas_limit: u64,
    /// The contract called.
    pub to: Address,
    /// The ether sent along, which an update never carries.
    pub value: U256,
    /// The calldata, as `0x`-prefixed hex on the wire.
    #[serde(with = "hex_bytes")]
    pub data: Bytes,
}

impl TxFields {
    /// The fields of `tx`, or why it cannot travel: a contract creation or an access list.
    pub fn from_transaction(tx: &EIP1559Transaction) -> Result<Self> {
        let TxKind::Call(to) = tx.to else {
            bail!("a contract creation is not an update");
        };
        ensure!(
            tx.access_list.is_empty(),
            "an update carries no access list"
        );
        Ok(Self {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            max_fee_per_gas: tx.max_fee_per_gas,
            gas_limit: tx.gas_limit,
            to,
            value: tx.value,
            data: tx.data.clone(),
        })
    }

    /// The transaction these fields describe, unsigned: the signature fields are zero.
    pub fn to_transaction(&self) -> EIP1559Transaction {
        EIP1559Transaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: TxKind::Call(self.to),
            value: self.value,
            data: self.data.clone(),
            access_list: Vec::new(),
            ..Default::default()
        }
    }
}

/// A secp256k1 signature in the form a transaction carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
    /// The recovery bit, `y_parity` in EIP-1559 terms.
    pub y_parity: bool,
}

/// What a quote updater sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Which addresses does this signer sign for, and which protocol does it speak?
    Hello,
    /// Sign this transaction with the key of `address`.
    Sign {
        /// The key, by the address it signs as.
        address: Address,
        /// The transaction to sign.
        tx: TxFields,
    },
}

/// What the signer answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// The answer to [`Request::Hello`].
    Hello {
        /// [`VERSION`] on the signer's side.
        version: u32,
        /// Every address the signer holds a key and a policy for.
        addresses: Vec<Address>,
    },
    /// The transaction was judged acceptable and signed.
    Signed {
        /// The signature over the transaction's fields.
        signature: Signature,
    },
    /// The signer declined: the transaction failed its policy. Not an error of the
    /// signer's; the updater should treat it as a quote it cannot publish.
    Refused {
        /// Which check failed, for the operator.
        reason: String,
    },
    /// The signer could not process the request: a malformed frame, an unknown address.
    Failed {
        /// What went wrong, for the operator.
        message: String,
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

/// `Bytes` as `0x`-prefixed hex.
mod hex_bytes {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
        let text = String::deserialize(deserializer)?;
        let hex = text
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("calldata must be 0x-prefixed hex"))?;
        hex::decode(hex).map(Bytes::from).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> TxFields {
        TxFields {
            chain_id: 1,
            nonce: 7,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 120_000,
            to: Address::from_low_u64_be(0xda7a),
            value: U256::zero(),
            data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
        }
    }

    #[test]
    fn fields_round_trip_through_a_transaction_and_through_json() {
        let fields = fields();
        let tx = fields.to_transaction();
        assert_eq!(TxFields::from_transaction(&tx).unwrap(), fields);
        assert_eq!(tx.signature_r, U256::zero(), "unsigned");

        let json = serde_json::to_string(&fields).unwrap();
        assert!(json.contains(r#""data":"0xdeadbeef""#), "{json}");
        assert_eq!(serde_json::from_str::<TxFields>(&json).unwrap(), fields);
    }

    #[test]
    fn a_creation_or_an_access_list_does_not_travel() {
        let mut tx = fields().to_transaction();
        tx.to = TxKind::Create;
        assert!(TxFields::from_transaction(&tx).is_err());

        let mut tx = fields().to_transaction();
        tx.access_list.push((Address::zero(), Vec::new()));
        assert!(TxFields::from_transaction(&tx).is_err());
    }

    #[tokio::test]
    async fn frames_round_trip_and_a_clean_close_reads_as_none() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let request = Request::Sign {
            address: Address::from_low_u64_be(1),
            tx: fields(),
        };
        write_frame(&mut a, &request).await.unwrap();
        write_frame(&mut a, &Request::Hello).await.unwrap();
        drop(a);
        assert_eq!(
            read_frame::<_, Request>(&mut b).await.unwrap(),
            Some(request)
        );
        assert_eq!(
            read_frame::<_, Request>(&mut b).await.unwrap(),
            Some(Request::Hello)
        );
        assert_eq!(read_frame::<_, Request>(&mut b).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_frame_claiming_more_than_the_bound_is_refused_before_it_is_read() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        let err = read_frame::<_, Request>(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn responses_are_tagged_by_kind() {
        let json = serde_json::to_string(&Response::Refused {
            reason: "lane".into(),
        })
        .unwrap();
        assert_eq!(json, r#"{"kind":"refused","reason":"lane"}"#);
    }
}

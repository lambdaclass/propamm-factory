//! The signature itself: keccak over the type-prefixed RLP payload of the fields, then a
//! recoverable secp256k1 signature, exactly as an EIP-1559 transaction is signed. One
//! implementation, used by the signer process and by a quote updater signing locally, so
//! the two can never disagree on what the bytes under the signature are.

use std::fmt;

use ethrex_common::{Address, H256, types::TxType, utils::keccak};
use ethrex_rlp::encode::PayloadRLPEncode;
use eyre::{Result, eyre};
use secp256k1::{
    Message, SECP256K1, SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};

use crate::protocol::{Signature, TxFields};

/// A secp256k1 key and the address it signs as.
///
/// `Debug` prints the address only: this type reaches logs through the structs that hold
/// it, and a key must never.
#[derive(Clone)]
pub struct SigningKey {
    secret: SecretKey,
    address: Address,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({:#x})", self.address)
    }
}

impl SigningKey {
    /// The key for `secret`.
    pub fn new(secret: SecretKey) -> Self {
        let address = address_of(&secret);
        Self { secret, address }
    }

    /// Parses a key from its hex, with or without `0x`. The error never quotes the input:
    /// what failed to parse may be most of a key.
    pub fn parse(text: &str) -> Result<Self> {
        let hex = text.trim().strip_prefix("0x").unwrap_or(text.trim());
        hex.parse::<SecretKey>()
            .map(Self::new)
            .map_err(|_| eyre!("not a valid secp256k1 private key"))
    }

    /// The address this key signs as.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Signs the transaction `fields` describe.
    pub fn sign(&self, fields: &TxFields) -> Signature {
        let digest = Message::from_digest(signing_hash(fields).0);
        let (recovery_id, compact) = SECP256K1
            .sign_ecdsa_recoverable(&digest, &self.secret)
            .serialize_compact();
        Signature {
            r: ethrex_common::U256::from_big_endian(&compact[..32]),
            s: ethrex_common::U256::from_big_endian(&compact[32..]),
            y_parity: i32::from(recovery_id) != 0,
        }
    }
}

/// The bytes an EIP-1559 signature covers: the type byte, then the RLP of the unsigned
/// fields.
pub fn signing_payload(fields: &TxFields) -> Vec<u8> {
    let mut payload = vec![TxType::EIP1559 as u8];
    payload.extend(fields.to_transaction().encode_payload_to_vec());
    payload
}

/// keccak256 of [`signing_payload`]: the digest actually signed.
pub fn signing_hash(fields: &TxFields) -> H256 {
    keccak(signing_payload(fields))
}

/// The address that produced `signature` over `fields`, or an error for a signature that
/// recovers to nothing. What a client checks a remote signature against before trusting
/// it.
pub fn recover(fields: &TxFields, signature: &Signature) -> Result<Address> {
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&signature.r.to_big_endian());
    compact[32..].copy_from_slice(&signature.s.to_big_endian());
    let recovery_id = RecoveryId::try_from(i32::from(signature.y_parity))
        .map_err(|err| eyre!("recovery id: {err}"))?;
    let recoverable = RecoverableSignature::from_compact(&compact, recovery_id)
        .map_err(|err| eyre!("malformed signature: {err}"))?;
    let digest = Message::from_digest(signing_hash(fields).0);
    let public_key = SECP256K1
        .recover_ecdsa(&digest, &recoverable)
        .map_err(|err| eyre!("signature recovers to no key: {err}"))?;
    Ok(Address::from(keccak(
        &public_key.serialize_uncompressed()[1..],
    )))
}

fn address_of(secret: &SecretKey) -> Address {
    Address::from(keccak(
        &secret.public_key(SECP256K1).serialize_uncompressed()[1..],
    ))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use ethrex_common::U256;

    use super::*;

    /// The first anvil account: a well-known public test key, not a secret.
    const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDR: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    fn fields() -> TxFields {
        TxFields {
            chain_id: 1,
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 40_000_000_000,
            gas_limit: 120_000,
            to: Address::from_low_u64_be(0xda7a),
            value: U256::zero(),
            data: Bytes::from_static(&[1, 2, 3, 4]),
        }
    }

    #[test]
    fn the_address_is_the_keys_and_debug_shows_nothing_else() {
        let key = SigningKey::parse(ANVIL_KEY).unwrap();
        assert_eq!(format!("{:x}", key.address()), ANVIL_ADDR);
        let shown = format!("{key:?}");
        assert!(shown.contains(ANVIL_ADDR), "{shown}");
        assert!(!shown.contains("ac0974"), "{shown}");
        assert!(SigningKey::parse("0x00").is_err());
        assert!(
            !SigningKey::parse("zz")
                .unwrap_err()
                .to_string()
                .contains("zz")
        );
    }

    #[test]
    fn a_signature_recovers_to_the_signer_and_to_nobody_else_over_other_fields() {
        let key = SigningKey::parse(ANVIL_KEY).unwrap();
        let fields = fields();
        let signature = key.sign(&fields);
        assert_eq!(recover(&fields, &signature).unwrap(), key.address());

        let mut other = fields.clone();
        other.nonce += 1;
        assert_ne!(recover(&other, &signature).unwrap(), key.address());
    }

    #[test]
    fn the_payload_is_the_type_byte_then_the_rlp_of_the_unsigned_fields() {
        let payload = signing_payload(&fields());
        assert_eq!(payload[0], 0x02);
        // The RLP of nine fields starts with a list prefix; the signature fields are not
        // in it, so re-encoding with a signature set must not change the payload.
        let mut tx = fields().to_transaction();
        tx.signature_r = U256::one();
        assert_eq!(
            payload[1..],
            tx.encode_payload_to_vec()[..],
            "the payload covers the unsigned fields only"
        );
    }
}

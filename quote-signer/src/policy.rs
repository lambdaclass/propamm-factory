//! What the signer agrees to sign. A key is released to the process; the policy is what
//! stops that process from being a blind signer for whoever can reach it: every request is
//! decoded and judged, and anything that is not an `updateState` to the configured
//! registry, for a lane this key is allowed to quote, at a price near a reference the
//! signer read for itself, is refused.
//!
//! Pure: no clock, no network. The reference price and the time are passed in, so every
//! verdict is a unit test.

use std::{sync::LazyLock, time::Duration};

use ethrex_common::{Address, U256, utils::keccak};
use serde::{Deserialize, Serialize};

use crate::protocol::TxFields;

/// The function every signed transaction must call.
pub const UPDATE_STATE_SIG: &str = "updateState(address,uint256,uint32,uint256[])";

static UPDATE_STATE_SELECTOR: LazyLock<[u8; 4]> = LazyLock::new(|| {
    let hash = keccak(UPDATE_STATE_SIG.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
});

/// The process-wide rules, and one entry per key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The only contract a signed transaction may call.
    pub registry: Address,
    /// The only chain a signed transaction may be for.
    pub chain_id: u64,
    /// The most gas an update may be allowed.
    pub max_gas_limit: u64,
    /// The highest fee cap an update may carry, in wei per gas; unset, any.
    #[serde(default)]
    pub max_fee_per_gas: Option<u64>,
    /// The keys, by address, and what each may sign.
    #[serde(default)]
    pub keys: Vec<KeyPolicy>,
}

/// What one key may sign.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPolicy {
    /// The key, by the address it signs as.
    pub address: Address,
    /// The only `target` an update by this key may name.
    pub target: Address,
    /// The lanes this key may quote.
    pub lanes: Vec<U256>,
    /// The price check, when the key's lane has a reference to check against.
    #[serde(default)]
    pub reference: Option<ReferenceBand>,
}

/// A published mid must sit within `max_distance` of a reference price the signer reads
/// itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceBand {
    /// The venue symbol the reference is read under.
    pub symbol: String,
    /// Whether the lane's mid is the reciprocal of the venue's price.
    #[serde(default)]
    pub inverted: bool,
    /// The decimals a published mid is scaled by.
    pub price_decimals: u32,
    /// The furthest the mid may sit from the reference, as a fraction (`0.02` is 2%).
    pub max_distance: f64,
    /// A reference older than this is no reference: the request is refused.
    pub max_age: Duration,
}

/// The `updateState` call a request's calldata decodes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    /// The contract the price is for.
    pub target: Address,
    /// The lane.
    pub lane: U256,
    /// The timestamp.
    pub ts: u32,
    /// The published half-spread.
    pub delta: U256,
    /// The published mid.
    pub mid: U256,
    /// The optional third slot.
    pub quote_id: Option<U256>,
}

/// A reference price and when it was read, in whatever clock the caller judges by.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reference {
    /// The venue's mid.
    pub mid: f64,
    /// How old it is at the moment of judging.
    pub age: Duration,
}

/// Decodes `updateState(address,uint256,uint32,uint256[])` calldata by hand: the ABI is
/// fixed, and the signer should not need a general decoder to read the one call it exists
/// to judge.
pub fn decode_update(data: &[u8]) -> Result<Update, String> {
    let selector = data
        .get(..4)
        .ok_or_else(|| "calldata shorter than a selector".to_owned())?;
    if selector != *UPDATE_STATE_SELECTOR {
        return Err(format!(
            "not an updateState call (selector 0x{})",
            hex::encode(selector)
        ));
    }
    let words = &data[4..];
    let word = |index: usize| -> Result<U256, String> {
        words
            .get(index * 32..(index + 1) * 32)
            .map(U256::from_big_endian)
            .ok_or_else(|| format!("calldata ends before word {index}"))
    };
    let target_word = word(0)?;
    if target_word > U256::from_big_endian(&[0xff; 20]) {
        return Err("target is not an address".to_owned());
    }
    let lane = word(1)?;
    let ts = word(2)?;
    let ts = u32::try_from(ts).map_err(|_| "timestamp does not fit u32".to_owned())?;
    let offset = word(3)?;
    if offset != U256::from(4 * 32) {
        return Err("the array offset is not the one a four-argument call has".to_owned());
    }
    let len = word(4)?;
    let len = usize::try_from(len).map_err(|_| "array length overflows".to_owned())?;
    if !(2..=3).contains(&len) {
        return Err(format!("the array holds {len} values, not 2 or 3"));
    }
    let delta = word(5)?;
    let mid = word(6)?;
    let quote_id = if len == 3 { Some(word(7)?) } else { None };
    if words.len() != (5 + len) * 32 {
        return Err("trailing bytes after the array".to_owned());
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&words[12..32]);
    Ok(Update {
        target: Address::from(target),
        lane,
        ts,
        delta,
        mid,
        quote_id,
    })
}

impl Policy {
    /// The entry for `address`, if the policy knows the key.
    pub fn key(&self, address: Address) -> Option<&KeyPolicy> {
        self.keys.iter().find(|key| key.address == address)
    }

    /// Judges a request to sign `tx` with the key of `address`. `reference` answers with
    /// the latest reading for a venue symbol, or `None` for one never read. `Ok(())` is
    /// permission to sign; `Err` names the check that failed.
    pub fn judge(
        &self,
        address: Address,
        tx: &TxFields,
        reference: impl Fn(&str) -> Option<Reference>,
    ) -> Result<(), String> {
        let key = self
            .key(address)
            .ok_or_else(|| format!("no policy for {address:#x}"))?;
        if tx.chain_id != self.chain_id {
            return Err(format!("chain id {} is not {}", tx.chain_id, self.chain_id));
        }
        if tx.to != self.registry {
            return Err(format!("calls {:#x}, not the registry", tx.to));
        }
        if !tx.value.is_zero() {
            return Err("carries value".to_owned());
        }
        if tx.gas_limit > self.max_gas_limit {
            return Err(format!(
                "gas limit {} above {}",
                tx.gas_limit, self.max_gas_limit
            ));
        }
        if let Some(max) = self.max_fee_per_gas
            && tx.max_fee_per_gas > max
        {
            return Err(format!("fee cap {} above {max}", tx.max_fee_per_gas));
        }
        if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
            return Err("priority fee above the fee cap".to_owned());
        }
        let update = decode_update(&tx.data)?;
        if update.target != key.target {
            return Err(format!("target {:#x} is not this key's", update.target));
        }
        if !key.lanes.contains(&update.lane) {
            return Err(format!(
                "lane {:#x} is not one this key may quote",
                update.lane
            ));
        }
        if let Some(band) = &key.reference {
            let reading = reference(&band.symbol)
                .ok_or_else(|| format!("no reference price for {}", band.symbol))?;
            if reading.age > band.max_age {
                return Err(format!(
                    "reference price for {} is {:.0}s old",
                    band.symbol,
                    reading.age.as_secs_f64()
                ));
            }
            let expected = if band.inverted {
                1.0 / reading.mid
            } else {
                reading.mid
            };
            let published = scaled_to_f64(update.mid, band.price_decimals);
            if !(expected.is_finite() && expected > 0.0) {
                return Err(format!("reference price for {} is not usable", band.symbol));
            }
            let distance = (published / expected - 1.0).abs();
            // `>` alone would let a NaN mid through: NaN compares false to everything.
            if distance.is_nan() || distance > band.max_distance {
                return Err(format!(
                    "mid {published} is {:.2}% from the reference {expected}, limit {:.2}%",
                    distance * 100.0,
                    band.max_distance * 100.0
                ));
            }
        }
        Ok(())
    }
}

/// A scaled integer as the number it stands for. Precise enough for a band check: the
/// comparison is to a few percent, not to a wei.
pub fn scaled_to_f64(value: U256, decimals: u32) -> f64 {
    let mut as_f64 = 0.0f64;
    for byte in value.to_big_endian() {
        as_f64 = as_f64 * 256.0 + f64::from(byte);
    }
    as_f64 / 10f64.powi(decimals as i32)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use ethrex_l2_common::calldata::Value;
    use ethrex_l2_sdk::calldata::encode_calldata;

    use super::*;

    fn registry() -> Address {
        Address::from_low_u64_be(0x1e9)
    }
    fn target() -> Address {
        Address::from_low_u64_be(0x7a1)
    }
    fn lane() -> U256 {
        U256::from(42)
    }
    fn key() -> Address {
        Address::from_low_u64_be(0xabc)
    }

    fn policy(reference: Option<ReferenceBand>) -> Policy {
        Policy {
            registry: registry(),
            chain_id: 1,
            max_gas_limit: 120_000,
            max_fee_per_gas: Some(100_000_000_000),
            keys: vec![KeyPolicy {
                address: key(),
                target: target(),
                lanes: vec![lane()],
                reference,
            }],
        }
    }

    fn band() -> ReferenceBand {
        ReferenceBand {
            symbol: "ETHUSDC".into(),
            inverted: false,
            price_decimals: 18,
            max_distance: 0.02,
            max_age: Duration::from_secs(30),
        }
    }

    fn calldata(target: Address, lane: U256, mid: U256, quote_id: Option<U256>) -> Bytes {
        let mut array = vec![Value::Uint(U256::from(1_000_000)), Value::Uint(mid)];
        if let Some(id) = quote_id {
            array.push(Value::Uint(id));
        }
        encode_calldata(
            UPDATE_STATE_SIG,
            &[
                Value::Address(target),
                Value::Uint(lane),
                Value::Uint(U256::from(1_700_000_000u64)),
                Value::Array(array),
            ],
        )
        .unwrap()
        .into()
    }

    fn mid(value: f64) -> U256 {
        U256::from((value * 1e6) as u64) * U256::exp10(12)
    }

    fn tx(data: Bytes) -> TxFields {
        TxFields {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 120_000,
            to: registry(),
            value: U256::zero(),
            data,
        }
    }

    fn fresh(mid: f64) -> impl Fn(&str) -> Option<Reference> {
        move |symbol| {
            (symbol == "ETHUSDC").then_some(Reference {
                mid,
                age: Duration::from_secs(1),
            })
        }
    }

    #[test]
    fn the_hand_decoder_agrees_with_the_reference_encoder() {
        let data = calldata(target(), lane(), mid(2500.0), None);
        let update = decode_update(&data).unwrap();
        assert_eq!(update.target, target());
        assert_eq!(update.lane, lane());
        assert_eq!(update.ts, 1_700_000_000);
        assert_eq!(update.delta, U256::from(1_000_000));
        assert_eq!(update.mid, mid(2500.0));
        assert_eq!(update.quote_id, None);

        let data = calldata(target(), lane(), mid(2500.0), Some(U256::from(9)));
        assert_eq!(decode_update(&data).unwrap().quote_id, Some(U256::from(9)));

        assert!(
            decode_update(&data[..40])
                .unwrap_err()
                .contains("ends before")
        );
        let mut other = data.to_vec();
        other[0] ^= 1;
        assert!(
            decode_update(&other)
                .unwrap_err()
                .contains("not an updateState")
        );
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(decode_update(&trailing).unwrap_err().contains("trailing"));
    }

    #[test]
    fn a_well_formed_update_inside_the_band_is_signed() {
        let policy = policy(Some(band()));
        let request = tx(calldata(target(), lane(), mid(2510.0), None));
        assert_eq!(policy.judge(key(), &request, fresh(2500.0)), Ok(()));
    }

    #[test]
    fn each_check_refuses_with_its_own_reason() {
        let policy = policy(Some(band()));
        let good = tx(calldata(target(), lane(), mid(2500.0), None));

        let unknown = policy
            .judge(Address::zero(), &good, fresh(2500.0))
            .unwrap_err();
        assert!(unknown.contains("no policy"), "{unknown}");

        let mut other_chain = good.clone();
        other_chain.chain_id = 11155111;
        assert!(
            policy
                .judge(key(), &other_chain, fresh(2500.0))
                .unwrap_err()
                .contains("chain id")
        );

        let mut other_contract = good.clone();
        other_contract.to = target();
        assert!(
            policy
                .judge(key(), &other_contract, fresh(2500.0))
                .unwrap_err()
                .contains("registry")
        );

        let mut with_value = good.clone();
        with_value.value = U256::one();
        assert!(
            policy
                .judge(key(), &with_value, fresh(2500.0))
                .unwrap_err()
                .contains("value")
        );

        let mut gassy = good.clone();
        gassy.gas_limit = 1_000_000;
        assert!(
            policy
                .judge(key(), &gassy, fresh(2500.0))
                .unwrap_err()
                .contains("gas limit")
        );

        let mut pricey = good.clone();
        pricey.max_fee_per_gas = 1_000_000_000_000;
        assert!(
            policy
                .judge(key(), &pricey, fresh(2500.0))
                .unwrap_err()
                .contains("fee cap")
        );

        let mut tipped = good.clone();
        tipped.max_priority_fee_per_gas = tipped.max_fee_per_gas + 1;
        assert!(
            policy
                .judge(key(), &tipped, fresh(2500.0))
                .unwrap_err()
                .contains("priority")
        );

        let mut not_an_update = good.clone();
        not_an_update.data = Bytes::from_static(&[0, 0, 0, 0]);
        assert!(
            policy
                .judge(key(), &not_an_update, fresh(2500.0))
                .unwrap_err()
                .contains("updateState")
        );

        let other_target = tx(calldata(Address::zero(), lane(), mid(2500.0), None));
        assert!(
            policy
                .judge(key(), &other_target, fresh(2500.0))
                .unwrap_err()
                .contains("target")
        );

        let other_lane = tx(calldata(target(), U256::from(7), mid(2500.0), None));
        assert!(
            policy
                .judge(key(), &other_lane, fresh(2500.0))
                .unwrap_err()
                .contains("lane")
        );
    }

    #[test]
    fn the_price_check_fails_closed_on_a_missing_stale_or_far_reference() {
        let policy = policy(Some(band()));
        let good = tx(calldata(target(), lane(), mid(2500.0), None));

        let missing = policy.judge(key(), &good, |_| None).unwrap_err();
        assert!(missing.contains("no reference"), "{missing}");

        let stale = policy
            .judge(key(), &good, |_| {
                Some(Reference {
                    mid: 2500.0,
                    age: Duration::from_secs(31),
                })
            })
            .unwrap_err();
        assert!(stale.contains("old"), "{stale}");

        let far = policy.judge(key(), &good, fresh(2600.0)).unwrap_err();
        assert!(far.contains("from the reference"), "{far}");

        let nan = policy.judge(key(), &good, fresh(f64::NAN)).unwrap_err();
        assert!(nan.contains("not usable"), "{nan}");
    }

    #[test]
    fn an_inverted_lane_is_checked_against_the_reciprocal() {
        let mut inverted = band();
        inverted.inverted = true;
        let policy = policy(Some(inverted));
        // A lane quoting USDC per WETH as WETH per USDC: 1/2500 = 0.0004.
        let request = tx(calldata(
            target(),
            lane(),
            U256::from(400_000_000_000_000u64),
            None,
        ));
        assert_eq!(policy.judge(key(), &request, fresh(2500.0)), Ok(()));
        assert!(policy.judge(key(), &request, fresh(2000.0)).is_err());
    }

    #[test]
    fn without_a_band_only_the_shape_is_checked() {
        let policy = policy(None);
        let request = tx(calldata(target(), lane(), mid(1.0), None));
        assert_eq!(policy.judge(key(), &request, |_| None), Ok(()));
    }

    #[test]
    fn scaled_values_read_as_numbers() {
        assert_eq!(scaled_to_f64(U256::exp10(18), 18), 1.0);
        assert_eq!(
            scaled_to_f64(U256::from(2500) * U256::exp10(18), 18),
            2500.0
        );
        assert_eq!(scaled_to_f64(U256::from(1_000_000), 6), 1.0);
    }
}

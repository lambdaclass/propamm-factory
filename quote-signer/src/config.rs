//! The signer's config file: where it listens, where its keys come from, what it signs,
//! and where it reads its reference prices. Every address, lane and fraction is a string
//! in the file; parsing turns them into the types the policy judges with.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use ethrex_common::{Address, U256};
use eyre::{Result, WrapErr, bail, ensure, eyre};
use serde::Deserialize;
use url::Url;

use crate::{
    policy::{KeyPolicy, Policy, ReferenceBand},
    serve::Listener,
};

/// The file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    listen: RawListen,
    keys: RawKeys,
    policy: RawPolicy,
    #[serde(default)]
    reference: RawReference,
    #[serde(default)]
    forward: Vec<RawForward>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListen {
    unix: Option<PathBuf>,
    vsock_port: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeys {
    file: Option<PathBuf>,
    nitro: Option<RawNitro>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNitro {
    boot_port: u32,
    region: String,
    kms_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    registry: String,
    chain_id: u64,
    max_gas_limit: u64,
    max_fee_per_gas_gwei: Option<u64>,
    keys: Vec<RawKeyPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyPolicy {
    address: String,
    target: String,
    lanes: Vec<String>,
    reference: Option<RawBand>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBand {
    symbol: String,
    #[serde(default)]
    inverted: bool,
    price_decimals: u32,
    max_distance: String,
    max_age_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReference {
    base_url: Option<String>,
    poll_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForward {
    listen: SocketAddr,
    cid: u32,
    port: u32,
}

/// Where the keys come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// A file of keys.
    File(PathBuf),
    /// The Nitro key release.
    Nitro(NitroSettings),
}

/// The Nitro key release's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NitroSettings {
    /// The vsock port the host's boot helper connects to with the ciphertexts and the
    /// credentials.
    pub boot_port: u32,
    /// The region the KMS key lives in.
    pub region: String,
    /// Where KMS is reached, when not its public endpoint (inside an enclave, a loopback
    /// address a `[[forward]]` tunnels out).
    pub kms_endpoint: Option<String>,
}

/// A loopback port tunnelled to a vsock port on the host: how an enclave, which has no
/// network, reaches KMS and the reference venue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// The loopback address to listen on.
    pub listen: SocketAddr,
    /// The context id to connect to (the host is `3`).
    pub cid: u32,
    /// The vsock port there.
    pub port: u32,
}

/// The reference feed's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSettings {
    /// The venue's base URL.
    pub base_url: Url,
    /// How often each symbol is read.
    pub every: Duration,
}

/// The config, parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Where to listen.
    pub listen: Listener,
    /// Where the keys come from.
    pub keys: KeySource,
    /// What to sign.
    pub policy: Policy,
    /// Where the reference prices come from.
    pub reference: ReferenceSettings,
    /// The tunnels to open before anything else.
    pub forward: Vec<Forward>,
}

/// The default reference venue.
pub const DEFAULT_REFERENCE_URL: &str = "https://api.binance.com/";

impl Config {
    /// Parses the file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: Raw = toml::from_str(text).wrap_err("config")?;
        let listen = match (raw.listen.unix, raw.listen.vsock_port) {
            (Some(path), None) => Listener::Unix(path),
            (None, Some(port)) => Listener::Vsock(port),
            (Some(_), Some(_)) => bail!("[listen]: set unix or vsock_port, not both"),
            (None, None) => bail!("[listen]: set unix = \"<socket path>\" or vsock_port = <port>"),
        };
        let keys = match (raw.keys.file, raw.keys.nitro) {
            (Some(path), None) => KeySource::File(path),
            (None, Some(nitro)) => KeySource::Nitro(NitroSettings {
                boot_port: nitro.boot_port,
                region: nitro.region,
                kms_endpoint: nitro.kms_endpoint,
            }),
            (Some(_), Some(_)) => bail!("[keys]: set file or nitro, not both"),
            (None, None) => bail!("[keys]: set file = \"<key file>\" or a nitro table"),
        };
        ensure!(
            !raw.policy.keys.is_empty(),
            "[policy]: no keys; nothing could be signed"
        );
        let mut key_policies = Vec::with_capacity(raw.policy.keys.len());
        for (index, key) in raw.policy.keys.into_iter().enumerate() {
            let at = format!("[[policy.keys]] #{}", index + 1);
            let lanes = key
                .lanes
                .iter()
                .map(|lane| parse_u256(lane).wrap_err_with(|| format!("{at}: lane {lane:?}")))
                .collect::<Result<Vec<_>>>()?;
            ensure!(!lanes.is_empty(), "{at}: no lanes; nothing could be signed");
            let reference = match key.reference {
                None => None,
                Some(band) => {
                    let max_distance: f64 = band.max_distance.parse().map_err(|_| {
                        eyre!("{at}: max_distance {:?} is not a number", band.max_distance)
                    })?;
                    ensure!(
                        max_distance > 0.0 && max_distance < 1.0,
                        "{at}: max_distance is a fraction of the price: 0.02 for 2%"
                    );
                    ensure!(band.max_age_secs > 0, "{at}: max_age_secs must be positive");
                    Some(ReferenceBand {
                        symbol: band.symbol,
                        inverted: band.inverted,
                        price_decimals: band.price_decimals,
                        max_distance,
                        max_age: Duration::from_secs(band.max_age_secs),
                    })
                }
            };
            key_policies.push(KeyPolicy {
                address: parse_address(&key.address).wrap_err_with(|| format!("{at}: address"))?,
                target: parse_address(&key.target).wrap_err_with(|| format!("{at}: target"))?,
                lanes,
                reference,
            });
        }
        let policy = Policy {
            registry: parse_address(&raw.policy.registry).wrap_err("[policy]: registry")?,
            chain_id: raw.policy.chain_id,
            max_gas_limit: raw.policy.max_gas_limit,
            max_fee_per_gas: raw
                .policy
                .max_fee_per_gas_gwei
                .map(|gwei| gwei * 1_000_000_000),
            keys: key_policies,
        };
        let base_url = raw
            .reference
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_REFERENCE_URL);
        let mut base_url = Url::parse(base_url).wrap_err("[reference]: base_url")?;
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let every = Duration::from_millis(raw.reference.poll_ms.unwrap_or(1000).max(100));
        let forward = raw
            .forward
            .into_iter()
            .map(|f| Forward {
                listen: f.listen,
                cid: f.cid,
                port: f.port,
            })
            .collect();
        Ok(Self {
            listen,
            keys,
            policy,
            reference: ReferenceSettings { base_url, every },
            forward,
        })
    }
}

fn parse_address(text: &str) -> Result<Address> {
    text.trim()
        .trim_start_matches("0x")
        .parse()
        .map_err(|_| eyre!("{text:?} is not a 20-byte hex address"))
}

fn parse_u256(text: &str) -> Result<U256> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(|_| eyre!("not a hex number"))
    } else {
        U256::from_dec_str(text).map_err(|_| eyre!("not a decimal number"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[listen]
unix = "/run/quote-signer.sock"

[keys]
file = "keys.txt"

[reference]
base_url = "https://api.binance.com"
poll_ms = 500

[policy]
registry = "0x00000000000000000000000000000000000001e9"
chain_id = 1
max_gas_limit = 120000
max_fee_per_gas_gwei = 300

[[policy.keys]]
address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
target = "0x00000000000000000000000000000000000007a1"
lanes = ["0x2a", "43"]
reference = { symbol = "ETHUSDC", inverted = true, price_decimals = 18, max_distance = "0.02", max_age_secs = 30 }

[[forward]]
listen = "127.0.0.1:443"
cid = 3
port = 8001
"#;

    #[test]
    fn a_full_config_parses_into_the_policy() {
        let config = Config::parse(FULL).unwrap();
        assert_eq!(
            config.listen,
            Listener::Unix("/run/quote-signer.sock".into())
        );
        assert_eq!(config.keys, KeySource::File("keys.txt".into()));
        assert_eq!(config.policy.chain_id, 1);
        assert_eq!(config.policy.max_fee_per_gas, Some(300_000_000_000));
        let key = &config.policy.keys[0];
        assert_eq!(key.lanes, vec![U256::from(42), U256::from(43)]);
        let band = key.reference.as_ref().unwrap();
        assert!(band.inverted);
        assert_eq!(band.max_distance, 0.02);
        assert_eq!(band.max_age, Duration::from_secs(30));
        assert_eq!(
            config.reference.base_url.as_str(),
            "https://api.binance.com/"
        );
        assert_eq!(config.reference.every, Duration::from_millis(500));
        assert_eq!(config.forward[0].cid, 3);
    }

    #[test]
    fn a_nitro_source_and_a_vsock_listener_parse() {
        let text = r#"
[listen]
vsock_port = 5000
[keys]
nitro = { boot_port = 5001, region = "eu-west-1", kms_endpoint = "https://127.0.0.1:8443" }
[policy]
registry = "0x00000000000000000000000000000000000001e9"
chain_id = 1
max_gas_limit = 120000
[[policy.keys]]
address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
target = "0x00000000000000000000000000000000000007a1"
lanes = ["1"]
"#;
        let config = Config::parse(text).unwrap();
        assert_eq!(config.listen, Listener::Vsock(5000));
        assert!(matches!(config.keys, KeySource::Nitro(ref n) if n.boot_port == 5001));
        assert_eq!(config.reference.base_url.as_str(), DEFAULT_REFERENCE_URL);
    }

    #[test]
    fn the_mistakes_an_operator_makes_are_named() {
        let cases = [
            (
                "[listen]\n[keys]\nfile = \"k\"\n[policy]\nregistry = \"0x00\"\nchain_id = 1\nmax_gas_limit = 1\nkeys = []\n",
                "[listen]",
            ),
            (
                "[listen]\nunix = \"s\"\n[keys]\n[policy]\nregistry = \"0x00\"\nchain_id = 1\nmax_gas_limit = 1\nkeys = []\n",
                "[keys]",
            ),
            (
                "[listen]\nunix = \"s\"\n[keys]\nfile = \"k\"\n[policy]\nregistry = \"0x00\"\nchain_id = 1\nmax_gas_limit = 1\nkeys = []\n",
                "no keys",
            ),
            (
                &FULL.replace("max_distance = \"0.02\"", "max_distance = \"2\""),
                "fraction",
            ),
            (
                &FULL.replace("lanes = [\"0x2a\", \"43\"]", "lanes = []"),
                "no lanes",
            ),
            (&FULL.replace("target = ", "goal = "), "unknown field"),
        ];
        for (text, expected) in cases {
            let err = format!("{:#}", Config::parse(text).unwrap_err());
            assert!(err.contains(expected), "{expected:?} not in {err}");
        }
    }
}

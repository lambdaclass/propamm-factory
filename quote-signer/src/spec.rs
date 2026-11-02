//! How a quote updater names a pair's key: the key itself, or where a signer holding it
//! listens. One string, so the same variable a pair already reads its key from can point
//! at a signer process instead.

use std::{fmt, path::PathBuf};

use ethrex_common::Address;
use eyre::{Result, bail, ensure, eyre};
use url::Url;

use crate::signing::SigningKey;

/// Where a signer process listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket at this path.
    Unix(PathBuf),
    /// A vsock port on this context id (the host side of an enclave is `3`; an enclave
    /// has the id it was started with).
    Vsock {
        /// The context id.
        cid: u32,
        /// The port.
        port: u32,
    },
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
            Self::Vsock { cid, port } => write!(f, "vsock://{cid}:{port}"),
        }
    }
}

/// What a key variable holds.
#[derive(Clone, Debug)]
pub enum KeySpec {
    /// The key itself.
    Local(SigningKey),
    /// A signer process that holds the key for `address`.
    Remote {
        /// Where it listens.
        endpoint: Endpoint,
        /// The address it signs as, which the updater needs before it ever connects (to
        /// report it, to check its authorization and balance).
        address: Address,
    },
}

impl KeySpec {
    /// Parses the variable's value. A value starting with `unix://` or `vsock://` is a
    /// signer endpoint with the key's address in its query, such as
    /// `unix:///run/quote-signer.sock?address=0x…` or `vsock://16:5000?address=0x…`;
    /// anything else is the hex of a key. Errors never quote the value.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if !(value.starts_with("unix://") || value.starts_with("vsock://")) {
            return SigningKey::parse(value).map(Self::Local);
        }
        let url = Url::parse(value).map_err(|err| eyre!("not a signer endpoint: {err}"))?;
        let mut address = None;
        for (key, text) in url.query_pairs() {
            ensure!(
                key == "address",
                "unknown query parameter {key:?} on a signer endpoint"
            );
            let parsed: Address = text
                .trim_start_matches("0x")
                .parse()
                .map_err(|_| eyre!("the signer endpoint's address is not a 20-byte hex address"))?;
            address = Some(parsed);
        }
        let address = address.ok_or_else(|| {
            eyre!("a signer endpoint needs the key's address: append ?address=0x…")
        })?;
        let endpoint = match url.scheme() {
            "unix" => {
                ensure!(
                    url.host_str().is_none_or(str::is_empty),
                    "a unix endpoint is unix:///absolute/path (three slashes)"
                );
                ensure!(
                    !url.path().is_empty(),
                    "a unix endpoint needs a socket path"
                );
                Endpoint::Unix(PathBuf::from(url.path()))
            }
            "vsock" => {
                let cid: u32 = url
                    .host_str()
                    .ok_or_else(|| eyre!("a vsock endpoint is vsock://<cid>:<port>"))?
                    .parse()
                    .map_err(|_| eyre!("the vsock context id must be a number"))?;
                let port = url
                    .port()
                    .ok_or_else(|| eyre!("a vsock endpoint needs a port: vsock://<cid>:<port>"))?;
                Endpoint::Vsock {
                    cid,
                    port: u32::from(port),
                }
            }
            other => bail!("unknown signer scheme {other:?}"),
        };
        Ok(Self::Remote { endpoint, address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hex_key_is_local_and_an_endpoint_is_remote() {
        let local =
            KeySpec::parse("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        assert!(matches!(local, KeySpec::Local(_)));

        let addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let KeySpec::Remote { endpoint, address } =
            KeySpec::parse(&format!("unix:///run/quote-signer.sock?address={addr}")).unwrap()
        else {
            panic!("remote");
        };
        assert_eq!(endpoint, Endpoint::Unix("/run/quote-signer.sock".into()));
        assert_eq!(format!("{address:#x}"), addr.to_lowercase());
        assert_eq!(endpoint.to_string(), "unix:///run/quote-signer.sock");

        let KeySpec::Remote { endpoint, .. } =
            KeySpec::parse(&format!("vsock://16:5000?address={addr}")).unwrap()
        else {
            panic!("remote");
        };
        assert_eq!(
            endpoint,
            Endpoint::Vsock {
                cid: 16,
                port: 5000
            }
        );
        assert_eq!(endpoint.to_string(), "vsock://16:5000");
    }

    #[test]
    fn an_endpoint_without_an_address_or_with_junk_is_refused_without_echoing_it() {
        let err = KeySpec::parse("unix:///run/s.sock")
            .unwrap_err()
            .to_string();
        assert!(err.contains("address"), "{err}");
        let err = KeySpec::parse("vsock://16?address=0x00")
            .unwrap_err()
            .to_string();
        assert!(err.contains("port") || err.contains("address"), "{err}");
        let err = KeySpec::parse("unix://host/path?address=0x0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("three slashes") || err.contains("address"),
            "{err}"
        );
        let err = KeySpec::parse("deadbeefsecret").unwrap_err().to_string();
        assert!(!err.contains("deadbeef"), "{err}");
    }
}

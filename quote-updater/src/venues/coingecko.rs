//! CoinGecko's HTTP API, which the pusher uses for one thing: the USD price of every vault
//! token, once a minute, for the dashboard (`vault.rs`). It is not a price source for
//! quoting: an aggregate refreshed about once a minute has no place in a mid, and polling it
//! per market would spend the plan's monthly calls in days.
//!
//! A paid plan's API key, when `COINGECKO_API_KEY` holds one, goes to the paid host with the
//! paid header: a paid key works only there, and the free host refuses it.

/// The free API, and the default `coingecko` endpoint setting.
pub const DEFAULT_ENDPOINT: &str = "https://api.coingecko.com/api/v3";

/// The paid API (Basic plan and up).
pub const PRO_ENDPOINT: &str = "https://pro-api.coingecko.com/api/v3";

/// The environment variable holding a paid plan's API key, if any.
pub const API_KEY_VAR: &str = "COINGECKO_API_KEY";

/// The key in `COINGECKO_API_KEY`, if any.
fn api_key() -> Option<String> {
    std::env::var(API_KEY_VAR)
        .ok()
        .filter(|key| !key.is_empty())
}

/// The header that carries the key, when there is one.
pub fn key_header() -> Option<(&'static str, String)> {
    header_for(api_key())
}

/// Where to send a request, given the configured `coingecko` endpoint.
pub fn url_base(configured: &str) -> String {
    base_for(configured, api_key().is_some())
}

fn header_for(key: Option<String>) -> Option<(&'static str, String)> {
    key.map(|key| ("x-cg-pro-api-key", key))
}

/// With a key, the default free host becomes the paid one; an endpoint set by hand (a mock)
/// is left alone.
fn base_for(configured: &str, keyed: bool) -> String {
    let configured = configured.trim_end_matches('/');
    if keyed && configured == DEFAULT_ENDPOINT {
        PRO_ENDPOINT.to_owned()
    } else {
        configured.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tested on the key as an argument, not through the environment: tests run in parallel,
    /// and one that set the variable would change what every other test sees.
    #[test]
    fn a_key_sends_requests_to_the_paid_api_with_the_paid_header() {
        assert_eq!(base_for(DEFAULT_ENDPOINT, false), DEFAULT_ENDPOINT);
        assert_eq!(
            base_for(&format!("{DEFAULT_ENDPOINT}/"), true),
            PRO_ENDPOINT
        );
        assert_eq!(base_for("http://127.0.0.1:9", true), "http://127.0.0.1:9");
        assert_eq!(header_for(None), None);
        assert_eq!(
            header_for(Some("CG-test".to_owned())),
            Some(("x-cg-pro-api-key", "CG-test".to_owned()))
        );
    }
}

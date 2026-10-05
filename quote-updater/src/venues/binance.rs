//! Binance: the `<symbol>@bookTicker` stream, one frame per change of the best bid or ask.
//! The market is named in the URL, so there is no subscribe message, and the server pings
//! on its own, so a protocol ping is the right probe for a quiet book.

use eyre::{Result, eyre};
use serde::Deserialize;

use crate::venue::{Connection, Keepalive, Quote};
use crate::venues::unwrap_alias;

/// The main Binance stream. Overridden from the settings for binance.us or a mock.
pub const DEFAULT_ENDPOINT: &str = "wss://stream.binance.com:9443/ws";

pub fn connection(endpoint: &str, symbol: &str) -> Connection {
    Connection::Stream {
        url: format!(
            "{}/{}@bookTicker",
            endpoint.trim_end_matches('/'),
            symbol.to_lowercase()
        ),
        subscribe: None,
        keepalive: Keepalive::Ping,
    }
}

/// Best bid/offer update as sent on a `<symbol>@bookTicker` stream.
#[derive(Deserialize)]
struct BookTicker {
    #[serde(rename = "b")]
    bid: String,
    #[serde(rename = "a")]
    ask: String,
}

/// Every frame on a bookTicker stream is a ticker, so anything else is malformed rather
/// than ignorable.
pub fn parse(text: &str) -> Result<Option<Quote>> {
    let ticker: BookTicker = serde_json::from_str(text)
        .map_err(|err| eyre!(err).wrap_err("not a bookTicker message"))?;
    Ok(Some(Quote::Book {
        bid: ticker.bid,
        ask: ticker.ask,
    }))
}

/// The stream a pair declared as `(base, quote)` should be reading: `ETHUSDC`. Order
/// matters: it is what makes a transposed `tokens` array detectable.
pub fn expected_symbol(base: &str, quote: &str) -> String {
    format!("{}{}", unwrap_alias(base), unwrap_alias(quote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_market_is_named_in_the_url_in_lower_case() {
        let Connection::Stream {
            url,
            subscribe,
            keepalive,
        } = connection("wss://stream.binance.com:9443/ws/", "ETHUSDC")
        else {
            panic!("streams")
        };
        assert_eq!(url, "wss://stream.binance.com:9443/ws/ethusdc@bookTicker");
        assert_eq!(subscribe, None);
        assert_eq!(keepalive, Keepalive::Ping);
    }

    #[test]
    fn a_book_ticker_frame_yields_its_bid_and_ask_verbatim() {
        let msg = r#"{"u":1,"s":"USDCUSDT","b":"0.99980000","B":"2.0","a":"1.00000000","A":"3.0"}"#;
        assert_eq!(
            parse(msg).unwrap(),
            Some(Quote::Book {
                bid: "0.99980000".into(),
                ask: "1.00000000".into(),
            })
        );
        assert!(parse("{}").is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn wrapped_tokens_map_to_their_underlying_market() {
        assert_eq!(expected_symbol("WETH", "USDC"), "ETHUSDC");
        assert_eq!(expected_symbol("WBTC", "USDT"), "BTCUSDT");
        assert_eq!(expected_symbol("USDC", "USDT"), "USDCUSDT");
    }
}

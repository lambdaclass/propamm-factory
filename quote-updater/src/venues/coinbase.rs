//! Coinbase Advanced Trade: the `ticker` channel of the public market-data feed, plus the
//! `heartbeats` channel. No authentication for either. Markets are `ETH-USD`.
//!
//! The feed takes a quiet socket to mean an unchanged book: a heartbeat or a pong re-stamps
//! the last price as current (see `feed::refresh_if_current`). That holds only for a channel
//! that sends when the best bid or ask changes. The Exchange feed's `ticker`
//! (`ws-feed.exchange.coinbase.com`) is not one: it sends one frame per match, so between
//! trades its last bid and ask went on reading as current while the book moved under them,
//! for seconds at a time on a busy market and for most of a minute on a thin one. This
//! channel sends when the best bid or ask moves, whether or not anything traded: held
//! against an order book kept from Coinbase's own `level2` channel, it never trailed the
//! book's best bid and ask by as much as a second, so here a quiet socket does mean an
//! unchanged book.
//!
//! A subscription takes one channel, hence two subscribe frames. `heartbeats` is the second
//! because Coinbase closes a subscription that has had no update for 60 to 90 seconds, which
//! a quiet market reaches; with it a frame arrives every second.

use std::time::SystemTime;

use eyre::{Result, eyre};
use serde::Deserialize;
use serde_json::json;

use crate::venue::{Connection, Keepalive, Quote};
use crate::venues::{rfc3339_utc, unwrap_alias};

pub const DEFAULT_ENDPOINT: &str = "wss://advanced-trade-ws.coinbase.com";

pub fn connection(endpoint: &str, symbol: &str) -> Connection {
    let subscribe = |channel: &str| {
        json!({ "type": "subscribe", "product_ids": [symbol], "channel": channel }).to_string()
    };
    Connection::Stream {
        url: endpoint.trim_end_matches('/').to_owned(),
        // The ticker first, so every acknowledgement on a working connection lists it; see
        // the `subscriptions` arm of `parse_stamped`.
        subscribe: vec![subscribe("ticker"), subscribe("heartbeats")],
        keepalive: Keepalive::Ping,
    }
}

#[derive(Deserialize)]
struct Frame {
    channel: Option<String>,
    /// Set on an error, which has no `channel`.
    #[serde(rename = "type")]
    kind: Option<String>,
    message: Option<String>,
    /// When Coinbase sent the frame, RFC 3339 (`2026-10-26T18:38:05.125013921Z`).
    timestamp: Option<String>,
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    tickers: Vec<Ticker>,
    /// On a `subscriptions` frame: what the connection is now subscribed to, by channel.
    subscriptions: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Ticker {
    best_bid: Option<String>,
    best_ask: Option<String>,
}

pub fn parse(text: &str) -> Result<Option<Quote>> {
    Ok(parse_stamped(text)?.map(|(quote, _)| quote))
}

/// [`parse`], with the frame's `timestamp`: the ticker carries no time of its own, so the
/// frame's is the stamp. One that does not read as RFC 3339 is taken as absent rather than
/// refusing the price: the price is what the frame is for.
pub fn parse_stamped(text: &str) -> Result<Option<(Quote, Option<SystemTime>)>> {
    let frame: Frame =
        serde_json::from_str(text).map_err(|err| eyre!(err).wrap_err("not a coinbase frame"))?;
    if frame.kind.as_deref() == Some("error") {
        return Err(eyre!(
            "coinbase error: {}",
            frame.message.unwrap_or_default()
        ));
    }
    match frame.channel.as_deref() {
        Some("ticker") => {
            // Coinbase batches tickers during a burst of matches, in order: the last one is
            // the book as it stands.
            let ticker = frame
                .events
                .iter()
                .flat_map(|event| &event.tickers)
                .next_back()
                .ok_or_else(|| eyre!("ticker frame without a ticker"))?;
            match (&ticker.best_bid, &ticker.best_ask) {
                (Some(bid), Some(ask)) => Ok(Some((
                    Quote::Book {
                        bid: bid.clone(),
                        ask: ask.clone(),
                    },
                    frame.timestamp.as_deref().and_then(rfc3339_utc),
                ))),
                _ => Err(eyre!("ticker without best_bid/best_ask")),
            }
        }
        // A product Coinbase does not list is not refused with an error: the subscription
        // is acknowledged with nothing in it, and only heartbeats follow. The ticker is
        // subscribed first, so on a working connection every acknowledgement lists it.
        Some("subscriptions") => {
            let ticker_subscribed = frame.events.iter().any(|event| {
                event
                    .subscriptions
                    .as_ref()
                    .is_some_and(|subscriptions| subscriptions.contains_key("ticker"))
            });
            if ticker_subscribed {
                Ok(None)
            } else {
                Err(eyre!(
                    "coinbase acknowledged no ticker subscription: is the product listed?"
                ))
            }
        }
        // `heartbeats`, and anything else the feed adds later.
        _ => Ok(None),
    }
}

pub fn expected_symbol(base: &str, quote: &str) -> String {
    format!("{}-{}", unwrap_alias(base), unwrap_alias(quote))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // Frames as the feed sent them on 2026-10-26, cut only where noted.
    const SNAPSHOT: &str = r#"{"channel":"ticker","timestamp":"2026-10-26T18:38:05.125013921Z","sequence_num":0,"events":[{"type":"snapshot","tickers":[{"type":"ticker","product_id":"ETH-USD","price":"2321.34","volume_24_h":"89922.45934932","low_24_h":"2290","high_24_h":"2354.67","low_52_w":"1505","high_52_w":"4254.23","price_percent_chg_24_h":"-1.33461410950636","best_bid":"2321.11","best_ask":"2321.27","best_bid_quantity":"2.51846454","best_ask_quantity":"5.68928218"}]}]}"#;
    const UPDATE: &str = r#"{"channel":"ticker","timestamp":"2026-10-26T18:38:05.908615035Z","sequence_num":4,"events":[{"type":"update","tickers":[{"type":"ticker","product_id":"ETH-USD","price":"2321.34","volume_24_h":"89922.45934932","low_24_h":"2290","high_24_h":"2354.67","low_52_w":"1505","high_52_w":"4254.23","price_percent_chg_24_h":"-1.33461410950636","best_bid":"2321.11","best_ask":"2321.23","best_bid_quantity":"2.51846454","best_ask_quantity":"7.05598668"}]}]}"#;
    const HEARTBEAT: &str = r#"{"channel":"heartbeats","timestamp":"2026-10-26T18:38:05.978074548Z","sequence_num":5,"events":[{"current_time":"2026-10-26 18:38:05.976030063 +0000 UTC m=+300961.243950112","heartbeat_counter":300961}]}"#;
    const TICKER_ACK: &str = r#"{"channel":"subscriptions","timestamp":"2026-10-26T18:38:05.125031113Z","sequence_num":1,"events":[{"subscriptions":{"ticker":["ETH-USD"]}}]}"#;
    const BOTH_ACK: &str = r#"{"channel":"subscriptions","timestamp":"2026-10-26T18:38:05.126337985Z","sequence_num":2,"events":[{"subscriptions":{"heartbeats":["heartbeats"],"ticker":["ETH-USD"]}}]}"#;

    #[test]
    fn subscribes_to_the_ticker_then_the_heartbeats_of_one_product() {
        let Connection::Stream {
            url,
            subscribe,
            keepalive,
        } = connection(DEFAULT_ENDPOINT, "ETH-USD")
        else {
            panic!("streams")
        };
        assert_eq!(url, DEFAULT_ENDPOINT);
        assert!(matches!(keepalive, Keepalive::Ping));
        let frames: Vec<serde_json::Value> = subscribe
            .iter()
            .map(|frame| serde_json::from_str(frame).unwrap())
            .collect();
        assert_eq!(
            frames,
            [
                json!({ "type": "subscribe", "product_ids": ["ETH-USD"], "channel": "ticker" }),
                json!({ "type": "subscribe", "product_ids": ["ETH-USD"], "channel": "heartbeats" }),
            ]
        );
    }

    #[test]
    fn reads_the_best_bid_and_ask_and_ignores_the_rest() {
        let book = |bid: &str, ask: &str| {
            Some(Quote::Book {
                bid: bid.into(),
                ask: ask.into(),
            })
        };
        assert_eq!(parse(SNAPSHOT).unwrap(), book("2321.11", "2321.27"));
        assert_eq!(parse(UPDATE).unwrap(), book("2321.11", "2321.23"));
        assert_eq!(parse(HEARTBEAT).unwrap(), None);
        assert_eq!(parse(TICKER_ACK).unwrap(), None);
        assert_eq!(parse(BOTH_ACK).unwrap(), None);
        // Two channels in one subscribe frame (the Exchange feed's form) is refused so.
        let err = r#"{"type":"error","message":"authentication failure"}"#;
        assert!(
            parse(err)
                .unwrap_err()
                .to_string()
                .contains("authentication failure")
        );
        assert!(parse("nope").is_err());
    }

    /// Built from the frame above: two tickers in one frame, as a batch arrives.
    #[test]
    fn a_batched_frame_is_read_at_its_last_ticker() {
        let batch = r#"{"channel":"ticker","timestamp":"2026-10-26T18:38:05.908615035Z","events":[{"type":"update","tickers":[{"type":"ticker","product_id":"ETH-USD","best_bid":"2321.11","best_ask":"2321.26"},{"type":"ticker","product_id":"ETH-USD","best_bid":"2321.11","best_ask":"2321.23"}]}]}"#;
        assert_eq!(
            parse(batch).unwrap(),
            Some(Quote::Book {
                bid: "2321.11".into(),
                ask: "2321.23".into()
            })
        );
    }

    /// What Coinbase sent for `ETH-NOPE`: an acknowledgement listing nothing, then one
    /// listing only the heartbeats.
    #[test]
    fn an_unlisted_product_is_an_error() {
        let nothing = r#"{"channel":"subscriptions","timestamp":"2026-10-26T18:38:07.428527302Z","sequence_num":0,"events":[{"subscriptions":{}}]}"#;
        let heartbeats_only = r#"{"channel":"subscriptions","timestamp":"2026-10-26T18:38:07.428554918Z","sequence_num":1,"events":[{"subscriptions":{"heartbeats":["heartbeats"]}}]}"#;
        for ack in [nothing, heartbeats_only] {
            assert!(
                parse(ack)
                    .unwrap_err()
                    .to_string()
                    .contains("no ticker subscription"),
                "{ack}"
            );
        }
    }

    #[test]
    fn a_ticker_is_stamped_with_its_frame_time() {
        // 2026-10-26T18:38:05Z is 1793039885 seconds after the epoch.
        assert_eq!(
            parse_stamped(SNAPSHOT).unwrap().unwrap().1,
            Some(SystemTime::UNIX_EPOCH + Duration::new(1_793_039_885, 125_013_921))
        );
        let unstamped = r#"{"channel":"ticker","events":[{"type":"update","tickers":[{"type":"ticker","product_id":"ETH-USD","best_bid":"2321.11","best_ask":"2321.23"}]}]}"#;
        assert_eq!(parse_stamped(unstamped).unwrap().unwrap().1, None);
    }
}

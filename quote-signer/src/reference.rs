//! The reference prices the policy checks a mid against, read by the signer itself so a
//! compromised updater cannot feed it the price it wants judged. Polled over HTTP from a
//! venue's book ticker; a failed read stores nothing, so a dead venue ages the reference
//! out and the policy refuses, rather than judging against the last price it ever saw.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, eyre};
use serde::Deserialize;
use url::Url;

use crate::policy::Reference;

/// The latest reading per venue symbol.
#[derive(Debug, Default)]
pub struct Book {
    readings: RwLock<HashMap<String, (f64, Instant)>>,
}

impl Book {
    /// The reading for `symbol` as of `now`, or `None` for one never read.
    pub fn reading(&self, symbol: &str, now: Instant) -> Option<Reference> {
        let readings = self
            .readings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        readings.get(symbol).map(|(mid, at)| Reference {
            mid: *mid,
            age: now.saturating_duration_since(*at),
        })
    }

    /// Records a reading.
    pub fn record(&self, symbol: &str, mid: f64, at: Instant) {
        let mut readings = self
            .readings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        readings.insert(symbol.to_owned(), (mid, at));
    }
}

/// A venue's book ticker, in the shape Binance and its lookalikes answer
/// `GET /api/v3/ticker/bookTicker?symbol=…` with.
#[derive(Deserialize)]
struct BookTicker {
    #[serde(rename = "bidPrice")]
    bid: String,
    #[serde(rename = "askPrice")]
    ask: String,
}

/// The mid of a book-ticker answer, or why it is not one.
pub fn parse_book_ticker(body: &str) -> Result<f64> {
    let ticker: BookTicker = serde_json::from_str(body).wrap_err("not a book ticker")?;
    let bid: f64 = ticker.bid.parse().wrap_err("bid is not a number")?;
    let ask: f64 = ticker.ask.parse().wrap_err("ask is not a number")?;
    if !(bid.is_finite() && ask.is_finite() && bid > 0.0 && ask >= bid) {
        return Err(eyre!("bid {bid} and ask {ask} are not a book"));
    }
    Ok((bid + ask) / 2.0)
}

/// Polls every symbol at a fixed cadence into a [`Book`].
pub struct Poller {
    base: Url,
    symbols: Vec<String>,
    every: Duration,
    http: reqwest::Client,
    book: Arc<Book>,
}

impl Poller {
    /// A poller reading `symbols` from `base` every `every`.
    pub fn new(base: Url, symbols: Vec<String>, every: Duration, book: Arc<Book>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(every.max(Duration::from_secs(2)))
            .build()?;
        Ok(Self {
            base,
            symbols,
            every,
            http,
            book,
        })
    }

    /// Polls forever. Each failure is logged and skipped; the reading ages out instead.
    pub async fn run(self) {
        loop {
            for symbol in &self.symbols {
                match self.read(symbol).await {
                    Ok(mid) => self.book.record(symbol, mid, Instant::now()),
                    Err(err) => tracing::warn!("reference {symbol}: {err:#}"),
                }
            }
            tokio::time::sleep(self.every).await;
        }
    }

    async fn read(&self, symbol: &str) -> Result<f64> {
        let mut url = self.base.join("api/v3/ticker/bookTicker")?;
        url.query_pairs_mut().append_pair("symbol", symbol);
        let body = self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        parse_book_ticker(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_book_ticker_reads_as_its_mid_and_a_broken_one_does_not() {
        let body = r#"{"symbol":"ETHUSDC","bidPrice":"2499.50000000","bidQty":"1","askPrice":"2500.50000000","askQty":"2"}"#;
        assert_eq!(parse_book_ticker(body).unwrap(), 2500.0);
        assert!(parse_book_ticker(r#"{"code":-1121,"msg":"Invalid symbol."}"#).is_err());
        assert!(parse_book_ticker(r#"{"bidPrice":"0","askPrice":"0"}"#).is_err());
        assert!(parse_book_ticker(r#"{"bidPrice":"3","askPrice":"2"}"#).is_err());
    }

    #[test]
    fn a_reading_ages_from_when_it_was_recorded() {
        let book = Book::default();
        let now = Instant::now();
        assert_eq!(book.reading("ETHUSDC", now), None);
        book.record("ETHUSDC", 2500.0, now);
        let later = book
            .reading("ETHUSDC", now + Duration::from_secs(5))
            .unwrap();
        assert_eq!(later.mid, 2500.0);
        assert_eq!(later.age, Duration::from_secs(5));
    }
}

//! Tokenized stocks: a stock core of its own and one module per token design, registered on
//! the builder by a binary that quotes stock pairs (see `docs/stocks.md`):
//!
//! - `ports`: what the core asks of a design (a price, the token's share multiplier and its
//!   corporate actions, the issuer's status, the token's transfer rules), and the shape of
//!   each answer.
//! - `pricer`, `guard`, `hours`: what every stock pair does, whoever issued the token: the
//!   pricer and its gates, the guard on the token's transfer rules, and `us_market_hours`,
//!   which withdraws outside 09:30–16:00 New York time on trading days by a calendar the
//!   config states.
//! - `issuers`: each design's adapters and the kinds built from them. Ondo Global Markets
//!   today: `ondo`, the pricer over Ondo's price, multiplier and status, and `ondo_token`,
//!   the guard over Ondo's pause, blocklist and sanctions list.
//! - `chain`: the reads of the chain every design shares, behind the [`chain::Calls`] trait
//!   a test answers with [`crate::testing::FakeChain`].
//!
//! A new design is a module under `issuers/`. See `example/config.stocks.toml` for a pair.

pub mod chain;
pub mod guard;
pub mod hours;
pub mod issuers;
#[cfg(test)]
mod mock_http;
pub mod ports;
pub mod pricer;

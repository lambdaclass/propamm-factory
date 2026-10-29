//! Tokenized stocks: what a stock pair needs beyond what every pair has, one module per
//! token design, registered on the builder by a binary that quotes stock pairs (see
//! `docs/stocks.md`).
//!
//! A stock pair is a pair like any other: its price comes from the issuer as a venue
//! (`venues/ondo.rs` reads Ondo's own price for its tokens), averaged, aged, judged by the
//! circuit breaker and the band, and priced by whatever pricing kind the pair names. This
//! module holds the guards that go with it:
//!
//! - `ports`: what the core asks of a design (the issuer's price ratio, the token's share
//!   multiplier and its corporate actions, the issuer's status, the token's transfer
//!   rules), and the shape of each answer.
//! - `status`, `guard`, `hours`: what every stock pair does, whoever issued the token: the
//!   issuer-status guard and its gates, the guard on the token's transfer rules, and
//!   `us_market_hours`, which withdraws outside 09:30–16:00 New York time on trading days
//!   by a calendar the config states.
//! - `issuers`: each design's adapters and the kinds built from them. Ondo Global Markets
//!   today: `ondo`, the status guard over Ondo's session, asset events and multiplier,
//!   with the guard over Ondo's pause, blocklist and sanctions list beside it
//!   ([`WithTokenRules`]); `ondo_token` is that guard on its own, for a pair that still
//!   lists it.
//! - `chain`: the reads of the chain every design shares, behind the [`chain::Calls`] trait
//!   a test answers with [`crate::testing::FakeChain`].
//!
//! A new design is a module under `issuers/`. See `example/config.stocks.toml` for a pair.

pub mod chain;
pub mod guard;
pub mod hours;
pub mod issuers;
pub mod ports;
pub mod status;

use crate::{
    eyre::{self, WrapErr},
    guard::{Candidate, Gate, QuoteGuard},
    pricing::{BoxFuture, BuildCtx, Diagnostics, FormField, PairShape, QuoteGuardFactory},
};

/// A tokenized-stock design a binary integrates: its status guard, which is the issuer
/// itself as a [`crate::pricing::QuoteGuardFactory`] over the design's adapters, and the
/// guard on its token's transfer rules. Register one with
/// [`crate::UpdaterBuilder::stock_issuer`], which uses the two names declared here, so a
/// binary names the issuers it integrates and nothing registers one implicitly. The status
/// guard's kind runs the token's rules beside the issuer's own checks ([`WithTokenRules`]):
/// the core builds them, so an issuer's factory builds its status guard alone. Ondo Global
/// Markets is [`issuers::ondo::Ondo`]; a second issuer, in this crate or in a crate of its
/// own, implements this over the ports the same way and needs no change to the builder.
/// Its price, though, is a venue, which lives in this crate (`venues/`).
pub trait Issuer: QuoteGuardFactory {
    /// The status guard's registered name, e.g. `ondo`.
    const STATUS_GUARD_KIND: &'static str;
    /// The token guard's registered name, e.g. `ondo_token`: kept for a pair that still
    /// lists the rules as a guard of their own, and offered to no new pair.
    const TOKEN_GUARD_KIND: &'static str;
    /// The factory of the guard on the token's transfer rules:
    /// [`guard::RestrictionGuardFactory`] for a design whose rules the core's guard reads
    /// through [`ports::Restrictions`].
    type TokenGuard: QuoteGuardFactory<Config: Default>;
    /// The token guard's factory.
    fn token_guard(&self) -> Self::TokenGuard;
    /// The token guard's settings for a status-guard stanza: its defaults, unless the
    /// design's stanza has keys for them.
    fn token_guard_cfg(
        &self,
        _cfg: &Self::Config,
    ) -> <Self::TokenGuard as QuoteGuardFactory>::Config {
        Default::default()
    }
}

/// An issuer's status guard with its token's transfer rules beside it, as one kind: what
/// [`crate::UpdaterBuilder::stock_issuer`] registers under the status guard's name, so
/// every issuer's pair is held to the token's rules whatever the issuer's own build does.
/// The stanza is the issuer's; the rules' settings come from it through
/// [`Issuer::token_guard_cfg`].
pub struct WithTokenRules<I: Issuer> {
    issuer: I,
    rules: I::TokenGuard,
}

impl<I: Issuer> WithTokenRules<I> {
    /// `issuer`'s status guard, with the guard [`Issuer::token_guard`] makes beside it.
    pub fn new(issuer: I) -> Self {
        let rules = issuer.token_guard();
        WithTokenRules { issuer, rules }
    }
}

impl<I: Issuer> QuoteGuardFactory for WithTokenRules<I> {
    type Config = I::Config;
    type Guard = StatusAndRules<I::Guard, <I::TokenGuard as QuoteGuardFactory>::Guard>;

    fn validate(&self, cfg: &I::Config, pair: &PairShape) -> eyre::Result<()> {
        self.issuer.validate(cfg, pair)?;
        self.rules
            .validate(&self.issuer.token_guard_cfg(cfg), pair)
            .wrap_err("the token's transfer rules")
    }

    fn fields(&self) -> &'static [FormField] {
        self.issuer.fields()
    }

    fn form_help(&self) -> &'static str {
        self.issuer.form_help()
    }

    fn summary(&self, cfg: &I::Config) -> String {
        self.issuer.summary(cfg)
    }

    fn build<'a>(
        &'a self,
        cfg: &'a I::Config,
        ctx: &'a mut BuildCtx,
    ) -> BoxFuture<'a, eyre::Result<Self::Guard>> {
        Box::pin(async move {
            let status = self.issuer.build(cfg, ctx).await?;
            let rules = self
                .rules
                .build(&self.issuer.token_guard_cfg(cfg), ctx)
                .await?;
            Ok(StatusAndRules { status, rules })
        })
    }
}

/// The guard [`WithTokenRules`] builds: the issuer's status first, then the token's rules,
/// the first that does not allow the quote answering for both.
pub struct StatusAndRules<S, R> {
    status: S,
    rules: R,
}

impl<S: QuoteGuard, R: QuoteGuard> QuoteGuard for StatusAndRules<S, R> {
    fn check(&mut self, candidate: &Candidate<'_>, out: &mut Diagnostics) -> Gate {
        match self.status.check(candidate, out) {
            Gate::Allow => self.rules.check(candidate, out),
            gate => gate,
        }
    }
}

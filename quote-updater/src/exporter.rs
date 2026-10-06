//! The `/metrics` listener. The only part of the metrics stack that does IO, kept apart
//! from `metrics.rs` so that module stays unit-testable without tokio or a socket.
//!
//! Binding is eager and its failure is returned to the caller, which makes it fatal at
//! startup: a metrics endpoint an operator believes exists but does not is the same class
//! of failure this crate already refuses loudly elsewhere — a pair believed to be guarded
//! that is not. Once bound, nothing here can take the process down: a render error becomes
//! a 500, and the serve loop owns no state any pair depends on.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    http::{StatusCode, header::CONTENT_TYPE},
    routing::get,
};
use eyre::{Result, WrapErr};
use tokio::task::JoinHandle;

use crate::metrics::Metrics;

/// Binds `addr` and serves the registry at `/metrics`. Returns the resolved address (so a
/// `:0` bind is observable) and the serving task's handle.
/// Whether binding here needs saying out loud: anything but a loopback address exposes the
/// exposition to the network.
///
/// `/metrics` is unauthenticated and carries lane mids, published prices and the signer's
/// balance and runway, so `METRICS_ADDR=0.0.0.0:9464` — the natural choice for someone whose
/// Prometheus lives on another host — publishes all of it in the clear. Every other
/// misconfiguration in this crate is refused or announced loudly, on the stated grounds that
/// the worst failure mode is an operator who believes something is guarded when it is not;
/// this one was documented in prose in `.env.example` and then bound silently.
///
/// A warning and not a refusal: unlike a breaker on a fixed mid, this is a thing an operator
/// may legitimately want (behind a firewall, or with a reverse proxy in front), so it prints
/// what it is doing and carries on.
pub(crate) fn exposes_to_network(addr: SocketAddr) -> bool {
    !addr.ip().is_loopback()
}

pub async fn bind(addr: SocketAddr, metrics: Arc<Metrics>) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .wrap_err_with(|| format!("failed to bind the metrics listener on {addr}"))?;
    let local = listener
        .local_addr()
        .wrap_err("bound metrics listener has no local address")?;
    if exposes_to_network(local) {
        tracing::warn!(
            "warning: /metrics is bound to {local}, not loopback, and it is unauthenticated \
             — it serves lane mids, published prices and the signer's balance to anything \
             that can reach that address. Put it behind something that authenticates, or \
             bind 127.0.0.1 and let the scraper reach it another way."
        );
    }

    let app = Router::new().route(
        "/metrics",
        get(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                match metrics.render() {
                    // Prometheus's own exposition format, not axum's default
                    // `text/plain; charset=utf-8`: the scrape works either way (a missing
                    // version falls back to the text parser), but the correct value is one
                    // constant this crate already depends on, so there is no reason to
                    // leave it to the default.
                    Ok(body) => (
                        StatusCode::OK,
                        [(CONTENT_TYPE, prometheus::TEXT_FORMAT)],
                        body,
                    ),
                    // Rendering cannot fail for any registry this crate builds, but a 500
                    // beats a panic in a task nothing awaits: the scrape fails, the alert
                    // on a missing scrape fires, and the pusher keeps quoting. Plain text,
                    // not the Prometheus content type: this body is an error message, not
                    // an exposition a scraper should try to parse as one.
                    Err(err) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
                        format!("{err:#}"),
                    ),
                }
            }
        }),
    );

    let task = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::warn!("metrics listener stopped: {err:#}");
        }
    });
    Ok((local, task))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A dependency-free HTTP GET: the crate has no HTTP client, and adding one for a test
    /// would cost the Cargo.lock budget this whole change is built to respect.
    async fn get(addr: SocketAddr, path: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn serves_the_registry_as_prometheus_text() {
        let m = std::sync::Arc::new(crate::metrics::Metrics::new().unwrap());
        m.for_pair("USDC/USDT").feed_ticks.inc();
        let (addr, _task) = bind("127.0.0.1:0".parse().unwrap(), m).await.unwrap();

        let body = get(addr, "/metrics").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(
            body.to_lowercase()
                .contains("content-type: text/plain; version=0.0.4"),
            "{body}"
        );
        assert!(
            body.contains(r#"quote_updater_feed_ticks_total{pair="USDC/USDT"} 1"#),
            "{body}"
        );
        assert!(
            body.contains("# TYPE quote_updater_feed_ticks_total counter"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn an_unknown_path_is_not_found() {
        let m = std::sync::Arc::new(crate::metrics::Metrics::new().unwrap());
        let (addr, _task) = bind("127.0.0.1:0".parse().unwrap(), m).await.unwrap();
        assert!(get(addr, "/").await.starts_with("HTTP/1.1 404"), "not 404");
    }

    #[tokio::test]
    async fn a_bind_failure_is_reported_rather_than_swallowed() {
        let m = std::sync::Arc::new(crate::metrics::Metrics::new().unwrap());
        let (addr, _task) = bind("127.0.0.1:0".parse().unwrap(), m.clone())
            .await
            .unwrap();
        // The same address a second time: an operator who typo'd a port onto a busy one
        // must find out at startup, not by an alert that never fires.
        assert!(bind(addr, m).await.is_err(), "second bind should fail");
    }

    #[test]
    fn only_a_loopback_metrics_bind_is_silent() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(!exposes_to_network(addr("127.0.0.1:9464")));
        // The whole IPv4 loopback block, not just the one address an operator usually types.
        assert!(!exposes_to_network(addr("127.9.9.9:9464")));
        assert!(!exposes_to_network(addr("[::1]:9464")));
        // The two that actually reach the network, and the pair this warning exists for:
        // 0.0.0.0 is the natural choice for someone whose Prometheus is on another host.
        assert!(exposes_to_network(addr("0.0.0.0:9464")));
        assert!(exposes_to_network(addr("10.0.0.5:9464")));
        assert!(exposes_to_network(addr("[::]:9464")));
    }

    /// The port `metrics_fixture_server` binds, from METRICS_FIXTURE_PORT. Kept pure so it
    /// is testable without touching the environment, which every test in this binary shares.
    fn fixture_port(raw: Option<&str>) -> u16 {
        // 9464 is the port deploy/prometheus/prometheus.yml scrapes and the one the docs
        // and .env.example use in their --metrics-addr examples.
        raw.and_then(|value| value.parse().ok()).unwrap_or(9464)
    }

    /// Ticks to run before the fixture latches WETH/USDC's breaker, from
    /// METRICS_FIXTURE_TRIP_AFTER. `None` — the default — never trips.
    fn fixture_trip_after(raw: Option<&str>) -> Option<u64> {
        raw.and_then(|value| value.parse().ok())
    }

    #[test]
    fn fixture_knobs_default_and_parse() {
        assert_eq!(fixture_port(None), 9464);
        assert_eq!(fixture_port(Some("9465")), 9465);
        // Garbage falls back rather than panicking a hand-run fixture, exactly as
        // builder.rs::mock_port does.
        assert_eq!(fixture_port(Some("")), 9464);
        assert_eq!(fixture_port(Some("not-a-port")), 9464);

        assert_eq!(fixture_trip_after(None), None);
        assert_eq!(fixture_trip_after(Some("")), None);
        assert_eq!(fixture_trip_after(Some("nonsense")), None);
        assert_eq!(fixture_trip_after(Some("120")), Some(120));
    }

    /// One pair's handles plus the shape of the numbers to drive through them.
    struct FixturePair {
        m: crate::metrics::PairMetrics,
        /// The one venue the fixture pair reads, for the rejected-ticks panel.
        venue: crate::metrics::VenueMetrics,
        builders: Vec<crate::metrics::BuilderMetrics>,
        base_mid: f64,
        /// Relative amplitude of the mid's walk. Chosen with `max_deviation` so the
        /// resulting `breaker_deviation_ratio` crosses PusherBreakerApproaching's 0.6 but
        /// never reaches 1.0 — the fixture should exercise the ticket, not fake the trip.
        amplitude: f64,
        /// The pair's configured limit, or `None` for a fixed-mid pair. A breaker on a
        /// static mid is refused at startup, so `None` here is not a gap: it is the
        /// configuration that makes `breaker_armed` legitimately 0.
        max_deviation: Option<f64>,
    }

    impl FixturePair {
        fn mid_at(&self, t: u64) -> f64 {
            self.base_mid * (1.0 + self.amplitude * ((t as f64) * 0.37).sin())
        }

        /// The one-time recording of a latch, matching what `drive` does on its way out:
        /// the halt decision is counted once and the pair then records nothing further,
        /// because its loop has returned. Separate from `tick` for exactly that reason — the
        /// halt branch used to live inside `tick`, so it re-counted the decision and
        /// re-wrote the gauges once per second forever. `rate(publish_decisions{action=
        /// "halt"})` then read a steady non-zero on the fixture where production produces a
        /// single step decaying to zero — the wrong shape to calibrate a panel or a rule
        /// against, and calibrating against this fixture is what deploy/README.md tells an
        /// operator to do.
        fn halt(&self) {
            use crate::metrics::PublishAction;
            self.m.breaker_tripped.set(1.0);
            self.m.publish_decisions(PublishAction::Halt).inc();
            // The feed task ends with the pair, and writes these three on its way out — see
            // `spawn_feed`'s `tx.closed()` arm. NaN, not 0: a halted pair has no feed task,
            // and one halt must not raise PusherFeedDown and PusherFeedStale on top of the
            // page PusherBreakerTripped already sent.
            self.m.feed_up.set(f64::NAN);
            self.m.feed_last_tick.set(f64::NAN);
            self.m.feed_sample_current.set(f64::NAN);
            for b in &self.builders {
                b.up.set(0.0);
                b.withdrawals.inc();
            }
        }

        fn tick(&self, t: u64) {
            use crate::metrics::{LandingResult, PublishAction, RpcCall, TickReject};
            use crate::update::UnusableKind;

            self.m.target_blocks.inc();

            // The three RPC calls a pair makes per target block, the same set `drive` makes.
            // Values straddle the 50ms requote budget the RPC panel and PusherRpcSlow are
            // drawn around. The head poll is not among them: it belongs to the process-wide
            // watcher, which the fixture drives through `HeadMetrics` below.
            for (call, base) in [
                (RpcCall::GetNonce, 0.006),
                (RpcCall::GetBalance, 0.011),
                (RpcCall::EthCall, 0.019),
            ] {
                self.m
                    .rpc_duration(call)
                    .observe(base * (1.0 + 0.5 * ((t as f64) * 0.11).sin()).abs());
            }
            // One in ~40 blocks loses a nonce read, so rpc_errors_total is non-zero on the
            // dashboard without the error rate looking like an outage.
            if t.is_multiple_of(41) {
                self.m.rpc_errors(RpcCall::GetNonce).inc();
            }

            self.m.breaker_tripped.set(0.0);

            let mid = self.mid_at(t);
            let delta = 0.00018 + 0.00006 * ((t as f64) * 0.23).sin().abs();

            match self.max_deviation {
                // A live feed: every gauge spawn_feed would write, written.
                Some(limit) => {
                    self.m.feed_up.set(1.0);
                    self.m.feed_ticks.inc();
                    self.m.feed_sample_current.set(1.0);
                    self.m.feed_last_tick.set(unix_now());
                    self.m.feed_mid.set(mid);
                    self.m.feed_delta.set(delta);
                    // The fixture pair reads one venue, so the composite is that venue
                    // and the venue series mirror the pair's.
                    self.m.feed_sources_fresh.set(1.0);
                    self.m.feed_sources_min.set(1.0);
                    self.venue.up.set(1.0);
                    self.venue.ticks.inc();
                    self.venue.sample_current.set(1.0);
                    self.venue.last_tick.set(unix_now());
                    self.venue.mid.set(mid);
                    self.venue.delta.set(delta);

                    let prev = self.mid_at(t.saturating_sub(1));
                    let jump = if prev == 0.0 {
                        0.0
                    } else {
                        ((mid - prev) / prev).abs()
                    };
                    self.m.breaker_armed.set(1.0);
                    self.m.breaker_deviation_ratio.set(jump / limit);

                    // A crossed book every so often, so the rejected-ticks panel and
                    // PusherFeedSampleNotCurrent have something to describe.
                    if t.is_multiple_of(53) {
                        self.venue.rejected(TickReject::Crossed).inc();
                        self.venue.sample_current.set(0.0);
                        self.m.feed_sample_current.set(0.0);
                    }
                }
                // A fixed-mid pair. `build_live` sets these three to NaN precisely so the
                // feed rules cannot mistake "no feed task" for "feed down"; the fixture
                // reproduces that rather than leaving them at their registered 0, because
                // that distinction is the subtlest thing the rules depend on.
                None => {
                    self.m.feed_up.set(f64::NAN);
                    self.m.feed_last_tick.set(f64::NAN);
                    self.m.feed_sample_current.set(f64::NAN);
                    self.m.breaker_armed.set(0.0);
                }
            }

            // One block in ~29 has no publishable price, so the withdraw path and
            // price_unusable_total are exercised alongside the happy one.
            if t.is_multiple_of(29) {
                self.m.publish_decisions(PublishAction::Withdraw).inc();
                self.m.price_unusable(UnusableKind::Stale).inc();
                self.m.landings(LandingResult::NotQuoted).inc();
                for b in &self.builders {
                    b.withdrawals.inc();
                }
                return;
            }

            self.m.publish_decisions(PublishAction::Publish).inc();
            self.m.published_mid.set(mid);
            self.m.published_delta.set(delta);

            // Landing: mostly yes. A short miss streak every ~90 blocks moves
            // consecutive_landing_misses without approaching PusherLandingUnverified's 50.
            let missing = (t % 90) < 3;
            if missing {
                self.m.landings(LandingResult::Missed).inc();
                self.m.consecutive_landing_misses.set((t % 90 + 1) as f64);
            } else {
                self.m.landings(LandingResult::Landed).inc();
                self.m.consecutive_landing_misses.set(0.0);
            }

            // A signer that visibly drains. The page this is here to demonstrate is
            // PusherSignerNearlyDry, and since that rule became a `predict_linear` over the
            // balance the thing to tune is the *slope*, not the size of the tank: a fixture
            // that merely starts low now fires at t=0 and demonstrates nothing. Draining
            // 12_000 updates over 608_400s — a week plus an hour — puts the key a shade over
            // seven days from empty at t=0 and exactly a week out an hour in, so with the
            // rule's `for: 30m` the page lands ~1h30m into a run. Long enough not to be
            // noise, short enough to sit and watch a page-severity rule fire for real.
            //
            // One update every ~51s is also roughly what a lane landing on one block in four
            // looks like, so the runway series stays a number an operator would recognise
            // rather than a ramp chosen to cross a line.
            const FIXTURE_DRAIN_PER_SEC: f64 = 12_000.0 / 608_400.0;
            let runway = (12_000f64 - t as f64 * FIXTURE_DRAIN_PER_SEC).max(0.0);
            self.m.signer_runway_updates.set(runway);
            // One update's worth of gas at a plausible base fee, so the two series stay
            // consistent with each other the way preflight derives them.
            self.m.signer_balance_wei.set(runway * 2.1e13);

            for (i, b) in self.builders.iter().enumerate() {
                b.seq.set(t as f64);
                // Every builder is down for one 20s window per ~6 minutes, staggered, so
                // the state timeline has gaps and sum by (pair) never reaches zero — a
                // fixture that pages PusherPairHasNoBuilder would be crying wolf.
                let down = (t + (i as u64) * 180) % 360 < 20;
                b.up.set(if down { 0.0 } else { 1.0 });
                if down {
                    b.send_errors.inc();
                    continue;
                }
                if (t + i as u64) % 360 == 20 {
                    b.reconnects.inc();
                }
                // Ack latency straddling the ~400ms eviction window the panel and
                // PusherAckLatencyNearEviction are drawn around.
                let slow = (t + i as u64).is_multiple_of(37);
                b.ack_latency
                    .observe(if slow { 0.46 } else { 0.03 + 0.02 * i as f64 });
                if (t + i as u64).is_multiple_of(71) {
                    b.rejections.inc();
                } else {
                    b.acks.inc();
                }
            }
        }
    }

    fn unix_now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    #[allow(clippy::print_stdout)] // a terminal tool a person runs, not library output
    /// Not a test: a long-running exporter serving one tick per second of synthetic —
    /// but correctly shaped and correctly labelled — metrics, so the Prometheus and
    /// Grafana stack in `deploy/` can be validated without a chain, a signer key or a
    /// Binance socket.
    ///
    ///   cargo test metrics_fixture_server -- --ignored --nocapture
    ///   METRICS_FIXTURE_PORT=9465 METRICS_FIXTURE_TRIP_AFTER=60 \
    ///     cargo test metrics_fixture_server -- --ignored --nocapture
    ///
    /// It exists because the dashboard and the alert rules were authored against no
    /// running Grafana at all and there was no way to see
    /// either of them resolve. `make price-service` is the higher-fidelity check but a
    /// strictly narrower one: it runs `--mode node`, which has no builders, so it cannot
    /// light up the ack-latency, rejection or seq series at all.
    ///
    /// Three pairs on purpose, because two of them are only interesting for what they do
    /// *not* record:
    ///
    /// - `WETH/USDC` — a live feed, an armed breaker, two builders: the full happy path.
    /// - `USDC/USDT` — a fixed mid, so its three `feed_*` gauges are permanently NaN.
    ///   That is not a fixture shortcut; it is what `build_live` does for a `Static`
    ///   source, and leaving those gauges at their registered 0 instead would fire
    ///   `PusherFeedDown`, `PusherFeedStale` and `PusherFeedSampleNotCurrent` forever.
    /// - `WBTC/USDC` — built and then never driven, holding only the values `build_live`
    ///   writes at construction: NaN feed gauges, a NaN balance and a +Inf runway. It
    ///   stands in for a pair stalled inside `drive` before its first runway check, which is
    ///   the exact case `PusherSignerNearlyDry` would otherwise page on — through the NaN
    ///   balance, since that rule is a `predict_linear` over the balance and one NaN sample
    ///   makes the whole range return nothing. A local `make price-service` run cannot
    ///   easily produce it; the whole point of the sentinels is that no rule here can see
    ///   this pair at all.
    #[tokio::test]
    #[ignore = "long-running metrics fixture, run explicitly"]
    async fn metrics_fixture_server() {
        let port = fixture_port(std::env::var("METRICS_FIXTURE_PORT").ok().as_deref());
        let trip_after =
            fixture_trip_after(std::env::var("METRICS_FIXTURE_TRIP_AFTER").ok().as_deref());

        let metrics = Arc::new(Metrics::new().unwrap());
        metrics.register_process("fixture").unwrap();
        let health = Arc::new(crate::supervisor::Health::new(3));
        metrics.register_health(Arc::clone(&health)).unwrap();
        // The head watcher's three series, driven below: registered here because the
        // fixture stands in for builder mode, which is the only mode that has a watcher.
        let head = metrics.register_head().unwrap();
        // The stalled pair, held for the life of the fixture: pairs_in_backoff reads 1
        // against a pairs_total of 3, so PusherNothingQuoting's
        // `halted + in_backoff >= total` has a real, non-firing comparison to make rather
        // than three zeros.
        let _stalled = health.enter_backoff();

        let pairs = [
            FixturePair {
                m: metrics.for_pair("WETH/USDC"),
                venue: metrics.for_venue("WETH/USDC", "binance"),
                builders: vec![
                    metrics.for_builder("WETH/USDC", "titan"),
                    metrics.for_builder("WETH/USDC", "beaver"),
                ],
                base_mid: 3542.0,
                amplitude: 0.0045,
                max_deviation: Some(0.0025),
            },
            FixturePair {
                m: metrics.for_pair("USDC/USDT"),
                venue: metrics.for_venue("USDC/USDT", "binance"),
                builders: vec![metrics.for_builder("USDC/USDT", "titan")],
                base_mid: 0.9998,
                amplitude: 0.0,
                max_deviation: None,
            },
        ];

        // WBTC/USDC: built, given exactly what `build_live` writes at construction, and
        // then never driven. Mirrors build_live's own ordering and its reasoning — +Inf
        // and NaN, not 0, so no rule can read "never recorded" as "unhealthy". The balance
        // is part of that now rather than a detail: this fixture used to leave it at the 0
        // `for_pair` registers, which was invisible while nothing read it and is not any
        // more — a flat 0 is the one balance a regression cannot fit, so it happened to stay
        // silent, by arithmetic rather than by the NaN that is supposed to do the work.
        let stalled = metrics.for_pair("WBTC/USDC");
        stalled.breaker_armed.set(0.0);
        stalled.breaker_tripped.set(0.0);
        stalled.signer_runway_updates.set(f64::INFINITY);
        stalled.signer_balance_wei.set(f64::NAN);
        stalled.feed_up.set(f64::NAN);
        stalled.feed_last_tick.set(f64::NAN);
        stalled.feed_sample_current.set(f64::NAN);

        let (addr, _task) = bind(
            SocketAddr::from(([127, 0, 0, 1], port)),
            Arc::clone(&metrics),
        )
        .await
        .expect("bind the fixture exporter");
        println!("metrics fixture serving http://{addr}/metrics");
        match trip_after {
            Some(n) => println!("WETH/USDC's breaker will latch after {n} ticks"),
            None => println!("set METRICS_FIXTURE_TRIP_AFTER=<ticks> to latch the breaker"),
        }

        let mut halted = false;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        // Bounded, though the fixture is meant to run until interrupted: an unbounded
        // `1u64..` wraps rather than ending when it runs out of range, which is a panic in
        // debug and is what clippy's `for_unbounded_range` objects to. The bound is
        // unreachable either way — one tick a second reaches u64::MAX in rather more than
        // the age of the universe — so this is about saying which ending is meant, not
        // about the ending.
        for t in 1u64..=u64::MAX {
            ticker.tick().await;
            if trip_after.is_some_and(|n| t > n) && !halted {
                // Counted once, when it latches, exactly as the real trip does — and the
                // pair records nothing at all after this, because `drive` has returned.
                pairs[0].m.breaker_trips.inc();
                health.halt();
                halted = true;
                pairs[0].halt();
                println!("tick {t}: WETH/USDC breaker latched");
            }
            // One head poll per tick, and a block every 12 ticks — the fixture's second is
            // standing in for a slot. Mostly cheap (the number came back and had not moved)
            // with the twelfth paying a block fetch, which is the bimodal shape the real
            // watcher has and the reason its panel reads a p95.
            let rolled = t.is_multiple_of(12);
            head.poll_duration
                .observe(if rolled { 0.031 } else { 0.006 });
            if rolled {
                head.number.set((21_000_000 + t / 12) as f64);
            }
            // One poll in ~97 is abandoned or refused, so head_poll_errors_total is
            // non-zero on the dashboard without reading as an outage.
            if t.is_multiple_of(97) {
                head.poll_errors.inc();
            }
            // A halted pair is not ticked again: nothing of its own — target blocks, RPC
            // calls, feed samples — is recorded once its loop has returned, and every gauge
            // stays frozen where the halt left it — except the three the departing feed
            // task sentinels, which `halt` above writes for it.
            if !halted {
                pairs[0].tick(t);
            }
            pairs[1].tick(t);
            if t.is_multiple_of(30) {
                println!("tick {t}: mid {:.2}", pairs[0].mid_at(t));
            }
        }
    }
}

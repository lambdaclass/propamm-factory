//! What stops a lane: the latch, and the guards that trip it.
//!
//! A lane's [`Latch`] is tripped by a market guard in the composite task, a quote guard in
//! the quote loop, a panic in any extension code, or a component's own task through the
//! handle its build got. It cannot be undone: the pair stops, and a reload builds the lane
//! a new one. That is the spec's "framework owns latching" rule, in the type: a `OnceLock`
//! has no reset. The `Notify` wakes the quote loop's `select!`, so a trip from outside the
//! loop halts it at once rather than on the next price move.

pub(crate) mod deviation;

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use ethrex_common::U256;
use tokio::sync::Notify;

use crate::{
    feed::scaled_to_f64,
    pricing::{Diagnostics, PricerOutput, Refusal, TickCtx},
    update::Bound,
};

/// The names a `[[pairs.guards]]` stanza cannot use and a binary cannot register: the
/// deviation breaker, configured with its own keys.
pub const BUILT_IN_GUARDS: &[&str] = &["deviation"];

/// Judges our quote, in the quote loop, after the pricer, the core's backstop and the
/// band: the last word before the gate. Synchronous and without I/O. Runs on every tick
/// the lane prices: on a pricer's output, on its refusal, and on the core's own (a feed
/// with no sample yet or a stale one, refused before the pricer runs; the backstop or the
/// band, after it), so "halt after ten minutes withdrawn" can be written whatever withdrew
/// the lane. On a refusal `Allow` is ignored, so a guard can escalate a refusal but never
/// reverse one. Every guard runs; the most severe answer wins.
pub trait QuoteGuard: Send + 'static {
    /// Every tick, whether or not the pricer ran (see [`Candidate::price`]). `out` takes
    /// the diagnostics this guard's build declared.
    fn check(&mut self, candidate: &Candidate<'_>, out: &mut Diagnostics) -> Gate;
}

/// A quote guard's answer, from least to most severe. Compares, so a test asserts on it.
#[derive(Clone, Debug, PartialEq)]
pub enum Gate {
    /// Nothing wrong with this quote (or this refusal).
    Allow,
    /// Withdraw this tick, under a reason the guard declared with [`super::pricing::BuildCtx::refusal`].
    Withdraw(Refusal),
    /// Stop the lane: the reason is latched and rendered where a trip is shown, its alarm
    /// prefixed with the guard's kind (see [`TripReason::alarm`]).
    Halt(TripReason),
}

/// One tick as a quote guard sees it: the pricer's tick, what it published or why it
/// refused, and the diagnostics it set this tick. On a tick the core refused for its feed's
/// freshness the pricer did not run: the tick has no market, no diagnostic is set, and the
/// price is that refusal.
#[non_exhaustive]
pub struct Candidate<'a> {
    tick: &'a TickCtx<'a>,
    price: Result<&'a PricerOutput, &'a Refusal>,
    diagnostics: &'a Diagnostics,
}

impl<'a> Candidate<'a> {
    pub(crate) fn new(
        tick: &'a TickCtx<'a>,
        price: Result<&'a PricerOutput, &'a Refusal>,
        diagnostics: &'a Diagnostics,
    ) -> Candidate<'a> {
        Candidate {
            tick,
            price,
            diagnostics,
        }
    }

    /// The tick the pricer priced: the pair, the market, when. No market
    /// ([`TickCtx::market_if_any`] is `None`) on a tick refused for the feed's freshness.
    pub fn tick(&self) -> &TickCtx<'a> {
        self.tick
    }

    /// What the pricer published, or why the tick is refused. The core's backstop and band
    /// have already judged an `Ok`: a guard sees only quotes the core would publish. An
    /// `Err` is the pricer's refusal or the core's, [`Refusal::reason`] naming which: the
    /// core's `no_sample` and `stale` before the pricer ran, its backstop's or band's after.
    pub fn price(&self) -> Result<&PricerOutput, &Refusal> {
        self.price
    }

    /// What the pricer set a diagnostic to this tick, through a handle the guard's build
    /// bound with [`super::pricing::BuildCtx::read_diagnostic`]. `None` when the pricer did
    /// not set it, which it may not have on a tick it refused, and never did on a tick it
    /// did not run.
    pub fn get(&self, handle: &ReadHandle) -> Option<f64> {
        self.diagnostics.value_at(handle.index)
    }
}

/// A pricer diagnostic a quote guard reads, bound once in the guard's build.
#[derive(Clone, Debug)]
pub struct ReadHandle {
    pub(crate) index: usize,
}

impl ReadHandle {
    #[cfg(test)]
    pub(crate) fn for_test(index: usize) -> ReadHandle {
        ReadHandle { index }
    }
}

/// A quote guard as a lane runs it: its kind, and the series its build bound.
pub(crate) struct BoundQuoteGuard {
    pub(crate) kind: &'static str,
    pub(crate) guard: Box<dyn QuoteGuard>,
    pub(crate) bound: Arc<Bound>,
}

/// A market guard as a lane runs it: its kind (the label its trip and diagnostics carry)
/// and the series its build bound.
pub(crate) struct BoundGuard {
    pub(crate) kind: &'static str,
    pub(crate) guard: Box<dyn MarketGuard>,
    pub(crate) bound: Arc<Bound>,
}

impl BoundGuard {
    /// A guard that declared nothing: the built-in deviation guard, and a test's.
    pub(crate) fn built_in(kind: &'static str, guard: Box<dyn MarketGuard>) -> BoundGuard {
        BoundGuard {
            kind,
            guard,
            bound: Bound::none(),
        }
    }
}

/// Which side of the pipeline a registered guard kind judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuardSide {
    /// In the composite task, before a sample is published.
    Market,
    /// In the quote loop, after the pricer, the backstop and the band.
    Quote,
}

/// A guard the registry built, as its side.
pub(crate) enum BuiltGuard {
    Market(Box<dyn MarketGuard>),
    Quote(Box<dyn QuoteGuard>),
}

impl std::fmt::Debug for BuiltGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BuiltGuard::Market(_) => "BuiltGuard::Market",
            BuiltGuard::Quote(_) => "BuiltGuard::Quote",
        })
    }
}

/// The reason a panic in extension code is latched with: which call of which kind, and
/// what it said. One text for all three places a trip is shown.
pub(crate) fn panic_reason(
    kind: &str,
    doing: &str,
    payload: &(dyn std::any::Any + Send),
) -> TripReason {
    TripReason::new(format!(
        "{doing} of `{kind}` panicked: {}",
        crate::kinds::panic_message(payload)
    ))
}

/// Judges the market, in the composite task, before any reader sees a sample. Synchronous
/// and without I/O; it cannot fail, only pass or trip. Built once per lane configuration
/// and kept for its life, through quote-loop restarts, so its reference survives an outage
/// the way the deviation breaker's always did.
pub trait MarketGuard: Send + 'static {
    /// Every composite sample, in arrival order. `out` takes the diagnostics this guard's
    /// build declared.
    fn assess(&mut self, sample: &CompositeSample, out: &mut Diagnostics) -> Verdict;
}

/// A market guard's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing wrong with this sample.
    Pass,
    /// Stop the lane: the reason is latched and rendered where a trip is shown, its alarm
    /// prefixed with the guard's kind (see [`TripReason::alarm`]).
    Trip(TripReason),
}

/// One composite sample as a market guard sees it: exact, in lane orientation, with the
/// venues that went into it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompositeSample {
    /// When the composite was computed.
    pub at: Instant,
    /// The weighted mid, exact, in lane orientation.
    pub mid: U256,
    /// The weighted half-spread as a fraction of the mid, exact.
    pub delta: U256,
    inverted: bool,
    decimals: u32,
    sources: Vec<SourceSample>,
}

impl CompositeSample {
    pub(crate) fn new(
        at: Instant,
        mid: U256,
        delta: U256,
        inverted: bool,
        decimals: u32,
        sources: Vec<SourceSample>,
    ) -> CompositeSample {
        CompositeSample {
            at,
            mid,
            delta,
            inverted,
            decimals,
            sources,
        }
    }

    /// The mid in market orientation (e.g. USDC per WETH), whatever the lane's.
    pub fn mid_f64(&self) -> f64 {
        let lane = scaled_to_f64(self.mid, self.decimals);
        if self.inverted { 1.0 / lane } else { lane }
    }

    /// The half-spread as a fraction of the mid (0.0001 = 1 bp), as
    /// [`super::pricing::Market::half_spread`] reads a market's.
    pub fn half_spread(&self) -> f64 {
        scaled_to_f64(self.delta, self.decimals)
    }

    /// The fresh venues this composite averaged, so a guard can judge whether they agree.
    pub fn sources(&self) -> &[SourceSample] {
        &self.sources
    }
}

/// One venue's contribution to a composite sample.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SourceSample {
    /// The venue, as `sources` names it (`binance`, `kraken`, ...).
    pub venue: &'static str,
    /// This venue's share of the composite's weight, 0 to 1, over the fresh sources.
    pub weight: f64,
    /// Its mid, exact, in lane orientation; [`Self::mid_f64`] reads it in market terms.
    pub mid: U256,
    /// Its half-spread as a fraction of its mid, exact; [`Self::half_spread`] as a number.
    pub delta: U256,
    /// How old its sample was when the composite was computed.
    pub age: std::time::Duration,
    inverted: bool,
    decimals: u32,
}

impl SourceSample {
    pub(crate) fn new(
        venue: &'static str,
        weight: f64,
        mid: U256,
        delta: U256,
        age: std::time::Duration,
        inverted: bool,
        decimals: u32,
    ) -> SourceSample {
        SourceSample {
            venue,
            weight,
            mid,
            delta,
            age,
            inverted,
            decimals,
        }
    }

    /// The venue's mid in market orientation (e.g. USDC per WETH), whatever the lane's, as
    /// [`CompositeSample::mid_f64`] reads the composite's: what a guard judging venue
    /// agreement compares.
    pub fn mid_f64(&self) -> f64 {
        let lane = scaled_to_f64(self.mid, self.decimals);
        if self.inverted { 1.0 / lane } else { lane }
    }

    /// The venue's half-spread as a fraction of its mid (0.0001 = 1 bp).
    pub fn half_spread(&self) -> f64 {
        scaled_to_f64(self.delta, self.decimals)
    }
}

/// Who tripped a latch, for the alarm line, the watchdog notice and `trip_source`.
/// `#[non_exhaustive]`, like every enum an observer matches on (it travels in
/// [`crate::observe::Event::Tripped`]): a fourth cause is not a breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cause {
    /// A guard's verdict, a built-in's or a registered one's.
    Guard,
    /// A panic in extension code: a pricer's `price`, a guard's `assess` or `check`, or a
    /// task a build spawned.
    Panic,
    /// A component's own call on the latch, from its code or a task of its own.
    External,
}

impl Cause {
    /// The `cause` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Cause::Guard => "guard",
            Cause::Panic => "panic",
            Cause::External => "external",
        }
    }
}

/// The three places a trip is rendered: the withdrawn header of the block summary, the
/// alarm line on stderr, and the tail of the reload line that clears it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripReason {
    /// After "withdrawn: " in the block header, e.g. `price deviation 4.10% exceeds the
    /// 2.00% limit`.
    pub header: String,
    /// The one warning line when the lane halts, e.g. `circuit breaker tripped: mid moved
    /// 4.10% > 2.00% (previous 1.00, new 1.04)`. For a registered guard the latch prefixes
    /// it with ``guard `<kind>` tripped: ``, so a guard's text says only what was seen.
    pub alarm: String,
    /// After "clearing the halt it took N ago " on re-arm: the deviation guard's `on a
    /// 4.10% move from previous 1.00 to 1.04 (limit 2.00%)`, which continues the sentence;
    /// [`TripReason::new`] parenthesizes its text so that any text does.
    pub rearm: String,
}

impl TripReason {
    /// One text for all three places, for a guard whose reason reads the same everywhere.
    /// The re-arm line gets it in parentheses, after "took N ago"; a registered guard's
    /// alarm gets its kind in front (see [`TripReason::alarm`]).
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        TripReason {
            header: text.clone(),
            alarm: text.clone(),
            rearm: format!("({text})"),
        }
    }
}

/// A latched trip: what tripped, how, why, and when.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Trip {
    /// The kind that tripped: `deviation`, or a registered guard's or pricer's name.
    pub source: &'static str,
    /// How.
    pub cause: Cause,
    /// The rendered reason.
    pub reason: TripReason,
    /// When, for the re-arm line's "took N ago".
    pub at: Instant,
}

#[derive(Default)]
struct Inner {
    trip: OnceLock<Trip>,
    notify: Notify,
    /// The run's observers and the lane's label, from the lane's adoption to its stop:
    /// every trip site (a guard, a panic, a binary's own component) reports through the
    /// latch itself, whichever task it happens on. See [`Latch::attach_observers`].
    observers: std::sync::Mutex<Telling>,
    /// The lane's series, set when the lane is built, so the trip's transition
    /// (`breaker_tripped`, `breaker_trips`, `trip_source`) is recorded here, once, and
    /// before any waiter wakes. Gated on adoption like every write of a lane's series.
    metrics: OnceLock<crate::feed::Gated<crate::metrics::PairMetrics>>,
    /// Whether the transition has been recorded, claimed by whichever of its writers gets
    /// there first: `trip`'s own write, the seed a lane is adopted with, and the re-check
    /// right after the switch (see [`Latch::record_trip`]). A flag apart from `trip`,
    /// because a trip can be set while its recording is still gated off.
    recorded: AtomicBool,
}

/// Who a latch tells of its trip, and whether it has. One lock over both, taken by the trip
/// and by the attach alike, so a trip racing the attach is told exactly once: whichever
/// of the two comes second finds the other's half and tells, and `told` keeps the first
/// from telling again. Two `OnceLock`s could not promise that: each side would set its own
/// and read the other's, and both reads can miss.
#[derive(Default)]
struct Telling {
    to: Option<(crate::observe::Observers, String)>,
    told: bool,
}

impl Telling {
    /// Tells the observers of `trip`, if there are any and they have not been told.
    fn tell(&mut self, trip: &Trip) {
        if let (Some((observers, pair)), false) = (&self.to, self.told) {
            self.told = true;
            observers.emit(crate::observe::Event::Tripped {
                pair: pair.clone(),
                source: trip.source,
                cause: trip.cause,
            });
        }
    }
}

/// A lane's latch, cloned into every task of the lane. The first trip wins and nothing
/// clears it.
#[derive(Clone, Default)]
pub struct Latch(Arc<Inner>);

impl Latch {
    /// A fresh, armed latch. The core builds one per lane; a binary builds one to test a
    /// component that trips its lane, with no lane around it.
    pub fn new() -> Latch {
        Latch::default()
    }

    /// Trips the latch. `true` if this call did; `false` if it was already tripped, whose
    /// trip stands: the first judgement is the one the operator was shown.
    pub fn trip(&self, source: &'static str, cause: Cause, mut reason: TripReason) -> bool {
        // A registered guard's alarm names the guard, as the deviation guard's names itself
        // in its own wording: an operator reading `half-spread 1.23% over the cap` needs
        // to know which guard said so, and `trip_source` is a metric, not the line. The
        // header stays the text alone (it follows "withdrawn: "), and a panic's text
        // already names its kind.
        if cause == Cause::Guard && !BUILT_IN_GUARDS.contains(&source) {
            reason.alarm = format!("guard `{source}` tripped: {}", reason.alarm);
        }
        let tripped = self
            .0
            .trip
            .set(Trip {
                source,
                cause,
                reason,
                at: Instant::now(),
            })
            .is_ok();
        if tripped {
            // The transition's series, before any waiter wakes: one trip is one increment
            // whichever task tripped it, and a loop that reads the gauges on waking reads
            // them recorded. Gated off before the lane adopted its series: a trip then is
            // recorded by the seed (`adopt_breaker_metrics`) if it saw it, or else by the
            // re-check `pair::adopt` makes right after the switch, and the claim in
            // `record_trip` makes it one of the three, never two.
            self.record_adopted();
            // Every waiter registered by now; a later one reads the latch in `notified`.
            self.0.notify.notify_waiters();
            // Once per latch, so the lock costs the quoting path nothing; `emit` never waits.
            if let Some(trip) = self.0.trip.get() {
                self.telling().tell(trip);
            }
        }
        tripped
    }

    /// Records the trip's transition (`breaker_tripped`, `breaker_trips`, `trip_source`)
    /// into `m`, if the latch has tripped and no writer has recorded it yet. `true` if this
    /// call recorded it. The claim is what makes it exactly once whatever the interleaving:
    /// the seed may see a trip whose own write has not run, and a trip may land after the
    /// seed's read while that write is still gated off; each writer records only what no
    /// other has.
    pub(crate) fn record_trip(&self, m: &crate::metrics::PairMetrics) -> bool {
        let Some(trip) = self.0.trip.get() else {
            return false;
        };
        if self.0.recorded.swap(true, Ordering::SeqCst) {
            return false;
        }
        m.breaker_tripped.set(1.0);
        m.breaker_trips.inc();
        m.trip_source(trip.source, trip.cause.as_str()).set(1.0);
        true
    }

    /// [`Self::record_trip`] through the series attached at build, gated on the lane
    /// owning them like every write of a lane's series: `trip`'s own write, and the
    /// re-check right after the switch. The claim is made under the gate, so a write the
    /// gate turned away leaves the transition for another writer to record.
    pub(crate) fn record_adopted(&self) {
        if let Some(metrics) = self.0.metrics.get() {
            metrics.record(|m| {
                self.record_trip(m);
            });
        }
    }

    /// Tells the run's observers of this latch's trip from now on, as `pair`: at the lane's
    /// adoption, right after its `LaneStarted`, and not at its build, where the latch is
    /// already live (its guards judge from the first sample) while the lane may be one an
    /// observer has not been told of: a startup lane not yet started, a rebuild the old
    /// generation is still quoting beside, or one that then fails and never runs. A trip
    /// in that window is told here, so it still follows `LaneStarted`; either way once.
    pub(crate) fn attach_observers(&self, observers: crate::observe::Observers, pair: String) {
        let mut telling = self.telling();
        telling.to = Some((observers, pair));
        if let Some(trip) = self.0.trip.get() {
            telling.tell(trip);
        }
    }

    /// Tells nobody from now on: the lane's generation is over and its `LaneStopped` is
    /// said, while a task of its own (the composite judging a last sample) can still be
    /// winding down with the latch in hand.
    pub(crate) fn detach_observers(&self) {
        self.telling().to = None;
    }

    /// The lock over who is told. A poisoned one is taken anyway: `tell` cannot leave it
    /// half-written, and the trip is the one thing that must not be lost to it.
    fn telling(&self) -> std::sync::MutexGuard<'_, Telling> {
        self.0
            .observers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The series a trip is recorded into. Once, at build; a later call changes nothing.
    pub(crate) fn attach_metrics(&self, metrics: crate::feed::Gated<crate::metrics::PairMetrics>) {
        let _ = self.0.metrics.set(metrics);
    }

    /// The trip, if any. A `OnceLock` read: no lock, safe on every tick.
    pub fn tripped(&self) -> Option<&Trip> {
        self.0.trip.get()
    }

    /// Resolves when the latch trips, or at once if it already has. The waiter registers
    /// before it reads the latch, so a trip landing between the two is not missed, and a
    /// waiter that comes late (a supervised restart, a component's task) returns from
    /// the read rather than from a stored permit, which would serve one late waiter and
    /// hang the next.
    pub async fn notified(&self) {
        let notified = self.0.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.0.trip.get().is_none() {
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trip's series (`breaker_tripped`, `breaker_trips`, `trip_source`) are written by
    /// the latch, once, before any waiter is woken: whichever task trips it and whichever
    /// wakes first, one trip is one transition, and a waiter that reads the gauges on
    /// waking reads them recorded.
    #[tokio::test]
    async fn a_latch_records_its_trip_once_before_anyone_wakes() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let pair = metrics.for_pair("A/B");
        let adopted = crate::feed::Adoption::new();
        adopted.adopt();
        let latch = Latch::new();
        latch.attach_metrics(crate::feed::Gated::new(pair.clone(), adopted));
        let waiter = {
            let (latch, pair) = (latch.clone(), pair.clone());
            tokio::spawn(async move {
                latch.notified().await;
                pair.breaker_tripped.get()
            })
        };
        tokio::task::yield_now().await;
        assert!(latch.trip("kill", Cause::Guard, TripReason::new("kill switch")));
        assert!(!latch.trip("other", Cause::Panic, TripReason::new("late")));
        assert_eq!(pair.breaker_tripped.get(), 1.0);
        assert_eq!(pair.breaker_trips.get(), 1, "one trip, one transition");
        assert_eq!(pair.trip_source("kill", "guard").get(), 1.0);
        assert_eq!(pair.trip_source("other", "panic").get(), 0.0);
        assert_eq!(waiter.await.unwrap(), 1.0, "recorded before the wake");
    }

    /// The transition has three writers: the seed (`adopt_breaker_metrics`, before the
    /// lane owns its series), the latch's own write in `trip` (gated on that ownership),
    /// and the re-check `pair::adopt` makes right after the switch. Whichever order a trip
    /// lands in among them, it is recorded exactly once. The order that used to count it
    /// twice: the trip is set, the seed sees it and records it, the switch is thrown, and
    /// only then does the latch's own write run, gated on now.
    #[test]
    fn a_trip_is_recorded_once_whichever_of_its_writers_gets_there_first() {
        #[derive(Clone, Copy, Debug)]
        enum Step {
            Trip,
            Seed,
            Switch,
            LateWrite,
            Recheck,
        }
        use Step::*;
        for order in [
            // Tripped before anyone looked: the seed records it.
            [Trip, Seed, Switch, Recheck, LateWrite],
            // Set before the seed's read, its own write landing after the switch.
            [Trip, Seed, Switch, LateWrite, Recheck],
            // Between the seed's read and the switch: the re-check records it.
            [Seed, Trip, Switch, Recheck, LateWrite],
            // After the switch: the latch's own write records it.
            [Seed, Switch, Trip, Recheck, LateWrite],
            [Seed, Switch, Recheck, Trip, LateWrite],
        ] {
            let metrics = crate::metrics::Metrics::new().unwrap();
            let pair = metrics.for_pair("A/B");
            let adopted = crate::feed::Adoption::new();
            let latch = Latch::new();
            latch.attach_metrics(crate::feed::Gated::new(pair.clone(), adopted.clone()));
            for step in order {
                match step {
                    // Through `trip`, whose own write is the gated one.
                    Trip => assert!(latch.trip("kill", Cause::Guard, TripReason::new("k"))),
                    Seed => {
                        latch.record_trip(&pair);
                    }
                    Switch => adopted.adopt(),
                    // `trip`'s own write, landing after the set: what it runs, again.
                    LateWrite | Recheck => latch.record_adopted(),
                }
            }
            assert_eq!(pair.breaker_tripped.get(), 1.0, "{order:?}");
            assert_eq!(
                pair.breaker_trips.get(),
                1,
                "one trip, one transition: {order:?}"
            );
            assert_eq!(pair.trip_source("kill", "guard").get(), 1.0, "{order:?}");
        }
    }

    /// The pairs whose trip `seen` holds, in order.
    fn tripped_pairs(seen: &std::sync::Mutex<Vec<crate::observe::Event>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                crate::observe::Event::Tripped { pair, .. } => Some(pair.clone()),
                _ => None,
            })
            .collect()
    }

    /// A trip in the build window, before the lane's observers attach at its adoption, is
    /// told at the attach (which follows the lane's `LaneStarted`); one after the attach is
    /// told as it happens; either way once.
    #[tokio::test(start_paused = true)]
    async fn a_trip_before_the_observers_attach_is_told_at_the_attach_and_once() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let (recorder, seen) = crate::observe::Recorder::new();
        let (hub, _tasks) = crate::observe::Observers::spawn(vec![Box::new(recorder)], &metrics);

        let early = Latch::new();
        early.trip(
            "tripwire",
            Cause::External,
            TripReason::new("while building"),
        );
        early.attach_observers(hub.clone(), "A/B".to_owned());
        early.attach_observers(hub.clone(), "A/B".to_owned());
        let late = Latch::new();
        late.attach_observers(hub.clone(), "C/D".to_owned());
        late.trip("kill", Cause::Guard, TripReason::new("kill switch"));
        late.trip("other", Cause::Panic, TripReason::new("refused"));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(tripped_pairs(&seen), ["A/B", "C/D"]);
    }

    /// A trip racing the attach from another thread is told exactly once: never lost
    /// between the two, never told by both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_trip_racing_the_attach_is_told_exactly_once() {
        const RACES: usize = 200;
        let metrics = crate::metrics::Metrics::new().unwrap();
        let (recorder, seen) = crate::observe::Recorder::new();
        let (hub, _tasks) = crate::observe::Observers::spawn(vec![Box::new(recorder)], &metrics);
        for i in 0..RACES {
            let latch = Latch::new();
            let tripper = {
                let latch = latch.clone();
                std::thread::spawn(move || {
                    latch.trip("kill", Cause::External, TripReason::new("kill switch"));
                })
            };
            latch.attach_observers(hub.clone(), i.to_string());
            tripper.join().unwrap();
        }
        let all = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while tripped_pairs(&seen).len() < RACES {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let told = tripped_pairs(&seen);
        assert!(all.is_ok(), "{} of {RACES} trips told", told.len());
        let expected: Vec<String> = (0..RACES).map(|i| i.to_string()).collect();
        assert_eq!(told, expected, "each race told once, in order");
    }

    /// Two tasks that start listening after the trip both wake: a component's task and
    /// the quote loop can both be late, and a stored permit serves only one.
    #[tokio::test]
    async fn two_late_waiters_both_wake() {
        let latch = Latch::new();
        latch.trip("kill", Cause::External, TripReason::new("kill switch"));
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            futures_util::future::join(latch.notified(), latch.notified()),
        )
        .await
        .expect("both late waiters resolve");
    }

    #[test]
    fn the_first_trip_wins_and_later_ones_are_refused() {
        let latch = Latch::new();
        assert!(latch.tripped().is_none());
        assert!(latch.trip("deviation", Cause::Guard, TripReason::new("moved 4%")));
        assert!(!latch.trip("funding", Cause::Panic, TripReason::new("later")));
        let trip = latch.tripped().expect("latched");
        assert_eq!(
            (trip.source, trip.cause, trip.reason.header.as_str()),
            ("deviation", Cause::Guard, "moved 4%")
        );
        assert!(trip.at.elapsed() < std::time::Duration::from_secs(1));
    }

    /// One text fills all three; the re-arm's is parenthesized, because it follows "took N
    /// ago" in a sentence that the deviation guard's own wording continues with "on a ..."
    /// and an arbitrary text cannot.
    #[test]
    fn a_reason_from_one_text_fills_all_three() {
        let reason = TripReason::new("x");
        assert_eq!(
            (
                reason.header.as_str(),
                reason.alarm.as_str(),
                reason.rearm.as_str()
            ),
            ("x", "x", "(x)")
        );
    }

    /// A registered guard's alarm names the guard, as the deviation guard's names itself:
    /// the operator reading the line at 3am needs to know which guard said so. The
    /// built-in's wording is its own and unchanged; a panic's names its kind already.
    #[test]
    fn a_registered_guards_alarm_names_the_guard_and_the_built_ins_is_unchanged() {
        let latch = Latch::new();
        assert!(latch.trip(
            "spread_cap",
            Cause::Guard,
            TripReason::new("half-spread 1.23% over the 0.30% cap")
        ));
        let trip = latch.tripped().unwrap();
        assert_eq!(
            trip.reason.alarm,
            "guard `spread_cap` tripped: half-spread 1.23% over the 0.30% cap"
        );
        assert_eq!(
            trip.reason.header, "half-spread 1.23% over the 0.30% cap",
            "the block header is the text alone"
        );

        let built_in = Latch::new();
        assert!(built_in.trip(
            "deviation",
            Cause::Guard,
            TripReason::new("circuit breaker tripped: mid moved 4%")
        ));
        assert_eq!(
            built_in.tripped().unwrap().reason.alarm,
            "circuit breaker tripped: mid moved 4%"
        );

        let panicked = Latch::new();
        assert!(panicked.trip(
            "adaptive",
            Cause::Panic,
            TripReason::new("price of `adaptive` panicked: boom")
        ));
        assert_eq!(
            panicked.tripped().unwrap().reason.alarm,
            "price of `adaptive` panicked: boom"
        );
    }

    /// A candidate hands a quote guard the pricer's tick, its output or refusal, and the
    /// diagnostics it set, readable by the handles the guard's build bound.
    #[test]
    fn a_candidate_reads_the_pricers_diagnostics_by_handle() {
        use crate::{pricing::PricerOutput, testing};
        let pair = testing::pair();
        let mut ctx = testing::build_ctx(&pair);
        let funding = ctx.diagnostic("funding").unwrap();
        let mut out = testing::diagnostics(&ctx);
        out.set(&funding, 0.25);
        let read = ReadHandle::for_test(0);
        let unset = ReadHandle::for_test(7);
        let priced = PricerOutput::new(U256::one(), U256::from(2));
        let tick = testing::tick(&pair, None);
        let candidate = Candidate::new(&tick, Ok(&priced), &out);
        assert_eq!(candidate.get(&read), Some(0.25));
        assert_eq!(candidate.get(&unset), None);
        assert_eq!(candidate.price().ok().map(|p| p.mid), Some(U256::from(2)));
        assert_eq!(candidate.tick().pair().label, pair.label);
    }

    /// The quote loop selects on this: a trip from the composite task or a component's own
    /// task must wake it at once, not on the next price move. And a loop that starts after
    /// the trip (a supervised restart) must not wait forever for a notification that was
    /// sent before it listened, however many such late waiters there are.
    #[tokio::test]
    async fn a_trip_wakes_a_waiter_and_late_waiters_return_at_once() {
        let latch = Latch::new();
        let waiter = latch.clone();
        let woken = tokio::spawn(async move {
            waiter.notified().await;
            waiter.tripped().is_some()
        });
        tokio::task::yield_now().await;
        assert!(latch.trip("t", Cause::External, TripReason::new("go")));
        assert!(woken.await.unwrap());
        for _ in 0..2 {
            tokio::time::timeout(std::time::Duration::from_millis(100), latch.notified())
                .await
                .expect("already tripped: no wait");
        }
    }
}

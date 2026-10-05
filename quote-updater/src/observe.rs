//! Observers: a binary's code that watches the run and never decides. An observer is
//! registered on the builder (`UpdaterBuilder::observer`), code-only: it lives for the
//! process, takes no part in a reload, and its secrets (a webhook) belong in the
//! environment. Events arrive at transitions and once per block, matching the per-block
//! summary line, never per tick.
//!
//! Best effort by design: each observer runs in a task of its own behind a bounded channel,
//! so a slow one costs the quote loop nothing; a full channel drops the event and counts it
//! (`quote_updater_observer_dropped_total{observer}`), and one that panics is logged,
//! removed and shown as not running (`quote_updater_observer_running{observer}`). A run
//! that ends normally (a shutdown, `--once`) lets each observer deliver what it already
//! holds, the lanes' last `LaneStopped` included, for up to two seconds before it returns;
//! one that ends on an error aborts them. An audit trail belongs in the recorder,
//! not here.
//!
//! Builder mode only. Every event is about a lane a `Service` adopted (its start, blocks,
//! landings, trip and stop) or a reload it answered, and `--mode node` runs no `Service`:
//! its ticker pushes a transaction per interval, not a quote per block, and it has no
//! reload. Its observers are not started and hear nothing, which the run says once at
//! startup, rather than inventing a block or a lifecycle that mode does not have.

use std::{any::Any, panic::AssertUnwindSafe, sync::Arc, time::Duration};

use futures_util::FutureExt;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    U256,
    guard::Cause,
    metrics::Metrics,
    pricing::{BoxFuture, LandingOutcome},
};

/// Something a binary runs beside the updater to watch it: a Slack notifier, a risk
/// system's feed, a log of its own. It is handed every [`Event`] in order, one at a time,
/// and can do nothing to the run.
pub trait Observer: Send + 'static {
    /// The `observer` label of its series; unique among the observers registered (a
    /// second under the same name is refused before the run reads any config).
    fn name(&self) -> &'static str;
    /// Called for every event, in order, awaited before the next. A slow one falls behind
    /// and loses events rather than delaying anything.
    fn on_event<'a>(&'a mut self, event: &'a Event) -> BoxFuture<'a, ()>;
}

/// What an observer is told. `pair` is the label the logs and metrics use. More variants
/// may come; match with a `_` arm. Every enum an observer matches on is
/// `#[non_exhaustive]` for the same reason: a new variant is not a breaking change. Every
/// variant with fields is too, so a new field is not one either: match its fields with
/// `..` (`Event::Tripped { pair, .. }`).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A lane's quote loop started: at startup, when a reload adds or restarts it.
    #[non_exhaustive]
    LaneStarted {
        /// The pair's label.
        pair: String,
    },
    /// A lane's quote loop ended: it halted on its latch, a reload removed or replaced it,
    /// it ended on its own, or the run is shutting down.
    #[non_exhaustive]
    LaneStopped {
        /// The pair's label.
        pair: String,
    },
    /// A block passed for the lane, with what it quoted for it or why it did not, and the
    /// pricer's declared diagnostics as of its last tick. Once per block, and none for the
    /// block a halt broke out of, which has not passed: the generation a reload re-arms
    /// says it passed, if it does.
    #[non_exhaustive]
    Block {
        /// The pair's label.
        pair: String,
        /// The block that passed.
        block: u64,
        /// What stood for it.
        outcome: BlockOutcome,
        /// The pricer's declared diagnostics, by name, as last published.
        diagnostics: Vec<(String, f64)>,
    },
    /// The lane's latch tripped. Once per trip; a reload clears it. Always between the
    /// lane's `LaneStarted` and its `LaneStopped`: a trip while the lane was being built is
    /// told right after it started, and one in a rebuild that then failed, never.
    #[non_exhaustive]
    Tripped {
        /// The pair's label.
        pair: String,
        /// Who: a guard's kind, `deviation`, the pricer or task kind that panicked, or a
        /// binary's own component.
        source: &'static str,
        /// A guard's judgement, a panic, or a binary's own call.
        cause: Cause,
    },
    /// A reload restarted a lane that had halted on its latch.
    #[non_exhaustive]
    Rearmed {
        /// The pair's label.
        pair: String,
    },
    /// The read-back after a block: whether the lane's update for it landed.
    #[non_exhaustive]
    Landing {
        /// The pair's label.
        pair: String,
        /// The block read back.
        block: u64,
        /// What the read-back found.
        outcome: LandingOutcome,
    },
    /// A reload was asked for (SIGHUP, the backoffice, a handle) and answered.
    #[non_exhaustive]
    Reload {
        /// How it went.
        outcome: ReloadOutcome,
    },
}

/// What a lane had standing when the block passed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockOutcome {
    /// A quote stood for the block.
    #[non_exhaustive]
    Quoted {
        /// The half-spread, in lane orientation and the chain's scale.
        delta: U256,
        /// The mid, likewise.
        mid: U256,
    },
    /// Nothing stood for the block.
    #[non_exhaustive]
    Withdrawn {
        /// Why, as the per-block summary's header says it.
        reason: String,
    },
}

/// How a reload went; see the reload lines for what each means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReloadOutcome {
    /// The file was applied: every change took, or there was none.
    Applied,
    /// The file was refused: nothing changed.
    Rejected,
    /// Applied, but some lane kept its previous config.
    Partial,
}

/// Events an observer can fall behind by before it starts losing them.
pub(crate) const CHANNEL_CAPACITY: usize = 1024;

/// How long a run that ends normally (a shutdown, `--once`) gives its observers to deliver
/// what is already queued, the drain's `LaneStopped`s and a last block and its landing,
/// before it returns and their tasks are aborted with the rest. Short, because it comes
/// after the withdraws, on the way out: a webhook's round trip or two, not a channel's
/// worth of backlog, which an observer that far behind was losing anyway.
pub(crate) const DELIVERY_GRACE: Duration = Duration::from_secs(2);

/// The hub every emit site holds: one bounded channel per observer. Cheap to clone; an
/// empty one (no observers) costs an emit a vector walk of nothing.
#[derive(Clone, Default)]
pub(crate) struct Observers {
    slots: Arc<Vec<Slot>>,
}

struct Slot {
    name: &'static str,
    tx: mpsc::Sender<Arc<Event>>,
    dropped: prometheus::IntCounter,
}

/// The observers' tasks, for the run to own: aborted with its other tasks on an error, or
/// let deliver what is queued first on a normal end ([`Self::finish`]). Apart from the hub
/// because the hub is cloned into every lane, and the end is the run's alone.
pub(crate) struct ObserverTasks {
    tasks: Vec<(&'static str, JoinHandle<()>)>,
    /// Raised by `finish`: each task stops taking events and delivers what it holds.
    closing: tokio::sync::watch::Sender<bool>,
}

impl Observers {
    /// Starts one task per observer on the current runtime, each shown as running.
    pub(crate) fn spawn(
        observers: Vec<Box<dyn Observer>>,
        metrics: &Metrics,
    ) -> (Observers, ObserverTasks) {
        let (closing, close) = crate::supervisor::shutdown_channel();
        let mut slots = Vec::with_capacity(observers.len());
        let mut tasks = Vec::with_capacity(observers.len());
        for mut observer in observers {
            let name = observer.name();
            let (tx, mut rx) = mpsc::channel::<Arc<Event>>(CHANNEL_CAPACITY);
            let running = metrics.observer_running(name);
            running.set(1.0);
            let mut close = close.clone();
            let task = tokio::spawn(async move {
                let mut closed = false;
                loop {
                    let event = tokio::select! {
                        // What is queued first, so a closing run's last events are
                        // delivered rather than raced against the close.
                        biased;
                        event = rx.recv() => event,
                        // Nothing new from here: what the channel holds is still received,
                        // then `None` ends the loop. A dropped sender never closes
                        // (`Shutdown::wait`), so a hub whose tasks were dropped keeps going.
                        () = close.wait(), if !closed => {
                            rx.close();
                            closed = true;
                            continue;
                        }
                    };
                    let Some(event) = event else { break };
                    // The observer is the binary's code: a panic ends this observer, not
                    // the process, and is said once. `on_event` is called inside the
                    // guarded future, not before it: the code that builds its future is
                    // the binary's too, and a panic there would otherwise unwind this task
                    // past the gauge and the line.
                    let outcome = AssertUnwindSafe(async { observer.on_event(&event).await })
                        .catch_unwind()
                        .await;
                    if let Err(payload) = outcome {
                        tracing::error!(
                            "observer `{name}` panicked and is removed: {}",
                            panic_message(&*payload)
                        );
                        // Only here: an observer that delivered its last event as the run
                        // ended did not fail, and a rule on 0 must not page for a shutdown.
                        running.set(0.0);
                        break;
                    }
                }
            });
            tasks.push((name, task));
            slots.push(Slot {
                name,
                tx,
                dropped: metrics.observer_dropped(name),
            });
        }
        (
            Observers {
                slots: Arc::new(slots),
            },
            ObserverTasks { tasks, closing },
        )
    }

    /// Hands `event` to every observer that has room for it. Never waits: a full channel
    /// drops it and counts the drop against that observer; a removed observer's closed
    /// channel is skipped.
    pub(crate) fn emit(&self, event: Event) {
        if self.slots.is_empty() {
            return;
        }
        let event = Arc::new(event);
        for slot in self.slots.iter() {
            match slot.tx.try_send(Arc::clone(&event)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => slot.dropped.inc(),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::trace!("observer `{}` is gone; event not delivered", slot.name);
                }
            }
        }
    }
}

impl ObserverTasks {
    /// The tasks, for the run's [`crate::tasks::Tasks`] to abort on a way out that does not
    /// [`Self::finish`].
    pub(crate) fn handles(&self) -> impl Iterator<Item = &JoinHandle<()>> {
        self.tasks.iter().map(|(_, task)| task)
    }

    /// Lets every observer deliver what is already queued, then end; bounded by
    /// [`DELIVERY_GRACE`] for all of them at once, after which a slow one is left to the
    /// abort and said by name. For a run that ends normally, once its lanes have drained:
    /// nothing emits after this, and an emit that did would find the channel closed.
    pub(crate) async fn finish(self) {
        self.closing.send_replace(true);
        let deadline = tokio::time::Instant::now() + DELIVERY_GRACE;
        let late: Vec<&str> =
            futures_util::future::join_all(self.tasks.into_iter().map(|(name, task)| async move {
                tokio::time::timeout_at(deadline, task)
                    .await
                    .is_err()
                    .then_some(name)
            }))
            .await
            .into_iter()
            .flatten()
            .collect();
        if !late.is_empty() {
            tracing::warn!(
                "observer(s) {} did not deliver their last events within {DELIVERY_GRACE:?}; \
                 what they had not delivered is lost",
                late.iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

impl std::fmt::Debug for Observers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.slots.iter().map(|slot| slot.name).collect();
        write!(f, "Observers({names:?})")
    }
}

/// Two observers under one name, refused as a kind registered twice is: the name is the
/// `observer` label of both its series, so the second would share the first's, one
/// panicking would show the other as not running, and their drops would merge. Every
/// duplicate at once, in registration order.
pub(crate) fn refuse_duplicate_names(observers: &[Box<dyn Observer>]) -> eyre::Result<()> {
    let mut seen = Vec::with_capacity(observers.len());
    let mut twice = Vec::new();
    for observer in observers {
        let name = observer.name();
        if seen.contains(&name) {
            if !twice.contains(&name) {
                twice.push(name);
            }
        } else {
            seen.push(name);
        }
    }
    let errors: Vec<String> = twice
        .iter()
        .map(|name| format!("observer `{name}` registered twice"))
        .collect();
    eyre::ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

/// What `--mode node` says once at startup when the binary registered observers, which
/// it does not start (see the module doc); `None` when there are none.
pub(crate) fn node_mode_notice(observers: &[Box<dyn Observer>]) -> Option<String> {
    let names: Vec<String> = observers
        .iter()
        .map(|observer| format!("`{}`", observer.name()))
        .collect();
    let who = match names.as_slice() {
        [] => return None,
        [one] => format!("observer {one} is"),
        many => format!("observers {} are", many.join(", ")),
    };
    Some(format!(
        "{who} told nothing in --mode node: observers watch builder mode's lanes, blocks \
         and reloads, which node mode does not run"
    ))
}

/// A panic's payload as text: what `panic!` was given, or a note that it was not a string.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a payload that is not a string".to_owned())
}

/// Keeps every event it is handed, for a test to read back what the run told it.
#[cfg(test)]
pub(crate) struct Recorder(Arc<std::sync::Mutex<Vec<Event>>>);

#[cfg(test)]
impl Recorder {
    /// The observer, and what it will have seen.
    pub(crate) fn new() -> (Recorder, Arc<std::sync::Mutex<Vec<Event>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        (Recorder(Arc::clone(&seen)), seen)
    }
}

#[cfg(test)]
impl Observer for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }
    fn on_event<'a>(&'a mut self, event: &'a Event) -> BoxFuture<'a, ()> {
        let seen = Arc::clone(&self.0);
        Box::pin(async move { seen.lock().unwrap().push(event.clone()) })
    }
}

/// What `#[non_exhaustive]` holds a binary to, compiled from outside the crate as a
/// binary's own code is: a variant's fields written out without `..` do not compile, so a
/// field added later (a trip's reason, a generation id) breaks no observer, and a [`Cause`]
/// matched without a `_` arm does not either, so a fourth cause breaks none.
///
/// ```compile_fail
/// use quote_updater::observe::Event;
/// fn tripped(event: &Event) -> Option<&str> {
///     match event {
///         Event::Tripped { pair, source: _, cause: _ } => Some(pair),
///         _ => None,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use quote_updater::observe::BlockOutcome;
/// fn reason(outcome: &BlockOutcome) -> Option<&str> {
///     match outcome {
///         BlockOutcome::Withdrawn { reason } => Some(reason),
///         _ => None,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use quote_updater::guard::Cause;
/// fn page(cause: Cause) -> bool {
///     match cause {
///         Cause::Guard | Cause::External => false,
///         Cause::Panic => true,
///     }
/// }
/// ```
#[cfg(doctest)]
pub struct OpenToGrowth;

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;
    use crate::pricing::BoxFuture;

    /// Takes an hour over every event: its channel fills.
    struct Slow;
    impl Observer for Slow {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn on_event<'a>(&'a mut self, _: &'a Event) -> BoxFuture<'a, ()> {
            Box::pin(tokio::time::sleep(Duration::from_secs(3600)))
        }
    }

    /// A webhook client with a bug, counting how many events it was handed.
    struct Panicky(Arc<std::sync::atomic::AtomicUsize>);
    impl Observer for Panicky {
        fn name(&self) -> &'static str {
            "panicky"
        }
        fn on_event<'a>(&'a mut self, _: &'a Event) -> BoxFuture<'a, ()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { panic!("the webhook client exploded") })
        }
    }

    /// A webhook client whose bug is in the synchronous part of `on_event`, before any
    /// future exists: a `catch_unwind` around the returned future alone never sees it.
    struct PanicsEarly;
    impl Observer for PanicsEarly {
        fn name(&self) -> &'static str {
            "early"
        }
        fn on_event<'a>(&'a mut self, _: &'a Event) -> BoxFuture<'a, ()> {
            panic!("the webhook client exploded before it built a request")
        }
    }

    /// Keeps every event it is handed.
    struct Fine(Arc<Mutex<Vec<Event>>>);
    impl Observer for Fine {
        fn name(&self) -> &'static str {
            "fine"
        }
        fn on_event<'a>(&'a mut self, event: &'a Event) -> BoxFuture<'a, ()> {
            let seen = Arc::clone(&self.0);
            Box::pin(async move { seen.lock().unwrap().push(event.clone()) })
        }
    }

    /// A full channel drops and counts; a panicking observer is logged, removed and shown
    /// as not running; neither slows the third, which sees every event.
    #[tokio::test(start_paused = true)]
    async fn a_slow_observer_drops_and_counts_and_a_panicking_one_is_removed() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let panicky_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (hub, _tasks) = Observers::spawn(
            vec![
                Box::new(Slow),
                Box::new(Panicky(Arc::clone(&panicky_calls))),
                Box::new(Fine(Arc::clone(&seen))),
            ],
            &metrics,
        );
        for name in ["slow", "panicky", "fine"] {
            assert_eq!(metrics.observer_running(name).get(), 1.0, "{name} runs");
        }
        // One event at a time, each observer given its turn: the fine one keeps up, the
        // slow one takes its first event and sleeps on it while its channel fills, and the
        // panicking one dies on its first.
        let total = 2 * CHANNEL_CAPACITY;
        for _ in 0..total {
            hub.emit(Event::LaneStarted {
                pair: "A/B".to_owned(),
            });
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            seen.lock().unwrap().len(),
            total,
            "the fine observer saw every event"
        );
        assert_eq!(metrics.observer_dropped("fine").get(), 0);
        assert_eq!(
            metrics.observer_dropped("slow").get(),
            (total - 1 - CHANNEL_CAPACITY) as u64,
            "one taken, a channel's worth buffered, the rest dropped"
        );
        assert_eq!(metrics.observer_running("slow").get(), 1.0);
        assert_eq!(metrics.observer_running("panicky").get(), 0.0, "removed");
        assert_eq!(
            panicky_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no second event reaches a removed observer"
        );
        assert_eq!(
            metrics.observer_dropped("panicky").get(),
            0,
            "a removed observer's closed channel is not a drop"
        );
        assert_eq!(metrics.observer_running("fine").get(), 1.0);
    }

    /// `finish` lets each observer deliver what is queued and end, and holds the run's
    /// return for [`DELIVERY_GRACE`] at most: one that cannot keep up is left to the abort.
    /// An observer that finished did not fail, so it is still shown as running, and an
    /// event after the close is neither delivered nor counted as a drop.
    #[tokio::test(start_paused = true)]
    async fn finishing_delivers_what_is_queued_and_waits_no_longer_than_the_grace() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (hub, tasks) = Observers::spawn(
            vec![Box::new(Fine(Arc::clone(&seen))), Box::new(Slow)],
            &metrics,
        );
        for _ in 0..3 {
            hub.emit(Event::LaneStopped {
                pair: "A/B".to_owned(),
            });
        }
        let started = tokio::time::Instant::now();
        tasks.finish().await;
        assert_eq!(started.elapsed(), DELIVERY_GRACE, "the slow one, no longer");
        assert_eq!(
            seen.lock().unwrap().len(),
            3,
            "everything queued, delivered"
        );

        hub.emit(Event::LaneStarted {
            pair: "A/B".to_owned(),
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(seen.lock().unwrap().len(), 3, "closed");
        assert_eq!(metrics.observer_dropped("fine").get(), 0);
        assert_eq!(metrics.observer_running("fine").get(), 1.0);
    }

    /// A panic while `on_event` builds its future, not while it runs, is the same bug: the
    /// observer is removed and shown as not running, rather than its task unwinding with
    /// the gauge left at 1 for the life of the process.
    #[tokio::test(start_paused = true)]
    async fn an_observer_that_panics_before_its_future_exists_is_removed_too() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let (hub, _tasks) = Observers::spawn(vec![Box::new(PanicsEarly)], &metrics);
        hub.emit(Event::LaneStarted {
            pair: "A/B".to_owned(),
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(metrics.observer_running("early").get(), 0.0, "removed");
    }
}

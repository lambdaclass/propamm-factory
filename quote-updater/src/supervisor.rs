//! Per-pair task supervision. Each pair runs independently, so one pair's failure must
//! not stop the others — but a pair silently dropping out is a slow leak, so every
//! restart is logged loudly and an all-pairs-down process exits rather than pretending
//! to quote.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use eyre::Result;
use tokio::sync::watch;

/// Backoff before the first restart.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
/// Ceiling on the backoff. A deterministic failure therefore produces a visible restart
/// loop at this cadence rather than silence; log volume is the intended signal.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The process-wide "stop quoting" signal, held by every pair.
///
/// A `watch` rather than a fresh `ctrl_c()` future per listener because its value is
/// **persistent state, not an event**: a task that starts listening after the signal was
/// raised still observes it. That is the whole point here. Previously the only listener
/// was created inside each pair's quote loop, so a pair sitting in a restart backoff had
/// none registered — tokio's `Signal` receiver starts at the current watch version and
/// does not replay, while tokio's installed handler has already replaced the default
/// kill-on-SIGINT disposition. Ctrl-c during a backoff therefore reached nobody, the
/// process did not die, and the pair went on to restart and publish prices again after
/// the operator had asked it to stop.
#[derive(Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// Whether shutdown has already been requested. Cheap and non-async, for the places
    /// that must not act (restart a pair) on a signal that arrived while they were busy.
    pub fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once shutdown has been requested, immediately if it already has. Safe to
    /// drop and recreate inside a `select!` loop, unlike a signal future: re-reading a
    /// watch value cannot miss it.
    pub async fn wait(&mut self) {
        if self.0.wait_for(|stopping| *stopping).await.is_err() {
            // The sender is gone without having raised anything, so no signal can ever
            // arrive. Waiting forever is the honest answer: resolving here would read a
            // lost sender as an operator pressing ctrl-c and stop every pair quoting
            // without one. That case means tokio could not install a SIGINT handler, in
            // which case the default kill-on-SIGINT disposition is still in place and
            // ctrl-c terminates the process anyway.
            std::future::pending::<()>().await
        }
    }
}

/// Creates the shutdown signal. The sender stays with the caller, which raises it from a
/// single top-level ctrl-c listener, so no pair ever has to own one.
pub fn shutdown_channel() -> (watch::Sender<bool>, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (tx, Shutdown(rx))
}

/// How many pairs are not currently quoting, against how many exist, split by whether
/// they are coming back on their own.
///
/// The split is the whole point. A pusher with nothing running is worse than a dead one
/// you notice, but the two ways of getting there call for opposite responses: pairs
/// waiting out a restart backoff want the process to exit so a supervisor restarts it,
/// while pairs halted by their circuit breaker must NOT be auto-restarted — that would
/// clear the very state a human is supposed to look at, and hand back a pusher quoting the
/// price that tripped it.
pub struct Health {
    in_backoff: AtomicUsize,
    halted: AtomicUsize,
    /// Raised while a reload is converging the pair set. See [`Self::reloading`].
    reloading: AtomicBool,
    /// Atomic rather than a plain `usize` because a config reload adds and removes pairs
    /// while the process runs. It is also read at Prometheus scrape time through
    /// [`Self::census`] (see `metrics::register_health`), from a thread that holds nothing.
    total: AtomicUsize,
    /// What each halted lane tripped on, for the watchdog's notice to name. Beside the
    /// `halted` count rather than folded into it, so the count's callers (and their tests)
    /// are untouched; a lane noted here is forgotten when it is removed or re-armed.
    trips: std::sync::Mutex<Vec<(&'static str, crate::guard::Cause)>>,
}

impl Health {
    pub fn new(total: usize) -> Self {
        Self {
            in_backoff: AtomicUsize::new(0),
            halted: AtomicUsize::new(0),
            reloading: AtomicBool::new(false),
            total: AtomicUsize::new(total),
            trips: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Remembers what a lane that just halted tripped on, for the notice.
    pub fn note_trip(&self, source: &'static str, cause: crate::guard::Cause) {
        self.trips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((source, cause));
    }

    /// Forgets one halted lane's trip: it was removed or re-armed.
    pub fn forget_trip(&self, source: &'static str, cause: crate::guard::Cause) {
        let mut trips = self.trips.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = trips.iter().position(|t| *t == (source, cause)) {
            trips.remove(i);
        }
    }

    /// What the halted lanes tripped on, in the order they halted.
    pub fn trips(&self) -> Vec<(&'static str, crate::guard::Cause)> {
        self.trips.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Marks a reload as in flight until the returned guard is dropped.
    ///
    /// A reload converges the pair set one lane at a time — `remove_pair`, then `add_pair`,
    /// with the lane's whole withdraw in between — so for as long as it runs these counts
    /// describe a state the process is passing through rather than one it is in. Read
    /// straight, they can say something no operator would recognise: restart one lane while
    /// another happens to be waiting out a backoff and, in the window where the first is
    /// counted out and not yet back in, `in_backoff` equals `total` and nothing is halted,
    /// which is `all_down`'s definition of a total outage.
    ///
    /// The watchdog only reports it, but reporting it is still wrong: a page saying nothing
    /// is quoting, fired by every reload that happens to overlap a backoff, is a page nobody
    /// reads by the second week. So the watchdog holds off entirely while this is raised:
    /// one skipped check is nothing, and every answer it could give in that window is about
    /// a pair set that does not exist.
    ///
    /// A guard rather than a pair of calls so an error path cannot leave it raised, which
    /// would silence the watchdog for the life of the process.
    pub fn reloading(&self) -> ReloadGuard<'_> {
        self.reloading.store(true, Ordering::SeqCst);
        ReloadGuard(self)
    }

    /// Whether a reload is mid-flight, so these counts are in transit.
    pub fn is_reloading(&self) -> bool {
        self.reloading.load(Ordering::SeqCst)
    }

    /// Counts one more pair, for a lane a reload has just started.
    pub fn add_pair(&self) {
        self.total.fetch_add(1, Ordering::SeqCst);
    }

    /// Stops counting a pair a reload has removed.
    ///
    /// Takes `was_halted` rather than leaving that to a second call because the two counters
    /// have to move together: dropping a halted lane while leaving it in the halted count
    /// would leave `any_halted` true forever, parking a process whose operator has already
    /// dealt with the pair, and `census` would report a halt against a lane that no longer
    /// exists.
    ///
    /// This is also how a re-armed lane stops being counted as halted. `halt` has no direct
    /// inverse because nothing needs one: a reload brings a halted pair back by stopping it
    /// and starting a new one, so the count comes down here, on the way out, and back up
    /// through [`Self::add_pair`]. While a restart was the only way back there was nothing to
    /// un-count at all — clearing a latch was a whole new process.
    pub fn remove_pair(&self, was_halted: bool) {
        decrement(&self.total);
        if was_halted {
            decrement(&self.halted);
        }
    }

    /// Counts this pair as waiting to restart until the returned guard is dropped.
    ///
    /// A guard rather than a pair of calls because the backoff it brackets is now
    /// cancellable: a task that leaves the wait early — the shutdown path below, or an
    /// `abort()` a future caller adds — would otherwise never decrement, and the count
    /// only ever rises until `all_down` kills a process that is in fact healthy.
    #[must_use = "the pair counts as in backoff for as long as the guard lives"]
    pub fn enter_backoff(&self) -> BackoffGuard<'_> {
        self.in_backoff.fetch_add(1, Ordering::SeqCst);
        BackoffGuard(self)
    }

    /// Counts this pair as stopped for good. Not a guard: unlike a backoff there is
    /// nothing to leave, which is exactly what makes it worth counting separately.
    pub fn halt(&self) {
        self.halted.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether any pair has halted. A halted pair cannot come back on its own, so this
    /// is what tells [`Self::all_down`] apart from an outage that will heal.
    pub fn any_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst) > 0
    }

    /// `(halted, in backoff, total)`, for the line that has to explain to an operator why
    /// nothing is quoting. The two causes want different responses from them — one needs a
    /// human, the other is already retrying — so a notice that merged them would be worse
    /// than no notice.
    pub fn census(&self) -> (usize, usize, usize) {
        (
            self.halted.load(Ordering::SeqCst),
            self.in_backoff.load(Ordering::SeqCst),
            self.total.load(Ordering::SeqCst),
        )
    }

    /// True when no pair is quoting, for whichever reason. A halted pair is counted
    /// alongside one in backoff because the question here is only whether anything is
    /// still publishing — [`Self::any_halted`] decides what to do about it.
    ///
    /// The two counts cannot double-count the same pair: a pair enters backoff only after
    /// its task returned `Err`, and halts only after it returned `Ok`.
    pub fn all_down(&self) -> bool {
        let down = self.in_backoff.load(Ordering::SeqCst) + self.halted.load(Ordering::SeqCst);
        let total = self.total.load(Ordering::SeqCst);
        total > 0 && down >= total
    }
}

/// Subtracts one without ever wrapping.
///
/// `fetch_sub` on a count that is already zero wraps to `usize::MAX`, which here would not
/// be a small error: `all_down` compares against these counts, so one bad decrement would
/// read as "every pair is down forever" and park or kill a healthy pusher. Saturating
/// leaves an accounting mistake as a wrong-by-one number instead of a catastrophic one.
fn decrement(counter: &AtomicUsize) {
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
        Some(count.saturating_sub(1))
    });
}

/// Marks a reload as in flight for as long as it is held. See [`Health::reloading`].
pub struct ReloadGuard<'a>(&'a Health);

impl Drop for ReloadGuard<'_> {
    fn drop(&mut self) {
        self.0.reloading.store(false, Ordering::SeqCst);
    }
}

/// Holds one pair's slot in [`Health`]'s in-backoff count; releases it on drop, however
/// the backoff is left.
pub struct BackoffGuard<'a>(&'a Health);

impl Drop for BackoffGuard<'_> {
    fn drop(&mut self) {
        self.0.in_backoff.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Aborts a task when dropped; see its one use in [`supervise`].
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs one pair's loop, restarting it with capped exponential backoff whenever it errors
/// or panics. Returns `Ok(())` when the loop finishes cleanly (which happens under
/// `--once`) or when shutdown is requested. The task is spawned rather than awaited inline
/// so a panic is caught as a `JoinError` instead of unwinding the whole process, and it
/// goes with this future: aborting the supervisor aborts the loop it is running.
///
/// Shutdown is checked in both places a restart could otherwise happen behind the
/// operator's back: after the task exits, and during the backoff wait itself.
pub async fn supervise<F, Fut>(
    label: String,
    health: Arc<Health>,
    initial_backoff: Duration,
    mut cancel: Shutdown,
    mut spawn: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    // Capped from the start, not only from the second restart on: an initial backoff
    // above the ceiling would otherwise sleep past the documented maximum exactly once.
    let mut backoff = initial_backoff.min(MAX_BACKOFF);
    let mut restarts = 0u32;
    loop {
        let task = tokio::spawn(spawn());
        // Dropping a `JoinHandle` detaches its task, so without this an aborted supervisor
        // (`Service::drop`, when `run` returns early) would leave the pair loop quoting in
        // the caller's runtime with nothing left to stop it. Dropped at the end of each
        // attempt too, when the task has already finished and the abort does nothing.
        let _abort = AbortOnDrop(task.abort_handle());
        let outcome = match task.await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => format!("{err:#}"),
            Err(join) if join.is_panic() => format!("panicked: {join}"),
            Err(join) => format!("{join}"),
        };
        // A task that failed *because* the process is shutting down must not be revived.
        if cancel.is_set() {
            tracing::info!("[{label}] shutting down; not restarting after: {outcome}");
            return Ok(());
        }
        restarts += 1;
        tracing::warn!(
            "[{label}] task exited: {outcome}; restarting in {backoff:?} (restart {restarts})"
        );
        // Guard, not enter/leave: the select! below can leave this wait by returning.
        let _guard = health.enter_backoff();
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = cancel.wait() => {
                tracing::info!("[{label}] shutting down while waiting to restart");
                return Ok(());
            }
        }
        drop(_guard);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A shutdown signal no one ever raises — the sender is dropped, which `wait` treats
    /// as "never", not as "now". What every test that is not about shutdown passes, so a
    /// `supervise` that returns early can only be the code under test doing it.
    fn never() -> Shutdown {
        shutdown_channel().1
    }

    /// Aborting the supervisor (what `Service::drop` does when `run` returns early) must
    /// stop the pair loop it is running, not detach it: a detached `quoting::run` would go
    /// on quoting inside the caller's runtime with nothing left that could stop it.
    #[tokio::test]
    async fn aborting_the_supervisor_stops_the_loop_it_runs() {
        let health = Arc::new(Health::new(1));
        let (started, running) = tokio::sync::oneshot::channel();
        let mut started = Some(started);
        // Every clone of `held` gone is the loop gone: `recv` then answers `None`.
        let (held, mut gone) = tokio::sync::mpsc::channel::<()>(1);
        let supervisor = tokio::spawn(supervise(
            "pair".to_owned(),
            health,
            Duration::from_millis(10),
            never(),
            move || {
                let (held, started) = (held.clone(), started.take());
                async move {
                    let _held = held;
                    if let Some(started) = started {
                        let _ = started.send(());
                    }
                    std::future::pending::<Result<()>>().await
                }
            },
        ));
        running.await.expect("the loop starts");

        supervisor.abort();
        let ended = tokio::time::timeout(Duration::from_secs(5), gone.recv()).await;
        assert!(
            matches!(ended, Ok(None)),
            "the loop outlived the supervisor that was running it"
        );
    }

    #[tokio::test]
    async fn returns_ok_when_the_task_completes_cleanly() {
        let health = Arc::new(Health::new(1));
        let result = supervise(
            "pair".to_owned(),
            health.clone(),
            Duration::from_millis(1),
            never(),
            || async { Ok(()) },
        )
        .await;
        assert!(result.is_ok());
        assert!(!health.all_down());
    }

    #[tokio::test]
    async fn restarts_a_failing_task_until_it_succeeds() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let health = Arc::new(Health::new(1));
        let counter = attempts.clone();
        supervise(
            "pair".to_owned(),
            health,
            Duration::from_millis(1),
            never(),
            move || {
                let counter = counter.clone();
                async move {
                    // Fail twice, then succeed.
                    if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                        eyre::bail!("transient")
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_panicking_task_is_restarted_like_a_failing_one() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let health = Arc::new(Health::new(1));
        let counter = attempts.clone();
        supervise(
            "pair".to_owned(),
            health,
            Duration::from_millis(1),
            never(),
            move || {
                let counter = counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("boom");
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn health_reports_all_down_only_when_every_pair_is_in_backoff() {
        let health = Health::new(2);
        assert!(!health.all_down());
        let first = health.enter_backoff();
        assert!(!health.all_down(), "one of two down is not all down");
        let second = health.enter_backoff();
        assert!(health.all_down());
        drop(second);
        assert!(!health.all_down());
        drop(first);
        assert!(!health.all_down());
    }

    /// The signal that reached nobody: a pair waiting out its restart backoff must stop
    /// there, not sleep through ctrl-c and come back quoting.
    ///
    /// Everything else about this run is valid — the task fails the way any task may fail,
    /// the supervisor is the real one, and the signal is raised the way `pusher::run` does —
    /// so the only thing that can end it inside the timeout is the backoff being
    /// cancellable. The 30s backoff is far longer than the 5s bound: sleeping it out
    /// cannot masquerade as passing.
    #[tokio::test]
    async fn a_shutdown_during_backoff_stops_the_pair_instead_of_restarting_it() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let health = Arc::new(Health::new(1));
        let counter = attempts.clone();
        let (stop, cancel) = shutdown_channel();
        tokio::spawn(async move {
            // Long enough for the first attempt to fail and the backoff to be entered.
            tokio::time::sleep(Duration::from_millis(100)).await;
            stop.send_replace(true);
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            supervise(
                "pair".to_owned(),
                health.clone(),
                Duration::from_secs(30),
                cancel,
                move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        eyre::bail!("still broken")
                    }
                },
            ),
        )
        .await
        .expect("ctrl-c during a backoff must end the pair, not be slept through");
        assert!(result.is_ok(), "a requested shutdown is not a failure");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the pair must not have been restarted after shutdown was requested"
        );
        // And the backoff slot was released on the way out — see BackoffGuard. Without
        // the guard this early return would leak the count and strand the process at
        // "every pair is down" while it is in fact shutting down cleanly.
        assert!(
            !health.all_down(),
            "leaving the backoff early must release the pair's in-backoff slot"
        );
    }

    /// Shutdown raised while the task itself was still running: the supervisor sees the
    /// task's error first, and must not treat it as a reason to restart.
    #[tokio::test]
    async fn a_shutdown_raised_before_the_task_exits_is_not_answered_with_a_restart() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let (stop, cancel) = shutdown_channel();
        stop.send_replace(true);

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            supervise(
                "pair".to_owned(),
                Arc::new(Health::new(1)),
                Duration::from_secs(30),
                cancel,
                move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        eyre::bail!("still broken")
                    }
                },
            ),
        )
        .await
        .expect("an already-raised shutdown must be observed without waiting");
        assert!(result.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// An initial backoff above the ceiling must not sleep past it even once.
    ///
    /// Runs on tokio's paused clock, so the sleep completes instantly while its *duration*
    /// — the thing the cap is about — stays observable. The task fails once and then
    /// succeeds, so exactly one backoff is waited out and the elapsed virtual time is that
    /// backoff and nothing else.
    #[tokio::test(start_paused = true)]
    async fn the_first_backoff_is_capped_like_every_later_one() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let started = tokio::time::Instant::now();
        supervise(
            "pair".to_owned(),
            Arc::new(Health::new(1)),
            MAX_BACKOFF * 10,
            never(),
            move || {
                let counter = counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        eyre::bail!("transient")
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "one restart, one backoff"
        );
        // Equality, not just `<=`: a cap that clamped to zero would satisfy a bound but
        // would have removed the backoff rather than capped it.
        assert_eq!(
            started.elapsed(),
            MAX_BACKOFF,
            "an initial backoff of {:?} must be capped to {MAX_BACKOFF:?}",
            MAX_BACKOFF * 10
        );
    }

    /// A halted pair is down and stays down: unlike a backoff there is no guard to drop,
    /// because nothing in this process brings it back.
    #[tokio::test]
    async fn a_halted_pair_counts_as_down_permanently() {
        let health = Health::new(2);
        assert!(!health.any_halted());
        health.halt();
        assert!(health.any_halted());
        assert!(!health.all_down(), "one of two halted is not all down");
        health.halt();
        assert!(health.all_down());
    }

    /// The mixed case the watchdog has to get right: one pair waiting out a restart and
    /// one halted means nothing is quoting, even though neither count alone reaches the
    /// total. The two cannot double-count one pair — a task enters backoff only after
    /// returning Err, and halts only after returning Ok.
    #[tokio::test]
    async fn a_backoff_and_a_halt_together_are_all_down() {
        let health = Health::new(2);
        health.halt();
        let waiting = health.enter_backoff();
        assert!(health.all_down());
        // The backoff ends and that pair quotes again; the halted one never will, so the
        // pusher is no longer fully down but is still permanently short a pair.
        drop(waiting);
        assert!(!health.all_down());
        assert!(health.any_halted());
    }

    /// What tells the watchdog's two responses apart. Pairs that merely failed are an
    /// outage: exiting for a supervisor to restart is right. A halt is a judgement that
    /// only a human can lift, so the same "nothing is quoting" state must be
    /// distinguishable — otherwise an auto-restart clears the breaker.
    #[tokio::test]
    async fn all_down_without_a_halt_is_an_outage_not_a_judgement() {
        let health = Health::new(1);
        let _waiting = health.enter_backoff();
        assert!(health.all_down());
        assert!(
            !health.any_halted(),
            "a restart backoff must not read as a breaker halt"
        );
    }

    /// The counts behind the operator notice. A halted pair and a pair waiting to restart
    /// both mean "not quoting", but they ask different things of whoever reads the line —
    /// one needs a human, the other is already retrying — so the notice reports them
    /// separately and the census has to keep them apart.
    #[tokio::test]
    async fn the_census_separates_halted_pairs_from_waiting_ones() {
        let health = Health::new(3);
        assert_eq!(health.census(), (0, 0, 3));
        health.halt();
        let _waiting = health.enter_backoff();
        assert_eq!(health.census(), (1, 1, 3));
    }

    /// A task that finishes cleanly — `--once` completing, or a halt, both of which reach
    /// `supervise` as `Ok` — stops without ever entering backoff, so it never counts
    /// towards the watchdog's all-down check on its way out.
    ///
    /// What distinguishes a halt from a clean finish is not visible here by design: this
    /// layer only knows Ok from Err. `service::record_outcome` is where that decision lives,
    /// and where it is tested.
    #[tokio::test]
    async fn a_task_that_returns_ok_stops_without_entering_backoff() {
        let health = Arc::new(Health::new(1));
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();

        supervise(
            "pair".to_owned(),
            health.clone(),
            INITIAL_BACKOFF,
            never(),
            move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .expect("a clean finish is not a supervision failure");

        assert_eq!(runs.load(Ordering::SeqCst), 1, "Ok must not be restarted");
        assert_eq!(
            health.census(),
            (0, 0, 1),
            "nothing halted, nothing waiting"
        );
        assert!(!health.all_down());
    }

    /// The whole life of a reloaded lane, in the order a reload drives it: started, halted
    /// on its breaker, re-armed by a reload, then removed by a later one. Every count has
    /// to come back to where it began, because these are the numbers `all_down` and the
    /// watchdog decide on.
    #[test]
    fn a_pair_added_halted_rearmed_and_removed_leaves_the_counts_where_it_found_them() {
        let health = Health::new(0);

        health.add_pair();
        assert_eq!(health.census(), (0, 0, 1));

        health.halt();
        assert_eq!(health.census(), (1, 0, 1));
        assert!(health.any_halted());
        assert!(health.all_down());

        // What a reload's re-arm actually is: the halted pair is stopped, and a fresh one
        // is started on the same lane.
        health.remove_pair(true);
        health.add_pair();
        assert_eq!(health.census(), (0, 0, 1));
        assert!(!health.any_halted(), "a re-armed pair is not halted");
        assert!(!health.all_down(), "and it is quoting again");

        health.remove_pair(false);
        assert_eq!(health.census(), (0, 0, 0));
    }

    /// Removing a lane that was halted has to clear both counts at once. Leaving it in the
    /// halted count would keep `any_halted` true for a pair that no longer exists, and the
    /// process parks on that.
    #[test]
    fn removing_a_halted_pair_stops_counting_it_as_halted() {
        let health = Health::new(2);
        health.halt();
        assert_eq!(health.census(), (1, 0, 2));

        health.remove_pair(true);
        assert_eq!(health.census(), (0, 0, 1));
        assert!(
            !health.any_halted(),
            "the halt left with the pair it belonged to"
        );
    }

    /// `all_down` multiplies these counts into a decision to park or exit, so a stray
    /// decrement must not wrap into `usize::MAX` and read as "everything is down".
    #[test]
    fn decrementing_past_zero_saturates_rather_than_wrapping() {
        let health = Health::new(0);

        health.remove_pair(true);
        health.remove_pair(true);

        assert_eq!(health.census(), (0, 0, 0));
        assert!(!health.all_down(), "an empty pusher is not a down one");
    }
}

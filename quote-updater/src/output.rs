//! Operator output: the lines an operator reads, as `tracing` events.
//!
//! The library reports through `tracing` and never prints, so a binary can route, filter,
//! silence or restructure what it says. [`layer`] renders this crate's events as the text
//! operators have always read: the message alone, INFO and below on stdout, WARN and ERROR
//! on stderr, written before the macro returns, one write per event, so a line-buffered
//! stdout and an unbuffered stderr interleave exactly as `println!`/`eprintln!` did.
//! Events from other crates are not written: ethrex, axum and hyper emit plenty, nobody saw
//! them while this crate had no subscriber, and turning one on must not change what an
//! operator reads.
//!
//! [`crate::UpdaterBuilder::run_from_env`] installs it. A binary with its own subscriber
//! adds [`layer`] to it, or leaves it out and formats this crate's events its own way.
//! A binary's own events (its observer's, say) are rendered only when it names its crate:
//! [`layer_for`], or [`crate::UpdaterBuilder::log_target`] for `run_from_env`.
//!
//! One hazard of a per-layer filter: tracing-subscriber decides `enabled` per callsite in a
//! thread-local before the event is built, so an event whose format arguments log an event
//! of their own (`info!("{}", f())` where `f` logs) is judged on the inner event's verdict
//! and can be rendered here although its target is another crate's. Log first, then
//! format.

use std::{fmt::Write as _, io::Write as _};

use tracing::{
    Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    filter::filter_fn,
    layer::{Context, Layer},
    registry::LookupSpan,
};

/// This crate's events all carry a target under its name (the module path).
const TARGET: &str = "quote_updater";

/// Renders the events it is given as operator lines; [`filtered`] decides which.
struct OperatorLayer {
    sink: Sink,
}

enum Sink {
    Terminal,
    #[cfg(test)]
    Capture(Capture),
}

/// The layer that writes this crate's events to stdout and stderr as plain lines. It
/// filters for itself (a per-layer filter), so it needs a subscriber built on
/// `tracing_subscriber::registry()`, as `fmt()` and `registry().with(..)` both are.
pub fn layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    layer_for(&[])
}

/// [`layer`], also rendering the events of `targets`: a binary's own crate name (a
/// `tracing` target is the module path, so `env!("CARGO_CRATE_NAME")`) and the modules
/// under it, judged by the prefix rule this crate's own events are judged by. A binary
/// whose observer logs, or which logs anything of its own, names itself here or on
/// [`crate::UpdaterBuilder::log_target`]; otherwise those lines are dropped, because a
/// layer that rendered every crate's events would print ethrex's and hyper's too.
pub fn layer_for<S>(targets: &[&'static str]) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    filtered_for(
        OperatorLayer {
            sink: Sink::Terminal,
        },
        targets,
    )
}

/// The operator layer as every subscriber gets it: interested in this crate's callsites,
/// in `targets`', and in no others. A per-layer filter, not `Layer::enabled`, which would
/// filter the whole subscriber and so hide ethrex's events from a JSON layer a binary
/// composed beside this one; and not a check in `on_event` alone, which leaves every
/// other crate's callsite enabled: each h2 and hyper span built and each `trace!`
/// dispatched on every RPC poll, only to be dropped. A metadata-only filter is cached per
/// callsite, so those cost what they did before this crate had a subscriber.
fn filtered_for<S>(inner: OperatorLayer, targets: &[&'static str]) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let targets: Vec<&'static str> = targets.to_vec();
    inner.with_filter(filter_fn(move |meta: &Metadata<'_>| {
        ours(meta.target()) || targets.iter().any(|root| under(meta.target(), root))
    }))
}

/// [`filtered_for`] with this crate's events only: what the tests build their sinks on.
#[cfg(test)]
fn filtered<S>(inner: OperatorLayer) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    filtered_for(inner, &[])
}

/// Installs [`layer_for`] as the process's global subscriber, unless one is already set.
/// Returns whether it did. A library never calls this: `run_from_env` does, for a binary,
/// with the targets it was given.
pub fn install_for(targets: &[&'static str]) -> bool {
    use tracing_subscriber::layer::SubscriberExt;
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer_for(targets)))
        .is_ok()
}

/// [`install_for`] with this crate's events only.
pub fn install() -> bool {
    install_for(&[])
}

/// Whether `target` is this crate or one of its modules, and not merely a name that starts
/// with the same letters.
fn ours(target: &str) -> bool {
    under(target, TARGET)
}

/// Whether `target` is `root` or a module under it (`root::x`), and not merely a name that
/// starts with the same letters (`root_x`).
fn under(target: &str, root: &str) -> bool {
    target == root
        || target
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with("::"))
}

impl<S: Subscriber> Layer<S> for OperatorLayer {
    // Only this crate's events arrive here: see `filtered`.
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut message = Message(String::new());
        event.record(&mut message);
        // Levels order by verbosity (TRACE is greatest), so this is WARN and ERROR.
        let stream = if *meta.level() <= Level::WARN {
            Stream::Stderr
        } else {
            Stream::Stdout
        };
        self.sink.write(stream, &message.0);
    }
}

/// Collects an event's `message` field and nothing else.
struct Message(String);

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    // `info!("...{}", x)` records the formatted message as `fmt::Arguments`, whose Debug
    // is its plain text: no quotes, no escaping.
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}

/// Which of the two streams a line goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

impl Sink {
    fn write(&self, stream: Stream, line: &str) {
        match self {
            // Locked per line, as println! does; a failed write (a closed pipe) is dropped
            // rather than panicking the task that logged, which println! would.
            Sink::Terminal => match stream {
                Stream::Stdout => {
                    let _ = writeln!(std::io::stdout().lock(), "{line}");
                }
                Stream::Stderr => {
                    let _ = writeln!(std::io::stderr().lock(), "{line}");
                }
            },
            #[cfg(test)]
            Sink::Capture(capture) => capture.0.lock().unwrap().push((stream, line.to_owned())),
        }
    }
}

/// Test sink: every line with its stream, in order.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Capture(std::sync::Arc<std::sync::Mutex<Vec<(Stream, String)>>>);

#[cfg(test)]
impl Capture {
    pub(crate) fn lines(&self) -> Vec<(Stream, String)> {
        self.0.lock().unwrap().clone()
    }
}

/// The operator layer, capturing, as this thread's default subscriber until the guard
/// drops: for a test elsewhere in the crate that asks which stream a line goes to. On a
/// current-thread runtime that covers every task the test spawns.
#[cfg(test)]
pub(crate) fn capture() -> (tracing::subscriber::DefaultGuard, Capture) {
    use tracing_subscriber::layer::SubscriberExt;
    let sink = Capture::default();
    let subscriber =
        tracing_subscriber::registry().with(filtered(OperatorLayer::capturing(sink.clone())));
    (tracing::subscriber::set_default(subscriber), sink)
}

/// A subscriber rendering this crate's events as the operator lines into a sink a test
/// reads back, for a test that asserts what was said: install it with
/// `tracing::subscriber::set_default` for the test's thread.
#[cfg(test)]
pub(crate) fn capturing() -> (Capture, impl tracing::Subscriber + Send + Sync) {
    use tracing_subscriber::layer::SubscriberExt;
    let sink = Capture::default();
    let subscriber =
        tracing_subscriber::registry().with(filtered(OperatorLayer::capturing(sink.clone())));
    (sink, subscriber)
}

#[cfg(test)]
impl OperatorLayer {
    fn capturing(capture: Capture) -> Self {
        OperatorLayer {
            sink: Sink::Capture(capture),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn captured(f: impl FnOnce()) -> Vec<(Stream, String)> {
        let sink = Capture::default();
        let subscriber =
            tracing_subscriber::registry().with(filtered(OperatorLayer::capturing(sink.clone())));
        tracing::subscriber::with_default(subscriber, f);
        sink.lines()
    }

    #[test]
    fn info_goes_to_stdout_and_warnings_and_errors_to_stderr() {
        let lines = captured(|| {
            tracing::info!("[WETH/USDC] quoting block {}", 7);
            tracing::warn!("[WETH/USDC] feed stale");
            tracing::error!("pair task failed");
        });
        assert_eq!(
            lines,
            [
                (Stream::Stdout, "[WETH/USDC] quoting block 7".to_owned()),
                (Stream::Stderr, "[WETH/USDC] feed stale".to_owned()),
                (Stream::Stderr, "pair task failed".to_owned()),
            ]
        );
    }

    /// The message is written as-is: a multi-line report (the startup table) keeps its
    /// lines, and fields a caller adds for structured output do not leak into the text.
    #[test]
    fn the_message_is_written_as_is_and_fields_are_not() {
        let lines = captured(|| tracing::info!(pair = "X", "a\nb"));
        assert_eq!(lines, [(Stream::Stdout, "a\nb".to_owned())]);
    }

    /// ethrex, axum and hyper already emit tracing events; nobody saw them before this
    /// crate had a subscriber, and installing one must not start showing them.
    #[test]
    fn events_from_other_crates_are_not_written() {
        let lines = captured(|| {
            tracing::info!(target: "ethrex_rpc::clients", "a request");
            tracing::warn!(target: "hyper_util::client", "a retry");
            tracing::info!(target: "quote_updater_lookalike", "not ours either");
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    /// A binary that names its own crate gets its lines rendered beside this crate's, by
    /// the same prefix rule: `probe::observer` is under `probe`, `probe_x` is not.
    #[test]
    fn a_named_target_is_rendered_and_a_lookalike_is_not() {
        use tracing_subscriber::layer::SubscriberExt;
        let sink = Capture::default();
        let subscriber = tracing_subscriber::registry().with(filtered_for(
            OperatorLayer::capturing(sink.clone()),
            &["probe"],
        ));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "probe", "a");
            tracing::info!(target: "probe::observer", "b");
            tracing::info!(target: "probe_x", "c");
            tracing::info!(target: "quote_updater", "d");
        });
        let lines: Vec<String> = sink.lines().into_iter().map(|(_, l)| l).collect();
        assert_eq!(lines, ["a", "b", "d"]);
    }

    /// What `subscriber` answers when a callsite for `target` registers, asked directly:
    /// `enabled!` would read the process-wide interest cache instead, which merges every
    /// live dispatcher, so a parallel test's catch-all subscriber would answer for this one.
    macro_rules! interest_in {
        ($subscriber:expr, $target:literal) => {{
            struct Site;
            static SITE: Site = Site;
            static META: Metadata<'static> = Metadata::new(
                "probe",
                $target,
                Level::TRACE,
                None,
                None,
                None,
                tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&SITE)),
                tracing::metadata::Kind::EVENT,
            );
            impl tracing::callsite::Callsite for Site {
                fn set_interest(&self, _: tracing::subscriber::Interest) {}
                fn metadata(&self) -> &Metadata<'_> {
                    &META
                }
            }
            Subscriber::register_callsite(&$subscriber, &META)
        }};
    }

    /// Filtered per callsite, not only skipped when written: another crate's callsite
    /// registers as never interesting, so (with this layer alone, as `install` sets it)
    /// h2's and hyper's spans are never built and their `trace!`s cost one cached check,
    /// as they did before this crate had a subscriber.
    #[test]
    fn other_crates_callsites_are_disabled_not_just_unwritten() {
        let subscriber = tracing_subscriber::registry()
            .with(filtered(OperatorLayer::capturing(Capture::default())));
        assert!(interest_in!(subscriber, "h2::proto").is_never());
        assert!(interest_in!(subscriber, "hyper_util::client").is_never());
        assert!(interest_in!(subscriber, "quote_updater_lookalike").is_never());
        assert!(interest_in!(subscriber, "quote_updater::quoting").is_always());
    }

    /// Per layer, not for the whole subscriber: a layer a binary composes beside this one
    /// still sees ethrex's and hyper's events.
    #[test]
    fn a_layer_beside_this_one_still_sees_other_crates_events() {
        struct Counting(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl<S: Subscriber> Layer<S> for Counting {
            fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let (sink, seen) = (Capture::default(), std::sync::Arc::default());
        let subscriber = tracing_subscriber::registry()
            .with(filtered(OperatorLayer::capturing(sink.clone())))
            .with(Counting(std::sync::Arc::clone(&seen)));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "hyper_util::client", "a retry");
            tracing::info!("ours");
        });
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(sink.lines(), [(Stream::Stdout, "ours".to_owned())]);
    }

    /// One write per event, before the macro returns: a buffered or background writer
    /// would reorder stdout against stderr, which the trip line relies on (quoting.rs).
    #[test]
    fn each_event_is_written_before_the_macro_returns() {
        let sink = Capture::default();
        let subscriber =
            tracing_subscriber::registry().with(filtered(OperatorLayer::capturing(sink.clone())));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("first");
            assert_eq!(sink.lines().len(), 1);
            tracing::info!("second");
            assert_eq!(sink.lines().len(), 2);
        });
    }
}

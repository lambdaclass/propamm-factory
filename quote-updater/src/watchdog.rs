//! What the run loop says, once a minute, about pairs that are not quoting: a halted lane
//! needs a human and a failing one is already retrying, and the notice tells those apart
//! rather than sending an operator to look at a feed they have no reason to doubt. It only
//! ever reports; nothing here ends the process.

use std::time::Duration;

use crate::guard::Cause;
use crate::supervisor;

/// How often the watchdog asks whether anything is still quoting.
pub(crate) const DOWN_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// How often a pusher parked on a circuit-breaker halt repeats why it is not quoting.
const HALTED_NOTICE_EVERY: Duration = Duration::from_secs(60);

/// What the watchdog should do this check. It only ever says something: Prometheus already
/// pages on a total outage (`PusherNothingQuoting`), so ending the process added nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Watchdog {
    Quiet,
    /// Print `halt_notice`: something is not quoting and someone should look.
    Notice,
}

/// The watchdog's decision, as a pure function of the pairs' health and the throttle.
///
/// A pusher with a pair that is not quoting is worse than a dead one you notice, and the
/// two ways of getting there call for opposite responses. Every pair merely *failing* is
/// an outage: exit non-zero so a process supervisor restarts the whole pusher. Any pair
/// **halted** on its breaker is a judgement only a human can lift: exiting — with *any*
/// status — would be read by systemd, k8s or a shell loop as "restart me", which clears
/// the breaker and puts the pusher straight back to quoting the price that tripped it, so
/// the process stays up and says why instead. That holds even when most of the pairs down
/// are merely failing: they lose nothing by it, since `supervise` retries them forever on
/// its own. And it holds while other pairs quote on: a halted lane is reminded about for
/// as long as the process is up, because one line at the trip and then silence is how a
/// halt goes unnoticed for a day.
///
/// The reminder is throttled to `HALTED_NOTICE_EVERY` — a halted pusher may sit for days,
/// and at the check cadence the notice alone would be the bulk of the log — and the
/// throttle is deliberately never reset by things briefly improving in between: the pairs
/// that reach this state are the ones that flap, and a reset on every check that caught
/// one up would bring the notice back at the check cadence.
pub(crate) fn watchdog_verdict(
    health: &supervisor::Health,
    last_notice: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> Watchdog {
    // A reload is mid-flight, so these counts are in transit between two pair sets and
    // every verdict below would be about neither. See `Health::reloading` for what taking
    // one of them seriously costs.
    if health.is_reloading() {
        return Watchdog::Quiet;
    }
    if health.any_halted() {
        let throttled = last_notice.is_some_and(|at| now.duration_since(at) < HALTED_NOTICE_EVERY);
        return if throttled {
            Watchdog::Quiet
        } else {
            Watchdog::Notice
        };
    }
    if !health.all_down() {
        return Watchdog::Quiet;
    }
    // Throttled like a halt: this can sit for as long as it takes someone to notice.
    let throttled = last_notice.is_some_and(|at| now.duration_since(at) < HALTED_NOTICE_EVERY);
    if throttled {
        Watchdog::Quiet
    } else {
        Watchdog::Notice
    }
}

/// The line `Watchdog::Notice` prints, from `Health::census`'s `(halted, waiting, total)`
/// and `Health::trips`, what each halted lane tripped on. Both counts are reported because
/// they ask different things of the operator: a halted pair needs a human, a waiting one is
/// already retrying. Ctrl-c still ends the process.
///
/// While every halted lane tripped on the deviation guard the notice reads as it always
/// has ("halted on their circuit breaker", "check that feed"); once a registered guard, a
/// panic or a kill switch can halt a lane, the notice names the sources instead, so a
/// panic in a pricer never pages as a feed problem.
pub(crate) fn halt_notice(
    (halted, waiting, total): (usize, usize, usize),
    backoffice: Option<&str>,
    sources: &[(&'static str, Cause)],
    reload_hint: &str,
) -> String {
    let named = describe_sources(sources);
    // Not a breaker story, and telling it as one sends the operator to look at feeds they
    // have no reason to doubt.
    if halted == 0 && waiting >= total && total > 0 {
        return match backoffice {
            Some(addr) => format!(
                "nothing is quoting: all {total} pair(s) are failing to start and none has \
                 halted, so this is the config rather than a feed. NOT exiting, so the \
                 backoffice stays reachable: fix it at http://{addr}/"
            ),
            None => format!(
                "nothing is quoting: all {total} pair(s) are failing to start and none has \
                 halted"
            ),
        };
    }
    if halted + waiting >= total {
        return match &named {
            None => format!(
                "nothing is quoting: {halted}/{total} pair(s) halted on their circuit \
                 breaker, {waiting} waiting to restart. NOT exiting, because a restart would \
                 clear the breakers; check those feeds and reload once you trust them \
                 ({reload_hint})"
            ),
            Some(named) => format!(
                "nothing is quoting: {halted}/{total} pair(s) halted: {named}, {waiting} \
                 waiting to restart. NOT exiting, because a restart would clear the latches; \
                 check those lanes and reload once you trust them \
                 ({reload_hint})"
            ),
        };
    }
    let quoting = total - halted - waiting;
    let waiting = if waiting > 0 {
        format!(", {waiting} waiting to restart")
    } else {
        String::new()
    };
    match &named {
        None => format!(
            "{halted}/{total} pair(s) halted on their circuit breaker, {quoting} still \
             quoting{waiting}. Check that feed and reload once you trust it \
             ({reload_hint})"
        ),
        Some(named) => format!(
            "{halted}/{total} pair(s) halted: {named}; {quoting} still quoting{waiting}. \
             Check those lanes and reload once you trust them \
             ({reload_hint})"
        ),
    }
}

/// `1 on \`deviation\`, 1 on a panic in \`funding\`, 1 on \`kill\` (external)`, or `None`
/// while there is nothing to name: no sources known, or every one of them the deviation
/// guard, which is today's wording.
fn describe_sources(sources: &[(&'static str, Cause)]) -> Option<String> {
    if sources
        .iter()
        .all(|(source, cause)| *source == "deviation" && *cause == Cause::Guard)
    {
        return None;
    }
    // Counted in first-seen order, so the notice is stable across polls.
    let mut counted: Vec<((&'static str, Cause), usize)> = Vec::new();
    for key in sources {
        match counted.iter_mut().find(|(k, _)| k == key) {
            Some((_, n)) => *n += 1,
            None => counted.push((*key, 1)),
        }
    }
    let parts: Vec<String> = counted
        .into_iter()
        .map(|((source, cause), n)| match cause {
            Cause::Guard => format!("{n} on `{source}`"),
            Cause::Panic => format!("{n} on a panic in `{source}`"),
            Cause::External => format!("{n} on `{source}` (external)"),
        })
        .collect();
    Some(parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::Cause;

    /// A binary run as a unit, so the expected lines read as they always have.
    fn notice(
        counts: (usize, usize, usize),
        backoffice: Option<&str>,
        sources: &[(&'static str, Cause)],
    ) -> String {
        halt_notice(
            counts,
            backoffice,
            sources,
            "systemctl --user reload example-quoter",
        )
    }

    /// While every tripped lane tripped on `deviation`, the notice reads as it always has;
    /// a panic or a registered guard is named, so it never pages as a feed problem.
    #[test]
    fn the_notice_names_sources_other_than_deviation() {
        let old = notice((1, 0, 2), None, &[("deviation", Cause::Guard)]);
        assert_eq!(
            old,
            "1/2 pair(s) halted on their circuit breaker, 1 still quoting. Check that feed \
             and reload once you trust it (systemctl --user reload example-quoter)"
        );
        // A binary that names no unit is told the signal, in the same place.
        let signal = halt_notice((1, 0, 2), None, &[("deviation", Cause::Guard)], "SIGHUP");
        assert!(signal.ends_with("(SIGHUP)"), "{signal}");
        let new = notice(
            (2, 0, 3),
            None,
            &[("deviation", Cause::Guard), ("funding", Cause::Panic)],
        );
        assert_eq!(
            new,
            "2/3 pair(s) halted: 1 on `deviation`, 1 on a panic in `funding`; 1 still \
             quoting. Check those lanes and reload once you trust them (systemctl --user \
             reload example-quoter)"
        );
        let external = notice((1, 0, 1), None, &[("kill", Cause::External)]);
        assert_eq!(
            external,
            "nothing is quoting: 1/1 pair(s) halted: 1 on `kill` (external), 0 waiting to \
             restart. NOT exiting, because a restart would clear the latches; check those \
             lanes and reload once you trust them (systemctl --user reload example-quoter)"
        );
    }

    /// A reload converges the pair set one lane at a time, so while it runs these counts
    /// describe neither the old set nor the new one, and the watchdog must not page on
    /// them. It no longer ends the process over them, but a spurious "nothing is quoting"
    /// on every reload is still noise nobody would keep reading.
    #[test]
    fn the_watchdog_holds_off_while_a_reload_is_converging() {
        let now = tokio::time::Instant::now();
        let health = supervisor::Health::new(1);
        // The window a restart passes through: the lane is counted out and not yet back in,
        // while another sits in a backoff. Read straight, that is a total outage.
        let _backoff = health.enter_backoff();
        assert_eq!(
            watchdog_verdict(&health, None, now),
            Watchdog::Notice,
            "the counts really do say every pair is down"
        );

        let converging = health.reloading();
        assert_eq!(
            watchdog_verdict(&health, None, now),
            Watchdog::Quiet,
            "but a reload is mid-flight, so they are about a pair set that does not exist"
        );

        drop(converging);
        assert_eq!(
            watchdog_verdict(&health, None, now),
            Watchdog::Notice,
            "and the guard must not silence the watchdog past the reload"
        );
    }

    /// Neither answer is "die". A total outage used to end the process so a supervisor
    /// would restart it; the cause is usually the config, so a restart fails the same way
    /// and takes the backoffice down with it. `PusherNothingQuoting` already pages on it.
    #[test]
    fn the_watchdog_only_ever_reports_and_never_ends_the_process() {
        let now = tokio::time::Instant::now();

        let outage = supervisor::Health::new(3);
        let _waiting = [
            outage.enter_backoff(),
            outage.enter_backoff(),
            outage.enter_backoff(),
        ];
        assert_eq!(
            watchdog_verdict(&outage, None, now),
            Watchdog::Notice,
            "a total outage is reported, not acted on"
        );

        let mixed = supervisor::Health::new(3);
        mixed.halt();
        let _waiting = [mixed.enter_backoff(), mixed.enter_backoff()];
        assert_eq!(watchdog_verdict(&mixed, None, now), Watchdog::Notice);

        let all_halted = supervisor::Health::new(2);
        all_halted.halt();
        all_halted.halt();
        assert_eq!(watchdog_verdict(&all_halted, None, now), Watchdog::Notice);

        let partial_outage = supervisor::Health::new(3);
        let _waiting = [partial_outage.enter_backoff()];
        assert_eq!(
            watchdog_verdict(&partial_outage, None, now),
            Watchdog::Quiet
        );

        assert_eq!(
            watchdog_verdict(&supervisor::Health::new(0), None, now),
            Watchdog::Quiet
        );
    }

    /// A halted pair is reminded about once a minute for as long as the process is up,
    /// whether or not the other pairs are quoting: one line at the trip and then silence
    /// is how a halted lane goes unnoticed for a day. The throttle is not reset by a pair
    /// briefly coming up in between — the pairs that reach this state are the ones that
    /// flap, and a reset on every check that caught one up would bring the notice back at
    /// the check cadence.
    #[test]
    fn a_halted_pair_is_reminded_about_once_a_minute_even_while_others_quote() {
        let now = tokio::time::Instant::now();
        let health = supervisor::Health::new(3);
        health.halt();
        assert_eq!(watchdog_verdict(&health, None, now), Watchdog::Notice);
        assert_eq!(
            watchdog_verdict(&health, Some(now - Duration::from_secs(10)), now),
            Watchdog::Quiet
        );
        assert_eq!(
            watchdog_verdict(&health, Some(now - HALTED_NOTICE_EVERY), now),
            Watchdog::Notice
        );
    }

    /// The notice's two shapes: nothing quoting is a different message from some quoting,
    /// and both carry the counts because they ask different things of the operator.
    /// A total outage with nothing halted is not a breaker story. Told as one it sends the
    /// operator to inspect feeds they have no reason to doubt, when what is actually wrong
    /// is the config: on a page-managed server, most often a pair added before any builder.
    #[test]
    fn a_config_outage_is_not_reported_as_a_halt() {
        let with_page = notice((0, 1, 1), Some("100.64.1.2:8088"), &[]);
        assert!(
            with_page.contains("this is the config rather than a feed"),
            "{with_page}"
        );
        assert!(with_page.contains("http://100.64.1.2:8088/"), "{with_page}");
        assert!(!with_page.contains("breaker"), "{with_page}");

        let without = notice((0, 2, 2), None, &[]);
        assert!(!without.contains("breaker"), "{without}");
        assert!(!without.contains("http://"), "{without}");

        // A halt in the mix is still a halt, and still says so.
        let halted = notice(
            (1, 1, 2),
            Some("100.64.1.2:8088"),
            &[("deviation", Cause::Guard)],
        );
        assert!(halted.contains("breaker"), "{halted}");
    }

    #[test]
    fn the_halt_notice_says_what_is_still_quoting() {
        let all_down = notice((1, 2, 3), None, &[("deviation", Cause::Guard)]);
        for expected in ["nothing is quoting", "1/3", "2 waiting", "NOT exiting"] {
            assert!(
                all_down.contains(expected),
                "missing {expected:?}: {all_down}"
            );
        }
        let partial = notice((1, 0, 3), None, &[("deviation", Cause::Guard)]);
        // Names the remedy, and specifically the reload rather than the restart it replaced:
        // restarting to recover one lane clears every other lane's breaker on the way.
        for expected in ["1/3", "2 still quoting", "reload"] {
            assert!(
                partial.contains(expected),
                "missing {expected:?}: {partial}"
            );
        }
        assert!(!partial.contains("nothing is quoting"), "{partial}");
    }
}

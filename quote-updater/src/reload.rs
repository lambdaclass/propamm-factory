//! What a config reload has to do, as a function of what is running and what the file now
//! says.
//!
//! `pairs.toml` is the desired state and this is the convergence: the file is re-read, each
//! lane is compared against the pair currently serving it, and only what actually differs
//! is touched. A lane that is quoting happily and whose stanza did not change is left
//! completely alone — no withdraw, no reconnect, no gap — which is the entire difference
//! between this and the restart it replaces.
//!
//! Pure and IO-free on purpose, like `breaker`: no tokio, no chain, no feeds. The caller
//! acts on the actions, which is what makes every rule here testable on its own.

use std::collections::{BTreeMap, BTreeSet};

use ethrex_common::U256;

use crate::config::PairSpec;

/// What to do with one lane. Keyed by lane rather than by label throughout: a label is
/// preflight's on-chain `symbol()` read, which exists for humans and can be missing (it
/// falls back to `lane 0x…`), while the lane is the pair's identity — it is what the
/// registry publishes to and what `PropAMM._pairKey` agrees on.
// PartialEq only: a custom stanza is a TOML table, and TOML floats are not Eq.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Not running: start it.
    Add(PairSpec),
    /// Running, but gone from the file: withdraw its quote and stop it.
    Remove(U256),
    /// Running, but not as the file now describes it — or not running at all because it
    /// halted. Stop it and start it from this spec.
    Restart(PairSpec),
    /// Halted on its circuit breaker, and the file would have it started or rebuilt: left
    /// halted, since only its re-arm brings it back (audit F-17). Emitted so the reload
    /// says so, rather than leaving an operator who resumed or edited it to wonder.
    StayTripped(U256),
}

impl Action {
    /// The lane this acts on, for logging and for the caller's registry lookups.
    pub fn lane(&self) -> U256 {
        match self {
            Action::Add(spec) | Action::Restart(spec) => spec.lane,
            Action::Remove(lane) | Action::StayTripped(lane) => *lane,
        }
    }
}

/// Diffs the desired pairs against the running ones.
///
/// `tripped` is the set of lanes whose pair stopped on its circuit breaker: running, or
/// shut down since (halted, or removed from the file) with the trip remembered. Such a lane
/// stays stopped, whatever the reload is for (audit F-17): an edit of another pair, an edit
/// of its own stanza, a new builder list, a resume of the pair after a halt, the pair added
/// back after a removal. Starting it would re-arm a breaker nobody looked at, and the new
/// lane would trust the very price that tripped it. Only a lane in `rearm` is started,
/// which is someone saying of that one pair "I have looked at this feed and I trust it
/// again" (`POST /api/pairs/{key_env}/rearm`, `UpdaterHandle::rearm`); it is built from
/// its stanza as the file has it then. Where the file would otherwise have started or
/// rebuilt one, [`Action::StayTripped`] says it was left. A running tripped lane the file
/// drops or halts is still removed.
///
/// `builders_changed` restarts every lane that is not tripped, whatever its stanza says. Each builder
/// connection is opened inside the pair's own quoting loop, so a lane cannot pick up a new
/// builder list without being rebuilt: the list is not per-lane state that can be swapped
/// underneath it. Marking them all as diverged is not a special case either, for the same
/// reason a halted lane is not: what is running no longer matches the file.
///
/// The blast radius is real and unavoidable. A process restart would stop every lane too,
/// and lose the process with it, so doing it here is the cheaper of the two. The caller
/// refuses the reload outright unless at least one of the new builders actually connects,
/// which is what stops a typo from taking every lane down at once.
///
/// `desired` is assumed to hold each lane at most once, which `config::parse_config`
/// guarantees by refusing a file with a duplicate lane.
pub fn plan(
    running: &BTreeMap<U256, PairSpec>,
    desired: &[PairSpec],
    tripped: &BTreeSet<U256>,
    rearm: &BTreeSet<U256>,
    builders_changed: bool,
) -> Vec<Action> {
    let desired: BTreeMap<U256, &PairSpec> = desired.iter().map(|spec| (spec.lane, spec)).collect();

    // Over the union of both sides, in lane order, so a reload's actions and the lines it
    // logs come out in the same order every time whatever the file's ordering was.
    let lanes: BTreeSet<U256> = running.keys().chain(desired.keys()).copied().collect();

    lanes
        .into_iter()
        .filter_map(|lane| match (running.get(&lane), desired.get(&lane)) {
            (Some(_), None) => Some(Action::Remove(lane)),
            (current, Some(spec)) if tripped.contains(&lane) => {
                if rearm.contains(&lane) {
                    return Some(match current {
                        Some(_) => Action::Restart((*spec).clone()),
                        None => Action::Add((*spec).clone()),
                    });
                }
                let would_start = match current {
                    Some(current) => current != *spec || builders_changed,
                    None => true,
                };
                would_start.then_some(Action::StayTripped(lane))
            }
            (None, Some(spec)) => Some(Action::Add((*spec).clone())),
            (Some(current), Some(spec)) => {
                let changed = current != *spec;
                (changed || builders_changed).then(|| Action::Restart((*spec).clone()))
            }
            // Not reachable: `lanes` is built from these two maps, so a lane in neither
            // cannot appear. Nothing to do about it either way.
            (None, None) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MidBand, PricingSpec};
    use ethrex_common::Address;

    fn lane(n: u64) -> U256 {
        U256::from(n)
    }

    /// A feed pair on `lane`, with a `delta` that tests can vary to mean "the operator
    /// edited this stanza".
    fn spec(lane_id: u64, delta: Option<u64>) -> PairSpec {
        PairSpec {
            tokens: (Address::zero(), Address::zero()),
            lane: lane(lane_id),
            invert: false,
            pricing: PricingSpec::feed_for_tests(delta.map(|d| d.to_string()).as_deref()),
            feeds: Some(crate::config::Feeds::single_binance("ETHUSDC")),
            band: MidBand::default(),
            breaker: None,
            guards: Vec::new(),
            key_env: format!("UPDATER_KEY_{lane_id}"),
            allow_symbol_mismatch: false,
            halt_reason: None,
        }
    }

    fn running(specs: &[PairSpec]) -> BTreeMap<U256, PairSpec> {
        specs.iter().map(|s| (s.lane, s.clone())).collect()
    }

    /// The case that has to cost nothing. A lane quoting on a stanza nobody touched must
    /// come out of a reload untouched: this is what makes reloading cheap enough to do for
    /// an unrelated pair, and the reason the whole design is a diff rather than a restart.
    #[test]
    fn an_unchanged_healthy_pair_is_left_alone() {
        let pairs = [spec(1, None), spec(2, None)];
        let actions = plan(
            &running(&pairs),
            &pairs,
            &BTreeSet::new(),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(actions, vec![], "nothing changed, so nothing to do");
    }

    #[test]
    fn a_pair_only_in_the_file_is_added() {
        let actions = plan(
            &running(&[spec(1, None)]),
            &[spec(1, None), spec(2, None)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(actions, vec![Action::Add(spec(2, None))]);
    }

    #[test]
    fn a_pair_only_in_the_running_set_is_removed() {
        let actions = plan(
            &running(&[spec(1, None), spec(2, None)]),
            &[spec(1, None)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(actions, vec![Action::Remove(lane(2))]);
    }

    #[test]
    fn a_pair_whose_stanza_changed_is_restarted_from_the_new_one() {
        let actions = plan(
            &running(&[spec(1, None)]),
            &[spec(1, Some(5))],
            &BTreeSet::new(),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(
            actions,
            vec![Action::Restart(spec(1, Some(5)))],
            "and carries the new spec, not the old"
        );
    }

    /// Audit F-17: a lane halted on its breaker stays halted through every reload, one for
    /// an unrelated pair, one that edits its own stanza, one that changes the builder list.
    /// Only its own re-arm restarts it, from the stanza as it is then.
    #[test]
    fn a_tripped_pair_is_restarted_only_when_it_is_re_armed() {
        let pairs = [spec(1, None), spec(2, None)];
        let tripped = BTreeSet::from([lane(2)]);
        let nobody = BTreeSet::new();

        assert_eq!(
            plan(&running(&pairs), &pairs, &tripped, &nobody, false),
            vec![]
        );
        let edited = [spec(1, Some(7)), spec(2, Some(9))];
        assert_eq!(
            plan(&running(&pairs), &edited, &tripped, &nobody, false),
            vec![
                Action::Restart(spec(1, Some(7))),
                Action::StayTripped(lane(2))
            ],
            "its own edit does not re-arm it either, and the reload says it was left"
        );
        assert_eq!(
            plan(&running(&pairs), &pairs, &tripped, &nobody, true),
            vec![Action::Restart(spec(1, None)), Action::StayTripped(lane(2))],
            "nor a new builder list"
        );

        let rearm = BTreeSet::from([lane(2)]);
        assert_eq!(
            plan(&running(&pairs), &edited, &tripped, &rearm, false),
            vec![
                Action::Restart(spec(1, Some(7))),
                Action::Restart(spec(2, Some(9)))
            ],
            "re-armed, from its stanza as it is now"
        );
        assert_eq!(
            plan(&running(&pairs), &pairs, &BTreeSet::new(), &rearm, false),
            vec![],
            "a re-arm of a lane that is not tripped does nothing"
        );
    }

    /// A tripped lane the service shut down (a halt, a removal) and whose pair the file has
    /// again (a resume, an add) is not started: its trip is remembered, and only its re-arm
    /// starts it.
    #[test]
    fn a_remembered_trip_holds_a_lane_the_file_asks_for_until_its_re_arm() {
        let pairs = [spec(1, None), spec(2, None)];
        let only_one = running(&[spec(1, None)]);
        let tripped = BTreeSet::from([lane(2)]);
        assert_eq!(
            plan(&only_one, &pairs, &tripped, &BTreeSet::new(), false),
            vec![Action::StayTripped(lane(2))]
        );
        assert_eq!(
            plan(
                &only_one,
                &pairs,
                &tripped,
                &BTreeSet::from([lane(2)]),
                false
            ),
            vec![Action::Add(spec(2, None))]
        );
    }

    /// A halted lane the operator deleted from the file is removed, not resurrected —
    /// `Remove` is decided before the halt is ever consulted.
    #[test]
    fn a_halted_pair_dropped_from_the_file_is_removed_not_rearmed() {
        let actions = plan(
            &running(&[spec(1, None), spec(2, None)]),
            &[spec(1, None)],
            &BTreeSet::from([lane(2)]),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(actions, vec![Action::Remove(lane(2))]);
    }

    /// Every kind at once, and in lane order, so the log an operator reads is stable
    /// however the stanzas happened to be arranged in the file.
    #[test]
    fn actions_come_out_in_lane_order() {
        let actions = plan(
            &running(&[spec(1, None), spec(2, None), spec(4, None)]), // Deliberately not in lane order.
            &[spec(3, None), spec(1, Some(9)), spec(2, None)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            false,
        );
        assert_eq!(
            actions,
            vec![
                Action::Restart(spec(1, Some(9))),
                // lane 2 is unchanged and absent
                Action::Add(spec(3, None)),
                Action::Remove(lane(4)),
            ]
        );
    }

    /// A changed builder list is not per-lane state: each connection is opened inside a
    /// pair's own quoting loop, so a lane cannot pick one up without being rebuilt. Every
    /// lane is therefore diverged, whatever its stanza says.
    #[test]
    fn a_changed_builder_list_restarts_every_lane() {
        let pairs = [spec(1, None), spec(2, None), spec(3, None)];
        let actions = plan(
            &running(&pairs),
            &pairs,
            &BTreeSet::new(),
            &BTreeSet::new(),
            true,
        );
        assert_eq!(
            actions,
            vec![
                Action::Restart(spec(1, None)),
                Action::Restart(spec(2, None)),
                Action::Restart(spec(3, None)),
            ]
        );
    }

    /// And it does not turn a removal into a restart, or start a pair the file dropped.
    #[test]
    fn a_changed_builder_list_still_honours_adds_and_removes() {
        let actions = plan(
            &running(&[spec(1, None), spec(2, None)]),
            &[spec(2, None), spec(3, None)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            true,
        );
        assert_eq!(
            actions,
            vec![
                Action::Remove(lane(1)),
                Action::Restart(spec(2, None)),
                Action::Add(spec(3, None)),
            ]
        );
    }
}

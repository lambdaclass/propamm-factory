//! The kill switch (audit F-06): one flag per pair, shared between whoever halts it and the
//! lane that quotes it.
//!
//! A halt used to be a config change like any other: a full reload, which checks every pair
//! on the chain before it touches one. So stopping a pair was refused while any other pair
//! failed a check, waited for as long as the RPC took to answer (or for ever), and queued
//! behind any change already in flight.
//!
//! Now a halt sets this flag, and every lane reads its own on every tick: set, it withdraws
//! its quote at every builder and sends nothing more (`quoting::PublishGate::decide`). The
//! flag also wakes the lane, which otherwise only looks again when its price moves or its
//! block passes. No lock, reload, RPC call or other pair stands between the two. The halt is then recorded
//! in the shared config and the file (`state.rs`), which is what keeps the pair halted
//! across a restart, and the service shuts the silent lane down when it gets to it.
//!
//! A flag belongs to the pair's lane, not to one run of it: a reload already in flight that
//! starts the lane again hands the new run the same flag, set.
//!
//! A halt always wins. From the moment it sets the flag until it is recorded, the lane is
//! held: a resume in flight that finishes meanwhile does not lift the flag, so the pair does
//! not quote between that resume and the halt made after it.

use std::{collections::BTreeMap, sync::Mutex};

use ethrex_common::U256;
use tokio::sync::watch;

/// A lane's view of its flag: read on every tick, and waited on so a halt wakes it.
#[derive(Clone, Debug)]
pub(crate) struct HaltSignal(watch::Receiver<bool>);

/// Unset, and never to change: what a lane is built with until the service hands it its
/// pair's flag, and what a test's lane runs with.
impl Default for HaltSignal {
    fn default() -> Self {
        Self(watch::channel(false).1)
    }
}

impl HaltSignal {
    pub(crate) fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves when the flag changes; never, for one nothing can change any more.
    pub(crate) async fn changed(&mut self) {
        if self.0.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// One lane's flag, and how many halts of it are set and not yet recorded.
struct Flag {
    set: watch::Sender<bool>,
    held: usize,
}

impl Default for Flag {
    fn default() -> Self {
        Self {
            set: watch::channel(false).0,
            held: 0,
        }
    }
}

/// Every lane's halt flag, created on first ask.
#[derive(Default)]
pub(crate) struct HaltFlags {
    flags: Mutex<BTreeMap<U256, Flag>>,
}

impl HaltFlags {
    fn flags(&self) -> std::sync::MutexGuard<'_, BTreeMap<U256, Flag>> {
        // A poisoned lock still holds a whole map: nothing is half-written under it.
        self.flags.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The flag `lane`'s runs read, for the service to hand each one as it starts it.
    pub(crate) fn flag(&self, lane: U256) -> HaltSignal {
        HaltSignal(self.flags().entry(lane).or_default().set.subscribe())
    }

    /// The halt: every lane in `lanes` withdraws at once, woken if it was waiting.
    pub(crate) fn set(&self, lanes: &[U256]) {
        let mut flags = self.flags();
        for lane in lanes {
            flags.entry(*lane).or_default().set.send_replace(true);
        }
    }

    /// [`Self::set`], held until [`Self::release`]: a halt not yet recorded, which no
    /// [`Self::clear`] lifts meanwhile.
    pub(crate) fn hold(&self, lanes: &[U256]) {
        let mut flags = self.flags();
        for lane in lanes {
            let flag = flags.entry(*lane).or_default();
            flag.held += 1;
            flag.set.send_replace(true);
        }
    }

    /// The end of a [`Self::hold`]: the halt is recorded, or was refused. The flag stays as
    /// it is.
    pub(crate) fn release(&self, lanes: &[U256]) {
        let mut flags = self.flags();
        for lane in lanes {
            if let Some(flag) = flags.get_mut(lane) {
                flag.held = flag.held.saturating_sub(1);
            }
        }
    }

    /// A resume, or a pair gone from the config: `lanes` may quote again. Not one a halt
    /// holds: that halt is still to be recorded, and comes after whatever asked for this.
    pub(crate) fn clear(&self, lanes: &[U256]) {
        let flags = self.flags();
        for lane in lanes {
            if let Some(flag) = flags.get(lane).filter(|flag| flag.held == 0) {
                flag.set.send_replace(false);
            }
        }
    }

    pub(crate) fn is_set(&self, lane: U256) -> bool {
        self.flags()
            .get(&lane)
            .is_some_and(|flag| *flag.set.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One flag per lane: a run started before the halt and one started after both read
    /// the halt, and a resume lets both quote. Other lanes are not touched.
    #[test]
    fn every_run_of_a_lane_reads_its_one_flag() {
        let flags = HaltFlags::default();
        let (a, b) = (U256::from(1), U256::from(2));
        let before = flags.flag(a);
        let other = flags.flag(b);

        flags.set(&[a]);
        let after = flags.flag(a);
        assert!(before.is_set() && after.is_set());
        assert!(!other.is_set());

        flags.clear(&[a]);
        assert!(!before.is_set() && !after.is_set());
    }

    /// A halt wakes a lane waiting on its flag.
    #[tokio::test]
    async fn a_halt_wakes_the_lane() {
        let flags = HaltFlags::default();
        let mut signal = flags.flag(U256::from(1));
        let waiting = tokio::spawn(async move {
            signal.changed().await;
            signal.is_set()
        });
        tokio::task::yield_now().await;
        flags.set(&[U256::from(1)]);
        assert!(waiting.await.unwrap(), "woken, and reads the halt");
    }

    /// A halt not yet recorded is not lifted by a resume that finishes meanwhile; once it is
    /// released, a later resume lifts it as any other.
    #[test]
    fn a_held_halt_is_not_lifted_until_it_is_released() {
        let flags = HaltFlags::default();
        let lane = U256::from(3);
        flags.hold(&[lane]);
        flags.clear(&[lane]);
        assert!(flags.is_set(lane), "held: the resume does not lift it");
        flags.release(&[lane]);
        assert!(flags.is_set(lane), "released, and still set");
        flags.clear(&[lane]);
        assert!(!flags.is_set(lane));
    }

    /// A lane halted before any run of it asked for its flag still starts halted.
    #[test]
    fn a_halt_before_the_lane_starts_holds() {
        let flags = HaltFlags::default();
        flags.set(&[U256::from(7)]);
        assert!(flags.flag(U256::from(7)).is_set());
        assert!(flags.is_set(U256::from(7)));
    }
}

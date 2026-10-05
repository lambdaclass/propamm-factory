//! What a pricer may read beyond its stanza and the reference market: the chain, the
//! market's σ history, the pair's vault inventory and the lane's own landings. Each is
//! handed out by [`super::BuildCtx`] while the pricer is built, so `price()` reads what its
//! build prepared and stays synchronous. All four exist for the core already; this is the
//! same plumbing, made reachable.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ethrex_common::Address;
use ethrex_rpc::clients::eth::EthClient;
use tokio::sync::watch;

pub use crate::volatile::Inventory;
use crate::volatile::{self, PriceHistory};

/// A read-only view of the chain, for a pricer that anchors to an oracle or reads a
/// contract of its own. Every call is bounded by the updater's RPC timeout (3s), so a hung
/// node fails the read rather than the build or the task making it. Cheap to clone into a
/// task started with [`super::BuildCtx::spawn`].
#[derive(Clone)]
pub struct Chain {
    pub(crate) client: EthClient,
    pub(crate) target: Address,
}

impl Chain {
    pub(crate) fn new(client: EthClient, target: Address) -> Chain {
        Chain { client, target }
    }

    /// `eth_call` at the latest block: `calldata` in, the return data out, neither decoded.
    /// ABI encoding is the caller's: [`Self::call_sig`] does it from a signature with the
    /// types re-exported as [`crate::calldata`], and bytes carry no type identity across
    /// the ethrex git pins the way `U256` does, so any encoder works here. The answer is
    /// read with [`crate::calldata::decode_return_data`].
    pub async fn call(&self, to: Address, calldata: Vec<u8>) -> eyre::Result<Vec<u8>> {
        crate::rpc::call_view(&self.client, to, calldata, None, None).await
    }

    /// [`Self::call`] with the calldata encoded here: `signature` as `balanceOf(address)`,
    /// `args` as [`crate::calldata::Value`]s. The answer is still undecoded:
    /// [`crate::calldata::decode_return_data`] reads it against the return types, as in
    /// `decode_return_data("(uint256)", &answer)`. Not `decode_calldata`, which expects a
    /// selector the answer does not have and would read every word four bytes late.
    pub async fn call_sig(
        &self,
        to: Address,
        signature: &str,
        args: &[crate::calldata::Value],
    ) -> eyre::Result<Vec<u8>> {
        let calldata = crate::calldata::encode_calldata(signature, args)
            .map_err(|err| eyre::eyre!("encoding `{signature}`: {err}"))?;
        self.call(to, calldata).await
    }
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chain(target {:#x})", self.target)
    }
}

/// The reference market's recent mids, one per second, from which σ is measured. Kept at
/// the process level per market, so a reload that rebuilds the lane does not restart the
/// minute of history σ needs; the volatile model reads the same samples.
#[derive(Clone, Debug)]
pub struct History(pub(crate) Arc<Mutex<PriceHistory>>);

impl History {
    /// A history with nothing in it yet: what `--check` hands a pricer, since it does not
    /// wait the minute σ needs.
    pub(crate) fn empty() -> History {
        History(Arc::new(Mutex::new(PriceHistory::new(Instant::now()))))
    }

    /// σ per √second over the last `window`, from the log returns of the samples in it, or
    /// `Err(covered)` with how much history there is when that is under a minute, which is
    /// what the volatile model refuses as `warming_up`. An hour is kept, so a longer
    /// `window` reads an hour.
    pub fn volatility(&self, now: Instant, window: Duration) -> Result<f64, Duration> {
        volatile::lock(&self.0).volatility(now, window)
    }
}

/// The pair's vault balances, refreshed every 12s by a task shared by every lane reading
/// the vault, which stops when the last of them drops its feed. Cheap to clone and to read.
#[derive(Clone)]
pub struct InventoryFeed(pub(crate) Arc<crate::vault::SharedReader>);

impl InventoryFeed {
    /// A feed over a receiver of its own: what a test seeds, and what a run's reader is
    /// registered as.
    pub(crate) fn from_receiver(rx: watch::Receiver<Inventory>) -> InventoryFeed {
        InventoryFeed(Arc::new(crate::vault::SharedReader { rx }))
    }

    /// The latest reading. Its age is the health signal: a refresher that cannot reach the
    /// chain leaves the reading where it was, and the volatile model refuses to tilt on one
    /// over a minute old (`no_inventory`).
    pub fn latest(&self) -> Inventory {
        *self.0.rx.borrow()
    }
}

impl std::fmt::Debug for InventoryFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InventoryFeed({:?})", self.latest())
    }
}

impl Inventory {
    /// How old this reading is at `now`.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.at)
    }
}

/// What happened to this lane's update for one block, as the read-back after the block
/// saw it: the same outcome `quote_updater_landings_total` counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandingReport {
    /// The block the update was quoted for.
    pub block: u64,
    /// How the block went for the lane.
    pub landing: LandingOutcome,
    /// When the read-back answered, on this process's clock.
    pub at: Instant,
}

/// The four ways a block can go for a lane. `#[non_exhaustive]` like every enum an
/// observer or a pricer matches on: a fifth would not be a breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingOutcome {
    /// The lane holds this pair's update for the block.
    Landed,
    /// An update was quoted for the block and the lane does not hold it.
    Missed,
    /// The read-back failed, so whether it landed is not known. Never a healthy sign.
    Unknown,
    /// Nothing was quoted for the block (the feed was stale, or the quote withdrawn), so
    /// nothing was expected to land and the block says nothing about the lane.
    NotQuoted,
}

impl From<crate::landing::Landing> for LandingOutcome {
    fn from(landing: crate::landing::Landing) -> LandingOutcome {
        use crate::landing::Landing;
        match landing {
            Landing::Landed => LandingOutcome::Landed,
            Landing::Missed => LandingOutcome::Missed,
            Landing::Unknown => LandingOutcome::Unknown,
            Landing::NotQuoted => LandingOutcome::NotQuoted,
        }
    }
}

/// This lane's landings, block by block, from the read-back the quote loop runs after each
/// block passes. Holds the latest report; a task started with [`super::BuildCtx::spawn`]
/// can await each one with [`Self::next`]. Cheap to clone.
#[derive(Clone)]
pub struct LandingFeed(pub(crate) watch::Receiver<Option<LandingReport>>);

impl LandingFeed {
    /// The latest report, or `None` before the first block has passed. A block behind the
    /// quote it answers for: the tick that quotes block `n` sees at most block `n - 1`'s.
    pub fn latest(&self) -> Option<LandingReport> {
        *self.0.borrow()
    }

    /// Waits for the next report after the last one this feed handed out (or after it was
    /// created), and hands it out; `None` once the lane is gone, which ends a task's loop.
    pub async fn next(&mut self) -> Option<LandingReport> {
        self.0.changed().await.ok()?;
        *self.0.borrow_and_update()
    }
}

impl std::fmt::Debug for LandingFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LandingFeed({:?})", self.latest())
    }
}

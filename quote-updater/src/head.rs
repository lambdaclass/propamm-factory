//! One process-wide view of the chain head.
//!
//! Kept in a task of its own rather than inside each pair's quote loop. A poll is an RPC
//! round-trip, and awaited inside the loop it held the loop for that long on every tick:
//! a price move arriving meanwhile could not be re-signed until the poll returned. Off
//! the loop, a pair only ever observes a value, which costs it nothing. One watcher for
//! the process rather than one per pair, so RPC load does not scale with the pair count
//! and every pair rolls to a new block at the same moment.
//!
//! The head arrives one of two ways. Polled: `eth_blockNumber` every `poll`, and the
//! block's header fetched once when the number moves. Or subscribed: given a WebSocket
//! endpoint, `newHeads` pushes each block's header the moment the node has it, and the
//! poll stands down to a slow liveness check — a node that keeps the socket open but
//! stops pushing looks exactly like a quiet chain, and only a poll can tell them apart.
//! Either way a pair sees a [`Head`] carrying what it stamps an update from, and never
//! fetches a block itself.
//!
//! Neither way is taken at its word. A head is published when it follows the one that
//! stands, by no more than [`MAX_HEAD_JUMP`]; any other reading is kept out, and only
//! replaces the standing head once the node has kept saying so for [`REANCHOR_AFTER`].
//! Without the first, one absurd header (a buggy node, one replica of several) stood as
//! the head and every real one after it read as older. Without the second, a standing head
//! that was itself wrong could never be left. [`judge`] is the rule.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use ethrex_common::types::BlockHeader;
use ethrex_rpc::{
    clients::eth::EthClient,
    types::block_identifier::{BlockIdentifier, BlockTag},
};
use eyre::{Result, WrapErr, bail, eyre};
use futures_util::{SinkExt, StreamExt};
use tokio::{sync::watch, time::Instant};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::{bounded, metrics::HeadMetrics, ws};

/// The latest block as far as the watcher knows, reduced to what a pair needs of it: the
/// number its next target follows, and the timestamp and base fee that target's update
/// is stamped and priced from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Head {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee_per_gas: Option<u64>,
}

impl From<&BlockHeader> for Head {
    fn from(header: &BlockHeader) -> Self {
        Head {
            number: header.number,
            timestamp: header.timestamp,
            base_fee_per_gas: header.base_fee_per_gas,
        }
    }
}

/// How long one poll may take before it is abandoned and the next one goes out. Without
/// a bound a hung RPC (TCP alive, never answering — reqwest's client has no request
/// timeout of its own) would hold the watcher forever, and every pair with it.
pub const POLL_TIMEOUT: Duration = Duration::from_secs(2);

/// How often to poll while a subscription is delivering heads: a liveness check on the
/// subscription, not the way heads normally arrive. Rare enough to cost nothing, and
/// well inside a slot, so a subscription that has silently died costs at most this
/// much rollover delay before the poll finds the block.
pub const SUBSCRIBED_POLL: Duration = Duration::from_secs(3);

/// How long a subscription may go without a new head before it is redialed. Mainnet
/// lands a block every 12s; five slots of silence is a socket that died without a FIN
/// or a chain that has halted, and redialing is harmless in the second case.
const SUBSCRIPTION_QUIET: Duration = Duration::from_secs(60);

/// Delay between redials of the subscription endpoint. Matches binance.rs.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// How far past the standing head a new one may be and still be taken at its word. Blocks
/// arrive one at a time, and a watcher cut off from its node for a few minutes comes back
/// that many blocks on; one epoch covers both. A head further on than that is not the
/// chain's next block. Either the node said something absurd, or the chain moved on while
/// nothing was watching, and only the second keeps being said (see [`REANCHOR_AFTER`]).
pub const MAX_HEAD_JUMP: u64 = 32;

/// How long the node has to keep contradicting the standing head, the same way and without
/// a break, before the watcher takes the node's word over its own. Three slots. A replica
/// a block behind has caught up, or another has answered, long before that, so a lagging
/// answer still never moves the head back; and one absurd answer is not repeated for
/// three blocks' worth of time.
pub const REANCHOR_AFTER: Duration = Duration::from_secs(36);

/// The longest two contradicting readings may be apart and still be one run: a slot, or
/// four polls where the poll is slower than that. The node is read several times a slot,
/// so a silence longer than this is the node not answering, not the node repeating itself,
/// and what it says when it answers again starts the count over. Without it two stray
/// answers with an outage between them counted as the node saying one thing throughout.
const DISPUTE_GAP: Duration = Duration::from_secs(12);

/// What one reading of the node's head means for the head that stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The block the standing head already is. Nothing to publish.
    Stands,
    /// The first head there is, or one that follows the standing head: published.
    Follows,
    /// Behind the standing head, or further past it than [`MAX_HEAD_JUMP`]: kept out.
    Disputed,
    /// As `Disputed`, and the node has said so without a break for [`REANCHOR_AFTER`]:
    /// this reading replaces the standing head.
    Reanchor,
}

/// An unbroken run of readings that contradict the standing head the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    /// When the run's first reading was taken, and the block it read.
    since: Instant,
    first: u64,
    /// When its latest was taken, and the block it read.
    last: Instant,
    number: u64,
}

/// The runs in progress, one for each way a reading can contradict the standing head. Two,
/// because what ends one does not end the other (see [`judge`]).
#[derive(Debug, Default)]
struct Disputes {
    behind: Option<Run>,
    ahead: Option<Run>,
}

/// Judges a reading numbered `number`, taken at `now`, against the head numbered `standing`,
/// and keeps `disputes` up to date with it. `gap` is the longest two readings of one run
/// may be apart.
///
/// The two ways of contradicting the standing head are held to different evidence, because
/// they are wrong in different ways.
///
/// A reading *behind* it is most often a replica that has not caught up, and then some
/// other reading soon says the standing block or one after it. Any such reading ends the
/// run: the standing block is a node's head, so it is not one to go back from. Only a node
/// that says nothing else for [`REANCHOR_AFTER`] is believed.
///
/// A reading *far ahead* of it is either absurd or true, and a true one is repeated and
/// grows: the next reading is the same block or a few past it, and within
/// [`REANCHOR_AFTER`] it is past it. So a run of them is believed only once it has grown;
/// a node repeating one absurd number never is. Readings that agree with the standing head
/// do not end this run. If they did, one replica stuck far behind would hold the head
/// there for as long as it answered, its every reading vouching for a head the rest of the
/// chain had left.
fn judge(
    standing: u64,
    number: u64,
    disputes: &mut Disputes,
    now: Instant,
    gap: Duration,
) -> Verdict {
    if number == standing {
        disputes.behind = None;
        return Verdict::Stands;
    }
    // Before the first head nothing stands (`Head::default()` is block 0), so there is
    // nothing for a reading to be too far from.
    if number > standing && (standing == 0 || number - standing <= MAX_HEAD_JUMP) {
        disputes.behind = None;
        return Verdict::Follows;
    }
    let ahead = number > standing;
    let (run, same_claim) = if ahead {
        // Only what the last reading could have grown into.
        let reachable = disputes
            .ahead
            .is_some_and(|run| number >= run.number && number - run.number <= MAX_HEAD_JUMP);
        (&mut disputes.ahead, reachable)
    } else {
        // Whatever older block it is: replicas lag by different amounts, and a node
        // catching up reads a little further each time.
        (&mut disputes.behind, true)
    };
    let (since, first) = match run {
        Some(run) if same_claim && now.duration_since(run.last) <= gap => (run.since, run.first),
        _ => (now, number),
    };
    *run = Some(Run {
        since,
        first,
        last: now,
        number,
    });
    let said_long_enough = now.duration_since(since) >= REANCHOR_AFTER;
    if said_long_enough && (!ahead || number > first) {
        Verdict::Reanchor
    } else {
        Verdict::Disputed
    }
}

/// The head the pairs observe, with what deciding whether to replace it needs. One, shared
/// by the poll and the subscription: a reading counts the same whichever way it arrived.
struct Standing {
    tx: watch::Sender<Head>,
    metrics: HeadMetrics,
    /// See [`judge`].
    disputes: Mutex<Disputes>,
    /// See [`DISPUTE_GAP`].
    gap: Duration,
}

impl Standing {
    /// `poll` is how often the node is read when nothing pushes heads.
    fn new(tx: watch::Sender<Head>, metrics: HeadMetrics, poll: Duration) -> Self {
        Standing {
            tx,
            metrics,
            disputes: Mutex::new(Disputes::default()),
            gap: DISPUTE_GAP.max(poll * 4),
        }
    }

    /// Publishes `head` if it follows the one that stands, or if the node has contradicted
    /// the standing one for long enough that `head` replaces it (see [`judge`]).
    ///
    /// Also the one site that writes `head_number`, and inside the accepted branch: this is
    /// the only place the channel's value changes, and both ways a head arrives — the poll
    /// and the subscription — come through here, so the gauge cannot drift from what the
    /// pairs actually observe. Not written on a rejected head: a lagging replica answering
    /// with an older block must no more move the gauge than it moves the channel.
    fn publish(&self, head: Head) {
        let mut disputes = self.disputes.lock().unwrap_or_else(|e| e.into_inner());
        self.tx.send_if_modified(|current| {
            match judge(
                current.number,
                head.number,
                &mut disputes,
                Instant::now(),
                self.gap,
            ) {
                Verdict::Stands | Verdict::Disputed => return false,
                Verdict::Follows => {}
                Verdict::Reanchor => {
                    // The one case the head can move back. A pair that was quoting past
                    // the old one sees it and goes on from this one (`quoting::drive`).
                    tracing::warn!(
                        "[head] for {REANCHOR_AFTER:?} the node has kept reporting a head \
                         that does not follow block {}; taking its block {} as the head \
                         instead",
                        current.number,
                        head.number
                    );
                    *disputes = Disputes::default();
                }
            }
            *current = head;
            self.metrics.number.set(head.number as f64);
            true
        });
    }

    /// Whether a block numbered `number` could change what stands, so its header is worth
    /// fetching. Counted as a reading either way: a poll that finds the standing block
    /// still at the head is what ends a dispute, and one that keeps finding another is
    /// what a re-anchor waits for.
    fn wants(&self, number: u64) -> bool {
        let mut disputes = self.disputes.lock().unwrap_or_else(|e| e.into_inner());
        let standing = self.tx.borrow().number;
        matches!(
            judge(standing, number, &mut disputes, Instant::now(), self.gap),
            Verdict::Follows | Verdict::Reanchor
        )
    }
}

/// How often to poll, given the requote cadence. Blocks land every ~12s, so polling at
/// the requote cadence would spend an RPC round-trip per tick for nothing; a stale view
/// only delays rolling to the next target block by up to this interval.
pub fn poll_interval(requote_ms: u64) -> Duration {
    Duration::from_millis(requote_ms.max(250))
}

/// Starts watching the head: polling `client` every `poll`, and — given `ws_url` —
/// subscribed to its `newHeads` as well. Publishes each new head with its header. The
/// value rises: a lagging replica behind a load balancer answering with an older head must
/// not roll a pair back to a block it has already quoted past. It moves back only when the
/// watcher re-anchors, after the node has contradicted the standing head for
/// [`REANCHOR_AFTER`]. The tasks end once every receiver is gone.
pub fn spawn(
    tasks: &mut crate::tasks::Tasks,
    client: EthClient,
    poll: Duration,
    poll_timeout: Duration,
    ws_url: Option<String>,
    metrics: HeadMetrics,
) -> watch::Receiver<Head> {
    let (tx, rx) = watch::channel(Head::default());
    let standing = Arc::new(Standing::new(tx, metrics, poll));
    let subscribed = Arc::new(AtomicBool::new(false));
    if let Some(url) = ws_url {
        tasks.spawn(subscribe_forever(url, standing.clone(), subscribed.clone()));
    }
    tasks.spawn(poll_forever(
        client,
        poll,
        poll_timeout,
        standing,
        subscribed,
    ));
    rx
}

async fn poll_forever(
    client: EthClient,
    poll: Duration,
    poll_timeout: Duration,
    standing: Arc<Standing>,
    subscribed: Arc<AtomicBool>,
) {
    let metrics = &standing.metrics;
    let mut last_error: Option<String> = None;
    loop {
        if standing.tx.is_closed() {
            return;
        }
        // Timed and counted here rather than inside `poll_once`: this is where the verdict
        // is consumed, and a timer around the call covers the block fetch `poll_once` makes
        // when the head moved — which is part of what a pair waits for, and is exactly what
        // a timer inside the number fetch would leave out.
        let started = std::time::Instant::now();
        let polled = poll_once(&client, poll_timeout, &standing).await;
        metrics
            .poll_duration
            .observe(started.elapsed().as_secs_f64());
        if polled.is_err() {
            metrics.poll_errors.inc();
        }
        match polled {
            Ok(number) => {
                if last_error.take().is_some() {
                    tracing::warn!("[head] block number fetch recovered at {number}");
                }
            }
            // Once per distinct error, not once per poll: at four polls a second an
            // outage would drown the per-block lines that matter.
            Err(err) => {
                let err = format!("{err:#}");
                if last_error.as_deref() != Some(err.as_str()) {
                    tracing::warn!("[head] failed to fetch block number (will retry): {err}");
                    last_error = Some(err);
                }
            }
        }
        let wait = if subscribed.load(Ordering::Relaxed) {
            SUBSCRIBED_POLL.max(poll)
        } else {
            poll
        };
        tokio::time::sleep(wait).await;
    }
}

/// One poll: the block number, and the block's header when that number could change what
/// stands. Returns the number polled.
async fn poll_once(client: &EthClient, poll_timeout: Duration, standing: &Standing) -> Result<u64> {
    let number = tokio::time::timeout(poll_timeout, client.get_block_number())
        .await
        .map_err(|_| eyre!("no answer in {poll_timeout:?}"))??;
    if standing.wants(number) {
        // `latest`, not `number`: the chain may have moved again meanwhile, and the
        // latest block is the parent a pair wants either way.
        let block =
            bounded(client.get_block_by_number(BlockIdentifier::Tag(BlockTag::Latest), false))
                .await
                .wrap_err("failed to fetch latest block")?;
        standing.publish(Head::from(&block.header));
    }
    Ok(number)
}

async fn subscribe_forever(url: String, standing: Arc<Standing>, subscribed: Arc<AtomicBool>) {
    // The host only, never the URL: a provider's key rides in the path.
    let host = Url::parse(&url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned());
    let mut last_error: Option<String> = None;
    loop {
        let outcome = subscription(&url, &host, &standing, &subscribed).await;
        subscribed.store(false, Ordering::Relaxed);
        if standing.tx.is_closed() {
            return;
        }
        match outcome {
            Ok(()) => {
                last_error = None;
                tracing::warn!("[head] new-heads subscription at {host} closed; reconnecting");
            }
            // Once per distinct error: a dead endpoint otherwise says so every
            // RECONNECT_DELAY forever. Polling carries the head meanwhile.
            Err(err) => {
                let err = format!("{err:#}");
                if last_error.as_deref() != Some(err.as_str()) {
                    tracing::warn!(
                        "[head] new-heads subscription at {host} failed (will retry; polling \
                         meanwhile): {err}"
                    );
                    last_error = Some(err);
                }
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// One subscription, until it closes, fails, or goes quiet past SUBSCRIPTION_QUIET.
async fn subscription(
    url: &str,
    host: &str,
    standing: &Standing,
    subscribed: &AtomicBool,
) -> Result<()> {
    let mut ws = ws::connect(url).await?;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": ["newHeads"],
    });
    ws.send(Message::text(request.to_string()))
        .await
        .wrap_err("subscribe request failed")?;
    loop {
        let msg = tokio::time::timeout(SUBSCRIPTION_QUIET, ws.next())
            .await
            .map_err(|_| eyre!("no new head in {SUBSCRIPTION_QUIET:?}"))?;
        let Some(msg) = msg else {
            return Ok(());
        };
        match msg.wrap_err("read failed")? {
            Message::Text(text) => {
                let reply: serde_json::Value =
                    serde_json::from_str(&text).wrap_err("not a JSON-RPC message")?;
                if reply["id"] == 1 {
                    if let Some(error) = reply.get("error") {
                        bail!("subscribe rejected: {error}");
                    }
                    subscribed.store(true, Ordering::Relaxed);
                    tracing::info!("[head] subscribed to new heads at {host}");
                } else if reply["method"] == "eth_subscription" {
                    standing.publish(head_from_json(&reply["params"]["result"])?);
                }
            }
            Message::Close(_) => return Ok(()),
            // tungstenite answers pings by itself while the stream is polled.
            _ => {}
        }
    }
}

/// A [`Head`] out of a header as JSON-RPC renders it — a `newHeads` notification's
/// payload. Only the three fields a head is are read; a provider may add or omit the
/// rest.
pub fn head_from_json(header: &serde_json::Value) -> Result<Head> {
    fn hex_field(header: &serde_json::Value, field: &str) -> Result<Option<u64>> {
        match header.get(field) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(hex)) => {
                u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16)
                    .map(Some)
                    .wrap_err_with(|| format!("header field {field} is not a hex number: {hex:?}"))
            }
            Some(other) => Err(eyre!("header field {field} is not a string: {other}")),
        }
    }
    Ok(Head {
        number: hex_field(header, "number")?.ok_or_else(|| eyre!("header has no number"))?,
        timestamp: hex_field(header, "timestamp")?
            .ok_or_else(|| eyre!("header has no timestamp"))?,
        base_fee_per_gas: hex_field(header, "baseFeePerGas")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_mock::MockRpc;
    use ethrex_rpc::clients::eth::EthClient;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use url::Url;

    fn client(rpc: &MockRpc) -> EthClient {
        EthClient::new(Url::parse(&rpc.url).unwrap()).unwrap()
    }

    /// A throwaway registry, one per call: these tests only need somewhere for the
    /// watcher's samples to land, and an independent registry keeps a count asserted in one
    /// test out of another's.
    fn test_head_metrics() -> HeadMetrics {
        crate::metrics::Metrics::new()
            .unwrap()
            .register_head()
            .unwrap()
    }

    fn head_at(number: u64) -> Head {
        Head {
            number,
            timestamp: 1_700_000_000,
            base_fee_per_gas: Some(1_000_000_000),
        }
    }

    /// A standing head of its own, with no node behind it: these tests are about what a
    /// run of readings does to it, and the clock is tokio's paused one.
    fn standing() -> (Standing, watch::Receiver<Head>) {
        let (tx, rx) = watch::channel(Head::default());
        (
            Standing::new(tx, test_head_metrics(), Duration::from_millis(250)),
            rx,
        )
    }

    /// The node read every three seconds for `secs`, the way a poll reads it: `block` is
    /// what it answers at each second since the call. The header is fetched and published
    /// only when the number is worth one, as `poll_once` does.
    async fn read_every_3s(standing: &Standing, secs: u64, block: impl Fn(u64) -> u64) {
        for at in (0..secs).step_by(3) {
            let number = block(at);
            if standing.wants(number) {
                standing.publish(head_at(number));
            }
            tokio::time::advance(Duration::from_secs(3)).await;
        }
    }

    /// One absurd header, from a buggy node or one replica of several, used to be kept as
    /// the head for being the greatest number seen, and every real head after it read as
    /// older until the process was restarted. It is kept out, and the chain goes on.
    #[tokio::test(start_paused = true)]
    async fn a_head_too_far_past_the_standing_one_is_kept_out() {
        let (standing, head) = standing();
        standing.publish(head_at(100));
        standing.publish(head_at(u64::MAX));
        standing.publish(head_at(100 + MAX_HEAD_JUMP + 1));
        assert_eq!(
            head.borrow().number,
            100,
            "neither is the chain's next block"
        );

        standing.publish(head_at(101));
        assert_eq!(
            head.borrow().number,
            101,
            "the real head after it is followed"
        );
        // As far as a head may move in one step, for a watcher that was cut off a while.
        standing.publish(head_at(101 + MAX_HEAD_JUMP));
        assert_eq!(head.borrow().number, 101 + MAX_HEAD_JUMP);
        assert_eq!(
            standing.metrics.number.get(),
            (101 + MAX_HEAD_JUMP) as f64,
            "the gauge carries what the pairs observe"
        );

        // Said again and again it is still not the chain: an absurd number repeated does
        // not grow, and the real blocks in between are followed as they come.
        read_every_3s(&standing, 60, |at| match at % 6 {
            0 => 1 << 60,
            _ => 133 + at / 12,
        })
        .await;
        assert_eq!(head.borrow().number, 137);
    }

    /// The absurd header can be the first one, with nothing standing for it to be too far
    /// from. Then it is the standing head that is wrong, and the node saying otherwise,
    /// block after block, is what replaces it.
    #[tokio::test(start_paused = true)]
    async fn a_standing_head_the_node_keeps_contradicting_is_replaced() {
        let (standing, head) = standing();
        standing.publish(head_at(1 << 60));
        assert_eq!(head.borrow().number, 1 << 60, "the first head is taken");

        // The real chain, a block every twelve seconds, read from t = 0 to t = 30.
        read_every_3s(&standing, 33, |at| 100 + at / 12).await;
        assert_eq!(head.borrow().number, 1 << 60, "not before REANCHOR_AFTER");
        // And at t = 33 and t = 36, where the run is REANCHOR_AFTER old.
        read_every_3s(&standing, 6, |_| 103).await;
        assert_eq!(head.borrow().number, 103, "the node's head replaces it");
        assert_eq!(standing.metrics.number.get(), 103.0);

        // And from there the chain is followed block by block again.
        standing.publish(head_at(104));
        assert_eq!(head.borrow().number, 104);
    }

    /// A chain that moved on by more than `MAX_HEAD_JUMP` while nothing was watching is
    /// kept out like an absurd header, and unlike one it keeps being said and keeps growing.
    #[tokio::test(start_paused = true)]
    async fn a_chain_that_moved_far_ahead_is_followed_once_it_keeps_being_said() {
        let (standing, head) = standing();
        standing.publish(head_at(100));
        read_every_3s(&standing, 36, |at| 1_000 + at / 12).await;
        assert_eq!(
            head.borrow().number,
            100,
            "36s of it is not yet REANCHOR_AFTER"
        );
        read_every_3s(&standing, 3, |_| 1_003).await;
        assert_eq!(head.borrow().number, 1_003);
    }

    /// One replica stuck far behind, answering every other read, used to be able to hold
    /// the head where it was: each of its answers agreed with the standing head and ended
    /// the dispute the rest of the chain had raised. Agreement does not end a run of
    /// readings far ahead, so the chain is followed, and the stale answers that keep
    /// coming afterwards do not take the head back.
    #[tokio::test(start_paused = true)]
    async fn a_replica_stuck_far_behind_does_not_hold_the_head_there() {
        let (standing, head) = standing();
        // The stale replica answered first.
        standing.publish(head_at(900));
        let alternating = |since: u64| {
            move |at: u64| match (at / 3) % 2 {
                0 => 900,
                _ => 1_000 + (since + at) / 12,
            }
        };
        read_every_3s(&standing, 36, alternating(0)).await;
        assert_eq!(head.borrow().number, 900, "not before REANCHOR_AFTER");
        read_every_3s(&standing, 6, alternating(36)).await;
        assert_eq!(
            head.borrow().number,
            1_003,
            "the live replica's head is taken"
        );

        // A minute more of the same two replicas: every other answer is 900, far behind,
        // and every other one is the head, which is what ends that run each time.
        read_every_3s(&standing, 60, alternating(42)).await;
        assert_eq!(
            head.borrow().number,
            1_008,
            "and it is followed, never left"
        );
    }

    /// Two stray answers with an outage between them are not the node saying one thing for
    /// the whole of the outage: a reading more than a slot after the last starts the run
    /// over, so a flapping endpoint cannot move the head back with a pair of them.
    #[tokio::test(start_paused = true)]
    async fn two_lagging_answers_an_outage_apart_do_not_move_the_head_back() {
        let (standing, head) = standing();
        standing.publish(head_at(100));
        assert!(!standing.wants(97));
        // Nothing answers for longer than REANCHOR_AFTER.
        tokio::time::advance(REANCHOR_AFTER + Duration::from_secs(4)).await;
        assert!(!standing.wants(97), "the second answer starts a new run");
        standing.publish(head_at(97));
        assert_eq!(head.borrow().number, 100);

        // Said without a break from here, it is believed REANCHOR_AFTER later, not sooner.
        read_every_3s(&standing, 36, |_| 97).await;
        assert_eq!(head.borrow().number, 100);
        read_every_3s(&standing, 3, |_| 97).await;
        assert_eq!(head.borrow().number, 97);
    }

    /// A replica behind the one that answered before must still never move the head back:
    /// any reading that agrees with the standing head ends the run, however long the
    /// lagging answers have been coming.
    #[tokio::test(start_paused = true)]
    async fn a_reading_that_agrees_with_the_standing_head_ends_a_run_behind_it() {
        let (standing, head) = standing();
        standing.publish(head_at(100));
        read_every_3s(&standing, 33, |_| 99).await;
        // The replica that is not behind answers: block 100 is still the head.
        assert!(!standing.wants(100));
        read_every_3s(&standing, 33, |_| 99).await;
        assert_eq!(
            head.borrow().number,
            100,
            "the run started over when a reading agreed"
        );
        // So does the block after it.
        standing.publish(head_at(101));
        read_every_3s(&standing, 33, |_| 99).await;
        assert_eq!(head.borrow().number, 101);
    }

    /// The verdicts one by one, and the bounds at their edges.
    #[tokio::test(start_paused = true)]
    async fn a_reading_is_judged_against_the_standing_head() {
        let gap = DISPUTE_GAP;
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut d = Disputes::default();
        // Nothing stands yet: any block is the first head, and block 0 is no head at all.
        assert_eq!(judge(0, 1 << 60, &mut d, t0, gap), Verdict::Follows);
        assert_eq!(judge(0, 0, &mut d, t0, gap), Verdict::Stands);
        assert_eq!(judge(100, 100, &mut d, t0, gap), Verdict::Stands);
        assert_eq!(judge(100, 101, &mut d, t0, gap), Verdict::Follows);
        let edge = 100 + MAX_HEAD_JUMP;
        assert_eq!(judge(100, edge, &mut d, t0, gap), Verdict::Follows);
        assert!(
            d.behind.is_none() && d.ahead.is_none(),
            "nothing contradicted it"
        );

        // Behind: a run, whatever older block each reading names, until it is old enough.
        assert_eq!(judge(100, 99, &mut d, at(0), gap), Verdict::Disputed);
        assert_eq!(judge(100, 97, &mut d, at(12), gap), Verdict::Disputed);
        assert_eq!(judge(100, 98, &mut d, at(24), gap), Verdict::Disputed);
        assert_eq!(d.behind.map(|run| run.since), Some(at(0)));
        assert_eq!(judge(100, 98, &mut d, at(35), gap), Verdict::Disputed);
        assert_eq!(judge(100, 98, &mut d, at(36), gap), Verdict::Reanchor);
        // One reading longer than the gap after the last starts it over.
        assert_eq!(judge(100, 98, &mut d, at(49), gap), Verdict::Disputed);
        assert_eq!(d.behind.map(|run| run.since), Some(at(49)));
        // And a reading that agrees ends it.
        assert_eq!(judge(100, 100, &mut d, at(50), gap), Verdict::Stands);
        assert_eq!(d.behind, None);

        // Far ahead: a run only while each reading is what the last could have grown into.
        assert_eq!(judge(100, edge + 1, &mut d, at(60), gap), Verdict::Disputed);
        assert_eq!(judge(100, edge + 2, &mut d, at(66), gap), Verdict::Disputed);
        assert_eq!(d.ahead.map(|run| run.since), Some(at(60)));
        // Readings that agree with the standing head do not end it.
        assert_eq!(judge(100, 100, &mut d, at(67), gap), Verdict::Stands);
        assert_eq!(judge(100, 101, &mut d, at(68), gap), Verdict::Follows);
        assert_eq!(d.ahead.map(|run| run.since), Some(at(60)));
        // A lower claim, or one out of reach of the last, is another claim: a new run.
        assert_eq!(judge(100, edge + 1, &mut d, at(70), gap), Verdict::Disputed);
        assert_eq!(d.ahead.map(|run| run.since), Some(at(70)));
        let far = edge + 2 + MAX_HEAD_JUMP;
        assert_eq!(judge(100, far, &mut d, at(72), gap), Verdict::Disputed);
        assert_eq!(d.ahead.map(|run| run.since), Some(at(72)));
        assert_eq!(judge(100, far, &mut d, at(84), gap), Verdict::Disputed);
        assert_eq!(judge(100, far, &mut d, at(96), gap), Verdict::Disputed);
        // Old enough, and still the number the run started with: a node repeating itself.
        assert_eq!(judge(100, far, &mut d, at(108), gap), Verdict::Disputed);
        // Grown by a block, it is a chain.
        assert_eq!(judge(100, far + 1, &mut d, at(109), gap), Verdict::Reanchor);
    }

    /// A poll slower than a slot still gets a run: four of its readings may be one.
    #[test]
    fn the_gap_between_readings_of_a_run_follows_a_slow_poll() {
        let gap = |poll_ms: u64| {
            let (tx, _rx) = watch::channel(Head::default());
            Standing::new(tx, test_head_metrics(), Duration::from_millis(poll_ms)).gap
        };
        assert_eq!(gap(250), DISPUTE_GAP);
        assert_eq!(gap(3_000), DISPUTE_GAP);
        assert_eq!(gap(15_000), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn publishes_the_head_and_never_moves_it_backwards() {
        let rpc = MockRpc::spawn(100).await;
        let poll = Duration::from_millis(20);
        let mut head_tasks = crate::tasks::Tasks::default();
        let mut head = spawn(
            &mut head_tasks,
            client(&rpc),
            poll,
            POLL_TIMEOUT,
            None,
            test_head_metrics(),
        );
        tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 100))
            .await
            .expect("the current head must be published")
            .unwrap();

        rpc.set_head(101);
        tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 101))
            .await
            .expect("a new head must be published")
            .unwrap();

        // A replica behind the one that answered before, as a load balancer can hand
        // out: no pair may be rolled back to a block it has already quoted past.
        rpc.set_head(99);
        let seen = rpc.calls("eth_blockNumber").len();
        assert!(
            rpc.wait_for_calls("eth_blockNumber", seen + 3, Duration::from_secs(2))
                .await,
            "polling must continue"
        );
        assert_eq!(
            head.borrow().number,
            101,
            "the head must never move backwards"
        );
    }

    /// A polled head carries the block's header too — timestamp and base fee are what
    /// an update is stamped from — so the pairs never fetch the block themselves.
    #[tokio::test]
    async fn a_polled_head_carries_the_blocks_header() {
        let rpc = MockRpc::spawn(100).await;
        let mut head_tasks = crate::tasks::Tasks::default();
        let mut head = spawn(
            &mut head_tasks,
            client(&rpc),
            Duration::from_millis(20),
            POLL_TIMEOUT,
            None,
            test_head_metrics(),
        );
        let head =
            *tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 100))
                .await
                .expect("the current head must be published")
                .unwrap();
        assert_eq!(head.timestamp, rpc.timestamp_of(100));
        assert_eq!(head.base_fee_per_gas, Some(1_000_000_000));
    }

    /// reqwest's client has no request timeout of its own, so a hung RPC — TCP alive,
    /// never answering — would otherwise hold the one poll forever, and every pair with
    /// it: nothing would ever roll to the next block again, with no line saying why.
    #[tokio::test]
    async fn a_poll_the_rpc_never_answers_is_abandoned_for_the_next_one() {
        let rpc = MockRpc::spawn(100).await;
        rpc.set_delay("eth_blockNumber", Duration::from_secs(3600));
        let metrics = test_head_metrics();
        let mut head_tasks = crate::tasks::Tasks::default();
        let mut head = spawn(
            &mut head_tasks,
            client(&rpc),
            Duration::from_millis(20),
            Duration::from_millis(100),
            None,
            metrics.clone(),
        );
        assert!(
            rpc.wait_for_calls("eth_blockNumber", 1, Duration::from_secs(2))
                .await,
            "the first poll never went out"
        );
        // The RPC comes back. Only requests from now on are answered; the first one
        // stays hung, so the head can only arrive through a later poll.
        rpc.set_delay("eth_blockNumber", Duration::ZERO);
        tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 100))
            .await
            .expect("a hung poll must be abandoned, not waited on: the head never arrived")
            .unwrap();

        // The abandoned poll is the whole subject of this test, and it is also the one
        // event `quote_updater_head_poll_errors_total` exists to make visible: a watcher
        // whose polls are timing out stalls every pair, and before this counter the only
        // trace of it was a stderr line printed once per distinct error.
        assert!(
            metrics.poll_errors.get() >= 1,
            "the abandoned poll must be counted"
        );
        // Timed either way, like `crate::metrics::timed`: a poll that fails is exactly the
        // one whose duration matters, and a histogram that only sees successes would report
        // a hung endpoint as fast.
        assert!(
            metrics.poll_duration.get_sample_count() >= 2,
            "both the abandoned poll and the one that succeeded must be timed"
        );
        assert_eq!(
            metrics.number.get(),
            100.0,
            "the gauge must carry the head the pairs are observing"
        );
    }

    /// With a subscription, a new head arrives as the node pushes it — with its header,
    /// so nothing fetches the block — and the fast poll stands down to a slow liveness
    /// check. The current head still comes from the first poll: a node pushes only the
    /// heads that follow the subscription.
    #[tokio::test]
    async fn a_subscription_delivers_new_heads_with_their_header_and_stops_the_polling() {
        let rpc = MockRpc::spawn(100).await;
        let mut head_tasks = crate::tasks::Tasks::default();
        let mut head = spawn(
            &mut head_tasks,
            client(&rpc),
            Duration::from_millis(20),
            POLL_TIMEOUT,
            Some(rpc.ws_url.clone()),
            test_head_metrics(),
        );
        tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 100))
            .await
            .expect("the current head must be published")
            .unwrap();
        assert!(
            rpc.wait_for_calls("eth_subscribe", 1, Duration::from_secs(2))
                .await,
            "never subscribed"
        );

        // Fifteen fast-poll intervals: subscribed, at most one poll may go out.
        let polled = rpc.calls("eth_blockNumber").len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            rpc.calls("eth_blockNumber").len() <= polled + 1,
            "still polling at the fast cadence while subscribed"
        );

        let fetched = rpc.calls("eth_getBlockByNumber").len();
        rpc.set_head(101);
        let pushed =
            *tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 101))
                .await
                .expect("the pushed head never arrived")
                .unwrap();
        assert_eq!(pushed.timestamp, rpc.timestamp_of(101));
        assert_eq!(pushed.base_fee_per_gas, Some(1_000_000_000));
        assert_eq!(
            rpc.calls("eth_getBlockByNumber").len(),
            fetched,
            "a pushed head must not be fetched again"
        );
    }

    /// A subscription endpoint that is down costs nothing but the polling that was
    /// there anyway; the head keeps arriving through it.
    #[tokio::test]
    async fn polling_carries_the_head_while_the_subscription_is_down() {
        let rpc = MockRpc::spawn(100).await;
        // A port nothing listens on: bound, then released.
        let dead = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            format!("ws://{}", listener.local_addr().unwrap())
        };
        let mut head_tasks = crate::tasks::Tasks::default();
        let mut head = spawn(
            &mut head_tasks,
            client(&rpc),
            Duration::from_millis(20),
            POLL_TIMEOUT,
            Some(dead),
            test_head_metrics(),
        );
        tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 100))
            .await
            .expect("the current head must be published")
            .unwrap();
        rpc.set_head(101);
        let polled =
            *tokio::time::timeout(Duration::from_secs(2), head.wait_for(|h| h.number == 101))
                .await
                .expect("a new head must still arrive by polling")
                .unwrap();
        assert_eq!(polled.timestamp, rpc.timestamp_of(101));
    }

    /// A newHeads notification is a full header; only three fields matter here, and a
    /// provider may add or omit the rest.
    #[test]
    fn a_new_head_notification_parses_the_three_fields_it_needs() {
        let header = serde_json::json!({
            "number": "0x65",
            "timestamp": "0x6a1b2c3d",
            "baseFeePerGas": "0x3b9aca00",
            "hash": "0xabc",
            "somethingNewer": 1,
        });
        assert_eq!(
            head_from_json(&header).unwrap(),
            Head {
                number: 0x65,
                timestamp: 0x6a1b_2c3d,
                base_fee_per_gas: Some(1_000_000_000),
            }
        );
        // A pre-London header carries no base fee; it is still a head.
        let no_fee = serde_json::json!({"number": "0x1", "timestamp": "0x2"});
        assert_eq!(head_from_json(&no_fee).unwrap().base_fee_per_gas, None);
        assert!(head_from_json(&serde_json::json!({"timestamp": "0x2"})).is_err());
        assert!(
            head_from_json(&serde_json::json!({"number": "nope", "timestamp": "0x2"})).is_err()
        );
    }
}

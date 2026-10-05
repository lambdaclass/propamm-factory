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

use std::{
    sync::{
        Arc,
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
use tokio::sync::watch;
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

/// How often to poll, given the requote cadence. Blocks land every ~12s, so polling at
/// the requote cadence would spend an RPC round-trip per tick for nothing; a stale view
/// only delays rolling to the next target block by up to this interval.
pub fn poll_interval(requote_ms: u64) -> Duration {
    Duration::from_millis(requote_ms.max(250))
}

/// Starts watching the head: polling `client` every `poll`, and — given `ws_url` —
/// subscribed to its `newHeads` as well. Publishes each new head with its header. The
/// value only ever rises: a lagging replica behind a load balancer answering with an
/// older head must not roll a pair back to a block it has already quoted past. The
/// tasks end once every receiver is gone.
pub fn spawn(
    tasks: &mut crate::tasks::Tasks,
    client: EthClient,
    poll: Duration,
    poll_timeout: Duration,
    ws_url: Option<String>,
    metrics: HeadMetrics,
) -> watch::Receiver<Head> {
    let (tx, rx) = watch::channel(Head::default());
    let tx = Arc::new(tx);
    let subscribed = Arc::new(AtomicBool::new(false));
    if let Some(url) = ws_url {
        tasks.spawn(subscribe_forever(
            url,
            tx.clone(),
            subscribed.clone(),
            metrics.clone(),
        ));
    }
    tasks.spawn(poll_forever(
        client,
        poll,
        poll_timeout,
        tx,
        subscribed,
        metrics,
    ));
    rx
}

/// Publishes `head` unless an equal or later one already stands.
///
/// Also the one site that writes `head_number`, and inside the accepted branch: this is the
/// only place the channel's value changes, and both ways a head arrives — the poll and the
/// subscription — come through here, so the gauge cannot drift from what the pairs actually
/// observe. Not written on a rejected head: a lagging replica answering with an older block
/// must no more move the gauge than it moves the channel.
fn publish(tx: &watch::Sender<Head>, head: Head, metrics: &HeadMetrics) {
    tx.send_if_modified(|current| {
        if head.number > current.number {
            *current = head;
            metrics.number.set(head.number as f64);
            true
        } else {
            false
        }
    });
}

async fn poll_forever(
    client: EthClient,
    poll: Duration,
    poll_timeout: Duration,
    tx: Arc<watch::Sender<Head>>,
    subscribed: Arc<AtomicBool>,
    metrics: HeadMetrics,
) {
    let mut last_error: Option<String> = None;
    loop {
        if tx.is_closed() {
            return;
        }
        // Timed and counted here rather than inside `poll_once`: this is where the verdict
        // is consumed, and a timer around the call covers the block fetch `poll_once` makes
        // when the head moved — which is part of what a pair waits for, and is exactly what
        // a timer inside the number fetch would leave out.
        let started = std::time::Instant::now();
        let polled = poll_once(&client, poll_timeout, &tx, &metrics).await;
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

/// One poll: the block number, and the block's header when the number has moved past
/// what stands. Returns the number polled.
async fn poll_once(
    client: &EthClient,
    poll_timeout: Duration,
    tx: &watch::Sender<Head>,
    metrics: &HeadMetrics,
) -> Result<u64> {
    let number = tokio::time::timeout(poll_timeout, client.get_block_number())
        .await
        .map_err(|_| eyre!("no answer in {poll_timeout:?}"))??;
    if number > tx.borrow().number {
        // `latest`, not `number`: the chain may have moved again meanwhile, and the
        // latest block is the parent a pair wants either way.
        let block =
            bounded(client.get_block_by_number(BlockIdentifier::Tag(BlockTag::Latest), false))
                .await
                .wrap_err("failed to fetch latest block")?;
        publish(tx, Head::from(&block.header), metrics);
    }
    Ok(number)
}

async fn subscribe_forever(
    url: String,
    tx: Arc<watch::Sender<Head>>,
    subscribed: Arc<AtomicBool>,
    metrics: HeadMetrics,
) {
    // The host only, never the URL: a provider's key rides in the path.
    let host = Url::parse(&url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned());
    let mut last_error: Option<String> = None;
    loop {
        let outcome = subscription(&url, &host, &tx, &subscribed, &metrics).await;
        subscribed.store(false, Ordering::Relaxed);
        if tx.is_closed() {
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
    tx: &watch::Sender<Head>,
    subscribed: &AtomicBool,
    metrics: &HeadMetrics,
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
                    publish(tx, head_from_json(&reply["params"]["result"])?, metrics);
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

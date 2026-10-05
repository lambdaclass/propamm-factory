//! Builder maker endpoint: streams signed quote-update transactions to a block builder as
//! Protocol Buffers messages over an authenticated WebSocket, instead of submitting them
//! to an RPC node. Titan defined this protocol
//! (<https://docs.titanbuilder.xyz/propamms/makers>) and other builders implement it, so
//! nothing here is specific to one of them: an endpoint, an `Authorization` key, and these
//! two messages are the whole interface.
//!
//! The wire messages (PWebsocketQuoteUpdateV1Args/Response) are small and fixed, so the
//! protobuf encoding is done by hand below rather than pulling in a codegen toolchain.

use eyre::{Result, WrapErr, bail, ensure, eyre};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

use crate::ws;

/// One PWebsocketQuoteUpdateV1Args message: a quote update valid for a single block that
/// supersedes the previous update with the same uuid — and withdraws it when `tx` is
/// empty.
pub struct QuoteUpdate<'a> {
    /// Raw signed transaction (type byte + RLP). Empty cancels the quote.
    pub tx: &'a [u8],
    /// The single block this quote is valid for.
    pub block_number: u64,
    /// 16-byte quote identity, stable for the lifetime of the maker session.
    pub replacement_uuid: [u8; 16],
    /// Must strictly increase with every message for the same uuid.
    pub replacement_seq_number: u64,
    /// Keep the quote in the region it was submitted to.
    pub disable_cross_region_sharing: bool,
    /// token0 ++ token1 pairs whose prices this update influences.
    pub asset_pairs: &'a [[u8; 40]],
    /// The contract takers quote against.
    pub quote_address: [u8; 20],
    /// The pools this update applies to.
    pub pool_addresses: &'a [[u8; 20]],
}

/// The builder's PWebsocketQuoteUpdateV1Response to one update.
#[derive(Debug, Default, PartialEq)]
pub struct Ack {
    pub replacement_uuid: Vec<u8>,
    pub replacement_seq_number: u64,
    /// When the RPC received the update, UNIX nanoseconds.
    pub timestamp: u64,
    /// Empty on success.
    pub error: String,
}

/// A connection to one regional maker endpoint.
pub struct BuilderClient {
    ws: ws::Stream,
}

impl BuilderClient {
    /// Connects with the onboarding-issued API key in the Authorization header.
    pub async fn connect(url: &str, api_key: &str) -> Result<Self> {
        let mut request = url
            .into_client_request()
            .wrap_err("invalid builder endpoint")?;
        request.headers_mut().insert(
            "Authorization",
            api_key
                .parse()
                .wrap_err("API key is not a valid header value")?,
        );
        let ws = ws::connect(request).await?;
        Ok(Self { ws })
    }

    /// Writes one quote update and returns as soon as it is on the wire. Its response
    /// arrives through `read_ack`, whichever order the builder answers in: matching a
    /// response to the update it answers is the caller's job (see quoting.rs), which is
    /// what lets a caller keep several updates in flight.
    pub async fn write(&mut self, update: &QuoteUpdate<'_>) -> Result<()> {
        self.ws
            .send(Message::Binary(encode_quote_update(update).into()))
            .await
            .wrap_err("send failed")
    }

    /// The next response the builder sends. Errors once the connection is closed or
    /// unreadable. Cancel-safe: dropping it mid-wait loses nothing, so it can sit in a
    /// `select!` alongside the caller's other work.
    pub async fn read_ack(&mut self) -> Result<Ack> {
        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or_else(|| eyre!("connection closed"))?
                .wrap_err("read failed")?;
            match msg {
                Message::Binary(bytes) => return decode_ack(&bytes),
                Message::Close(frame) => bail!("connection closed: {frame:?}"),
                // tungstenite answers pings by itself while the stream is polled.
                _ => {}
            }
        }
    }
}

/// Whether `key` can be sent as the `Authorization` header. `connect` parses it into a
/// header value, and a key with a stray newline or a non-ASCII byte fails there; exposing
/// the predicate lets config validation reject it at startup, naming the builder.
pub fn is_valid_api_key(key: &str) -> bool {
    key.parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
        .is_ok()
}

// ---- Protobuf wire codec ----
//
// Only what the two messages need: wire type 0 (varint) and 2 (length-delimited).
// proto3 field presence: a field holding its default value (0, false, empty) is omitted
// on encode, which is also what makes an empty `tx` a cancel on the wire.

fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

fn put_uint(buf: &mut Vec<u8>, field: u64, value: u64) {
    put_varint(buf, field << 3);
    put_varint(buf, value);
}

fn put_bytes(buf: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_varint(buf, (field << 3) | 2);
    put_varint(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

fn encode_quote_update(update: &QuoteUpdate<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    if !update.tx.is_empty() {
        put_bytes(&mut buf, 1, update.tx);
    }
    if update.block_number != 0 {
        put_uint(&mut buf, 2, update.block_number);
    }
    put_bytes(&mut buf, 3, &update.replacement_uuid);
    if update.replacement_seq_number != 0 {
        put_uint(&mut buf, 4, update.replacement_seq_number);
    }
    if update.disable_cross_region_sharing {
        put_uint(&mut buf, 5, 1);
    }
    for pair in update.asset_pairs {
        put_bytes(&mut buf, 6, pair);
    }
    put_bytes(&mut buf, 7, &update.quote_address);
    for pool in update.pool_addresses {
        put_bytes(&mut buf, 8, pool);
    }
    buf
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos).ok_or_else(|| eyre!("truncated varint"))?;
        *pos += 1;
        ensure!(shift < 64, "varint too long");
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

fn get_bytes<'a>(buf: &'a [u8], pos: &mut usize, field: u64) -> Result<&'a [u8]> {
    let len = get_varint(buf, pos)? as usize;
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| eyre!("truncated field {field}"))?;
    let bytes = &buf[*pos..end];
    *pos = end;
    Ok(bytes)
}

/// Decodes a PWebsocketQuoteUpdateV1Response, skipping unknown fields so a server that
/// grows new ones keeps working.
fn decode_ack(buf: &[u8]) -> Result<Ack> {
    let mut ack = Ack::default();
    let mut pos = 0;
    while pos < buf.len() {
        let tag = get_varint(buf, &mut pos)?;
        let (field, wire) = (tag >> 3, tag & 7);
        match wire {
            0 => {
                let v = get_varint(buf, &mut pos)?;
                match field {
                    2 => ack.replacement_seq_number = v,
                    3 => ack.timestamp = v,
                    _ => {}
                }
            }
            2 => {
                let bytes = get_bytes(buf, &mut pos, field)?;
                match field {
                    1 => ack.replacement_uuid = bytes.to_vec(),
                    4 => ack.error = String::from_utf8_lossy(bytes).into_owned(),
                    _ => {}
                }
            }
            1 | 5 => {
                // Fixed 64/32-bit scalars: no current field uses them; skip.
                let width = if wire == 1 { 8 } else { 4 };
                ensure!(pos + width <= buf.len(), "truncated field {field}");
                pos += width;
            }
            _ => bail!("unsupported wire type {wire} for field {field}"),
        }
    }
    Ok(ack)
}

/// A local endpoint that speaks the maker protocol, for driving clients and builder tasks
/// in tests without an API key, a network, or a chain. Lives outside `mod tests` so
/// `quoting.rs` can use it too.
#[cfg(test)]
pub(crate) mod mock {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{
            Message,
            handshake::server::{Request, Response},
        },
    };

    use super::{Ack, get_bytes, get_varint, put_bytes, put_uint};

    /// How a mock endpoint behaves. Each variant's counter is per connection, so a
    /// reconnect starts the behaviour over while the recorded updates accumulate.
    pub(crate) enum Behaviour {
        /// Ack every update.
        Ack,
        /// Read every update and never respond. The hung-builder case: this is what makes
        /// a shared send loop dangerous, since `send` waits ACK_TIMEOUT for each one.
        Silent,
        /// Ack `n` updates, then close the socket.
        CloseAfter(usize),
        /// Accept the TCP connection, then drop it before the WebSocket handshake
        /// completes. The connect attempt fails just as it would against a dead
        /// endpoint, but — unlike a closed port, which fails before the server sees
        /// anything at all — each attempt leaves a countable trace in
        /// `Mock::connect_attempts`, which is what a redial-throttling test needs.
        DropConnection,
        /// Ack every update with the given non-empty error: reachable and answering, but
        /// saying no. The realistic misconfiguration this stands in for is a builder
        /// quoting a pool or pair it does not recognize.
        Reject(&'static str),
        /// Ack every update, but only this long after receiving it, while still reading
        /// the next update the moment it arrives: a builder that is quick to receive and
        /// slow to answer, which is what makes waiting for each ack before the next
        /// write cost latency.
        SlowAck(Duration),
    }

    /// One update as the endpoint saw it on the wire.
    #[derive(Clone, Debug, PartialEq)]
    pub(crate) struct Received {
        pub tx: Vec<u8>,
        pub block_number: u64,
        pub uuid: Vec<u8>,
        pub seq: u64,
        /// When it arrived, for tests about what a task was sending at a given moment.
        pub at: std::time::Instant,
    }

    pub(crate) struct Mock {
        pub url: String,
        received: Arc<Mutex<Vec<Received>>>,
        connect_attempts: Arc<Mutex<usize>>,
    }

    impl Mock {
        pub(crate) fn received(&self) -> Vec<Received> {
            self.received.lock().unwrap().clone()
        }

        pub(crate) fn count(&self) -> usize {
            self.received.lock().unwrap().len()
        }

        /// How many TCP connections this endpoint has accepted, counted independently of
        /// `received`: a `DropConnection` endpoint never gets far enough to record an
        /// update, so this is the only observable trace of a redial attempt.
        pub(crate) fn connect_attempts(&self) -> usize {
            *self.connect_attempts.lock().unwrap()
        }

        /// Waits until at least `n` updates have arrived. Returns false on timeout, so a
        /// failing assertion can report the count it did reach.
        pub(crate) async fn wait_for(&self, n: usize, timeout: Duration) -> bool {
            tokio::time::timeout(timeout, async {
                while self.count() < n {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok()
        }
    }

    /// Binds an ephemeral port and serves `behaviour` until dropped.
    pub(crate) async fn spawn(behaviour: Behaviour) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}/ws/sendquoteupdate");
        let received = Arc::new(Mutex::new(Vec::new()));
        let connect_attempts = Arc::new(Mutex::new(0usize));
        let recorder = received.clone();
        let attempts = connect_attempts.clone();
        tokio::spawn(async move {
            // Accept repeatedly: a reconnect must find the endpoint still there.
            while let Ok((stream, _)) = listener.accept().await {
                *attempts.lock().unwrap() += 1;
                if matches!(behaviour, Behaviour::DropConnection) {
                    // Drop before the WebSocket handshake: the connect still fails, but
                    // the attempt above is now on the record.
                    continue;
                }
                let recorder = recorder.clone();
                // Reject answers every update, same as Ack, just with an error string
                // instead of an empty one.
                let limit = match behaviour {
                    Behaviour::Ack | Behaviour::Reject(_) | Behaviour::SlowAck(_) => usize::MAX,
                    Behaviour::Silent => 0,
                    Behaviour::CloseAfter(n) => n,
                    // Handled above, before this stream reaches the handshake.
                    Behaviour::DropConnection => unreachable!(),
                };
                let closes = matches!(behaviour, Behaviour::CloseAfter(_));
                let reject = match behaviour {
                    Behaviour::Reject(msg) => msg,
                    _ => "",
                };
                let ack_delay = match behaviour {
                    Behaviour::SlowAck(delay) => Some(delay),
                    _ => None,
                };
                tokio::spawn(async move {
                    // accept_hdr_async fixes the callback's Result type, so the size of
                    // its Err variant is not ours to shrink.
                    #[allow(clippy::result_large_err)]
                    let ws = accept_hdr_async(stream, |_: &Request, resp: Response| Ok(resp))
                        .await
                        .unwrap();
                    // Reads and writes are decoupled, so a delayed ack never holds up the
                    // read of the next update. Every ack goes through one writer task;
                    // when the last sender is gone it exits and the sink closes with it.
                    let (mut sink, mut stream) = ws.split();
                    let (acks, mut to_write) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    let writer = tokio::spawn(async move {
                        while let Some(bytes) = to_write.recv().await {
                            if sink.send(Message::Binary(bytes.into())).await.is_err() {
                                return;
                            }
                        }
                    });
                    let mut acked = 0usize;
                    while let Some(Ok(Message::Binary(bytes))) = stream.next().await {
                        let (tx, block_number, uuid, seq) = decode_update(&bytes);
                        recorder.lock().unwrap().push(Received {
                            tx,
                            block_number,
                            uuid: uuid.clone(),
                            seq,
                            at: std::time::Instant::now(),
                        });
                        if acked >= limit {
                            if closes {
                                break;
                            }
                            continue; // hold the socket open, answer nothing
                        }
                        acked += 1;
                        let ack = encode_ack(&Ack {
                            replacement_uuid: uuid,
                            replacement_seq_number: seq,
                            timestamp: 1,
                            error: reject.to_owned(),
                        });
                        match ack_delay {
                            Some(delay) => {
                                let acks = acks.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    let _ = acks.send(ack);
                                });
                            }
                            None => {
                                let _ = acks.send(ack);
                            }
                        }
                    }
                    // Closing: drop both halves so the connection goes with them.
                    drop(acks);
                    drop(stream);
                    let _ = writer.await;
                });
            }
        });
        Mock {
            url,
            received,
            connect_attempts,
        }
    }

    /// Test-side encoder for the response message (what a real builder sends back). Body
    /// moved verbatim from `mod tests`, changing only the visibility, so the hand-computed
    /// field tags cannot drift from the codec they mirror.
    pub(crate) fn encode_ack(ack: &Ack) -> Vec<u8> {
        let mut buf = Vec::new();
        if !ack.replacement_uuid.is_empty() {
            put_bytes(&mut buf, 1, &ack.replacement_uuid);
        }
        if ack.replacement_seq_number != 0 {
            put_uint(&mut buf, 2, ack.replacement_seq_number);
        }
        if ack.timestamp != 0 {
            put_uint(&mut buf, 3, ack.timestamp);
        }
        if !ack.error.is_empty() {
            put_bytes(&mut buf, 4, ack.error.as_bytes());
        }
        buf
    }

    /// Test-side decoder for the update message: (tx, block_number, uuid, seq). Body moved
    /// verbatim from `mod tests`, changing only the visibility.
    pub(crate) fn decode_update(buf: &[u8]) -> (Vec<u8>, u64, Vec<u8>, u64) {
        let (mut tx, mut block, mut uuid, mut seq) = (Vec::new(), 0, Vec::new(), 0);
        let mut pos = 0;
        while pos < buf.len() {
            let tag = get_varint(buf, &mut pos).unwrap();
            match (tag >> 3, tag & 7) {
                (1, 2) => tx = get_bytes(buf, &mut pos, 1).unwrap().to_vec(),
                (2, 0) => block = get_varint(buf, &mut pos).unwrap(),
                (3, 2) => uuid = get_bytes(buf, &mut pos, 3).unwrap().to_vec(),
                (4, 0) => seq = get_varint(buf, &mut pos).unwrap(),
                (_, 0) => {
                    get_varint(buf, &mut pos).unwrap();
                }
                (f, 2) => {
                    get_bytes(buf, &mut pos, f).unwrap();
                }
                other => panic!("unexpected tag {other:?}"),
            }
        }
        (tx, block, uuid, seq)
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{decode_update, encode_ack};
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 1, 127, 128, 300, 0xffff_ffff, u64::MAX] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(get_varint(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len());
        }
        // 300 is the canonical two-byte example: 0xAC 0x02.
        let mut buf = Vec::new();
        put_varint(&mut buf, 300);
        assert_eq!(buf, [0xac, 0x02]);
    }

    #[test]
    fn encode_quote_update_matches_hand_computed_bytes() {
        let update = QuoteUpdate {
            tx: &[0xde, 0xad],
            block_number: 3,
            replacement_uuid: [0x11; 16],
            replacement_seq_number: 7,
            disable_cross_region_sharing: false,
            asset_pairs: &[[0xaa; 40]],
            quote_address: [0xbb; 20],
            pool_addresses: &[[0xcc; 20]],
        };
        let mut want = vec![0x0a, 0x02, 0xde, 0xad]; // 1: tx
        want.extend([0x10, 0x03]); // 2: block_number
        want.extend([0x1a, 0x10]); // 3: uuid
        want.extend([0x11; 16]);
        want.extend([0x20, 0x07]); // 4: seq (5 omitted: false)
        want.extend([0x32, 0x28]); // 6: asset pair
        want.extend([0xaa; 40]);
        want.extend([0x3a, 0x14]); // 7: quote address
        want.extend([0xbb; 20]);
        want.extend([0x42, 0x14]); // 8: pool address
        want.extend([0xcc; 20]);
        assert_eq!(encode_quote_update(&update), want);
    }

    #[test]
    fn cancel_omits_the_tx_field() {
        let update = QuoteUpdate {
            tx: &[],
            block_number: 3,
            replacement_uuid: [0x11; 16],
            replacement_seq_number: 8,
            disable_cross_region_sharing: true,
            asset_pairs: &[],
            quote_address: [0xbb; 20],
            pool_addresses: &[],
        };
        let encoded = encode_quote_update(&update);
        let (tx, block, uuid, seq) = decode_update(&encoded);
        assert!(tx.is_empty());
        assert_eq!((block, seq), (3, 8));
        assert_eq!(uuid, [0x11; 16]);
        // 5: disable_cross_region_sharing = true is on the wire.
        assert!(encoded.windows(2).any(|w| w == [0x28, 0x01]));
    }

    #[test]
    fn decode_ack_round_trips_and_skips_unknown_fields() {
        let ack = Ack {
            replacement_uuid: vec![9; 16],
            replacement_seq_number: 300,
            timestamp: 1_755_000_000_000_000_000,
            error: "quote too old".into(),
        };
        let mut buf = encode_ack(&ack);
        // Unknown varint field 9, unknown bytes field 10, unknown fixed32 field 11:
        // all must be skipped, not break decoding.
        put_uint(&mut buf, 9, 5);
        put_bytes(&mut buf, 10, b"future");
        put_varint(&mut buf, (11 << 3) | 5);
        buf.extend([1, 2, 3, 4]);
        assert_eq!(decode_ack(&buf).unwrap(), ack);
    }

    #[test]
    fn decode_ack_rejects_truncated_input() {
        let mut buf = Vec::new();
        put_bytes(&mut buf, 1, &[1; 16]);
        buf.pop(); // cut the last uuid byte
        assert!(decode_ack(&buf).is_err());
        assert!(decode_ack(&[0x80]).is_err()); // unterminated varint
    }

    /// End to end over a local mock endpoint: the Authorization header arrives, the
    /// update decodes on the server side, and every response comes back through
    /// `read_ack` in the order the builder sent it — a stale one first, then the one
    /// that answers the update — for the caller to match.
    // accept_hdr_async fixes the handshake callback's Result type, so the size of its Err
    // variant is not ours to shrink.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn client_sends_update_and_matches_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let auth = Arc::new(Mutex::new(None::<String>));
        let auth_seen = auth.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
                *auth_seen.lock().unwrap() = req
                    .headers()
                    .get("Authorization")
                    .map(|v| v.to_str().unwrap().to_owned());
                Ok(resp)
            })
            .await
            .unwrap();
            let Some(Ok(Message::Binary(bytes))) = ws.next().await else {
                panic!("no update frame");
            };
            let (tx, block, uuid, seq) = decode_update(&bytes);
            assert_eq!(tx, [0xde, 0xad]);
            assert_eq!(block, 100);
            // A response to an older update still in flight: the client must skip it.
            let stale = Ack {
                replacement_uuid: uuid.clone(),
                replacement_seq_number: seq - 1,
                timestamp: 1,
                error: String::new(),
            };
            ws.send(Message::Binary(encode_ack(&stale).into()))
                .await
                .unwrap();
            let ack = Ack {
                replacement_uuid: uuid,
                replacement_seq_number: seq,
                timestamp: 42,
                error: String::new(),
            };
            ws.send(Message::Binary(encode_ack(&ack).into()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let url = format!("ws://{addr}/ws/sendquoteupdate");
        let mut client = BuilderClient::connect(&url, "test-key").await.unwrap();
        client
            .write(&QuoteUpdate {
                tx: &[0xde, 0xad],
                block_number: 100,
                replacement_uuid: [7; 16],
                replacement_seq_number: 3,
                disable_cross_region_sharing: false,
                asset_pairs: &[[0xaa; 40]],
                quote_address: [0xbb; 20],
                pool_addresses: &[[0xcc; 20]],
            })
            .await
            .unwrap();
        let stale = client.read_ack().await.unwrap();
        assert_eq!(stale.replacement_seq_number, 2);
        let ack = client.read_ack().await.unwrap();
        assert_eq!(ack.replacement_seq_number, 3);
        assert_eq!(ack.timestamp, 42);
        assert!(ack.error.is_empty());
        assert_eq!(auth.lock().unwrap().as_deref(), Some("test-key"));
    }

    #[test]
    fn mock_port_defaults_and_parses() {
        assert_eq!(mock_port(None), 8560);
        assert_eq!(mock_port(Some("8561")), 8561);
        // Garbage falls back to the default rather than panicking a hand-run mock.
        assert_eq!(mock_port(Some("")), 8560);
        assert_eq!(mock_port(Some("not-a-port")), 8560);
    }

    /// The port `builder_mock_server` listens on, from BUILDER_MOCK_PORT. Kept pure so it is
    /// testable without touching the environment, which other tests share.
    fn mock_port(raw: Option<&str>) -> u16 {
        raw.and_then(|value| value.parse().ok()).unwrap_or(8560)
    }

    /// Not a test: a long-running local mock of a builder's maker endpoint, for smoke-testing
    /// the binary by hand without an API key. Acks every update it receives and prints it.
    /// Run one per builder you want to fan out to:
    ///   BUILDER_MOCK_PORT=8560 cargo test builder_mock_server -- --ignored --nocapture &
    ///   BUILDER_MOCK_PORT=8561 cargo test builder_mock_server -- --ignored --nocapture &
    // See client_sends_update_and_matches_ack: the callback's Err type comes from tungstenite.
    #[allow(clippy::print_stdout)] // a terminal tool a person runs, not library output
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    #[ignore = "long-running mock endpoint, run explicitly"]
    async fn builder_mock_server() {
        let port = mock_port(std::env::var("BUILDER_MOCK_PORT").ok().as_deref());
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        println!("mock builder listening on ws://127.0.0.1:{port}/ws/sendquoteupdate");
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
                    // Presence only, never the value: this mock exists so operators can
                    // repoint a real `builders.toml` at it for a smoke test, which makes
                    // printing the header's value the same as printing a live API key.
                    println!(
                        "[{peer}] connected, Authorization: {}",
                        if req.headers().get("Authorization").is_some() {
                            "present"
                        } else {
                            "absent"
                        }
                    );
                    Ok(resp)
                })
                .await
                .unwrap();
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Binary(bytes) = msg else {
                        continue;
                    };
                    let (tx, block, uuid, seq) = decode_update(&bytes);
                    println!(
                        "[{peer}] {} block {block} seq {seq} uuid {} ({} tx bytes)",
                        if tx.is_empty() { "CANCEL" } else { "quote " },
                        hex::encode(&uuid),
                        tx.len(),
                    );
                    let ack = Ack {
                        replacement_uuid: uuid,
                        replacement_seq_number: seq,
                        timestamp: 1,
                        error: String::new(),
                    };
                    let _ = ws.send(Message::Binary(encode_ack(&ack).into())).await;
                }
            });
        }
    }
}

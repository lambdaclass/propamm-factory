//! Did the update land? The per-block `getState` read-back both send paths verify with,
//! the miss counter the `PusherLandingUnverified` alert reads, and the signer-runway check
//! priced off the same block. The constants the alert rules mirror live at the crate root
//! (`NOT_LANDING_BLOCKS`, `RUNWAY_CHECK_BLOCKS`) and in `update.rs` (`MAX_PRICE_AGE`,
//! `BLOCK_TIME_SECS`); the test at the bottom pins the rules file to them.

use std::collections::HashSet;

use ethrex_common::{Address, U256};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_sdk::calldata::encode_calldata;
use ethrex_rpc::{clients::eth::EthClient, types::block_identifier::BlockIdentifier};
use eyre::Result;

use crate::{
    NOT_LANDING_BLOCKS,
    metrics::{self, LandingResult, RpcCall},
    pair::SendOpts,
    preflight,
    rpc::{bounded, call_view, decode_return_data},
};

const GET_STATE_SIG: &str = "getState(uint256,uint32,uint32)";

/// `getState(lane, 0, u32::MAX)` calldata — a lane read over the whole timestamp window.
///
/// The window is deliberately maximal wherever this is used: a window that excludes the
/// stored timestamp makes the registry revert `StaleUpdate` (`PrioUpdateRegistry.sol:99`),
/// and through `eth_call` a revert is indistinguishable from an RPC failure. Over the full
/// window a never-written lane reads as timestamp 0 instead, which is a miss the caller can
/// tell apart from an error.
pub(crate) fn get_state_calldata(lane: U256) -> Result<Vec<u8>> {
    Ok(encode_calldata(
        GET_STATE_SIG,
        &[
            Value::Uint(lane),
            Value::Uint(U256::zero()),
            Value::Uint(u32::MAX.into()),
        ],
    )?)
}

/// Whether a pair's update for one target block reached the chain.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Landing {
    /// Nothing was quoted for the block — the feed was stale, or the quote was withdrawn —
    /// so nothing was expected to land and the block says nothing about the pair's health.
    NotQuoted,
    Landed,
    /// A transaction was quoted for the block and the lane does not hold it.
    Missed,
    /// The lane holds an update stamped for the block, its price is none of the ones this
    /// process signed for it, and this pair's key landed nothing in the block: another key
    /// wrote the lane. The registry authorizes an updater for every lane of its target, so
    /// any other pair's key can.
    Foreign,
    /// The read-back itself failed, so inclusion is unknown. Never counted as landed: an
    /// unverifiable state must not render as a healthy one.
    Unknown,
}

/// Reads a lane back at `block` the way the target would, and reports whether this pair's
/// update for that block is what it holds.
///
/// Without this the builder path has no landed-verification at all. `sign_update_tx`
/// overrides the gas limit, so nothing estimates gas and nothing touches the balance:
/// signing succeeds, the builders ack, and the per-block line prints normally while the
/// transaction can never be included. A key that has run dry, a builder dropping the
/// quote, wrong `asset_pairs` semantics and a missed slot that makes `ts` wrong all
/// render identically to success until something reads the lane.
///
/// `signed` is every `(delta, mid)` this pair signed for the block. The timestamp alone
/// cannot say whose update the lane holds: the registry takes a write only in the block
/// whose timestamp it carries, so every write to a lane in one block is stamped alike, and
/// another key's write used to be booked here as this pair's update landing.
///
/// A price that is none of those is not yet another key's. This process is not the only
/// thing that signs with this pair's key: the loop that ran before a restart or a reload
/// did, moments ago and for this same block, and so does a second updater left running.
/// `signer` settles it: the key, and the nonce every update this loop signed for the block
/// carried. If the key's nonce at the block is past that one, a transaction of the key's
/// is in the chain by this block, and the lane's update is the pair's own
/// ([`attribution`]).
///
/// One `eth_call` per pair per block, next to the process-wide head watcher's polls (~48
/// per block at the default cadence, or a slow liveness check under a subscription), and a
/// nonce read on the rare block whose price this process did not sign.
// Eight: the seven things a read-back is of, and the signer that settles whose it is.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_landed(
    client: &EthClient,
    metrics: &metrics::PairMetrics,
    opts: &SendOpts,
    lane: U256,
    ts: u32,
    block: u64,
    signed: &HashSet<(U256, U256)>,
    signer: (Address, u64),
) -> Landing {
    let Ok(calldata) = get_state_calldata(lane) else {
        return Landing::Unknown;
    };
    // Pinned to the target block, and read as the target: `getState` is scoped to
    // msg.sender, and at `latest` a later block's update would answer for this one. Wrapped
    // in `timed` under `RpcCall::EthCall`: this is the read whose failure produces
    // `Landing::Unknown`, the outcome `PusherLandingUnverified` pages on, so its error rate
    // is where an operator paged by it looks first.
    let call = metrics::timed(
        metrics,
        RpcCall::EthCall,
        call_view(
            client,
            opts.registry,
            calldata,
            Some(opts.target),
            Some(BlockIdentifier::Number(block)),
        ),
    )
    .await;
    let Ok(ret) = call else {
        return Landing::Unknown;
    };
    let landing = match decode_return_data("r(uint32,uint256[])", &ret).as_deref() {
        Ok([Value::Uint(stored), Value::Array(slots)]) => {
            landing_of(*stored == U256::from(ts), slots, signed)
        }
        _ => Landing::Unknown,
    };
    if landing != Landing::Foreign {
        return landing;
    }
    // At the block, like the lane: a nonce read at `latest` or `pending` could come from a
    // node that has not seen the block yet, and would say the key landed nothing.
    let (address, signed_with) = signer;
    let nonce = metrics::timed(
        metrics,
        RpcCall::GetNonce,
        bounded(client.get_nonce(address, BlockIdentifier::Number(block))),
    )
    .await;
    attribution(nonce.ok(), signed_with)
}

/// Whose a price this process did not sign is, from the signer's nonce at the block it is
/// stamped for (`None` when that could not be read) and the nonce this process signed the
/// block's updates with.
///
/// Past it, the key landed a transaction by this block, so the update in the lane is the
/// key's own: counted as a landing, which it is. Not past it, the key landed nothing, and
/// something else wrote the lane. One case this cannot tell apart: this key's update and
/// another key's both landing in the one block, the other's last. That reads as a landing.
fn attribution(nonce_at_block: Option<u64>, signed_with: u64) -> Landing {
    match nonce_at_block {
        Some(nonce) if nonce > signed_with => Landing::Landed,
        Some(_) => Landing::Foreign,
        // Never a foreign write on a guess: that is a page telling someone to revoke a key.
        None => Landing::Unknown,
    }
}

/// What a read-back means for a block no builder was holding this pair's quote for when it
/// was built: the feed was stale, the quote was withdrawn, nothing was ever acknowledged.
///
/// An update in the lane under the block's stamp is there all the same, whether it is one
/// this pair had signed before it withdrew (a builder is asked to drop a withdrawn quote,
/// and nothing makes it) or another key's. Nothing else says anything: no update was
/// expected, so one not being there is not a miss, and a read-back that failed is not a
/// landing nobody could verify.
pub(crate) fn unquoted(landing: Landing) -> Landing {
    match landing {
        Landing::Landed | Landing::Foreign => landing,
        Landing::Missed | Landing::Unknown | Landing::NotQuoted => Landing::NotQuoted,
    }
}

/// What a lane read back at the target block says: `stamped` is whether it carries the
/// block's timestamp, `slots` what it holds.
///
/// A pair re-signs whenever its price moves, so the builder may have included any of the
/// versions quoted during the block, and every one of them is a correct landing. A price
/// that is none of them, under this block's stamp, is not this pair's: only the first two
/// slots are compared, since the third, when there is one, is a signing instant that a
/// pair does not keep per version.
fn landing_of(stamped: bool, slots: &[Value], signed: &HashSet<(U256, U256)>) -> Landing {
    if !stamped {
        return Landing::Missed;
    }
    match slots {
        [Value::Uint(delta), Value::Uint(mid), ..] if signed.contains(&(*delta, *mid)) => {
            Landing::Landed
        }
        // Fewer than two slots included: this pair never writes that either.
        _ => Landing::Foreign,
    }
}

/// The metric label for a landing outcome. A free function with a test for the same reason
/// as `action_label`: a new `Landing` variant must fail to compile, not fall into a bucket.
/// `pub(crate)`, unlike `action_label`, because `drive` — the only caller — lives in
/// `quoting`, not here.
pub(crate) fn landing_label(landing: Landing) -> LandingResult {
    match landing {
        Landing::Landed => LandingResult::Landed,
        Landing::Missed => LandingResult::Missed,
        Landing::Foreign => LandingResult::Foreign,
        Landing::Unknown => LandingResult::Unknown,
        Landing::NotQuoted => LandingResult::NotQuoted,
    }
}

/// Turns a run of block-by-block [`Landing`]s into the few lines worth printing: nothing
/// while the lane can be read back (landed or not), one warning once the read-back has
/// failed for long enough that a blip does not explain it, and one line when it recovers.
#[derive(Default)]
pub(crate) struct LandingTracker {
    /// Consecutive quoted blocks whose read-back failed. A block where the update simply
    /// was not included (no swap) resets nothing and counts nothing: it is the normal case.
    misses: u32,
    /// Whether the current streak has already been reported, so recovery is worth a line.
    warned: bool,
}

impl LandingTracker {
    pub(crate) fn record(&mut self, landing: Landing) -> Option<String> {
        match landing {
            // A block nobody quoted for is not evidence either way, and the reason it was
            // not quoted is already logged where it happened.
            Landing::NotQuoted => None,
            // All three mean the read-back worked: the lane's state was read and had the
            // update, did not, or had someone else's. Not having it is what a block with no
            // swap looks like; someone else's is reported where it is found, every time,
            // not here.
            Landing::Landed | Landing::Missed | Landing::Foreign => {
                let misses = std::mem::take(&mut self.misses);
                std::mem::take(&mut self.warned).then(|| {
                    format!(
                        "lane readable again after {misses} block(s) that could not be verified"
                    )
                })
            }
            Landing::Unknown => {
                self.misses += 1;
                self.misses.is_multiple_of(NOT_LANDING_BLOCKS).then(|| {
                    self.warned = true;
                    format!(
                        "could not read this lane back for {} consecutive blocks; the RPC is \
                         not answering getState, so whether updates land is unknown",
                        self.misses
                    )
                })
            }
        }
    }

    /// The current miss streak, for the caller to record — this stays IO-free, like
    /// `runway_row`, so the recording site (and its test) can live where the metric handle
    /// does instead of threading one in here.
    pub(crate) fn misses(&self) -> u32 {
        self.misses
    }
}

/// One mid-run runway check: what to print, and what the two gauges should read.
///
/// One `runway_row` call, not two. `runway_alert` and `runway_gauges` used to be separate
/// functions that each priced the same key with the same arguments and threw away half of
/// what came back — one keeping the string, the other the number. The duplication was
/// harmless (the call is pure and cheap) but it meant two places could drift on what the
/// same balance means, so the recording site now takes both from one result.
///
/// `NaN` for both gauges when the balance could not be read, rather than leaving the
/// previous reading in place, which is what this used to do. A failed `eth_getBalance` left
/// both gauges holding a number priced off a balance and a base fee from the last successful
/// check — up to `RUNWAY_CHECK_BLOCKS` blocks ago, and unboundedly stale if the read kept
/// failing — so `PusherSignerNearlyDry` went on answering a question nobody had asked since.
/// A frozen gauge and a healthy one are indistinguishable to a threshold rule, which is the
/// same trap `Metrics::for_pair`'s eagerly-registered zeros sit in; `NaN` is the same answer,
/// for the same reason. `PusherSignerNearlyDry` is a `predict_linear` over
/// `signer_balance_wei`, and one NaN sample anywhere in its window makes the whole range
/// return nothing, so the page falls silent and `PusherSignerRunwayUnknown` fires instead —
/// see `deploy/alerts/quote-updater.rules.yml`. Note the silence now outlasts the
/// outage: the NaN suppresses until it ages out of the window, not just while the read is
/// failing, which is the cost of asking a regression rather than a threshold.
///
/// That trade is deliberate: losing the page while the balance is unreadable is the point.
/// `runway_row`'s own warning for this case says it out loud — "this is not a claim that
/// the key is empty" — and a page whose premise is an hour-old balance is worse than one
/// that admits it cannot see.
///
/// Pure, and separate from the recording site, so the branch that matters here is testable
/// without a chain: the happy path already has coverage through `drive`, the failed read
/// did not.
pub(crate) struct RunwayCheck {
    /// The line to print, if anything about this check is worth saying.
    pub alert: Option<String>,
    pub balance_wei: f64,
    pub runway: f64,
}

pub(crate) fn runway_check(
    address: Address,
    balance: Option<U256>,
    base_fee: Option<U256>,
) -> RunwayCheck {
    // Through `runway_row`, not a second derivation, for the reason its own doc gives: one
    // key must not be priced two ways.
    let (runway, warning) = preflight::runway_row(address, balance, base_fee);
    let alert = warning.or_else(|| {
        // `runway_row` leaves an unreadable base fee to the report-level warning, which
        // only startup prints; mid-run there is no such line, so say it here.
        (runway.is_none())
            .then(|| format!("could not read the base fee, so {address:#x}'s runway is unknown"))
    });
    let (balance_wei, runway) = match (balance, runway) {
        (Some(balance), Some(runway)) => (
            crate::feed::scaled_to_f64(balance, 0),
            // Truncated by `runway_updates`, so this is exact for every runway a u64 can
            // hold; f64 loses precision past 2^53 updates, a balance no key has.
            runway as f64,
        ),
        // Either half missing means the round produced no reading at all. Both gauges go
        // NaN together: a balance with no runway beside it invites exactly the arithmetic
        // an operator should not be doing by hand.
        _ => (f64::NAN, f64::NAN),
    };
    RunwayCheck {
        alert,
        balance_wei,
        runway,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUNWAY_CHECK_BLOCKS, UPDATE_GAS_LIMIT,
        update::{self, BLOCK_TIME_SECS},
    };

    #[test]
    fn every_landing_maps_to_its_own_label() {
        assert_eq!(landing_label(Landing::Landed), LandingResult::Landed);
        assert_eq!(landing_label(Landing::Missed), LandingResult::Missed);
        assert_eq!(landing_label(Landing::Foreign), LandingResult::Foreign);
        assert_eq!(landing_label(Landing::Unknown), LandingResult::Unknown);
        assert_eq!(landing_label(Landing::NotQuoted), LandingResult::NotQuoted);
    }

    /// The timestamp alone used to decide a landing, and every write to a lane in a block
    /// carries the same one, so a price another key wrote read as this pair's update
    /// landing. The price decides now: any version signed for the block is a landing, and
    /// anything else under the block's stamp is someone else's write.
    #[test]
    fn a_price_this_pair_never_signed_is_a_foreign_write_not_a_landing() {
        let quote = |delta: u64, mid: u64| (U256::from(delta), U256::from(mid));
        let slots = |values: &[u64]| -> Vec<Value> {
            values.iter().map(|v| Value::Uint(U256::from(*v))).collect()
        };
        // Two versions signed during the block: the price moved once.
        let signed: HashSet<(U256, U256)> = [quote(5, 4_000), quote(5, 4_001)].into();

        assert_eq!(
            landing_of(true, &slots(&[5, 4_000]), &signed),
            Landing::Landed
        );
        assert_eq!(
            landing_of(true, &slots(&[5, 4_001]), &signed),
            Landing::Landed
        );
        // With the optional third slot, which is not part of the comparison.
        assert_eq!(
            landing_of(true, &slots(&[5, 4_001, 1_700_000_000]), &signed),
            Landing::Landed
        );

        // Another key's price under this block's stamp: the mid, the spread, or both.
        assert_eq!(
            landing_of(true, &slots(&[5, 400_000]), &signed),
            Landing::Foreign
        );
        assert_eq!(
            landing_of(true, &slots(&[0, 4_000]), &signed),
            Landing::Foreign
        );
        // A lane this pair would never have written at all.
        assert_eq!(landing_of(true, &slots(&[5]), &signed), Landing::Foreign);
        assert_eq!(landing_of(true, &[], &signed), Landing::Foreign);

        // An older stamp is the ordinary block with no swap, whatever the lane holds.
        assert_eq!(
            landing_of(false, &slots(&[5, 400_000]), &signed),
            Landing::Missed
        );
        assert_eq!(
            landing_of(false, &slots(&[5, 4_000]), &signed),
            Landing::Missed
        );
    }

    /// A price this process did not sign is another key's only if this pair's key landed
    /// nothing in the block. The loop that ran before a restart signs with the same key
    /// for the same block, and its update landing used to read as a foreign write: a page
    /// telling the operator to revoke a key, for a reload late in a slot.
    #[test]
    fn a_price_another_generation_of_this_pair_signed_is_a_landing_not_a_foreign_write() {
        // Every update this loop signed for the block carried nonce 7.
        assert_eq!(
            attribution(Some(8), 7),
            Landing::Landed,
            "the key landed one"
        );
        assert_eq!(
            attribution(Some(7), 7),
            Landing::Foreign,
            "the key landed nothing"
        );
        assert_eq!(attribution(Some(3), 7), Landing::Foreign);
        assert_eq!(
            attribution(None, 7),
            Landing::Unknown,
            "an unreadable nonce is not grounds to page for a foreign write"
        );
    }

    /// A block this pair was not quoting for is still read back: a price under its stamp
    /// is there whoever wrote it. What it cannot be is a miss or an unverified landing,
    /// since nothing was expected to land.
    #[test]
    fn an_unquoted_block_reports_what_is_in_the_lane_and_nothing_that_is_not() {
        assert_eq!(unquoted(Landing::Foreign), Landing::Foreign);
        assert_eq!(unquoted(Landing::Landed), Landing::Landed);
        assert_eq!(unquoted(Landing::Missed), Landing::NotQuoted);
        assert_eq!(unquoted(Landing::Unknown), Landing::NotQuoted);
        assert_eq!(unquoted(Landing::NotQuoted), Landing::NotQuoted);
    }

    /// The steady state of a lane nobody is swapping against: block after block with the
    /// update not included. That is how the mechanism works (a builder includes the update
    /// only when a swap hits the lane), so no amount of it may produce a line.
    #[test]
    fn blocks_without_a_swap_are_never_worth_a_warning() {
        let mut tracker = LandingTracker::default();
        for _ in 0..(NOT_LANDING_BLOCKS * 3) {
            assert_eq!(tracker.record(Landing::Missed), None);
        }
        assert_eq!(tracker.misses(), 0);
        assert_eq!(tracker.record(Landing::Landed), None);
    }

    /// The failure this exists for: the read-back itself failing, block after block. Every
    /// other input is the same as the quiet case above, so only the streak of unverifiable
    /// blocks can produce the warning.
    #[test]
    fn a_lane_that_cannot_be_read_back_says_so_and_says_when_it_recovers() {
        let mut tracker = LandingTracker::default();
        for _ in 0..(NOT_LANDING_BLOCKS - 1) {
            assert_eq!(tracker.record(Landing::Unknown), None);
        }
        let warning = tracker
            .record(Landing::Unknown)
            .expect("a lane unreadable for a whole streak must be reported");
        assert!(
            warning.contains(&NOT_LANDING_BLOCKS.to_string()),
            "the warning must say how long: {warning}"
        );

        // Still broken, and still saying so, once per further streak rather than per block.
        for _ in 0..(NOT_LANDING_BLOCKS - 1) {
            assert_eq!(tracker.record(Landing::Unknown), None);
        }
        assert!(tracker.record(Landing::Unknown).is_some());

        // Recovery is a line of its own: without it, a lane that flaps leaves the operator
        // reading a warning that is no longer true. A block read back without the update in
        // it is a recovery too: the RPC answered.
        let recovery = tracker
            .record(Landing::Missed)
            .expect("recovery after a reported outage must be reported too");
        assert!(recovery.contains(&format!("{}", NOT_LANDING_BLOCKS * 2)));
        // And the counter really reset: the next outage has to earn its own warning.
        assert_eq!(tracker.record(Landing::Unknown), None);
        assert_eq!(tracker.misses(), 1);
    }

    /// A block nobody quoted for says nothing about the pair: the feed being stale is
    /// already logged where it happens, and it must not accumulate into this warning, nor
    /// hide a real outage that follows.
    #[test]
    fn a_quiet_block_neither_counts_nor_resets() {
        let mut quiet = LandingTracker::default();
        for _ in 0..(NOT_LANDING_BLOCKS * 3) {
            assert_eq!(quiet.record(Landing::NotQuoted), None);
        }
        for _ in 0..(NOT_LANDING_BLOCKS - 1) {
            assert_eq!(quiet.record(Landing::Unknown), None);
        }
        assert_eq!(quiet.record(Landing::NotQuoted), None);
        assert!(quiet.record(Landing::Unknown).is_some());
    }

    #[test]
    fn a_shortening_runway_is_reported_and_a_healthy_one_is_not() {
        let address = Address::from_low_u64_be(0xaaa1);
        let base_fee = U256::from(1_000_000_000u64); // 1 gwei
        let per_update = U256::from(UPDATE_GAS_LIMIT) * base_fee;
        // Comfortably above LOW_RUNWAY: silence is correct.
        assert_eq!(
            runway_check(
                address,
                Some(per_update * (preflight::LOW_RUNWAY + 1)),
                Some(base_fee)
            )
            .alert,
            None
        );
        // One update short of the threshold: the same key, the same fee, one wei less.
        let low = runway_check(
            address,
            Some(per_update * (preflight::LOW_RUNWAY - 1)),
            Some(base_fee),
        )
        .alert
        .expect("a key below LOW_RUNWAY must be reported");
        assert!(low.contains(&format!("{address:#x}")), "which key: {low}");

        // A balance that could not be read must not pass as a comfortable one — the
        // failure mode this whole check exists for is a key going quiet.
        let unread = runway_check(address, None, Some(base_fee))
            .alert
            .expect("an unreadable balance is not a healthy balance");
        assert!(unread.contains("unknown"), "unexpected wording: {unread}");
        assert!(
            runway_check(address, Some(per_update * 5_000u64), None)
                .alert
                .is_some()
        );
    }

    #[test]
    fn an_unreadable_balance_makes_both_runway_gauges_nan() {
        let address = Address::from_low_u64_be(0xaaa2);
        let base_fee = U256::from(1_000_000_000u64); // 1 gwei
        let per_update = U256::from(UPDATE_GAS_LIMIT) * base_fee;

        let priced = runway_check(address, Some(per_update * 8_333u64), Some(base_fee));
        assert_eq!(priced.runway, 8_333.0, "a readable balance prices exactly");
        assert_eq!(priced.balance_wei, (per_update * 8_333u64).as_u128() as f64);
        assert_eq!(priced.alert, None, "8333 updates is not worth a line");

        // The branch that had no coverage, and the whole point of the function: a failed
        // eth_getBalance must overwrite the last check's numbers, not leave them standing.
        // NaN because every comparison PusherSignerNearlyDry makes against it is false —
        // the same device `Metrics::for_pair`'s doc comment describes for a gauge that has
        // never been recorded, applied to one that has stopped being.
        let unread = runway_check(address, None, Some(base_fee));
        assert!(
            unread.runway.is_nan(),
            "an unreadable balance is not a runway"
        );
        assert!(
            unread.balance_wei.is_nan(),
            "a runway with no balance beside it invites hand arithmetic"
        );
        // The same call carries the line, so the recording site prices the key once. A
        // second `runway_row` call for the string is what this replaced.
        assert!(
            unread.alert.is_some_and(|line| line.contains("unknown")),
            "the unreadable-balance line must come from the same call as the gauges"
        );
        // Stated as the rule sees it, not just as IEEE — though what the rule does changed,
        // so this is no longer a comparison against `preflight::LOW_RUNWAY` and should not be
        // put back as one. PusherSignerNearlyDry is a `predict_linear` over
        // `signer_balance_wei`, and a regression does not compare, it fits. The property it
        // depends on is that an unread balance is not a number at all: one NaN poisons the
        // whole range and the rule returns nothing, where a future `0.0` here would be fitted
        // as the key hitting empty — paging hardest at the exact moment nothing has managed
        // to look at it.
        assert!(
            !unread.balance_wei.is_finite(),
            "a balance nothing could read must not be fittable as a real reading"
        );
    }

    /// The alert rules hard-code the thresholds these constants define. A rule that silently
    /// stops matching the behaviour it was written for is the failure mode this whole change
    /// exists to prevent, so the two are pinned together here.
    #[test]
    fn alert_rule_thresholds_still_match_the_constants() {
        assert_eq!(NOT_LANDING_BLOCKS, 50);
        assert_eq!(update::MAX_PRICE_AGE, std::time::Duration::from_secs(30));
        // `preflight::LOW_RUNWAY` is deliberately NOT asserted here any more, and should not
        // be put back: PusherSignerNearlyDry stopped comparing a count of updates when it
        // became a question about time, so the constant no longer mirrors anything in the
        // rules file. It still governs the startup report, which has one balance and one base
        // fee and no rate to extrapolate from. Pinning it in a test named for the alert rules
        // would assert a correspondence that does not exist — the exact confusion this test
        // was written to prevent, pointed the wrong way.

        let rules = include_str!("../../deploy/alerts/quote-updater.rules.yml");
        assert!(
            rules.contains("quote_updater_consecutive_landing_misses >= 50"),
            "landing threshold drifted"
        );
        assert!(
            rules.contains("quote_updater_feed_last_tick_timestamp_seconds > 30"),
            "feed age threshold drifted"
        );

        // PusherSignerRunwayUnknown's window is not a threshold but a cadence: the runway
        // is repriced every RUNWAY_CHECK_BLOCKS blocks, so three failed reads is
        // 3 * 50 * 12s = 30 minutes of not knowing, and the 45m window leaves room for the
        // third failure to be scraped before the first leaves it. Raise
        // RUNWAY_CHECK_BLOCKS to 500 and the rule needs three failures inside a window
        // barely wider than one check — unsatisfiable, and silently so, which is the whole
        // reason this test exists.
        assert_eq!(RUNWAY_CHECK_BLOCKS, 50);
        assert_eq!(BLOCK_TIME_SECS, 12);

        // PusherSignerNearlyDry hangs off the same cadence, for a sharper reason. It is a
        // `predict_linear` over a 2h window of `signer_balance_wei`, and that gauge is only
        // rewritten once per runway check — so the cadence decides how many points the
        // regression actually has. Twelve today. `predict_linear` over a range holding fewer
        // than two returns no sample at all, so raising RUNWAY_CHECK_BLOCKS would not make
        // the page more tolerant, it would switch the page off: at 500 blocks the cadence is
        // 100 minutes and a 2h window holds one reading. Silently, and on a page-severity
        // rule about a key running out of money, which is why the arithmetic is done here
        // rather than left to whoever next edits the constant.
        const RUNWAY_WINDOW_SECS: u64 = 2 * 60 * 60;
        assert_eq!(
            RUNWAY_WINDOW_SECS / (RUNWAY_CHECK_BLOCKS * BLOCK_TIME_SECS),
            12,
            "the 2h predict_linear window no longer holds 12 balance readings"
        );
        // The window, the horizon and the `for` in one match, through the end of the line.
        // The `for` is here because it is the part that looks like a debounce and is not:
        // the balance moves every 10 minutes, so anything under that holds back nothing, and
        // 30m is what spans three fresh readings.
        assert!(
            rules.contains(
                "expr: predict_linear(quote_updater_signer_balance_wei[2h], 7 * 24 * 3600) < 0\n        for: 30m\n"
            ),
            "PusherSignerNearlyDry's window, horizon or `for` drifted"
        );
        // Matched through the end of the line, so `>= 30` cannot satisfy a check for
        // `>= 3` the way the three prefix matches above would.
        assert!(
            rules.contains(
                "expr: increase(quote_updater_rpc_errors_total{call=\"get_balance\"}[45m]) >= 3\n"
            ),
            "runway-unknown window drifted from RUNWAY_CHECK_BLOCKS"
        );

        // PusherHeadStalled's window is a cadence too, against the only constant that
        // matters to it: a block time. Five minutes with the head unchanged is ~25 missed
        // slots at BLOCK_TIME_SECS, which no ordinary chain produces — but the same window
        // on a chain with a 60s block time would be five slots, tight enough to page on an
        // unlucky quiet stretch. If BLOCK_TIME_SECS ever moves, this window has to be
        // reconsidered rather than silently inherited, which is what pinning it here forces.
        assert!(
            rules.contains("expr: changes(quote_updater_head_number[5m]) == 0\n"),
            "head-stall window drifted from BLOCK_TIME_SECS"
        );
        // The `for` is load-bearing rather than a debounce: `changes` over a window holding
        // one sample is also 0, so without it the rule pages at every process start. The
        // behaviour itself is no longer pinned by a fixture; this pins the line that
        // produces it, since deleting the `for` looks like a simplification.
        assert!(
            rules.contains("expr: changes(quote_updater_head_number[5m]) == 0\n        for: 2m\n"),
            "PusherHeadStalled lost its `for`, which is what stops it paging on startup"
        );
    }
}

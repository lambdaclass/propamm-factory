//! What a reload changed, setting by setting, as the person who edited the file reads it.
//!
//! `reload::plan` decides *whether* a lane changed, on the parsed `PairSpec`. This says
//! *what* changed, on the stanza as written: `pricing.delta 0.0005 → 0.0008`, in the file's
//! own key names and spelling, which is what an operator searches `config.toml` for. The
//! journal prints every line, and `ReloadMetrics::show_changes` exports them for the
//! `PusherConfigChanged` alert to put in Slack.
//!
//! Pure and IO-free, like `reload`. A change is judged on the values as written, secrets
//! included, and shown redacted by the same rules the recorder's `redacted_config` applies:
//! a rotated key is a change, so it gets a line, but the line says only that it changed.

use std::collections::{BTreeMap, BTreeSet};

use ethrex_common::U256;
use serde_json::Value;

use crate::{
    config::{self, BuilderConfig, RawConfig},
    record,
};

/// How many settings one section lists before the rest are left to the journal. A normal
/// retune (`delta`, `max_deviation` and a band together) fits; a rewritten pricing stanza
/// does not, and twenty lines of it would bury the pairs listed after it.
pub(crate) const MAX_SETTINGS: usize = 8;

/// Longest value one exported line carries, in characters. Every value lands in a
/// Prometheus label that is stored for the whole retention, and a scrape with a label over
/// a configured `label_value_length_limit` is refused whole — every updater series with it.
pub(crate) const MAX_VALUE_CHARS: usize = 80;

/// The heading builder-list changes are listed under. Not a pair label: those come from an
/// on-chain `symbol()` and are `BASE/QUOTE` or `lane 0x…`.
pub(crate) const BUILDERS: &str = "builders";

/// The keys a halt is spelled with. A halt and a resume are said as a note ("halted",
/// "resumed"), not as `halted true → unset`.
const HALT_KEYS: [&str; 2] = ["halted", "halt_reason"];

/// One setting that differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Change {
    /// The key as written, dotted: `max_deviation`, `pricing.delta`, `sources[1].weight`,
    /// `titan-eu.endpoint`.
    pub setting: String,
    /// `(old, new)` as shown, or `None` when both show the same because the difference is
    /// inside a redacted value: the change is real, and what it was is not printable.
    pub values: Option<(String, String)>,
}

impl Change {
    /// `pricing.delta 0.0005 → 0.0008`, or `builder.api_key changed (hidden)`.
    pub(crate) fn line(&self) -> String {
        match &self.values {
            Some((old, new)) => format!("{} {old} → {new}", self.setting),
            None => format!("{} {HIDDEN}", self.setting),
        }
    }
}

/// What a line says about a setting whose change is inside a redacted value.
const HIDDEN: &str = "changed (hidden)";

/// Everything one reload says about one pair, or about the builder list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Section {
    /// The pair's label, or [`BUILDERS`].
    pub heading: String,
    /// What happened to it that is not a setting: `added`, `removed`, `re-armed`, …
    pub notes: Vec<String>,
    pub changes: Vec<Change>,
}

/// One line of the exported change list. Empty fields are left off the series: Prometheus
/// drops an empty label, so a setting line always has `old` and `new` (`unset` and `""`
/// are spelled out) and a note line never does, which is how the alert tells them apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub section: String,
    pub setting: String,
    pub old: String,
    pub new: String,
    pub note: String,
}

/// Every stanza in the file, as written, keyed by the lane its tokens make: the lane is
/// how `reload::plan` matches a running pair to the file, so it is how the old stanza is
/// found for the new one. A stanza whose tokens do not parse has no lane and is skipped;
/// a file holding one never got past `load_config_and_raw`.
pub(crate) fn stanzas_by_lane(raw: &RawConfig) -> BTreeMap<U256, Value> {
    raw.pairs
        .iter()
        .filter_map(|pair| {
            let [a, b] = pair.tokens.as_slice() else {
                return None;
            };
            let (a, b) = (
                config::parse_address(a).ok()?,
                config::parse_address(b).ok()?,
            );
            let lane = if a < b {
                config::lane_of(a, b)
            } else {
                config::lane_of(b, a)
            };
            Some((lane, serde_json::to_value(pair).ok()?))
        })
        .collect()
}

/// Whether a stored stanza is one the file halts.
pub(crate) fn is_halted(stanza: &Value) -> bool {
    stanza.get("halted").and_then(Value::as_bool) == Some(true)
}

/// The settings that differ between two stanzas of one pair, in key order. The halt keys
/// are left out (see [`HALT_KEYS`]). The credential-name rule applies inside `pricing` and
/// `guards`, where a kind's own keys are and where `redacted_config` applies it: the
/// pair's own keys are the updater's, and two of them (`key_env`, `tokens`) would match it.
pub(crate) fn pair_changes(old: Option<&Value>, new: &Value) -> Vec<Change> {
    let strip = |stanza: &Value| {
        let mut stanza = stanza.clone();
        if let Some(map) = stanza.as_object_mut() {
            for key in HALT_KEYS {
                map.remove(key);
            }
        }
        stanza
    };
    let (old, new) = (old.map(strip), strip(new));
    let mut out = Vec::new();
    walk(old.as_ref(), Some(&new), "", Rule::PairTop, &mut out);
    out
}

/// The differences between two builder lists, matched by name: `titan-eu.endpoint …`.
/// A builder added or dropped is every one of its fields going from or to `unset`. Every
/// field is under the credential-name rule, which is what hides `api_key`, and every
/// string is cut as `redact_text` cuts it, which is what keeps a key in an endpoint's
/// path out.
pub(crate) fn builder_changes(old: &[BuilderConfig], new: &[BuilderConfig]) -> Vec<Change> {
    let by_name = |list: &[BuilderConfig]| -> BTreeMap<String, Value> {
        list.iter()
            .filter_map(|builder| {
                let mut value = serde_json::to_value(builder).ok()?;
                value.as_object_mut()?.remove("name");
                Some((builder.name.clone(), value))
            })
            .collect()
    };
    let (old, new) = (by_name(old), by_name(new));
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut out = Vec::new();
    for name in names {
        walk(
            old.get(name),
            new.get(name),
            name,
            Rule::Credentials,
            &mut out,
        );
    }
    out
}

/// The changes on one line, for the journal: every one, unclipped.
pub(crate) fn describe(changes: &[Change]) -> String {
    changes
        .iter()
        .map(Change::line)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The lines exported for the alert, in the order it prints them: per section its notes,
/// then at most [`MAX_SETTINGS`] settings and a line counting the rest. Every section is
/// listed whatever its size, so the cap can shorten a pair but never hide one.
pub(crate) fn rows(sections: &[Section]) -> Vec<Row> {
    let mut rows = Vec::new();
    for section in sections {
        let row = |setting: &str, old: &str, new: &str, note: &str| Row {
            section: clip(&section.heading),
            setting: clip(setting),
            old: clip(old),
            new: clip(new),
            note: clip(note),
        };
        for note in &section.notes {
            rows.push(row("", "", "", note));
        }
        for change in section.changes.iter().take(MAX_SETTINGS) {
            rows.push(match &change.values {
                Some((old, new)) => row(&change.setting, old, new, ""),
                None => row(&change.setting, "", "", HIDDEN),
            });
        }
        let more = section.changes.len().saturating_sub(MAX_SETTINGS);
        if more > 0 {
            let settings = if more == 1 { "setting" } else { "settings" };
            rows.push(row(
                "",
                "",
                "",
                &format!("… and {more} more {settings}, see the journal"),
            ));
        }
    }
    rows
}

/// Where in a stanza the walk is, for the credential-name rule.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// A pair's own keys: no name rule, but `pricing` and `guards` switch it on.
    PairTop,
    /// Under the name rule: a key whose name matches it hides everything below.
    Credentials,
    /// Below such a key: hidden.
    Hidden,
}

impl Rule {
    fn below(self, key: &str) -> Rule {
        match self {
            Rule::PairTop if key == "pricing" || key == "guards" => Rule::Credentials,
            Rule::PairTop => Rule::PairTop,
            Rule::Credentials if record::is_credential_name(key) => Rule::Hidden,
            other => other,
        }
    }
}

/// Both trees at once, so a key present on one side only still comes out in key order
/// beside the others. Two tables (or two arrays) are descended into, and anything else
/// is a leaf: compared as written, shown as [`shown`] renders it.
fn walk(old: Option<&Value>, new: Option<&Value>, path: &str, rule: Rule, out: &mut Vec<Change>) {
    let key = |name: &str| {
        if path.is_empty() {
            name.to_owned()
        } else {
            format!("{path}.{name}")
        }
    };
    let as_table = |v: Option<&Value>| match v {
        Some(Value::Object(map)) => Some(map.clone()),
        None => Some(serde_json::Map::new()),
        _ => None,
    };
    let as_array = |v: Option<&Value>| match v {
        Some(Value::Array(items)) => Some(items.clone()),
        None => Some(Vec::new()),
        _ => None,
    };
    let either = |f: fn(&Value) -> bool| old.is_some_and(f) || new.is_some_and(f);

    if either(Value::is_object)
        && let (Some(a), Some(b)) = (as_table(old), as_table(new))
    {
        let names: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        for name in names {
            walk(a.get(name), b.get(name), &key(name), rule.below(name), out);
        }
        return;
    }
    if either(Value::is_array)
        && let (Some(a), Some(b)) = (as_array(old), as_array(new))
    {
        for i in 0..a.len().max(b.len()) {
            walk(a.get(i), b.get(i), &format!("{path}[{i}]"), rule, out);
        }
        return;
    }
    if old == new {
        return;
    }
    let hidden = rule == Rule::Hidden;
    let (was, now) = (shown(old, hidden), shown(new, hidden));
    out.push(Change {
        setting: path.to_owned(),
        values: (was != now).then_some((was, now)),
    });
}

/// A value as a line shows it: a string bare (`0.02`, not `"0.02"`) and cut by
/// `redact_text`, an empty one as `""`, a missing one as `unset`, and a hidden one as
/// `<redacted>` — so adding a key reads `unset → <redacted>`.
fn shown(value: Option<&Value>, hidden: bool) -> String {
    match value {
        None | Some(Value::Null) => "unset".to_owned(),
        Some(_) if hidden => "<redacted>".to_owned(),
        Some(Value::String(text)) if text.is_empty() => "\"\"".to_owned(),
        Some(Value::String(text)) => {
            let mut text = text.clone();
            record::redact_text(&mut text);
            text
        }
        Some(other) => other.to_string(),
    }
}

/// At most [`MAX_VALUE_CHARS`] characters, the last of them `…` when anything was cut.
/// By character, not byte: a cut inside a multi-byte character would not be a string.
fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_VALUE_CHARS {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(MAX_VALUE_CHARS - 1).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn change(setting: &str, old: &str, new: &str) -> Change {
        Change {
            setting: setting.to_owned(),
            values: Some((old.to_owned(), new.to_owned())),
        }
    }

    fn stanza() -> Value {
        json!({
            "tokens": ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"],
            "symbol": "ETHUSDC",
            "key_env": "UPDATER_KEY_WETH_USDC",
            "max_deviation": "0.02",
            "pricing": { "kind": "feed", "delta": "0.0005" },
        })
    }

    #[test]
    fn a_retune_reads_as_the_settings_it_moved_in_key_order() {
        let mut new = stanza();
        new["max_deviation"] = json!("0.03");
        new["pricing"]["delta"] = json!("0.0008");
        assert_eq!(
            pair_changes(Some(&stanza()), &new),
            vec![
                change("max_deviation", "0.02", "0.03"),
                change("pricing.delta", "0.0005", "0.0008"),
            ]
        );
        assert_eq!(
            describe(&pair_changes(Some(&stanza()), &new)),
            "max_deviation 0.02 → 0.03, pricing.delta 0.0005 → 0.0008"
        );
    }

    #[test]
    fn an_identical_stanza_has_no_changes() {
        assert!(pair_changes(Some(&stanza()), &stanza()).is_empty());
    }

    #[test]
    fn a_key_added_or_dropped_reads_unset_on_that_side() {
        let mut new = stanza();
        new["min_mid"] = json!("0.0001");
        new.as_object_mut().unwrap().remove("symbol");
        assert_eq!(
            pair_changes(Some(&stanza()), &new),
            vec![
                change("min_mid", "unset", "0.0001"),
                change("symbol", "ETHUSDC", "unset"),
            ]
        );
    }

    #[test]
    fn arrays_are_compared_entry_by_entry() {
        let mut old = stanza();
        old["sources"] = json!([{ "venue": "binance", "symbol": "ETHUSDC" }]);
        let mut new = stanza();
        new["sources"] = json!([
            { "venue": "binance", "symbol": "ETHUSDC", "weight": "2" },
            { "venue": "okx", "symbol": "ETH-USDC" },
        ]);
        assert_eq!(
            pair_changes(Some(&old), &new),
            vec![
                change("sources[0].weight", "unset", "2"),
                change("sources[1].symbol", "unset", "ETH-USDC"),
                change("sources[1].venue", "unset", "okx"),
            ]
        );
    }

    /// The promise made when this was proposed: a credential typed into a custom stanza
    /// never reaches a line, changed or not.
    #[test]
    fn a_credential_in_a_custom_stanza_is_never_shown() {
        let mut old = stanza();
        old["pricing"]["api_key"] = json!("sk-old-secret");
        old["guards"] = json!([{ "kind": "oracle", "auth": { "token": "t-old" } }]);
        let mut new = old.clone();
        new["pricing"]["api_key"] = json!("sk-new-secret");
        new["guards"][0]["auth"]["token"] = json!("t-new");
        new["pricing"]["webhook_secret"] = json!("whsec-added");

        let changes = pair_changes(Some(&old), &new);
        assert_eq!(
            changes,
            vec![
                Change {
                    setting: "guards[0].auth.token".to_owned(),
                    values: None,
                },
                Change {
                    setting: "pricing.api_key".to_owned(),
                    values: None,
                },
                change("pricing.webhook_secret", "unset", "<redacted>"),
            ]
        );
        let printed = format!(
            "{} {:?}",
            describe(&changes),
            rows(&[Section {
                heading: "WETH/USDC".to_owned(),
                notes: Vec::new(),
                changes,
            }])
        );
        for secret in [
            "sk-old-secret",
            "sk-new-secret",
            "t-old",
            "t-new",
            "whsec-added",
        ] {
            assert!(!printed.contains(secret), "{secret} leaked: {printed}");
        }
    }

    /// The name rule is the recorder's, and its scope is too: `key_env` and `tokens` match
    /// it by name, and hiding them would hide the two settings that say which key signs and
    /// which pair this is.
    #[test]
    fn the_pairs_own_keys_are_shown_even_where_their_names_match_the_rule() {
        let mut new = stanza();
        new["key_env"] = json!("UPDATER_KEY_WETH_USDC_2");
        new["tokens"] = json!([
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        ]);
        let changes = pair_changes(Some(&stanza()), &new);
        assert_eq!(
            changes[0],
            change(
                "key_env",
                "UPDATER_KEY_WETH_USDC",
                "UPDATER_KEY_WETH_USDC_2"
            )
        );
        assert_eq!(changes[1].setting, "tokens[0]");
        assert!(changes.iter().all(|c| c.values.is_some()), "{changes:?}");
    }

    #[test]
    fn a_url_is_cut_to_its_host_and_a_change_past_the_host_is_hidden() {
        let mut old = stanza();
        old["pricing"]["endpoint"] = json!("https://a.example.com/v2/key-one");
        let mut new = old.clone();
        new["pricing"]["endpoint"] = json!("https://a.example.com/v2/key-two");
        assert_eq!(
            pair_changes(Some(&old), &new),
            vec![Change {
                setting: "pricing.endpoint".to_owned(),
                values: None,
            }]
        );
        new["pricing"]["endpoint"] = json!("https://b.example.com/v2/key-two");
        assert_eq!(
            pair_changes(Some(&old), &new),
            vec![change(
                "pricing.endpoint",
                "https://a.example.com",
                "https://b.example.com"
            )]
        );
    }

    #[test]
    fn a_halt_is_not_a_setting() {
        let mut halted = stanza();
        halted["halted"] = json!(true);
        halted["halt_reason"] = json!("kill switch");
        assert!(is_halted(&halted));
        assert!(pair_changes(Some(&halted), &stanza()).is_empty());
    }

    #[test]
    fn builders_are_matched_by_name_and_their_keys_hidden() {
        let builder = |name: &str, endpoint: &str, key: &str| BuilderConfig {
            name: name.to_owned(),
            endpoint: endpoint.to_owned(),
            api_key: key.to_owned(),
            disable_cross_region: None,
        };
        let old = vec![
            builder("titan-eu", "wss://eu.rpc.titanbuilder.xyz/ws/x", "maker-1"),
            builder("gone", "wss://gone.example/ws", "maker-2"),
        ];
        let new = vec![
            builder("titan-eu", "wss://us.rpc.titanbuilder.xyz/ws/x", "maker-3"),
            builder("token-builder", "wss://new.example/ws", "maker-4"),
        ];
        let changes = builder_changes(&old, &new);
        assert_eq!(
            changes,
            vec![
                change("gone.api_key", "<redacted>", "unset"),
                change("gone.endpoint", "wss://gone.example", "unset"),
                Change {
                    setting: "titan-eu.api_key".to_owned(),
                    values: None,
                },
                change(
                    "titan-eu.endpoint",
                    "wss://eu.rpc.titanbuilder.xyz",
                    "wss://us.rpc.titanbuilder.xyz"
                ),
                // A builder's name is not under the rule, though this one matches it.
                change("token-builder.api_key", "unset", "<redacted>"),
                change("token-builder.endpoint", "unset", "wss://new.example"),
            ]
        );
        let printed = describe(&changes);
        for secret in ["maker-1", "maker-2", "maker-3", "maker-4"] {
            assert!(!printed.contains(secret), "{secret} leaked: {printed}");
        }
    }

    #[test]
    fn a_section_lists_eight_settings_and_counts_the_rest() {
        let changes: Vec<Change> = (0..15)
            .map(|i| change(&format!("pricing.k{i:02}"), "1", "2"))
            .collect();
        let rows = rows(&[
            Section {
                heading: "WETH/USDC".to_owned(),
                notes: vec!["re-armed".to_owned()],
                changes,
            },
            Section {
                heading: "USDC/USDT".to_owned(),
                notes: vec!["added".to_owned()],
                changes: Vec::new(),
            },
        ]);
        // The note, eight settings and the count, then the next pair: still listed.
        assert_eq!(rows.len(), 1 + MAX_SETTINGS + 1 + 1);
        assert_eq!(rows[0].note, "re-armed");
        assert_eq!(rows[8].setting, "pricing.k07");
        assert_eq!(rows[9].note, "… and 7 more settings, see the journal");
        assert_eq!(rows[9].setting, "");
        assert_eq!(rows[10].section, "USDC/USDT");
        assert_eq!(rows[10].note, "added");
    }

    #[test]
    fn a_setting_line_always_has_both_values_and_a_note_line_neither() {
        let rows = rows(&[Section {
            heading: "WETH/USDC".to_owned(),
            notes: vec!["re-armed".to_owned()],
            changes: vec![
                change("pricing.delta", "0.0005", "0.0008"),
                change("pricing.label", "\"\"", "unset"),
                Change {
                    setting: "pricing.api_key".to_owned(),
                    values: None,
                },
            ],
        }]);
        for row in &rows {
            let setting_line = !row.old.is_empty();
            assert_eq!(setting_line, !row.new.is_empty(), "{row:?}");
            assert_eq!(setting_line, row.note.is_empty(), "{row:?}");
        }
        assert_eq!(rows[3].setting, "pricing.api_key");
        assert_eq!(rows[3].note, "changed (hidden)");
    }

    #[test]
    fn a_long_value_is_clipped_by_character() {
        let long = "é".repeat(200);
        let rows = rows(&[Section {
            heading: "WETH/USDC".to_owned(),
            notes: Vec::new(),
            changes: vec![change("pricing.venues", &long, "x")],
        }]);
        assert_eq!(rows[0].old.chars().count(), MAX_VALUE_CHARS);
        assert!(rows[0].old.ends_with('…'));
        assert_eq!(rows[0].new, "x");
    }

    #[test]
    fn stanzas_are_keyed_by_the_lane_of_their_sorted_tokens() {
        let raw: RawConfig = toml::from_str(
            r#"
            target = "0x0000000000000000000000000000000000000001"
            [[pairs]]
            tokens = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
            key_env = "UPDATER_KEY_WETH_USDC"
            pricing = { kind = "feed" }
            "#,
        )
        .unwrap();
        let weth = config::parse_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let usdc = config::parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let stanzas = stanzas_by_lane(&raw);
        let stanza = &stanzas[&config::lane_of(usdc, weth)];
        assert_eq!(stanza["key_env"], json!("UPDATER_KEY_WETH_USDC"));
    }
}

//! Read-only contract drift detection.
//!
//! Compares a pinned baseline contract document against a candidate contract
//! document, both supplied as JSON on stdin. The command is offline: it performs
//! no network access and no writes. It reports the structural drift — added,
//! removed, type-changed and value-changed paths — and never applies, guesses
//! or auto-merges a change. Sanitized: the only document-derived text carried
//! is the original object key names (contract field identifiers) and JSON type
//! names; the values of fields, and array element values, never enter the
//! report.
//!
//! The report is order-stable: every difference carries an exact structural
//! path and the change list is emitted in one deterministic total order
//! (structural path, then change kind), so the same pair of documents always
//! produces identical output regardless of member order in the input. Both
//! documents must be JSON objects; anything else is refused as
//! `incomparable_documents` instead of being reported as a single root-level
//! difference, because a contract document has fields to compare and a scalar
//! or array root does not.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

/// Maximum number of individual drift entries reported. Keeps the output
/// bounded for unexpectedly large documents; anything dropped because of the
/// cap sets `truncated`.
const MAX_CHANGES: usize = 256;
/// Maximum path depth walked. A deeper subtree is folded into a single
/// `truncated` marker so a pathological document cannot exhaust the stack.
const MAX_DEPTH: usize = 64;

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// One step of a structural path: an object member name or an array index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PathStep {
    Key(String),
    Index(usize),
}

/// Structural address of a difference. Kept as steps rather than a rendered
/// string so the report's order follows the document structure: a parent path
/// precedes its children, member names compare as names, and array indices
/// compare numerically instead of as text.
type Path = Vec<PathStep>;

/// A reported difference and its sanitized detail: JSON type names and element
/// counts only, never document values. Deriving `Ord` gives the report's
/// deterministic order together with `Change`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ChangeKind {
    Added(&'static str),
    Removed(&'static str),
    ValueChanged {
        baseline: &'static str,
        candidate: &'static str,
    },
    LengthChanged {
        baseline: usize,
        candidate: usize,
    },
    Truncated,
}

impl ChangeKind {
    fn name(&self) -> &'static str {
        match self {
            ChangeKind::Added(_) => "added",
            ChangeKind::Removed(_) => "removed",
            ChangeKind::ValueChanged { .. } => "value_changed",
            ChangeKind::LengthChanged { .. } => "length_changed",
            ChangeKind::Truncated => "truncated",
        }
    }
}

/// One report entry, ordered by exact path and then change kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Change {
    path: Path,
    kind: ChangeKind,
}

impl Change {
    fn render(&self) -> Value {
        let path = render_path(&self.path);
        let kind = self.kind.name();
        match &self.kind {
            ChangeKind::Added(document_type) => {
                json!({"path": path, "kind": kind, "type": document_type})
            }
            ChangeKind::Removed(document_type) => {
                json!({"path": path, "kind": kind, "type": document_type})
            }
            ChangeKind::ValueChanged {
                baseline,
                candidate,
            } => json!({
                "path": path,
                "kind": kind,
                "baseline_type": baseline,
                "candidate_type": candidate
            }),
            ChangeKind::LengthChanged {
                baseline,
                candidate,
            } => json!({
                "path": path,
                "kind": kind,
                "baseline": baseline,
                "candidate": candidate
            }),
            ChangeKind::Truncated => json!({
                "path": path,
                "kind": kind,
                "note": "path deeper than the supported depth; subtree not expanded"
            }),
        }
    }
}

/// Render an exact structural path. Member names that are field identifiers use
/// dot notation; any other name is JSON-quoted so a dot, bracket or quote
/// inside a name can never be confused with the path syntax itself.
fn render_path(path: &[PathStep]) -> String {
    let mut rendered = String::from("$");
    for step in path {
        match step {
            PathStep::Key(key) => {
                rendered.push('.');
                if is_field_identifier(key) {
                    rendered.push_str(key);
                } else {
                    match serde_json::to_string(key) {
                        Ok(quoted) => rendered.push_str(&quoted),
                        Err(_) => rendered.push('?'),
                    }
                }
            }
            PathStep::Index(index) => {
                rendered.push('[');
                rendered.push_str(&index.to_string());
                rendered.push(']');
            }
        }
    }
    rendered
}

fn is_field_identifier(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Record one difference. Returns `false` when the change budget is exhausted,
/// which stops the walk and marks the report truncated.
fn record(out: &mut Vec<Change>, path: &[PathStep], kind: ChangeKind) -> bool {
    if out.len() >= MAX_CHANGES {
        return false;
    }
    out.push(Change {
        path: path.to_vec(),
        kind,
    });
    true
}

/// Recursively diff `base` against `cand` at `path`, appending change records to
/// `out`. Member names are visited in sorted order and the union covers both
/// sides, so the walk never depends on the map's own iteration order. Returns
/// `false` when the change budget is exhausted (recursion then stops).
fn diff(path: &mut Path, base: &Value, cand: &Value, out: &mut Vec<Change>, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return record(out, path, ChangeKind::Truncated);
    }
    match (base, cand) {
        (Value::Object(baseline), Value::Object(candidate)) => {
            let mut keys: Vec<&str> = baseline.keys().map(String::as_str).collect();
            for key in candidate.keys() {
                if !baseline.contains_key(key.as_str()) {
                    keys.push(key.as_str());
                }
            }
            keys.sort_unstable();
            for key in keys {
                if out.len() >= MAX_CHANGES {
                    return false;
                }
                path.push(PathStep::Key(key.to_owned()));
                let keep_walking = match (baseline.get(key), candidate.get(key)) {
                    (None, Some(present)) => {
                        record(out, path, ChangeKind::Added(type_name(present)))
                    }
                    (Some(present), None) => {
                        record(out, path, ChangeKind::Removed(type_name(present)))
                    }
                    (Some(left), Some(right)) => diff(path, left, right, out, depth + 1),
                    (None, None) => true,
                };
                path.pop();
                if !keep_walking {
                    return false;
                }
            }
            true
        }
        (Value::Array(baseline), Value::Array(candidate)) => {
            if baseline.len() != candidate.len()
                && !record(
                    out,
                    path,
                    ChangeKind::LengthChanged {
                        baseline: baseline.len(),
                        candidate: candidate.len(),
                    },
                )
            {
                return false;
            }
            for (index, (left, right)) in baseline.iter().zip(candidate).enumerate() {
                if out.len() >= MAX_CHANGES {
                    return false;
                }
                path.push(PathStep::Index(index));
                let keep_walking = diff(path, left, right, out, depth + 1);
                path.pop();
                if !keep_walking {
                    return false;
                }
            }
            // Trailing elements past the shared prefix are real removals or
            // additions: a bare length change would silently drop them.
            if baseline.len() > candidate.len() {
                for (index, present) in baseline.iter().enumerate().skip(candidate.len()) {
                    if out.len() >= MAX_CHANGES {
                        return false;
                    }
                    path.push(PathStep::Index(index));
                    let keep_walking = record(out, path, ChangeKind::Removed(type_name(present)));
                    path.pop();
                    if !keep_walking {
                        return false;
                    }
                }
            } else {
                for (index, present) in candidate.iter().enumerate().skip(baseline.len()) {
                    if out.len() >= MAX_CHANGES {
                        return false;
                    }
                    path.push(PathStep::Index(index));
                    let keep_walking = record(out, path, ChangeKind::Added(type_name(present)));
                    path.pop();
                    if !keep_walking {
                        return false;
                    }
                }
            }
            true
        }
        (baseline, candidate) => {
            if baseline == candidate {
                true
            } else {
                record(
                    out,
                    path,
                    ChangeKind::ValueChanged {
                        baseline: type_name(baseline),
                        candidate: type_name(candidate),
                    },
                )
            }
        }
    }
}

/// Strict admission for the one JSON document on stdin: duplicate object
/// members are refused instead of silently keeping the last one, and the parse
/// must consume the whole input. A repeated member would otherwise make the
/// comparison depend on which copy the parser kept.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Document;

        impl<'de> Visitor<'de> for Document {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("one JSON document with unique object members")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                StrictValue::deserialize(deserializer)
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = access.next_element::<StrictValue>()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut members = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if members.contains_key(key.as_str()) {
                        return Err(de::Error::custom("duplicate JSON object member"));
                    }
                    let StrictValue(value) = access.next_value::<StrictValue>()?;
                    members.insert(key, value);
                }
                Ok(StrictValue(Value::Object(members)))
            }
        }

        deserializer.deserialize_any(Document)
    }
}

/// A refusal payload: no report is produced, so no `in_sync` claim is made.
fn refusal(code: &str, message: &str) -> Value {
    json!({
        "schema_version": 1,
        "type": "contract_drift_report",
        "error": code,
        "message": message
    })
}

/// Compare a pinned baseline contract document against a candidate contract
/// document. Both are JSON objects carried in the stdin input. Returns a
/// sanitized drift report with changes in one deterministic order; never
/// modifies or applies anything. Documents that are not both objects are
/// refused as `incomparable_documents` rather than compared.
pub fn check(input: &str) -> Value {
    let parsed = match serde_json::from_str::<StrictValue>(input) {
        Ok(document) => document.0,
        Err(error) => {
            let message = match error.classify() {
                serde_json::error::Category::Data => {
                    "input must be one JSON document with unique object members"
                }
                _ => "input must be a JSON object with baseline and candidate",
            };
            return refusal("invalid_input", message);
        }
    };
    let envelope = match parsed {
        Value::Object(envelope) => envelope,
        _ => {
            return refusal(
                "invalid_input",
                "input must be a JSON object with baseline and candidate",
            );
        }
    };
    let (baseline, candidate) = match (envelope.get("baseline"), envelope.get("candidate")) {
        (Some(baseline), Some(candidate)) => (baseline, candidate),
        _ => {
            return refusal("invalid_input", "both baseline and candidate are required");
        }
    };
    // A contract document has fields to compare. A scalar or array root does
    // not, so it is refused instead of being reported as one root-level change.
    match (baseline, candidate) {
        (Value::Object(_), Value::Object(_)) => {}
        (Value::Object(_), _) => {
            return refusal(
                "incomparable_documents",
                &format!(
                    "candidate must be a JSON object contract document; found {}",
                    type_name(candidate)
                ),
            );
        }
        _ => {
            return refusal(
                "incomparable_documents",
                &format!(
                    "baseline must be a JSON object contract document; found {}",
                    type_name(baseline)
                ),
            );
        }
    }

    let mut changes: Vec<Change> = Vec::new();
    let mut path: Path = Vec::new();
    let complete = diff(&mut path, baseline, candidate, &mut changes, 0);
    // The walk already visits paths in this order; sorting makes the reported
    // order an explicit property of the report rather than of the traversal.
    changes.sort();
    let change_count = changes.len();
    let truncated = !complete;
    let rendered: Vec<Value> = changes.iter().map(Change::render).collect();
    json!({
        "schema_version": 1,
        "type": "contract_drift_report",
        "in_sync": rendered.is_empty() && !truncated,
        "change_count": change_count,
        "truncated": truncated,
        "changes": rendered
    })
}

/// Describe the command's input/output contract for `buaa schema`.
pub fn schema() -> Value {
    json!({
        "check": {
            "input": {
                "type": "object",
                "required": ["baseline", "candidate"],
                "properties": {
                    "baseline": {
                        "type": "object",
                        "description": "pinned contract document (JSON object)"
                    },
                    "candidate": {
                        "type": "object",
                        "description": "candidate contract document to compare against the baseline"
                    }
                }
            },
            "output": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["schema_version", "type", "in_sync", "change_count", "changes"],
                        "properties": {
                            "schema_version": {"const": 1},
                            "type": {"const": "contract_drift_report"},
                            "in_sync": {"type": "boolean"},
                            "change_count": {"type": "integer", "minimum": 0},
                            "truncated": {"type": "boolean"},
                            "changes": {
                                "type": "array",
                                "maxItems": MAX_CHANGES,
                                "description": "differences in one deterministic order: structural path, then change kind",
                                "items": {
                                    "type": "object",
                                    "required": ["path", "kind"],
                                    "properties": {
                                        "path": {
                                            "type": "string",
                                            "description": "exact structural path: $ root, .member for field identifiers, JSON-quoted member names otherwise, [index] for array elements"
                                        },
                                        "kind": {
                                            "enum": ["added", "removed", "value_changed", "length_changed", "truncated"]
                                        },
                                        "type": {"type": "string", "description": "added/removed: JSON type of the present side"},
                                        "baseline_type": {"type": "string", "description": "value_changed: JSON type in the baseline"},
                                        "candidate_type": {"type": "string", "description": "value_changed: JSON type in the candidate"},
                                        "baseline": {"type": "integer", "minimum": 0, "description": "length_changed: baseline element count"},
                                        "candidate": {"type": "integer", "minimum": 0, "description": "length_changed: candidate element count"},
                                        "note": {"type": "string", "description": "truncated: why the subtree was not expanded"}
                                    }
                                }
                            }
                        }
                    },
                    {
                        "type": "object",
                        "required": ["schema_version", "type", "error", "message"],
                        "properties": {
                            "schema_version": {"const": 1},
                            "type": {"const": "contract_drift_report"},
                            "error": {"enum": ["invalid_input", "incomparable_documents"]},
                            "message": {
                                "type": "string",
                                "description": "why no report was produced; carries JSON type names only, never document values"
                            }
                        }
                    }
                ]
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(baseline: &Value, candidate: &Value) -> Value {
        check(&json!({"baseline": baseline, "candidate": candidate}).to_string())
    }

    fn pairs(report: &Value) -> Vec<(String, String)> {
        report["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|change| {
                (
                    change["path"].as_str().unwrap().to_owned(),
                    change["kind"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn identical_documents_are_in_sync() {
        let doc = json!({"a": 1, "b": ["x", "y"], "c": {"d": true}});
        let out = run(&doc, &doc);
        assert_eq!(out["in_sync"], true);
        assert_eq!(out["change_count"], 0);
        assert_eq!(out["truncated"], false);
        assert!(out["changes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn added_removed_and_value_changes_are_named_by_path() {
        let baseline = json!({"keep": 1, "gone": 2, "num": 3, "obj": {"x": 1}});
        let candidate = json!({"keep": 1, "new": 9, "num": 4, "obj": {"x": 1}});
        let out = run(&baseline, &candidate);
        assert_eq!(out["in_sync"], false);
        let kinds = pairs(&out);
        assert!(kinds.contains(&("$.gone".into(), "removed".into())));
        assert!(kinds.contains(&("$.new".into(), "added".into())));
        assert!(kinds.contains(&("$.num".into(), "value_changed".into())));
        assert!(!kinds.iter().any(|(path, _)| path == "$.keep"));
    }

    #[test]
    fn changes_are_reported_in_exact_structural_order() {
        // Synthetic pair with one change of every kind, deliberately written in
        // non-alphabetical member order on both sides.
        let baseline = json!({
            "zeta": 1,
            "nested": {"b": 2, "a": "same"},
            "list": [1, 2, 3],
            "keep": true
        });
        let candidate = json!({
            "alpha": 0,
            "nested": {"b": 3, "a": "same"},
            "list": [1, 9],
            "keep": true
        });
        let out = run(&baseline, &candidate);
        assert_eq!(out["in_sync"], false);
        assert_eq!(out["truncated"], false);
        assert_eq!(out["change_count"], 6);
        assert_eq!(
            pairs(&out),
            vec![
                ("$.alpha".to_string(), "added".to_string()),
                ("$.list".to_string(), "length_changed".to_string()),
                ("$.list[1]".to_string(), "value_changed".to_string()),
                ("$.list[2]".to_string(), "removed".to_string()),
                ("$.nested.b".to_string(), "value_changed".to_string()),
                ("$.zeta".to_string(), "removed".to_string()),
            ]
        );
        let changes = out["changes"].as_array().unwrap();
        // Added/removed name the type of the side that still has the member.
        assert_eq!(changes[0]["type"], "number");
        assert_eq!(changes[3]["type"], "number");
        assert_eq!(changes[5]["type"], "number");
        // Length and value changes carry both sides' sanitized detail.
        assert_eq!(changes[1]["baseline"], 3);
        assert_eq!(changes[1]["candidate"], 2);
        assert_eq!(changes[2]["baseline_type"], "number");
        assert_eq!(changes[2]["candidate_type"], "number");
        assert_eq!(changes[4]["baseline_type"], "number");
        assert_eq!(changes[4]["candidate_type"], "number");
    }

    #[test]
    fn array_indices_sort_numerically_not_lexicographically() {
        let baseline = vec![json!(0); 12];
        let mut candidate = baseline.clone();
        candidate[2] = json!(7);
        candidate[10] = json!(5);
        let out = run(
            &json!({"l": Value::Array(baseline)}),
            &json!({"l": Value::Array(candidate)}),
        );
        assert_eq!(
            pairs(&out),
            vec![
                ("$.l[2]".to_string(), "value_changed".to_string()),
                ("$.l[10]".to_string(), "value_changed".to_string()),
            ]
        );
    }

    #[test]
    fn member_order_in_the_input_does_not_change_the_report() {
        let ordered = concat!(
            r#"{"baseline":{"b":1,"a":2,"c":{"y":1,"x":2}},"#,
            r#""candidate":{"b":9,"a":2,"d":3,"c":{"y":1,"x":8}}}"#
        );
        let shuffled = concat!(
            r#"{"candidate":{"c":{"x":8,"y":1},"d":3,"a":2,"b":9},"#,
            r#""baseline":{"c":{"x":2,"y":1},"b":1,"a":2}}"#
        );
        let left = check(ordered);
        let right = check(shuffled);
        assert_eq!(left, right);
        assert_eq!(left.to_string(), right.to_string());
        assert_eq!(
            pairs(&left),
            vec![
                ("$.b".to_string(), "value_changed".to_string()),
                ("$.c.x".to_string(), "value_changed".to_string()),
                ("$.d".to_string(), "added".to_string()),
            ]
        );
    }

    #[test]
    fn type_change_reports_both_type_names() {
        let out = run(&json!({"v": "s"}), &json!({"v": 5}));
        assert_eq!(out["in_sync"], false);
        let change = &out["changes"][0];
        assert_eq!(change["path"], "$.v");
        assert_eq!(change["kind"], "value_changed");
        assert_eq!(change["baseline_type"], "string");
        assert_eq!(change["candidate_type"], "number");
    }

    #[test]
    fn array_length_change_and_element_drift_are_reported() {
        let out = run(&json!({"l": [1, 2, 3]}), &json!({"l": [1, 9]}));
        let kinds = pairs(&out);
        assert!(kinds.contains(&("$.l".into(), "length_changed".into())));
        assert!(kinds.contains(&("$.l[1]".into(), "value_changed".into())));
        assert!(kinds.contains(&("$.l[2]".into(), "removed".into())));
    }

    #[test]
    fn exact_paths_quote_member_names_that_are_not_field_identifiers() {
        let out = run(&json!({"a.b": 1, "c[0]": 2, "plain_-9": 3}), &json!({}));
        assert_eq!(
            pairs(&out),
            vec![
                ("$.\"a.b\"".to_string(), "removed".to_string()),
                ("$.\"c[0]\"".to_string(), "removed".to_string()),
                ("$.plain_-9".to_string(), "removed".to_string()),
            ]
        );

        // Quoting survives nesting, including behind an array index.
        let out = run(
            &json!({"outer": {"in.ner": 2, "list": [{"x y": 3}, 1]}}),
            &json!({"outer": {"in.ner": 2, "list": [{}, 1]}}),
        );
        assert_eq!(
            pairs(&out),
            vec![("$.outer.list[0].\"x y\"".to_string(), "removed".to_string())]
        );
    }

    #[test]
    fn raw_values_never_leak_into_the_report() {
        let secret = "TOP-SECRET-CONTRACT-VALUE-abc123";
        let other = "candidate-value-marker";
        let out = run(&json!({"x": secret}), &json!({"x": other}));
        let rendered = out.to_string();
        assert!(
            !rendered.contains(secret) && !rendered.contains(other),
            "report must not carry raw values"
        );
        assert_eq!(out["changes"][0]["kind"], "value_changed");
    }

    #[test]
    fn non_object_documents_are_refused_as_incomparable() {
        let out = run(&json!({"a": 1}), &json!(["sensitive-candidate"]));
        assert_eq!(out["error"], "incomparable_documents");
        assert!(out.get("in_sync").is_none());
        assert!(out.get("changes").is_none());
        let message = out["message"].as_str().unwrap();
        assert!(message.contains("candidate"), "{message}");
        assert!(message.contains("array"), "{message}");
        assert!(!message.contains("sensitive-candidate"), "{message}");

        // Either side can be the incomparable one; scalars are refused too.
        let out = run(&json!([1, 2]), &json!({"a": 1}));
        assert_eq!(out["error"], "incomparable_documents");
        assert!(out["message"].as_str().unwrap().contains("baseline"));

        let out = run(&Value::Null, &json!({"a": 1}));
        assert_eq!(out["error"], "incomparable_documents");
        assert!(out["message"].as_str().unwrap().contains("null"));
    }

    #[test]
    fn non_object_input_root_is_refused() {
        for input in [
            "[]",
            r#"[{"baseline":{},"candidate":{}}]"#,
            "null",
            r#""text""#,
            "7",
        ] {
            let out = check(input);
            assert_eq!(out["error"], "invalid_input", "input: {input}");
            assert!(out.get("in_sync").is_none(), "input: {input}");
        }
    }

    #[test]
    fn duplicate_object_members_are_refused() {
        for input in [
            r#"{"baseline":{"a":1,"a":2},"candidate":{"a":1}}"#,
            r#"{"baseline":{"o":{"x":1,"x":2}},"candidate":{"o":{"x":1}}}"#,
            r#"{"baseline":{},"candidate":{},"baseline":{"a":1}}"#,
        ] {
            let out = check(input);
            assert_eq!(out["error"], "invalid_input", "input: {input}");
            let message = out["message"].as_str().unwrap();
            assert!(message.contains("unique"), "input: {input} / {message}");
        }
    }

    #[test]
    fn trailing_document_is_refused() {
        let out = check(r#"{"baseline":{},"candidate":{}} {"baseline":{}}"#);
        assert_eq!(out["error"], "invalid_input");
    }

    #[test]
    fn invalid_input_is_rejected_without_panicking() {
        let out = check("not json at all");
        assert_eq!(out["error"], "invalid_input");

        let out = check(&json!({"baseline": 1}).to_string());
        assert_eq!(out["error"], "invalid_input");

        let out = check(&json!({"baseline": {}, "candidate": {}, "extra": 1}).to_string());
        assert_eq!(out["in_sync"], true);
    }

    #[test]
    fn deeply_nested_documents_stay_bounded() {
        // Build two documents nested past MAX_DEPTH, differing only at the leaf.
        let build = |leaf: u64| {
            let mut doc = json!(leaf);
            for _ in 0..(MAX_DEPTH + 10) {
                doc = json!({"k": doc});
            }
            doc
        };
        let out = run(&build(0), &build(1));
        assert!(out["changes"].as_array().unwrap().len() <= MAX_CHANGES);
        assert_eq!(out["in_sync"], false);
        assert_eq!(out["change_count"], 1);
        assert_eq!(out["changes"][0]["kind"], "truncated");
    }

    #[test]
    fn change_count_is_capped_and_truncated_flagged() {
        let mut baseline = Map::new();
        let mut candidate = Map::new();
        for i in 0..(MAX_CHANGES + 10) {
            baseline.insert(format!("k{i:04}"), json!(i));
            candidate.insert(format!("k{i:04}"), json!(i + 1000));
        }
        let out = run(&Value::Object(baseline), &Value::Object(candidate));
        assert_eq!(out["change_count"], MAX_CHANGES as u64);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["changes"].as_array().unwrap().len(), MAX_CHANGES);
        assert_eq!(out["in_sync"], false);
    }

    #[test]
    fn exactly_capped_changes_are_not_falsely_truncated() {
        let mut baseline = Map::new();
        let mut candidate = Map::new();
        for i in 0..MAX_CHANGES {
            baseline.insert(format!("k{i:04}"), json!(i));
            candidate.insert(format!("k{i:04}"), json!(i + 1000));
        }
        let out = run(&Value::Object(baseline), &Value::Object(candidate));
        assert_eq!(out["change_count"], MAX_CHANGES as u64);
        assert_eq!(out["truncated"], false);
        assert_eq!(out["in_sync"], false);
    }
}

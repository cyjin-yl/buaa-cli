//! Read-only contract drift detection.
//!
//! Compares a pinned baseline contract document against a candidate contract
//! document, both supplied as JSON on stdin. The command is offline: it performs
//! no network access and no writes. It reports the structural drift — added,
//! removed, type-changed and value-changed paths — and never applies, guesses
//! or auto-merges a change. Sanitized: the report names paths and change kinds
//! plus type names and array lengths, never the raw values of the documents.

use serde_json::{Value, json};

/// Maximum number of individual drift entries reported. Keeps the output
/// bounded for unexpectedly large documents without truncating the summary.
const MAX_CHANGES: usize = 256;
/// Maximum path depth walked. Deeper nesting is folded into a single
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

/// Recursively diff `base` against `cand`, appending change records to `out`.
/// Returns `false` when the change cap is reached (recursion then stops).
fn diff(path: &str, base: &Value, cand: &Value, out: &mut Vec<Value>, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        if out.len() < MAX_CHANGES {
            out.push(json!({
                "path": path,
                "kind": "truncated",
                "note": "path deeper than the supported depth; subtree not expanded"
            }));
        }
        return true;
    }
    match (base, cand) {
        (Value::Object(a), Value::Object(b)) => {
            // serde_json objects are key-sorted, so iterating keys is
            // deterministic; the union is covered by visiting both orders.
            let mut keys: Vec<&String> = a.keys().collect();
            for key in b.keys() {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            keys.sort();
            for key in keys {
                if !can_record(out) {
                    return false;
                }
                let child = format!("{path}.{key}");
                match (a.get(key), b.get(key)) {
                    (None, Some(y)) => {
                        out.push(json!({"path": child, "kind": "added", "type": type_name(y)}));
                    }
                    (Some(x), None) => {
                        out.push(json!({"path": child, "kind": "removed", "type": type_name(x)}));
                    }
                    (Some(x), Some(y)) => {
                        if !diff(&child, x, y, out, depth + 1) {
                            return false;
                        }
                    }
                    (None, None) => {}
                }
            }
            true
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                out.push(json!({
                    "path": path,
                    "kind": "length_changed",
                    "baseline": a.len(),
                    "candidate": b.len()
                }));
            }
            for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                if out.len() >= MAX_CHANGES {
                    return false;
                }
                if !diff(&format!("{path}[{i}]"), x, y, out, depth + 1) {
                    return false;
                }
            }
            true
        }
        (a, b) => {
            if a == b {
                true
            } else {
                out.push(json!({
                    "path": path,
                    "kind": "value_changed",
                    "baseline_type": type_name(a),
                    "candidate_type": type_name(b)
                }));
                true
            }
        }
    }
}

/// Whether the change budget still allows one more entry.
fn can_record(out: &[Value]) -> bool {
    out.len() < MAX_CHANGES
}

/// Compare a pinned baseline contract document against a candidate contract
/// document. Both are JSON values carried in the stdin input. Returns a
/// sanitized drift report; never modifies or applies anything.
pub fn check(input: &str) -> Value {
    let parsed: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => {
            return json!({
                "schema_version": 1,
                "type": "contract_drift_report",
                "error": "invalid_input",
                "message": "input must be a JSON object with baseline and candidate"
            });
        }
    };
    let (baseline, candidate) = match (parsed.get("baseline"), parsed.get("candidate")) {
        (Some(b), Some(c)) => (b, c),
        _ => {
            return json!({
                "schema_version": 1,
                "type": "contract_drift_report",
                "error": "invalid_input",
                "message": "both baseline and candidate are required"
            });
        }
    };

    let mut changes: Vec<Value> = Vec::new();
    diff("$", baseline, candidate, &mut changes, 0);
    let truncated = changes.len() >= MAX_CHANGES;
    changes.truncate(MAX_CHANGES);

    json!({
        "schema_version": 1,
        "type": "contract_drift_report",
        "in_sync": changes.is_empty() && !truncated,
        "change_count": changes.len(),
        "truncated": truncated,
        "changes": changes
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
                    "baseline": {"description": "pinned contract document (any JSON value)"},
                    "candidate": {"description": "candidate contract document to compare against the baseline"}
                }
            },
            "output": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["schema_version", "type", "in_sync", "change_count", "changes"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "contract_drift_report"},
                    "in_sync": {"type": "boolean"},
                    "change_count": {"type": "integer", "minimum": 0},
                    "truncated": {"type": "boolean"},
                    "changes": {"type": "array", "maxItems": MAX_CHANGES}
                }
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

    #[test]
    fn identical_documents_are_in_sync() {
        let doc = json!({"a": 1, "b": ["x", "y"], "c": {"d": true}});
        let out = run(&doc, &doc);
        assert_eq!(out["in_sync"], true);
        assert_eq!(out["change_count"], 0);
        assert!(out["changes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn added_removed_and_value_changes_are_named_by_path() {
        let baseline = json!({"keep": 1, "gone": 2, "num": 3, "obj": {"x": 1}});
        let candidate = json!({"keep": 1, "new": 9, "num": 4, "obj": {"x": 1}});
        let out = run(&baseline, &candidate);
        assert_eq!(out["in_sync"], false);
        let kinds: Vec<(&str, &str)> = out["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["path"].as_str().unwrap(), c["kind"].as_str().unwrap()))
            .collect();
        assert!(kinds.contains(&("$.gone", "removed")));
        assert!(kinds.contains(&("$.new", "added")));
        assert!(kinds.contains(&("$.num", "value_changed")));
        assert!(!kinds.contains(&("$.keep", "value_changed")));
    }

    #[test]
    fn type_change_reports_both_type_names() {
        let out = run(&json!({"v": "s"}), &json!({"v": 5}));
        assert_eq!(out["in_sync"], false);
        let change = &out["changes"][0];
        assert_eq!(change["kind"], "value_changed");
        assert_eq!(change["baseline_type"], "string");
        assert_eq!(change["candidate_type"], "number");
    }

    #[test]
    fn array_length_change_and_element_drift_are_reported() {
        let out = run(&json!({"l": [1, 2, 3]}), &json!({"l": [1, 9]}));
        let kinds: Vec<&str> = out["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"length_changed"));
        assert!(kinds.contains(&"value_changed"));
    }

    #[test]
    fn raw_values_never_leak_into_the_report() {
        let secret = "TOP-SECRET-CONTRACT-VALUE-abc123";
        let out = run(&json!({"x": secret}), &json!({"x": "changed"}));
        let rendered = out.to_string();
        assert!(
            !rendered.contains(secret),
            "report must not carry raw values"
        );
        assert_eq!(out["changes"][0]["kind"], "value_changed");
    }

    #[test]
    fn invalid_input_is_rejected_without_panicking() {
        let out = check("not json at all");
        assert_eq!(out["error"], "invalid_input");

        let out = check(&json!({"baseline": 1}).to_string());
        assert_eq!(out["error"], "invalid_input");
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
        // No panic; a deep change is reported (or the subtree is truncated).
        assert!(out["in_sync"].as_bool().unwrap() || out["change_count"].as_u64().unwrap() > 0);
        assert!(out["truncated"].as_bool().unwrap() || out["change_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn change_count_is_capped_and_truncated_flagged() {
        let mut baseline = serde_json::Map::new();
        let mut candidate = serde_json::Map::new();
        for i in 0..(MAX_CHANGES + 10) {
            baseline.insert(format!("k{i}"), json!(i));
            candidate.insert(format!("k{i}"), json!(i + 1000));
        }
        let out = run(&Value::Object(baseline), &Value::Object(candidate));
        assert_eq!(out["change_count"], MAX_CHANGES as u64);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["changes"].as_array().unwrap().len(), MAX_CHANGES);
        assert_eq!(out["in_sync"], false);
    }
}

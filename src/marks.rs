//! Marks/GPA and change monitoring.
//!
//! Deterministic, fully offline computation over owner-supplied grades and a
//! caller-supplied *published* grade-point policy. No policy is embedded in the
//! repository: the policy JSON carries its own provenance (`id`, `source`) so
//! every result records exactly which published rule was applied. Nothing here
//! reads the network, the governor, or any campus account.
//!
//! Policy kinds:
//!   - "table": inclusive [min, max] score bands, each mapped to a fixed point;
//!     the bands must exactly cover [pass_min, 100].
//!   - "formula": point = a - b*(100-score)^2 / c, clamped to [0, a];
//!     a in (0, 5], b > 0, c > 0 (e.g. a=4, b=3, c=1600).
//!
//! A course below `pass_min` (default 60) is `pass: false`, earns no point,
//! and is excluded from the weighted average. `buaa marks baseline` persists an
//! idempotent local snapshot used by the structured diff.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_PATH: usize = 4096;
const DEFAULT_PASS_MIN: u8 = 60;

fn invalid() -> Value {
    json!({"error":"invalid_input","message":"marks input is invalid"})
}

fn unavailable(message: &'static str) -> Value {
    json!({"error":"unavailable","message":message})
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind")]
enum PolicySpec {
    #[serde(rename = "table")]
    Table {
        bands: Vec<TableBand>,
        #[serde(default = "default_pass_min")]
        pass_min: u8,
    },
    #[serde(rename = "formula")]
    Formula {
        a: f64,
        b: f64,
        c: f64,
        #[serde(default = "default_pass_min")]
        pass_min: u8,
    },
}

fn default_pass_min() -> u8 {
    DEFAULT_PASS_MIN
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableBand {
    min: u8,
    max: u8,
    point: f64,
}

#[derive(Debug, Clone, PartialEq)]
enum Policy {
    Table(Vec<TableBand>, u8),
    Formula {
        a: f64,
        b: f64,
        c: f64,
        pass_min: u8,
    },
}

struct PolicyContext {
    policy: Policy,
    id: String,
    source: String,
}
impl PolicyContext {
    fn point_for(&self, score: u8) -> f64 {
        match &self.policy {
            Policy::Table(bands, pass_min) => {
                if score < *pass_min {
                    return 0.0;
                }
                bands
                    .iter()
                    .find(|band| score >= band.min && score <= band.max)
                    .map(|band| band.point)
                    .unwrap_or(0.0)
            }
            Policy::Formula { a, b, c, .. } => {
                let x = f64::from(100u8) - f64::from(score);
                (a - b * x * x / c).clamp(0.0, *a)
            }
        }
    }

    fn pass_min(&self) -> u8 {
        match &self.policy {
            Policy::Table(_, pass_min) | Policy::Formula { pass_min, .. } => *pass_min,
        }
    }

    fn as_value(&self) -> Value {
        match &self.policy {
            Policy::Table(bands, pass_min) => json!({
                "kind":"table","pass_min":pass_min,
                "bands": bands.iter().map(|band| json!({"min":band.min,"max":band.max,"point":band.point})).collect::<Vec<_>>()
            }),
            Policy::Formula { a, b, c, pass_min } => {
                json!({"kind":"formula","a":a,"b":b,"c":c,"pass_min":pass_min})
            }
        }
    }
}

fn parse_policy(raw: &Value) -> Result<PolicyContext, Value> {
    let id = raw
        .get("policy")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source = raw
        .get("policy")
        .and_then(|value| value.get("source"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if id.is_empty() || source.is_empty() {
        return Err(
            json!({"error":"invalid_input","message":"policy requires non-empty id and source provenance"}),
        );
    }
    let mut spec_value = raw["policy"].clone();
    if let Some(map) = spec_value.as_object_mut() {
        map.remove("id");
        map.remove("source");
    }
    let spec = match serde_json::from_value::<PolicySpec>(spec_value) {
        Ok(spec) => spec,
        Err(_) => return Err(invalid()),
    };
    match spec {
        PolicySpec::Table {
            mut bands,
            pass_min,
        } => {
            if bands.is_empty() || pass_min > 100 {
                return Err(invalid());
            }
            bands.sort_by_key(|band| band.min);
            let mut cursor = pass_min;
            for band in &bands {
                if band.min > band.max || band.max > 100 || band.point < 0.0 || band.point > 5.0 {
                    return Err(invalid());
                }
                if band.min != cursor {
                    return Err(invalid());
                }
                cursor = band.max + 1;
            }
            if cursor != 101 {
                return Err(invalid());
            }
            Ok(PolicyContext {
                policy: Policy::Table(bands, pass_min),
                id,
                source,
            })
        }
        PolicySpec::Formula { a, b, c, pass_min } => {
            if a <= 0.0
                || a > 5.0
                || b <= 0.0
                || c <= 0.0
                || pass_min > 100
                || !a.is_finite()
                || !b.is_finite()
                || !c.is_finite()
            {
                return Err(invalid());
            }
            Ok(PolicyContext {
                policy: Policy::Formula { a, b, c, pass_min },
                id,
                source,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Courses and computation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CourseInput {
    name: String,
    score: u8,
    credit: f64,
}

struct Course {
    name: String,
    score: u8,
    credit: f64,
}

fn parse_courses(raw: &Value) -> Result<Vec<Course>, Value> {
    let Some(list) = raw.get("courses").and_then(Value::as_array) else {
        return Err(invalid());
    };
    if list.len() > 10_000 {
        return Err(invalid());
    }
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut courses = Vec::with_capacity(list.len());
    for item in list {
        let input: CourseInput = match serde_json::from_value(item.clone()) {
            Ok(value) => value,
            Err(_) => return Err(invalid()),
        };
        if input.name.is_empty()
            || input.score > 100
            || !input.credit.is_finite()
            || input.credit <= 0.0
        {
            return Err(invalid());
        }
        if seen.insert(input.name.clone(), ()).is_some() {
            return Err(
                json!({"error":"invalid_input","message":"duplicate course name in selection"}),
            );
        }
        courses.push(Course {
            name: input.name,
            score: input.score,
            credit: input.credit,
        });
    }
    Ok(courses)
}

/// Parse a `gpa_baseline` document's course list leniently: baseline lines
/// carry derived fields (point, counts) beyond the strict input schema.
fn parse_baseline_courses(baseline: &Value) -> Result<Vec<Course>, Value> {
    let Some(list) = baseline.get("courses").and_then(Value::as_array) else {
        return Err(json!({"error":"invalid_input","message":"baseline courses are malformed"}));
    };
    if list.len() > 10_000 {
        return Err(json!({"error":"invalid_input","message":"baseline courses are malformed"}));
    }
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut courses = Vec::with_capacity(list.len());
    for item in list {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(
                || json!({"error":"invalid_input","message":"baseline courses are malformed"}),
            )?
            .to_string();
        let score = item
            .get("score")
            .and_then(Value::as_u64)
            .filter(|score| *score <= 100)
            .ok_or_else(
                || json!({"error":"invalid_input","message":"baseline courses are malformed"}),
            )?;
        let credit = item
            .get("credit")
            .and_then(Value::as_f64)
            .filter(|credit| credit.is_finite() && *credit > 0.0)
            .ok_or_else(
                || json!({"error":"invalid_input","message":"baseline courses are malformed"}),
            )?;
        if seen.insert(name.clone(), ()).is_some() {
            return Err(
                json!({"error":"invalid_input","message":"duplicate course name in baseline"}),
            );
        }
        courses.push(Course {
            name,
            score: score as u8,
            credit,
        });
    }
    Ok(courses)
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[derive(Debug, Clone)]
struct Calculation {
    gpa: Option<f64>,
    counted_credits: f64,
    total_credits: f64,
    lines: Vec<Value>,
}

fn compute(context: &PolicyContext, courses: &[Course]) -> Calculation {
    let mut numerator = 0.0;
    let mut counted_credits = 0.0;
    let mut total_credits = 0.0;
    let mut lines = Vec::with_capacity(courses.len());
    for course in courses {
        let pass = course.score >= context.pass_min();
        let point = if pass {
            context.point_for(course.score)
        } else {
            0.0
        };
        if pass {
            numerator += point * course.credit;
            counted_credits += course.credit;
        }
        total_credits += course.credit;
        lines.push(json!({
            "name": course.name,
            "score": course.score,
            "credit": course.credit,
            "point": round4(point),
            "counts": pass
        }));
    }
    let gpa = if counted_credits > 0.0 {
        Some(round4(numerator / counted_credits))
    } else {
        None
    };
    Calculation {
        gpa,
        counted_credits: round4(counted_credits),
        total_credits: round4(total_credits),
        lines,
    }
}

fn policy_provenance(context: &PolicyContext) -> Value {
    json!({"id": context.id, "source": context.source, "policy": context.as_value()})
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Compute GPA for `{"policy":{...},"courses":[...]}` (optionally with a
/// `baseline` object for the structured diff).
pub fn gpa(input: &str) -> Value {
    if input.len() as u64 > MAX_POLICY_BYTES {
        return invalid();
    }
    let raw: Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return invalid(),
    };
    let Ok(context) = parse_policy(&raw) else {
        return invalid();
    };
    let Ok(courses) = parse_courses(&raw) else {
        return invalid();
    };
    let current = compute(&context, &courses);
    let mut out = json!({
        "schema_version": 1,
        "type": "gpa_calculation",
        "policy": policy_provenance(&context),
        "courses": current.lines,
        "counted_credits": current.counted_credits,
        "total_credits": current.total_credits,
        "gpa": current.gpa,
    });
    if let Some(baseline) = raw.get("baseline") {
        out["diff"] = diff_value(baseline, &current, &context, &courses);
    }
    out
}

fn normalized_policy_content(raw: &Value) -> Option<Value> {
    // A canonical baseline nests the provenance policy content; a raw policy
    // object carries id/source inside itself. Compare the normalized content
    // (same shape as `PolicyContext::as_value`), never the raw bytes.
    let content = raw.get("policy").unwrap_or(raw);
    let mut value = content.clone();
    if let Some(map) = value.as_object_mut() {
        map.remove("id");
        map.remove("source");
    }
    let kind = value.get("kind")?.as_str()?;
    match kind {
        "table" => {
            let pass_min = value
                .get("pass_min")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_PASS_MIN as u64);
            let bands = value.get("bands")?.as_array()?.clone();
            let mut sorted = bands;
            sorted.sort_by_key(|band| band.get("min").and_then(Value::as_u64).unwrap_or(u64::MAX));
            Some(json!({"kind":"table","pass_min":pass_min,"bands":sorted}))
        }
        "formula" => Some(json!({
            "kind":"formula",
            "a":value.get("a")?,
            "b":value.get("b")?,
            "c":value.get("c")?,
            "pass_min":value.get("pass_min").and_then(Value::as_u64).unwrap_or(DEFAULT_PASS_MIN as u64),
        })),
        _ => None,
    }
}

fn diff_value(
    baseline: &Value,
    current: &Calculation,
    context: &PolicyContext,
    courses: &[Course],
) -> Value {
    // The baseline must be a snapshot produced by this tool (or equivalent):
    // it must carry the same policy id and a parseable course list.
    let baseline_policy = baseline.get("policy");
    let baseline_policy_ok = baseline_policy
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        == Some(context.id.as_str());
    if !baseline_policy_ok {
        return json!({"error":"invalid_input","message":"baseline policy id does not match current policy"});
    }
    // A policy id is a label, not a version: the normalized policy content
    // must match as well, or the diff would re-score unchanged courses under
    // a silently different scale.
    let baseline_content = baseline_policy.and_then(normalized_policy_content);
    if baseline_content.as_ref() != Some(&context.as_value()) {
        return json!({"error":"invalid_input","message":"baseline policy content does not match current policy for the same id"});
    }
    let baseline_courses = match parse_baseline_courses(baseline) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let baseline_calc = compute(context, &baseline_courses);

    let mut baseline_by_name: BTreeMap<String, (u8, f64)> = BTreeMap::new();
    for course in &baseline_courses {
        baseline_by_name.insert(course.name.clone(), (course.score, course.credit));
    }
    let mut current_by_name: BTreeMap<String, (u8, f64)> = BTreeMap::new();
    for course in courses {
        current_by_name.insert(course.name.clone(), (course.score, course.credit));
    }

    let mut added: Vec<String> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    let mut changed: Vec<Value> = Vec::new();
    for (name, (score, credit)) in &current_by_name {
        match baseline_by_name.get(name) {
            None => added.push(name.clone()),
            Some((old_score, old_credit)) => {
                if old_score != score || (old_credit - credit).abs() > 1e-9 {
                    changed.push(json!({
                        "name": name,
                        "score": {"baseline": old_score, "current": score},
                        "credit": {"baseline": old_credit, "current": credit}
                    }));
                }
            }
        }
    }
    for name in baseline_by_name.keys() {
        if !current_by_name.contains_key(name) {
            removed.push(name.clone());
        }
    }
    added.sort();
    removed.sort();
    changed.sort_by(|a, b| a["name"].as_str().unwrap().cmp(b["name"].as_str().unwrap()));

    let gpa_baseline = baseline_calc.gpa;
    let gpa_current = current.gpa;
    let delta = match (gpa_baseline, gpa_current) {
        (Some(before), Some(after)) => Some(round4(after - before)),
        _ => None,
    };
    json!({
        "added": added,
        "removed": removed,
        "changed": changed,
        "gpa": {"baseline": gpa_baseline, "current": gpa_current, "delta": delta}
    })
}

// ---------------------------------------------------------------------------
// Baseline persistence (idempotent, atomic, local-only)
// ---------------------------------------------------------------------------

fn valid_baseline_path(path: &str) -> Result<PathBuf, Value> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') || !path.starts_with('/') {
        return Err(
            json!({"error":"invalid_input","message":"baseline path must be an absolute path within the length limit"}),
        );
    }
    Ok(PathBuf::from(path))
}

fn load_current(input: &str) -> Result<(PolicyContext, Vec<Course>, Calculation), Value> {
    let raw: Value = serde_json::from_str(input).map_err(|_| invalid())?;
    let context = parse_policy(&raw)?;
    let courses = parse_courses(&raw)?;
    let calculation = compute(&context, &courses);
    Ok((context, courses, calculation))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn without_timestamp(document: &Value) -> Value {
    let mut copy = document.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove("saved_at_unix_ms");
    }
    copy
}

fn baseline_document(context: &PolicyContext, calc: &Calculation) -> Value {
    json!({
        "schema_version": 1,
        "type": "gpa_baseline",
        "saved_at_unix_ms": now_unix_ms(),
        "policy": policy_provenance(context),
        "counted_credits": calc.counted_credits,
        "total_credits": calc.total_credits,
        "gpa": calc.gpa,
        "courses": calc.lines,
    })
}

/// Save the current input as a baseline at `path`. Idempotent: an identical
/// existing baseline (timestamp ignored) is reported unchanged and the file is
/// not rewritten.
pub fn baseline_save(input: &str, path: &str) -> Value {
    let path = match valid_baseline_path(path) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let (context, courses, calc) = match load_current(input) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let document = baseline_document(&context, &calc);
    let unchanged = fs::read_to_string(&path)
        .ok()
        .and_then(|existing| serde_json::from_str::<Value>(&existing).ok())
        .is_some_and(|existing_doc| {
            without_timestamp(&document) == without_timestamp(&existing_doc)
        });
    if unchanged {
        return json!({
            "schema_version":1,
            "type":"baseline_saved",
            "result":"unchanged",
            "path": path.to_string_lossy()
        });
    }
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty())
        && fs::create_dir_all(parent).is_err()
    {
        return unavailable("baseline directory could not be created");
    }
    // Atomic write: stage in the same directory, then rename over the target.
    let temp = path.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let body = format!("{}\n", serde_json::to_string(&document).unwrap());
    let outcome = match fs::write(&temp, body) {
        Ok(()) => match fs::rename(&temp, &path) {
            Ok(()) => true,
            Err(_) => {
                let _ = fs::remove_file(&temp);
                false
            }
        },
        Err(_) => false,
    };
    if !outcome {
        return unavailable("baseline could not be written");
    }
    json!({
        "schema_version":1,
        "type":"baseline_saved",
        "result":"saved",
        "path": path.to_string_lossy(),
        "policy": policy_provenance(&context),
        "gpa": calc.gpa,
        "course_count": courses.len()
    })
}

/// Load a baseline and report its provenance and recorded GPA.
pub fn baseline_show(path: &str) -> Value {
    let path = match valid_baseline_path(path) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let text = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(_) => return unavailable("baseline file is not readable"),
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            return json!({"error":"invalid_input","message":"baseline file is not valid JSON"});
        }
    };
    if doc.get("type").and_then(Value::as_str) != Some("gpa_baseline") {
        return json!({"error":"invalid_input","message":"baseline file has the wrong document type"});
    }
    doc
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

pub fn schema() -> Value {
    json!({"gpa": {
        "stdin": {"type":"object","required":["policy","courses"],
            "properties":{
                "policy":{"type":"object","required":["kind","id","source"],
                    "properties":{"id":{"type":"string","minLength":1},
                        "source":{"type":"string","minLength":1},
                        "kind":{"enum":["table","formula"]},
                        "pass_min":{"type":"integer","minimum":0,"maximum":100},
                        "bands":{"type":"array","items":{"type":"object","required":["min","max","point"]}},
                        "a":{"type":"number"},"b":{"type":"number"},"c":{"type":"number"}}},
                "courses":{"type":"array","items":{"type":"object","required":["name","score","credit"],
                    "properties":{"name":{"type":"string","minLength":1},
                        "score":{"type":"integer","minimum":0,"maximum":100},
                        "credit":{"type":"number","exclusiveMinimum":0}}}},
                "baseline":{"type":"object","description":"optional gpa_baseline document for the structured diff; must carry the same policy id and the same normalized policy content as the current input"}}},
        "output": {"type":"object","required":["schema_version","type","policy","courses","counted_credits","total_credits","gpa"],
            "properties":{"gpa":{"type":["number","null"],"minimum":0,"maximum":5},
                "diff":{"type":"object","required":["added","removed","changed","gpa"]}}},
        "policy_provenance":"every result carries the published policy id/source; no policy is embedded in the repository"
    },
    "baseline": {
        "operations": ["save <absolute-path>", "show <absolute-path>"],
        "save": {"stdin":"same as gpa input","result":"saved|unchanged (idempotent, atomic, local-only)"},
        "show": {"stdout":"the stored gpa_baseline document"}
    }})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE_POLICY: &str = r#"{
        "kind": "table",
        "id": "test-table",
        "source": "https://example.invalid/policy",
        "pass_min": 60,
        "bands": [
            {"min": 85, "max": 100, "point": 4.0},
            {"min": 75, "max": 84, "point": 3.0},
            {"min": 60, "max": 74, "point": 2.0}
        ]
    }"#;

    const FORMULA_POLICY: &str = r#"{
        "kind": "formula",
        "id": "test-formula",
        "source": "https://example.invalid/formula",
        "a": 4.0,
        "b": 3.0,
        "c": 1600.0
    }"#;

    #[test]
    fn table_policy_computes_weighted_gpa_and_excludes_failures() {
        let input = format!(
            r#"{{"policy":{},"courses":[
                {{"name":"课程A","score":92,"credit":4.0}},
                {{"name":"课程B","score":78,"credit":2.0}},
                {{"name":"课程C","score":59,"credit":3.0}}]}}"#,
            TABLE_POLICY
        );
        let out = gpa(&input);
        assert!(out.get("error").is_none());
        // 92 -> 4.0 (4cr), 78 -> 3.0 (2cr), 59 -> fail (excluded).
        // gpa = (4.0*4 + 3.0*2) / 6 = 22/6 = 3.6667
        assert_eq!(out["gpa"], 3.6667);
        assert_eq!(out["counted_credits"], 6.0);
        assert_eq!(out["total_credits"], 9.0);
        assert_eq!(out["courses"][2]["counts"], false);
        assert_eq!(out["courses"][2]["point"], 0.0);
    }

    #[test]
    fn formula_policy_matches_known_values() {
        let input = format!(
            r#"{{"policy":{},"courses":[{{"name":"X","score":100,"credit":1.0}}]}}"#,
            FORMULA_POLICY
        );
        let out = gpa(&input);
        assert_eq!(out["gpa"], 4.0);
        // 90 -> 4 - 3*100/1600 = 3.8125
        let input = format!(
            r#"{{"policy":{},"courses":[{{"name":"X","score":90,"credit":1.0}}]}}"#,
            FORMULA_POLICY
        );
        let out = gpa(&input);
        assert_eq!(out["gpa"], 3.8125);
    }

    #[test]
    fn no_countable_courses_yields_null_gpa() {
        let input = format!(
            r#"{{"policy":{},"courses":[{{"name":"Fail","score":40,"credit":1.0}}]}}"#,
            TABLE_POLICY
        );
        let out = gpa(&input);
        assert_eq!(out["gpa"], serde_json::Value::Null);
        assert_eq!(out["counted_credits"], 0.0);
    }

    #[test]
    fn diff_reports_added_removed_changed_and_gpa_delta() {
        let baseline = r#"{
            "policy":{"id":"test-table","source":"https://example.invalid/policy","policy":{"kind":"table","pass_min":60,"bands":[{"min":85,"max":100,"point":4.0},{"min":75,"max":84,"point":3.0},{"min":60,"max":74,"point":2.0}]}},
            "courses":[
                {"name":"课程A","score":92,"credit":4.0},
                {"name":"课程B","score":78,"credit":2.0}]
        }"#;
        let current = format!(
            r#"{{"policy":{},"courses":[
                {{"name":"课程A","score":92,"credit":4.0}},
                {{"name":"课程B","score":88,"credit":2.0}},
                {{"name":"课程D","score":95,"credit":2.0}}],
            "baseline":{}}}"#,
            TABLE_POLICY, baseline
        );
        let out = gpa(&current);
        assert_eq!(out["diff"]["added"], serde_json::json!(["课程D"]));
        assert_eq!(out["diff"]["removed"], serde_json::json!([]));
        assert_eq!(out["diff"]["changed"][0]["name"], "课程B");
        assert_eq!(out["diff"]["changed"][0]["score"]["baseline"], 78);
        assert_eq!(out["diff"]["changed"][0]["score"]["current"], 88);
        // baseline gpa = (4*4+3*2)/6 = 3.6667; current = (4*4+4*2+4*2)/8 = 4.0
        assert_eq!(out["diff"]["gpa"]["baseline"], 3.6667);
        assert_eq!(out["diff"]["gpa"]["current"], 4.0);
        assert_eq!(out["diff"]["gpa"]["delta"], 0.3333);
    }

    #[test]
    fn diff_with_policy_mismatch_is_invalid() {
        let baseline = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}]}}"#,
            FORMULA_POLICY
        );
        let current = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}],"baseline":{}}}"#,
            TABLE_POLICY, baseline
        );
        let out = gpa(&current);
        assert_eq!(out["diff"]["error"], "invalid_input");
    }

    #[test]
    fn diff_with_same_id_policy_content_change_is_invalid() {
        // Same id/source, one band re-scored: the diff must reject the
        // comparison instead of re-scoring unchanged courses under a
        // silently different scale.
        let mutated_policy = r#"{"kind":"table","id":"test-table","source":"https://example.invalid/policy","pass_min":60,"bands":[{"min":85,"max":100,"point":3.5},{"min":75,"max":84,"point":3.0},{"min":60,"max":74,"point":2.0}]}"#;
        let baseline = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}]}}"#,
            mutated_policy
        );
        let current = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}],"baseline":{}}}"#,
            TABLE_POLICY, baseline
        );
        let out = gpa(&current);
        assert_eq!(out["diff"]["error"], "invalid_input");
        assert_eq!(
            out["diff"]["message"],
            "baseline policy content does not match current policy for the same id"
        );
    }

    #[test]
    fn baseline_save_is_idempotent_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("buaa-marks-test-{}", std::process::id()));
        let path = dir.join("baseline.json");
        let _ = fs::remove_file(&path);
        let input = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}]}}"#,
            TABLE_POLICY
        );
        let first = baseline_save(&input, path.to_str().unwrap());
        assert_eq!(first["result"], "saved");
        // Re-save after a time step: identical content -> unchanged.
        let second = baseline_save(&input, path.to_str().unwrap());
        assert_eq!(second["result"], "unchanged");
        let shown = baseline_show(path.to_str().unwrap());
        assert_eq!(shown["type"], "gpa_baseline");
        assert_eq!(shown["gpa"], 4.0);
        assert_eq!(shown["policy"]["id"], "test-table");
        // A different current -> saved again.
        let changed = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":88,"credit":4.0}}]}}"#,
            TABLE_POLICY
        );
        let third = baseline_save(&changed, path.to_str().unwrap());
        assert_eq!(third["result"], "saved");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_baseline_drives_diff_round_trip() {
        let dir = std::env::temp_dir().join(format!("buaa-marks-rt-{}", std::process::id()));
        let path = dir.join("baseline.json");
        let _ = fs::remove_file(&path);
        let current = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":92,"credit":4.0}}]}}"#,
            TABLE_POLICY
        );
        let saved = baseline_save(&current, path.to_str().unwrap());
        assert_eq!(saved["result"], "saved");
        // The stored gpa_baseline (with derived point/counts fields) must parse
        // as a diff baseline, not be rejected by the strict input schema.
        let baseline = baseline_show(path.to_str().unwrap());
        let later = format!(
            r#"{{"policy":{},"courses":[{{"name":"课程A","score":88,"credit":4.0}},{{"name":"课程B","score":90,"credit":2.0}}],"baseline":{}}}"#,
            TABLE_POLICY, baseline
        );
        let out = gpa(&later);
        assert!(out.get("error").is_none());
        assert_eq!(out["diff"]["added"], serde_json::json!(["课程B"]));
        assert_eq!(out["diff"]["removed"], serde_json::json!([]));
        assert_eq!(out["diff"]["changed"][0]["name"], "课程A");
        assert_eq!(out["diff"]["changed"][0]["score"]["baseline"], 92);
        assert_eq!(out["diff"]["changed"][0]["score"]["current"], 88);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn score_over_100_and_error_echo_are_rejected() {
        // score 150 must not count as a pass; it is invalid input.
        let over = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":150,"credit":1.0}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(gpa(&over)["error"], "invalid_input");
        // A top-level "error" field in the input is data, not an echoed result.
        let echo = format!(
            r#"{{"error":"bogus","policy":{},"courses":[{{"name":"A","score":92,"credit":4.0}}]}}"#,
            TABLE_POLICY
        );
        let out = gpa(&echo);
        assert!(out.get("error").is_none());
        assert_eq!(out["type"], "gpa_calculation");
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert_eq!(gpa("not json")["error"], "invalid_input");
        // Missing policy provenance.
        let out = gpa(r#"{"policy":{"kind":"formula","a":4.0,"b":3.0,"c":1600.0},"courses":[]}"#);
        assert_eq!(out["error"], "invalid_input");
        // Table with a gap.
        let gap = r#"{"policy":{"kind":"table","id":"x","source":"y","pass_min":60,
            "bands":[{"min":60,"max":80,"point":2.0},{"min":85,"max":100,"point":4.0}]},
            "courses":[]}"#;
        assert_eq!(gpa(gap)["error"], "invalid_input");
        // Overlapping/ascending table.
        let overlap = r#"{"policy":{"kind":"table","id":"x","source":"y","pass_min":60,
            "bands":[{"min":60,"max":90,"point":2.0},{"min":80,"max":100,"point":4.0}]},
            "courses":[]}"#;
        assert_eq!(gpa(overlap)["error"], "invalid_input");
        // Duplicate course names.
        let dup = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":1.0}},{{"name":"A","score":80,"credit":1.0}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(gpa(&dup)["error"], "invalid_input");
        // Zero/negative credit.
        let bad_credit = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":0.0}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(gpa(&bad_credit)["error"], "invalid_input");
        // Non-absolute baseline path.
        let out = baseline_save(
            &format!(r#"{{"policy":{},"courses":[]}}"#, TABLE_POLICY),
            "relative/path.json",
        );
        assert_eq!(out["error"], "invalid_input");
    }
}
